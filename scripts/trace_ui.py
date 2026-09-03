#!/usr/bin/env python3
"""Local pipeline inspector.

Serves one page that runs a request through the real gateway and shows every
stage: what arrived, what each detector found, what policy decided, what actually
crossed the boundary, what came back, and what restoration produced.

    python scripts/trace_ui.py            # http://127.0.0.1:8090

**Development only, and it refuses to start otherwise.** The page displays
original text, matched finding values and the token mapping table — precisely
what the gateway exists to keep inside. It is a script rather than a route in
``app/`` so that it cannot be switched on in a deployed service by flipping a
flag: to run it, someone has to run this file.

It binds to loopback for the same reason.

The trace comes from the real orchestrator through its ``trace`` hook, not from a
reimplementation. A debugging view that quietly diverges from the code is worse
than none — it builds confidence in behaviour that is not there.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import threading
import traceback
from collections.abc import Coroutine
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TypeVar

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import Principal, get_settings  # noqa: E402
from app.core.deadlines import Deadline  # noqa: E402
from app.core.errors import GatewayError, InvalidRequest  # noqa: E402
from app.detectors.image_classifier import HeuristicImageClassifier  # noqa: E402
from app.detectors.keyword_detector import KeywordDetector  # noqa: E402
from app.detectors.local_model_detector import (  # noqa: E402
    LocalModelDetector,
    OpenAICompatibleLocalModel,
)
from app.detectors.regex_detector import RegexDetector  # noqa: E402
from app.domain.content import Manifest  # noqa: E402
from app.domain.requests import RequestContext  # noqa: E402
from app.domain.scopes import ScopeLimits  # noqa: E402
from app.external.openai_compatible import OpenAICompatibleAdapter  # noqa: E402
from app.gateway.normalizer import Normalizer  # noqa: E402
from app.gateway.orchestrator import Orchestrator, OrchestratorDependencies  # noqa: E402
from app.gateway.scope_service import InMemoryScopeStore, ScopeService  # noqa: E402
from app.gateway.trace import TraceRecorder  # noqa: E402
from app.ocr.local_ocr import build_ocr_engine  # noqa: E402
from app.parsers.base import ParserLimits, ParserRegistry, sniff_mime  # noqa: E402
from app.parsers.docx import DocxParser  # noqa: E402
from app.parsers.image import ImageParser  # noqa: E402
from app.parsers.pdf import PdfParser  # noqa: E402
from app.parsers.pdf_render import PdfiumRenderer  # noqa: E402
from app.parsers.plain_text import PlainTextParser  # noqa: E402
from app.parsers.xlsx import XlsxParser  # noqa: E402
from app.policy.engine import PolicyEngine  # noqa: E402
from app.policy.loader import get_policy  # noqa: E402
from app.restore.restorer import Restorer  # noqa: E402
from app.vault.crypto import StaticKeyProvider, VaultCipher  # noqa: E402
from app.vault.memory_vault import MemoryVault  # noqa: E402

HTML_PATH = Path(__file__).parent / "trace_ui.html"

SAMPLE = """理赔申请材料
被保险人  张伟          身份证号 320502199003079999
联系电话 138-1234-5678   详细地址 江苏省苏州市工业园区星海街88号3幢501室
号牌号码 苏E·12345      投保单位 苏州捷安汽车服务有限公司

出险经过：2026年3月4日15时40分，张伟驾车在路口与王秀英车辆碰撞，气囊未弹出，
车辆受损轻微。张伟当场受伤，送往苏州市立医院急诊科，接诊医师李建国，
诊断：左尺骨骨折，建议休治45天。患者既往2019年左尺骨骨折史。
发票付款人 张伟，金额 18642.35 元。

请判断：伤情与事故形态是否吻合，是否存在既往伤，材料间有无矛盾。
涉及当事人时请使用材料中的标记指代。"""


T = TypeVar("T")


class LoopRunner:
    """One event loop for the process, on a background thread.

    ``asyncio.run`` per request looks tidy and is wrong here: the httpx clients
    inside the local-model and provider adapters are created lazily and cached,
    so they bind to the loop of whichever request built them. The next request
    gets a fresh loop, the pooled connection still points at the closed one, and
    the second run dies with "Event loop is closed" while the first looked fine.

    The gateway itself does not have this problem — uvicorn keeps one loop for
    the process lifetime — so this is the debug server matching the runtime it is
    pretending to be. Serialising requests is a bonus: one trace at a time is
    what a person reading the page wants anyway.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="trace-loop")
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def submit(self, coro: Coroutine[Any, Any, T], timeout: float) -> T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)


class Gateway:
    """One long-lived gateway with an in-memory scope store and vault."""

    def __init__(self) -> None:
        settings = get_settings()
        if settings.is_production:
            raise SystemExit(
                "trace_ui exposes original content and token mappings; "
                f"refusing to run with APP_ENV={settings.app_env}"
            )
        self.settings = settings
        policy = PolicyEngine(get_policy(settings.policy_file))
        limits = policy.document.limits

        cipher = VaultCipher(
            StaticKeyProvider(master=settings.vault_master_key(), hmac=settings.vault_hmac_key())
        )
        self.scope_store = InMemoryScopeStore()
        self.vault = MemoryVault(cipher, self.scope_store.live_scopes())
        self.scopes = ScopeService(
            self.scope_store, self.vault,
            limits=ScopeLimits(
                max_turns=limits.max_scope_turns, max_files=limits.max_scope_files,
                max_bytes=limits.max_scope_bytes, max_pages=limits.max_scope_pages,
                max_mappings=limits.max_scope_mappings,
            ),
            idle_ttl_seconds=settings.scope_idle_ttl_seconds,
            absolute_ttl_seconds=settings.scope_absolute_ttl_seconds,
            policy_version=policy.version,
        )

        ocr = build_ocr_engine(settings.ocr_backend)
        parser_limits = ParserLimits(
            max_file_bytes=limits.max_file_bytes, max_pages=limits.max_scope_pages,
            max_ocr_pixels=limits.max_ocr_pixels,
        )
        self.parser_limits = parser_limits
        self.local_model = OpenAICompatibleLocalModel(
            base_url=settings.local_model_base_url, model=settings.local_model_name,
            api_key=settings.local_model_api_key,
            timeout_seconds=settings.local_model_timeout_seconds,
            disable_thinking=settings.local_model_disable_thinking,
            max_tokens=settings.local_model_max_tokens, prompt=settings.local_model_prompt,
        )
        vision_classifier = None
        if settings.local_model_image_analysis:
            from app.detectors.vlm_image_classifier import LocalVlmImageClassifier

            vision_classifier = LocalVlmImageClassifier(
                base_url=settings.local_model_base_url,
                model=settings.local_model_name,
                api_key=settings.local_model_api_key,
                timeout_seconds=settings.local_model_timeout_seconds,
            )

        self.adapter = OpenAICompatibleAdapter(
            base_url=settings.external_base_url, api_key=settings.external_api_key,
            allowed_models=settings.allowed_models,
            timeout_seconds=settings.external_timeout_seconds,
            reasoning=settings.external_reasoning,
            vision_models=settings.vision_models,
            model_temperatures=settings.model_temperatures,
        )
        self.orchestrator = Orchestrator(
            OrchestratorDependencies(
                policy=policy,
                parsers=ParserRegistry([
                    PlainTextParser(), DocxParser(), XlsxParser(),
                    PdfParser(ocr_engine=ocr, renderer=PdfiumRenderer(
                        max_pixels=limits.max_ocr_pixels)),
                    ImageParser(ocr_engine=ocr, classifier=HeuristicImageClassifier()),
                ]),
                regex_detector=RegexDetector(),
                keyword_detector=KeywordDetector(),
                local_model_detector=LocalModelDetector(self.local_model),
                adapter=self.adapter,
                vision_classifier=vision_classifier,
                vault=self.vault,
                restorer=Restorer(self.vault),
                hmac_key=settings.vault_hmac_key(),
                mapping_ttl_seconds=settings.mapping_ttl_seconds,
                parser_limits=parser_limits,
                scope_limits=self.scopes.limits,
                allowed_models=settings.allowed_models,
            )
        )
        self.normalizer = Normalizer(
            max_request_bytes=limits.max_request_bytes, max_file_bytes=limits.max_file_bytes
        )
        self.principal = Principal(
            principal_id="trace-ui", tenant_id="tenant-local",
            allowed_purposes=frozenset({"general", "medical_report_analysis"}),
        )
        self.model = sorted(settings.allowed_models)[0] if settings.allowed_models else ""

    async def run(
        self,
        text: str,
        purpose: str,
        scope_id: str | None,
        uploads: list[dict[str, str]] | None = None,
        model: str | None = None,
    ) -> dict:
        scope = (
            await self.scopes.require_active(
                tenant_id=self.principal.tenant_id, scope_id=scope_id
            )
            if scope_id
            else await self.scopes.create(tenant_id=self.principal.tenant_id)
        )
        content: list[dict[str, str]] = []
        files: dict[str, bytes] = {}
        if text.strip():
            content.append({"type": "text", "item_id": "prompt-1", "text": text})
        for index, upload in enumerate(uploads or [], start=1):
            data = base64.b64decode(upload["b64"])
            item_id = f"file-{index}"
            field = f"file_{item_id}"
            files[field] = data
            # The real API has the client declare file vs image, because it knows
            # what it is sending. Here the type is derived from the bytes so that
            # dragging a photo in routes it as a photo — a convenience of the
            # inspector, not of the gateway.
            try:
                mime = sniff_mime(data, filename=upload.get("name"))
            except GatewayError:
                mime = "application/octet-stream"
            content.append({
                "type": "image" if mime.startswith("image/") else "file",
                "item_id": item_id,
                "file_field": field,
                "filename": upload.get("name") or item_id,
            })
        if not content:
            raise InvalidRequest("nothing to inspect", public_detail="nothing to inspect")

        chosen = model if model in self.settings.allowed_models else self.model
        manifest = Manifest.model_validate({
            "purpose": purpose, "model": chosen,
            "messages": [{"role": "user", "content": content}],
        })
        normalized = self.normalizer.normalize(manifest, files, self.parser_limits)
        await self.scopes.admit_turn(
            scope, files=normalized.file_count, byte_count=normalized.total_bytes
        )
        context = RequestContext.create(
            principal=self.principal, scope=scope, manifest=manifest,
            deadline=Deadline.after(self.settings.request_deadline_seconds),
        )
        recorder = TraceRecorder()
        result: dict = {
            "scope_id": scope.scope_id,
            "request_id": context.request_id,
            "input": text,
            "purpose": purpose,
            "model": chosen,
            "attachments": [
                {
                    "item_id": item.item_id,
                    "filename": item.filename,
                    "bytes": item.byte_size,
                    "detected_mime": item.detected_mime,
                    "declared_type": item.item_type.value,
                }
                for item in normalized.items
                if item.is_attachment
            ],
        }
        try:
            response = await self.orchestrator.process(context, normalized, trace=recorder)
            await self.scopes.complete_turn(
                scope, files=normalized.file_count,
                byte_count=normalized.total_bytes, pages=0,
            )
            result["status"] = "completed"
            result["output"] = response.output
            result["privacy"] = json.loads(response.privacy.model_dump_json())
        except GatewayError as exc:
            # A blocked or failed-closed request is the interesting case, not an
            # error to hide: the stages recorded before it explain the decision.
            result["status"] = "failed"
            result["error"] = {"code": exc.code, "detail": exc.public_detail,
                               "message": str(exc), "meta": dict(exc.meta)}
        result["stages"] = recorder.to_json_obj()
        result["scope_privacy_mode"] = scope.privacy_mode.value
        result["mappings"] = await self._mappings(scope.scope_id)
        return result

    async def _mappings(self, scope_id: str) -> list[dict]:
        """The vault contents, decrypted. Local view only — see module docstring."""
        out: list[dict] = []
        for (tenant, scope, token), mapping in self.vault._by_token.items():  # noqa: SLF001
            if scope != scope_id:
                continue
            original = await self.vault.resolve(
                tenant_id=tenant, scope_id=scope, token=token
            )
            out.append({"token": token, "entity_type": mapping.entity_type.value,
                        "original": original})
        return sorted(out, key=lambda m: m["token"])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    gateway: Gateway
    loop: LoopRunner

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            body = HTML_PATH.read_bytes()
            self._send(200, body, "text/html; charset=utf-8")
        elif self.path == "/api/config":
            self._json(200, {
                "local_model": {
                    "base_url": self.gateway.settings.local_model_base_url,
                    "model": self.gateway.settings.local_model_name,
                    "thinking_disabled": self.gateway.settings.local_model_disable_thinking,
                    "prompt": self.gateway.settings.local_model_prompt,
                },
                "external": {
                    "base_url": self.gateway.settings.external_base_url,
                    "model": self.gateway.model,
                    "models": sorted(self.gateway.settings.allowed_models),
                    "vision_models": sorted(self.gateway.settings.vision_models),
                    "reasoning": self.gateway.settings.external_reasoning,
                },
                "policy_version": self.gateway.orchestrator.deps.policy.version,
                "sample": SAMPLE,
            })
        else:
            self._json(404, {"error": "not found"})

    MAX_BODY_BYTES = 64 * 1024 * 1024

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/trace":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > self.MAX_BODY_BYTES:
            self._json(413, {"error": "payload too large",
                             "message": f"body exceeds {self.MAX_BODY_BYTES} bytes"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return
        try:
            result = self.loop.submit(
                self.gateway.run(
                    payload.get("text") or "",
                    payload.get("purpose") or "general",
                    payload.get("scope_id") or None,
                    payload.get("files") or [],
                    payload.get("model"),
                ),
                timeout=self.gateway.settings.request_deadline_seconds + 30,
            )
        except Exception as exc:  # noqa: BLE001 - a debug tool should show the failure
            self._json(500, {"error": type(exc).__name__, "message": str(exc),
                             "traceback": traceback.format_exc()[-3000:]})
            return
        self._json(200, result)

    def _json(self, status: int, body: dict) -> None:
        self._send(status, json.dumps(body, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    port = int(os.environ.get("TRACE_UI_PORT", "8090"))
    Handler.gateway = Gateway()
    Handler.loop = LoopRunner()
    # Loopback only. The page shows unredacted content by design.
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"pipeline inspector: http://127.0.0.1:{port}")
    print("development only — this page shows original content and token mappings")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
