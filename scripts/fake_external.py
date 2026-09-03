#!/usr/bin/env python3
"""Development/test-only external provider.

Two jobs:

1. answer like an OpenAI-compatible endpoint so the whole pipeline can run
   offline;
2. **record exactly what crossed the boundary** so tests and the deployment
   checklist can assert that protected fixture content never left the gateway
   (guide §19.5, §22.2).

It echoes any gateway tokens it received, which is what makes the restoration
path exercisable end to end without a real model.

Standard library only, so it starts instantly in CI and adds no dependency to the
runtime image.
"""

from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN_RE = re.compile(r"\[\[PGW_V1_[A-Z_]+_[A-Z0-9]{12}\]\]")

CAPTURED: list[dict[str, object]] = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        return  # captured bodies must not reach stdout

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/captured":
            self._json(200, {"requests": CAPTURED})
        elif self.path == "/captured/reset":
            CAPTURED.clear()
            self._json(200, {"cleared": True})
        elif self.path.startswith("/v1/models"):
            self._json(200, {"data": [{"id": "model-a"}, {"id": "external-vlm-model"}]})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        CAPTURED.append(
            {
                "path": self.path,
                "idempotency_key": self.headers.get("Idempotency-Key"),
                "body": payload,
                "raw_size": len(raw),
            }
        )

        text_parts: list[str] = []
        image_count = 0
        for message in payload.get("messages", []):
            content = message.get("content")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
                    elif part.get("type") == "image_url":
                        image_count += 1

        joined = "\n".join(text_parts)
        tokens = TOKEN_RE.findall(joined)
        reply = (
            f"Analysed {len(text_parts)} text part(s) and {image_count} image(s). "
            + (f"Subjects referenced: {', '.join(dict.fromkeys(tokens))}." if tokens else "No identifiers were present.")
        )

        self._json(
            200,
            {
                "id": "fake-completion",
                "model": payload.get("model", "model-a"),
                "choices": [
                    {"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": reply}}
                ],
                "usage": {"prompt_tokens": len(joined) // 4, "completion_tokens": 32},
            },
        )

    def _json(self, status: int, body: dict[str, object]) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> int:
    port = int(os.environ.get("FAKE_EXTERNAL_PORT", "9100"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104
    print(f"fake external provider listening on :{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
