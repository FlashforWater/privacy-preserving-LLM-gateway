#!/usr/bin/env python3
"""Manual smoke cases from guide §20.3.

Run against a live gateway::

    python scripts/smoke_test.py http://localhost:8080 dev-token-1

Never use real personal data here. Every value below is synthetic.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
import uuid

SYNTHETIC_ID = "110101199003079999"      # valid checksum, not a real person
SYNTHETIC_PHONE = "13812345678"


def _post(url: str, token: str, *, fields: dict[str, str],
          files: dict[str, tuple[str, bytes, str]] | None = None) -> dict:
    boundary = uuid.uuid4().hex
    body = bytearray()
    for name, value in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += value.encode() + b"\r\n"
    for name, (filename, data, mime) in (files or {}).items():
        body += f"--{boundary}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode()
        body += data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    request = urllib.request.Request(
        url, data=bytes(body), method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Idempotency-Key": uuid.uuid4().hex,
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())


def _create_scope(base: str, token: str) -> str:
    request = urllib.request.Request(
        f"{base}/v1/scopes", data=b"{}", method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())["scope_id"]


def _manifest(text: str, purpose: str = "general") -> str:
    return json.dumps(
        {
            "purpose": purpose,
            "model": "model-a",
            "messages": [
                {"role": "user", "content": [{"type": "text", "item_id": "p1", "text": text}]}
            ],
        }
    )


def main(argv: list[str]) -> int:
    base = argv[1].rstrip("/") if len(argv) > 1 else "http://localhost:8080"
    token = argv[2] if len(argv) > 2 else "dev-token-1"
    failures = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        status = "PASS" if condition else "FAIL"
        if not condition:
            failures += 1
        print(f"[{status}] {name}{'  ' + detail if detail else ''}")

    # 1. Safe question takes the fast path.
    scope = _create_scope(base, token)
    result = _post(f"{base}/v1/scopes/{scope}/messages", token,
                   fields={"manifest": _manifest("What documents are needed for a claim?")})
    check("safe question uses fast path", result["privacy"]["path"] == "fast",
          f"path={result['privacy']['path']}")

    # 2. Synthetic name + phone: sanitized path, response restored.
    scope = _create_scope(base, token)
    result = _post(
        f"{base}/v1/scopes/{scope}/messages", token,
        fields={"manifest": _manifest(f"Patient: Wei Zhang, phone {SYNTHETIC_PHONE}. Summarise.")},
    )
    check("identifiers take sanitized path", result["privacy"]["path"] == "sanitized")
    check("tokenize action recorded", result["privacy"]["actions"].get("TOKENIZE", 0) > 0,
          str(result["privacy"]["actions"]))

    # 3. Same scope, second turn: scope stays locked.
    result = _post(f"{base}/v1/scopes/{scope}/messages", token,
                   fields={"manifest": _manifest("Any follow-up questions?")})
    check("scope stays SANITIZED_LOCKED", result["privacy"]["path"] == "sanitized",
          f"mode={result['privacy']['scope_privacy_mode']}")

    # 4. Medical content is blocked without the purpose override.
    scope = _create_scope(base, token)
    try:
        _post(f"{base}/v1/scopes/{scope}/messages", token,
              fields={"manifest": _manifest("Diagnosis: acute hepatitis, ALT 320 U/L.")})
        check("medical data blocked by default", False, "request was accepted")
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())
        check("medical data blocked by default",
              exc.code == 422 and body["error"]["code"] == "CONTENT_BLOCKED",
              f"{exc.code} {body['error']['code']}")

    # 5. Same content under the approved purpose passes, identifiers still tokenized.
    scope = _create_scope(base, token)
    result = _post(
        f"{base}/v1/scopes/{scope}/messages", token,
        fields={
            "manifest": _manifest(
                f"Patient: Wei Zhang, ID {SYNTHETIC_ID}. Diagnosis: acute hepatitis, ALT 320 U/L.",
                purpose="medical_report_analysis",
            )
        },
    )
    check("medical purpose override permits analysis", result["status"] == "completed")
    check("identifiers still tokenized under override",
          result["privacy"]["actions"].get("TOKENIZE", 0) > 0)

    # 6. Closed scope refuses further messages.
    urllib.request.urlopen(
        urllib.request.Request(
            f"{base}/v1/scopes/{scope}/close", data=b"", method="POST",
            headers={"Authorization": f"Bearer {token}"},
        ),
        timeout=30,
    )
    try:
        _post(f"{base}/v1/scopes/{scope}/messages", token,
              fields={"manifest": _manifest("hello")})
        check("closed scope rejects messages", False, "request was accepted")
    except urllib.error.HTTPError as exc:
        check("closed scope rejects messages", exc.code == 409, f"HTTP {exc.code}")

    print()
    print("smoke test:", "all checks passed" if failures == 0 else f"{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
