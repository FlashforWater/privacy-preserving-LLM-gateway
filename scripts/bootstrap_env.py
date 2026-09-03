#!/usr/bin/env python3
"""Fill the local ``.env`` with freshly generated development keys.

Refuses to touch a file whose ``APP_ENV`` is a production environment: this
script generates keys on a developer machine, and those must never become the
keys a production deployment uses.
"""

from __future__ import annotations

import base64
import os
import re
import sys
from pathlib import Path

ENV_PATH = Path(".env")


def main() -> int:
    if not ENV_PATH.exists():
        print(".env not found; copy .env.example first", file=sys.stderr)
        return 1
    text = ENV_PATH.read_text(encoding="utf-8")

    match = re.search(r"^APP_ENV=(.*)$", text, flags=re.M)
    if match and match.group(1).strip() in ("staging", "production"):
        print(
            "refusing to write development keys into a production .env; "
            "production keys come from the secret manager",
            file=sys.stderr,
        )
        return 2

    for name in ("VAULT_MASTER_KEY_B64", "VAULT_HMAC_KEY_B64"):
        value = base64.b64encode(os.urandom(32)).decode()
        line = f"{name}={value}"
        text, count = re.subn(rf"^{name}=.*$", line, text, flags=re.M)
        if count == 0:
            text += ("" if text.endswith("\n") else "\n") + line + "\n"

    ENV_PATH.write_text(text, encoding="utf-8")
    ENV_PATH.chmod(0o600)
    print("wrote development vault keys into .env (mode 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
