#!/usr/bin/env python3
"""Print base64 keys for local development.

Development only. Production keys come from a KMS or secret manager and are never
generated on a developer machine or written to a file in the repository.
"""

from __future__ import annotations

import base64
import os

if __name__ == "__main__":
    print(f"VAULT_MASTER_KEY_B64={base64.b64encode(os.urandom(32)).decode()}")
    print(f"VAULT_HMAC_KEY_B64={base64.b64encode(os.urandom(32)).decode()}")
