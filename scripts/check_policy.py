#!/usr/bin/env python3
"""Validate a policy file. Used by CI and by ``make lint``.

Exits non-zero on any validation failure so a policy that would stop the service
from becoming ready cannot be merged.
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.core.errors import ConfigurationError
from app.policy.loader import load_policy_document


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path("config/policy.default.yaml")
    try:
        policy = load_policy_document(path)
    except ConfigurationError as exc:
        print(f"INVALID  {path}: {exc}", file=sys.stderr)
        return 1
    print(f"valid    {path}  version={policy.version}")
    print(f"         entities={len(policy.entities)} content_classes={len(policy.content_classes)}")
    print(f"         purpose_overrides={len(policy.purpose_overrides)}")
    for entity, rule in sorted(policy.entities.items(), key=lambda kv: kv[0].value):
        print(f"         {entity.value:20s} {rule.action.value:32s} min_conf={rule.minimum_confidence}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
