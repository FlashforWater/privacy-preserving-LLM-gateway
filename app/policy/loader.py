"""Policy loading and validation.

No hot reload (guide §9.4): different workers evaluating the same conversation
under different policies is worse than a restart. The file is read once at
startup, validated, and then frozen for the process lifetime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.core.errors import ConfigurationError

from .schema import PolicyDocument


def load_policy_document(path: Path | str) -> PolicyDocument:
    policy_path = Path(path)
    if not policy_path.is_file():
        raise ConfigurationError(f"policy file not found: {policy_path}")
    try:
        raw: Any = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"policy file is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("policy file must contain a mapping at the top level")
    try:
        return PolicyDocument.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 - re-raised as a startup failure
        raise ConfigurationError(f"policy file failed validation: {exc}") from exc


_CACHE: dict[str, PolicyDocument] = {}


def get_policy(path: Path | str) -> PolicyDocument:
    """Process-lifetime cache. Deploy a new version to change the policy."""
    key = str(Path(path).resolve())
    if key not in _CACHE:
        _CACHE[key] = load_policy_document(key)
    return _CACHE[key]


def clear_policy_cache() -> None:
    """Test hook only."""
    _CACHE.clear()
