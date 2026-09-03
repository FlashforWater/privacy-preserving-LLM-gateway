"""Safe logging (guide §17.3).

The allow-list is the mechanism, not the redaction filter. ``safe_extra`` drops
every field that is not explicitly permitted, so a new call site cannot leak a
payload by accident — the worst it can do is log nothing.

The redaction filter underneath is a second line of defence for third-party
libraries that log on our behalf. It is explicitly *not* a licence to pass
payloads into the logger and rely on scrubbing.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import sys
from typing import Any

#: Fields that may appear in a log record (guide §17.3).
ALLOWED_LOG_FIELDS: frozenset[str] = frozenset(
    {
        "request_id",
        "scope_id",
        "tenant_hash",
        "principal_hash",
        "route",
        "method",
        "status",
        "status_code",
        "duration_ms",
        "bytes_in",
        "bytes_out",
        "item_count",
        "file_count",
        "policy_version",
        "path",
        "action_counts",
        "entity_counts",
        "finding_count",
        "component",
        "result_code",
        "provider_status",
        "error_code",
        "reason_code",
        "stage",
        "attempt",
        "token_count",
        "restored_count",
        "unknown_token_count",
    }
)

_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(authorization|api[-_]?key|bearer)\b\s*[:=]\s*\S+"),
    re.compile(r"\b\d{12,19}\b"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\[\[PGW_V1_[A-Z_]+_[A-Z0-9]+\]\]"),
)


class RedactionFilter(logging.Filter):
    """Backstop scrubber for messages produced outside our call sites."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never let logging raise
            record.msg = "<unformattable log record suppressed>"
            record.args = ()
            return True
        redacted = message
        for pattern in _SENSITIVE_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.addFilter(RedactionFilter())
    if json_output:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
        )
    root.addHandler(handler)
    root.setLevel(level.upper())
    # Access logs would echo user-controlled paths and query strings.
    logging.getLogger("uvicorn.access").disabled = True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json

        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "safe", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            # Type and location only: a traceback's local variables can contain payloads.
            payload["exc_type"] = getattr(record.exc_info[0], "__name__", "Exception")
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def safe_extra(**fields: Any) -> dict[str, Any]:
    """Build the ``extra=`` payload for a log call, dropping non-allow-listed keys."""
    kept = {k: v for k, v in fields.items() if k in ALLOWED_LOG_FIELDS}
    return {"safe": kept}


def pseudonymous_id(value: str, key: bytes) -> str:
    """Stable, non-reversible id for tenants and principals in logs."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def content_fingerprint(value: str, key: bytes) -> str:
    """Keyed fingerprint used in place of raw finding text (guide §7.3).

    Keyed, not a bare hash: an unsalted digest of a phone number is trivially
    reversed by enumeration, which would turn the audit log into a lookup table.
    """
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
