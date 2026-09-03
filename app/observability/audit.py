"""Decision audit records (guide §17.4).

Metadata only. An audit record answers "what did the gateway decide, under which
policy, and what did it forward" — never "what did the content say". Findings are
serialized through :meth:`Finding.to_audit_dict`, which emits a keyed fingerprint
instead of the matched text.

Records are emitted through the safe logger, so even a mistake in this module
cannot put a payload in the log: the allow-list filter drops unknown fields.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import safe_extra
from app.domain.decisions import DecisionBundle
from app.domain.findings import Finding

logger = logging.getLogger("gateway.audit")


@dataclass(slots=True)
class AuditRecord:
    request_id: str
    scope_id: str
    tenant_hash: str
    principal_hash: str
    policy_version: str
    path: str = ""
    outcome: str = ""
    item_count: int = 0
    finding_count: int = 0
    action_counts: dict[str, int] = field(default_factory=dict)
    entity_counts: dict[str, int] = field(default_factory=dict)
    withheld_item_ids: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    error_code: str | None = None
    stage: str | None = None

    def add_findings(self, findings: list[Finding]) -> None:
        self.finding_count += len(findings)
        for finding in findings:
            self.entity_counts[finding.entity_type.value] = (
                self.entity_counts.get(finding.entity_type.value, 0) + 1
            )
            self.findings.append(finding.to_audit_dict())

    def add_decisions(self, bundle: DecisionBundle) -> None:
        self.action_counts = bundle.action_counts()
        self.withheld_item_ids = list(bundle.withheld_item_ids())

    def emit(self) -> None:
        logger.info(
            "gateway.request.decided",
            extra=safe_extra(
                request_id=self.request_id,
                scope_id=self.scope_id,
                tenant_hash=self.tenant_hash,
                principal_hash=self.principal_hash,
                policy_version=self.policy_version,
                path=self.path,
                status=self.outcome,
                item_count=self.item_count,
                finding_count=self.finding_count,
                action_counts=self.action_counts,
                entity_counts=self.entity_counts,
                error_code=self.error_code,
                stage=self.stage,
            ),
        )
