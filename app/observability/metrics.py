"""Prometheus metrics (guide §22.3).

Label values are drawn from closed vocabularies only — entity types, actions,
reason codes, component names, status categories. No scope id, request id,
tenant id, filename or any payload-derived string is ever a label: those are
unbounded cardinality *and* they would leak content into a system that is
explicitly not allowed to see it.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

requests_total = Counter(
    "gateway_requests_total",
    "Gateway requests by forward path and outcome.",
    ("path", "outcome"),
    registry=REGISTRY,
)

request_duration_seconds = Histogram(
    "gateway_request_duration_seconds",
    "End-to-end request duration by forward path.",
    ("path",),
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 40, 80, 120),
    registry=REGISTRY,
)

findings_total = Counter(
    "gateway_findings_total",
    "Findings produced, by entity type and detector source.",
    ("entity_type", "source"),
    registry=REGISTRY,
)

policy_actions_total = Counter(
    "gateway_policy_actions_total",
    "Policy decisions, by action and reason code.",
    ("action", "reason_code"),
    registry=REGISTRY,
)

component_errors_total = Counter(
    "gateway_component_errors_total",
    "Component failures, by component and result code.",
    ("component", "result_code"),
    registry=REGISTRY,
)

fail_closed_total = Counter(
    "gateway_fail_closed_total",
    "Requests that failed closed, by stage.",
    ("stage",),
    registry=REGISTRY,
)

tokens_issued_total = Counter(
    "gateway_tokens_issued_total",
    "Tokens minted, by entity type.",
    ("entity_type",),
    registry=REGISTRY,
)

tokens_restored_total = Counter(
    "gateway_tokens_restored_total",
    "Tokens restored in provider responses.",
    registry=REGISTRY,
)

unattributed_responses_total = Counter(
    "gateway_unattributed_responses_total",
    "Sanitized requests whose reply referenced none of the tokens sent. The "
    "analysis may be fine, but no conclusion in it can be attributed to a person.",
    registry=REGISTRY,
)

unknown_tokens_total = Counter(
    "gateway_unknown_tokens_total",
    "Token-shaped strings in provider responses that did not resolve. "
    "A rise here means the provider is inventing tokens.",
    registry=REGISTRY,
)

escaped_token_like_total = Counter(
    "gateway_escaped_token_like_total",
    "Token-shaped strings found in caller content and escaped before sanitization.",
    registry=REGISTRY,
)

withheld_items_total = Counter(
    "gateway_withheld_items_total",
    "Items withheld from the external provider, by action.",
    ("action",),
    registry=REGISTRY,
)

provider_requests_total = Counter(
    "gateway_provider_requests_total",
    "External provider calls by status category.",
    ("status_category",),
    registry=REGISTRY,
)

active_scopes = Gauge(
    "gateway_active_scopes",
    "Scopes currently ACTIVE.",
    registry=REGISTRY,
)

vault_mappings = Gauge(
    "gateway_vault_mappings",
    "Token mappings currently stored.",
    registry=REGISTRY,
)


def observe_outcome(path: str, outcome: str, duration_seconds: float) -> None:
    requests_total.labels(path=path, outcome=outcome).inc()
    request_duration_seconds.labels(path=path).observe(duration_seconds)
