# ADR 0001 — Detectors produce evidence; policy produces actions

**Status:** accepted

## Context

Detection is probabilistic. Regexes miss variants, checksums only cover
structured identifiers, and a local model is wrong some of the time in ways that
are hard to predict. Authorization — may this content leave the trusted zone? —
must not inherit that uncertainty.

## Decision

Detectors return `Finding` objects and nothing else. They may not import
`app.policy` or `app.external`, which `tests/security/test_layer_isolation.py`
enforces at the source level. The policy engine is the only component that maps
evidence to a `PolicyAction`, and it never calls a model.

## Consequences

* A detector improvement can never accidentally widen what is forwarded.
* Every forwarding decision has a `policy_rule_id` and a `reason_code` that can
  be reviewed without reading detector code.
* Detector confidence is compared against a policy threshold rather than being
  interpreted by the detector itself, so tuning a threshold is a policy change
  that goes through review.
