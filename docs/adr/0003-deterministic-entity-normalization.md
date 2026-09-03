# ADR 0003 — Deterministic canonicalization only; no alias or coreference merging

**Status:** accepted

## Context

Token consistency within a scope is what makes multi-turn conversations useful:
the same person should keep the same token so the external model can reason about
"the same person". The tempting next step is to merge aliases — treat
`Zhang San`, `Mr. Zhang`, `the patient` and `the driver` as one entity.

## Decision

Canonicalization is deterministic and format-level only: Unicode NFKC, whitespace,
configured punctuation, and separator removal for phone and card numbers. Two
values share a token only when their canonical forms are exactly equal.

## Consequences

* One person may receive several tokens across different spellings. The model
  sees two subjects where there is one, and may under-connect the material.
* Two people can never be merged into one token. The failure mode is a weaker
  answer, never a wrong attribution of one person's data to another.

The asymmetry is the whole point: incorrectly merging two people is a privacy
incident and a correctness incident at once, while splitting one person costs
analytical quality. A future version can accept an explicit `subject_id` from the
business system — an assertion from a system that actually knows, rather than an
inference from a model that does not.
