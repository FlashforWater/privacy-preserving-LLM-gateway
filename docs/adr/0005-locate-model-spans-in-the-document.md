# ADR 0005 — Verify the local model's text, not its offsets

**Status:** accepted
**Supersedes:** the literal reading of guide §10.3, "`input[start:end]` exactly
equals the returned text"

## Context

The specification's acceptance rule for local-model output requires that the
returned character offsets reproduce the returned text exactly, and that any
entity failing this be discarded. The intent is sound: never act on text the
model invented.

Measured against the deployed endpoint (vLLM-served Qwen3.8, `enable_thinking`
off, native `json_schema` structured output) on a four-line clinical note
containing six entities:

| Entity | `text` correct | offsets correct |
|---|---|---|
| `Wei Zhang` (PERSON) | yes | yes |
| `88 Xinghai Street, Suzhou Industrial Park` (ADDRESS) | yes | no |
| `Dr. Li` (PERSON) | yes | no |
| `Suzhou Municipal Hospital` (ORGANIZATION) | yes | no |
| `acute hepatitis` (MEDICAL_DATA) | yes | no |
| `ALT 320 U/L` (MEDICAL_DATA) | yes | no |

The model identifies entities well and counts characters badly; the drift grows
with position, so only the entity nearest the start survived. Under the offset
rule, five of six real identifiers were discarded — and because the deterministic
rules do not cover unlabelled names, hospital names or clinical values, that
content would have reached the external model untouched, while the audit trail
recorded "no findings".

That is the exact shape of failure this service exists to prevent, and it is the
worst shape: silent under-detection that looks like a clean request.

## Decision

Treat the model's `text` as a claim about what the document contains, and locate
it ourselves:

1. if the reported offsets happen to reproduce the text, use them;
2. otherwise search the document for that exact string and use the positions we
   find, marking the finding `relocated`;
3. if the string does not occur, reject the entity as hallucinated;
4. mark every occurrence when a claim appears more than once;
5. reject claims shorter than 2 characters or longer than the span limit, and
   any entity type outside the allow-list.

`raw_text` is always sliced from the document, never taken from the reply.

## Consequences

* Recall on the measured sample goes from 1/6 to 6/6 with no hallucination
  accepted.
* The safety property is stronger, not weaker. The old rule trusted the model's
  arithmetic; this one trusts only a claim the gateway verifies directly — *does
  this exact string occur in this document?*
* A claimed string occurring several times marks all of them. Over-marking costs
  utility; under-marking discloses data.
* `relocated` is recorded per finding. A rising relocation rate means the served
  model's offsets are drifting further, which is worth watching but is no longer
  a correctness risk.
* The prompt now tells the model that offsets are a hint and exact text copying
  is what matters, which is the instruction it can actually follow.
