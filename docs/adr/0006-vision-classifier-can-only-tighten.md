# ADR 0006 — The vision classifier may tighten a verdict, never loosen one

**Status:** accepted

## Context

Image classification decides whether original pixels leave the trusted zone. The
heuristic classifier reads OCR text, which makes it blind to any picture without
text — an injury photograph, a face, a screenshot of an app. Those come back
`ORDINARY_IMAGE`, and the original bytes are forwarded. In a claims file the
injury photographs are among the most sensitive things present, so the blind spot
sits exactly where it hurts.

Verified against the deployed Qwen3.8 endpoint, which does accept images: a
portrait stripped of all EXIF and containing no text is classified
`ORDINARY_IMAGE` by the heuristic and `SENSITIVE_IMAGE` by the vision model.

The obvious objection is that a probabilistic component now participates in a
decision about disclosure.

## Decision

The vision model's verdict is combined with the heuristic's by taking whichever
is stricter. It can never produce a looser outcome than the deterministic pass
would have produced on its own.

Consequences of that rule:

* a model that wrongly says "ordinary" changes nothing;
* a model that wrongly says "identity document" costs one photograph;
* an unreachable, slow or off-schema model leaves the heuristic verdict standing,
  so the pipeline is exactly as safe as it was without the classifier.

`unclear` maps to `SENSITIVE_IMAGE`, not `UNKNOWN_IMAGE`. `UNKNOWN` was the first
choice — a model that cannot tell should not fall back to the one answer that
forwards pixels — but `UNKNOWN` blocks the entire request, and an optional
tightening signal should not hold a veto. A plain photograph of a dented bumper
can read as "unclear", and killing the claim over it buys no protection that
withholding the pixels does not already give.

## Consequences

* Only the cheap failure mode is reachable. The expensive one — a sensitive image
  forwarded because a model said it was fine — is unreachable by construction,
  not by the model being accurate.
* It costs one model call per image, so it is off by default
  (`LOCAL_MODEL_IMAGE_ANALYSIS`) and requires a served model that accepts images.
* When the verdict is tightened, `original_bytes_forwardable` is cleared:
  pixels cleared by the text-based pass are no longer cleared once something
  stricter has been said about them.
