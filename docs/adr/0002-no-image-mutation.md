# ADR 0002 — Approved images are forwarded byte-for-byte or not at all

**Status:** accepted

## Context

The obvious design for a sensitive photo is to redact the sensitive region and
send the rest. Doing that safely needs layout-aware bounding boxes, conservative
padding, proof that no original metadata or layer survived re-encoding, and
visual regression fixtures. None of that exists yet.

A half-implemented version is worse than none: an image that *looks* redacted
carries an implicit promise the system cannot keep.

## Decision

The MVP has exactly two outcomes for an image:

* fully inspected and clean → forward the original bytes, unmodified;
* anything else → keep the bytes local and send locally extracted, sanitized text.

There is no re-encode, strip-metadata, crop or blur path. `ImageParser` sets
`original_bytes_forwardable` only when decode, metadata inspection and OCR all
succeeded and found nothing protected.

## Consequences

* A photo carrying EXIF GPS cannot be forwarded at all, because "strip the GPS"
  is not an available action. This is a real utility cost and it is intentional.
* The fast path can be honest about what "original" means: the user's exact bytes.
* Adding pixel redaction later is an additive change behind the same decision
  point, not a rewrite.
