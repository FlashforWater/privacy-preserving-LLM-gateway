# Privacy-Preserving LLM Gateway — MVP Development Guide

**Document status:** Implementation specification — Version 2, incorporating confirmed MVP decisions  
**Primary audience:** AI coding agents and engineers  
**Recommended MVP stack:** Python 3.12, FastAPI, Pydantic v2, PostgreSQL, local OCR, local open-source model, Docker Compose  
**Deployment target:** A private inference server with optional NVIDIA GPU acceleration  

---

## 1. Purpose

Build a gateway that sits between internal users/applications and an external LLM or VLM. The gateway detects policy-protected information, transforms only the content that must be protected, sends the permitted multimodal content to the external model, restores known placeholders in the model response, and returns the result.

The core routing rule is:

1. If no policy-protected information is detected, send the original logical request to the external LLM/VLM without privacy redaction or tokenization. For an approved image this means sending the original image bytes without re-encoding.
2. If protected information is detected, sanitize only the affected text, document sections, or image items.
3. Withhold any item classified as `LOCAL_ONLY` or `BLOCK`.
4. Send the remaining sanitized multimodal request to the external model.
5. Restore only valid, scope-scoped placeholder tokens in the external response.
6. Never treat a parser, OCR, detector, policy, or vault failure as permission to pass content through.

The local model is a detection assistant, not the decision-maker. The policy engine is authoritative. The external LLM remains the reasoning engine.

---

## 2. Product boundaries

### 2.1 MVP goals

- Accept text and common document/image attachments.
- Detect direct identifiers using deterministic rules and local-model-assisted semantic detection.
- Make policy decisions at entity and content-item level.
- Preserve a fast path for requests that contain no protected data.
- Tokenize identifiers while maintaining referential consistency within one gateway-managed scope.
- Withhold sensitive document images when policy requires it.
- Forward ordinary images unchanged when they pass inspection.
- Allow faces to pass unchanged when the configured policy explicitly permits them.
- Allow medical or health analytical content to pass when the configured policy permits it, while tokenizing direct identifiers around it.
- Restore scope-scoped placeholders in external-model text responses.
- Be observable without logging private payloads.
- Fail closed on uncertainty or subsystem failure.

### 2.2 Explicit non-goals for the first release

- Training or fine-tuning a model.
- Guaranteeing perfect privacy detection.
- General-purpose image redaction for arbitrary layouts.
- Restoring identifiers inside newly generated images, audio, or video.
- Cross-scope identity linking or fuzzy alias/coreference merging.
- A visual policy administration platform.
- Automatic correction or human-review routing for external-model identity-attribution errors; this question is explicitly deferred.
- A human-review system for rare diagnoses, extreme values, or other long-tail re-identification risks.
- Derived-fact generation.
- Multi-provider routing or failover.
- Letting the local model make final routing decisions.
- Sending unsupported or uninspected formats to an external provider.

### 2.3 Confirmed MVP decisions

| Topic | Confirmed decision |
|---|---|
| Scope ownership | Gateway creates `scope_id`; business system stores and reuses it |
| Scope lifetime | Explicit close, two-hour idle expiry, 24-hour absolute expiry |
| Tenancy | One configured tenant; keep and enforce `tenant_id` in all isolation keys |
| Fast path | Retained only after complete inspection; disabled permanently for a scope after its first tokenization |
| Safe images | Send the original file bytes without re-encoding or metadata modification |
| Sensitive images | Keep original bytes local; local OCR/VLM produces validated sanitized text for the external LLM |
| Medical data | Default `BLOCK`; `PASS` only under an approved purpose override; direct identifiers remain tokenized |
| Entity normalization | Deterministic exact canonicalization only; no fuzzy alias/coreference merging |
| Scope capacity | 50 turns, 20 files, 200 MB, 200 pages, and 5,000 mappings |
| File formats | Direct text, PDF, DOCX, XLSX, JPEG/JPG, and PNG |
| Local endpoint | Capability probe at deployment; native `json_schema` when available; no `reasoning_effort` |
| Database | PostgreSQL on a separate production server; no Redis in the MVP |
| Derived facts | Not implemented |
| External providers | One provider and one adapter implementation |
| Deferred questions | Identity-attribution correction and long-tail human-review behavior are not designed in the MVP |

---

## 3. Non-negotiable design principles

1. **Policy is authoritative.** Detectors produce evidence; policy produces actions.
2. **No implicit pass.** Absence of a successful inspection is not evidence of safety.
3. **Minimum necessary transformation.** Do not redact unrelated analytical content.
4. **Item-level routing.** One sensitive attachment must not automatically discard safe attachments.
5. **Scope-scoped tokens.** A token must be meaningless outside its gateway-managed scope and tenant.
6. **Exact restoration only.** Restore only tokens created by this gateway for the current scope.
7. **Private by default.** Payload bodies, OCR text, model prompts, vault mappings, and restored outputs must not appear in normal logs.
8. **Deterministic precedence.** Higher-risk evidence and stricter policy actions win.
9. **External provider isolation.** All provider-specific behavior belongs behind an adapter.
10. **Configuration validation at startup.** Invalid policy or missing security settings must prevent the service from becoming ready.

---

## 4. High-level architecture

```mermaid
flowchart TD
    A[Internal client] --> B[FastAPI gateway]
    B --> C[Request normalizer]
    C --> D[Text and file parsers]
    D --> E[Deterministic rules]
    D --> F[Local OCR and image classifier]
    D --> G[Local open-source model]
    E --> H[Evidence merger]
    F --> H
    G --> H
    H --> I[Authoritative policy engine]
    I -->|No protected content| J[Original-request fast path]
    I -->|Protected content| K[Sanitizer and item router]
    K --> L[Encrypted vault on separate PostgreSQL server]
    J --> M[External LLM/VLM adapter]
    K --> M
    M --> N[Response validator]
    N --> O[Exact-token restore]
    O --> P[Internal client]
```

### 4.1 Trust boundaries

| Zone | Components | May see original sensitive content? |
|---|---|---:|
| Internal trusted zone | Gateway, parsers, OCR, rules, local model, policy engine, vault | Yes |
| External provider zone | External LLM/VLM API | Only content allowed or sanitized by policy |
| Observability zone | Logs, metrics, traces | No payload content by default |

All parsing, OCR, classification, detection, tokenization, and restoration must run inside the trusted zone.

---

## 5. End-to-end request lifecycle

### 5.1 Normal path

1. Authenticate the caller and resolve `tenant_id`.
2. Validate the gateway-generated `scope_id`, assign `request_id`, and establish an end-to-end deadline.
3. Validate content type, size, attachment count, and declared purpose.
4. Normalize text and attachments into typed content items.
5. Inspect every item locally.
6. Merge deterministic and local-model findings into canonical evidence.
7. Evaluate policy for every finding and every content item.
8. Compute the strictest effective action for each item.
9. If every item is safe, no protected finding exists, and the scope is not `SANITIZED_LOCKED`, forward the original logical request through the fast path.
10. Otherwise, tokenize, transform to sanitized text, withhold, or block according to policy.
11. Save scope-scoped token mappings in the encrypted vault; the first tokenization changes the scope to `SANITIZED_LOCKED`.
12. Forward the permitted request through the external-provider adapter.
13. Validate the provider response and restore exact known tokens in textual fields only.
14. Return the restored response plus a non-sensitive decision summary.
15. Expire the vault mappings when the scope closes, after two hours of inactivity, or at the 24-hour absolute lifetime limit.

### 5.2 Multimodal item-level example

Input:

- `case.txt`: description containing a name and phone number.
- `accident.jpg`: ordinary accident image.
- `identity-card.jpg`: government ID image.
- `medical-report.pdf`: medical values plus direct identifiers.

Effective routing:

| Item | Decision | External representation |
|---|---|---|
| `case.txt` | `TOKENIZE` selected spans | Text with scope-scoped placeholders |
| `accident.jpg` | `PASS` | Original image bytes |
| `identity-card.jpg` | `LOCAL_ANALYZE_TO_SANITIZED_TEXT` | Original bytes withheld; locally extracted and sanitized text only |
| `medical-report.pdf` | Mixed | Sanitized extracted text; identifiers tokenized, allowed medical facts retained |

### 5.3 Scope lifecycle

The gateway, not the business system, creates `scope_id`. The business system stores the returned opaque identifier and reuses it for later turns.

The MVP runs as one configured internal tenant. Keep `tenant_id` in API context, database keys, vault lookups, and audit metadata, and resolve it from the authenticated service identity rather than the request body. Do not build tenant administration or tenant-specific policy UI in the MVP.

```text
POST /v1/scopes
  -> ACTIVE / CLEAN

First protected finding requiring tokenization
  -> ACTIVE / SANITIZED_LOCKED

POST /v1/scopes/{scope_id}/close
or 2-hour idle timeout
or 24-hour absolute lifetime
  -> CLOSED
  -> token mappings become unavailable and are scheduled for deletion
```

MVP scope limits:

- 50 message turns;
- 20 files;
- 20 MB per file;
- 50 MB per request;
- 200 MB cumulative input;
- 200 cumulative document pages;
- 5,000 token mappings.

The gateway stores scope state, mappings, policy version, and non-sensitive audit metadata. The business system stores conversation history; the gateway does not persist raw files, OCR text, or complete messages after processing.

### 5.4 Request state machine

```text
RECEIVED
  -> VALIDATING
  -> INSPECTING
  -> POLICY_EVALUATED
  -> SANITIZING (only when needed)
  -> FORWARDING
  -> RESTORING
  -> COMPLETED

Any state may transition to:
  -> BLOCKED
  -> FAILED_CLOSED
  -> EXTERNAL_FAILED
```

Persist only non-sensitive state metadata unless an approved encrypted audit feature is enabled.

---

## 6. Recommended repository structure

```text
privacy-gateway/
├── app/
│   ├── main.py
│   ├── api/
│   │   ├── routes_gateway.py
│   │   ├── routes_scopes.py
│   │   ├── routes_health.py
│   │   ├── dependencies.py
│   │   └── error_handlers.py
│   ├── core/
│   │   ├── config.py
│   │   ├── enums.py
│   │   ├── errors.py
│   │   ├── logging.py
│   │   ├── security.py
│   │   └── deadlines.py
│   ├── domain/
│   │   ├── scopes.py
│   │   ├── requests.py
│   │   ├── content.py
│   │   ├── findings.py
│   │   ├── decisions.py
│   │   └── responses.py
│   ├── gateway/
│   │   ├── orchestrator.py
│   │   ├── normalizer.py
│   │   ├── evidence_merger.py
│   │   └── request_builder.py
│   ├── parsers/
│   │   ├── base.py
│   │   ├── plain_text.py
│   │   ├── pdf.py
│   │   ├── docx.py
│   │   ├── xlsx.py
│   │   └── image.py
│   ├── detectors/
│   │   ├── base.py
│   │   ├── regex_detector.py
│   │   ├── checksum.py
│   │   ├── keyword_detector.py
│   │   ├── local_model_detector.py
│   │   ├── image_classifier.py
│   │   └── prompts/
│   │       └── entity_detection_v1.txt
│   ├── ocr/
│   │   ├── base.py
│   │   └── local_ocr.py
│   ├── policy/
│   │   ├── engine.py
│   │   ├── loader.py
│   │   ├── schema.py
│   │   └── policies/
│   │       └── default.yaml
│   ├── sanitization/
│   │   ├── tokenizer.py
│   │   ├── span_rewriter.py
│   │   └── item_router.py
│   ├── vault/
│   │   ├── base.py
│   │   ├── crypto.py
│   │   ├── postgres_vault.py
│   │   └── memory_vault.py
│   ├── external/
│   │   ├── base.py
│   │   ├── openai_compatible.py
│   │   ├── retry.py
│   │   └── response_validation.py
│   ├── restore/
│   │   ├── restorer.py
│   │   └── token_scanner.py
│   └── observability/
│       ├── metrics.py
│       ├── audit.py
│       └── tracing.py
├── config/
│   ├── policy.default.yaml
│   └── logging.yaml
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── security/
│   ├── failure_injection/
│   └── fixtures/
├── scripts/
│   ├── check_policy.py
│   ├── smoke_test.py
│   └── generate_dev_key.py
├── migrations/
├── Dockerfile
├── docker-compose.yml
├── docker-compose.gpu.yml
├── .env.example
├── pyproject.toml
├── README.md
└── Makefile
```

Keep domain models independent of FastAPI, database, OCR, and provider SDKs. This makes the policy and orchestration logic easy to test.

---

## 7. Core domain model

### 7.1 Entity types

Start with a deliberately small taxonomy:

```python
class EntityType(str, Enum):
    PERSON = "PERSON"
    ID_CARD = "ID_CARD"
    PHONE = "PHONE"
    BANK_CARD = "BANK_CARD"
    EMAIL = "EMAIL"
    ADDRESS_DETAILED = "ADDRESS_DETAILED"
    ORGANIZATION = "ORGANIZATION"
    VEHICLE_PLATE = "VEHICLE_PLATE"
    MEDICAL_DATA = "MEDICAL_DATA"
    FACE = "FACE"
    ID_DOCUMENT_IMAGE = "ID_DOCUMENT_IMAGE"
    ORDINARY_IMAGE = "ORDINARY_IMAGE"
    UNKNOWN_SENSITIVE = "UNKNOWN_SENSITIVE"
```

Do not add a new entity type without adding policy, test fixtures, metrics labels, and expected failure behavior for it.

### 7.2 Policy actions

```python
class PolicyAction(str, Enum):
    PASS = "PASS"
    TOKENIZE = "TOKENIZE"
    REDACT = "REDACT"
    LOCAL_ANALYZE_TO_SANITIZED_TEXT = "LOCAL_ANALYZE_TO_SANITIZED_TEXT"
    LOCAL_ONLY = "LOCAL_ONLY"
    BLOCK = "BLOCK"
```

Suggested precedence, from least to most restrictive:

```text
PASS < TOKENIZE < REDACT < LOCAL_ANALYZE_TO_SANITIZED_TEXT < LOCAL_ONLY < BLOCK
```

### 7.3 Finding schema

```python
class Finding(BaseModel):
    finding_id: UUID
    item_id: str
    entity_type: EntityType
    source: Literal["regex", "checksum", "keyword", "local_model", "ocr", "image_classifier"]
    start: int | None = None
    end: int | None = None
    text_hash: str | None = None       # Never log raw finding text
    confidence: float
    rule_id: str | None = None
    metadata: dict[str, JsonValue] = {}
```

The finding may refer to raw text internally during processing, but serialized audit records must contain a keyed hash or non-sensitive fingerprint instead of the raw value.

### 7.4 Decision schema

```python
class PolicyDecision(BaseModel):
    finding_id: UUID | None
    item_id: str
    action: PolicyAction
    policy_rule_id: str
    reason_code: str
    policy_version: str
```

Every externally forwarded item must have a traceable decision. Missing decision means do not forward.

---

## 8. Public API

### 8.1 Scope endpoints

```http
POST /v1/scopes
Authorization: Bearer <internal-token>
Content-Type: application/json
```

The business system may supply its own opaque `client_conversation_id` for idempotency/correlation, but the gateway always generates the authoritative `scope_id`.

Example response:

```json
{
  "scope_id": "scp_01...",
  "status": "active",
  "privacy_mode": "clean",
  "idle_expires_at": "2026-09-02T12:00:00Z",
  "absolute_expires_at": "2026-09-03T10:00:00Z"
}
```

Close a scope explicitly:

```http
POST /v1/scopes/{scope_id}/close
Authorization: Bearer <internal-token>
```

Closing is idempotent. A closed or expired scope cannot accept new messages or restore tokens.

### 8.2 Message endpoint

```http
POST /v1/scopes/{scope_id}/messages
Content-Type: multipart/form-data
Authorization: Bearer <internal-token>
Idempotency-Key: <unique-key>
```

Multipart fields:

- `manifest`: JSON request metadata and ordered text/image/document items.
- `file_<item_id>`: bytes for each attachment referenced in the manifest.

Example manifest:

```json
{
  "purpose": "medical_report_analysis",
  "model": "external-vlm-model",
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "text", "item_id": "prompt-1", "text": "Analyze this report."},
        {"type": "file", "item_id": "report-1", "file_field": "file_report-1"},
        {"type": "image", "item_id": "photo-1", "file_field": "file_photo-1"}
      ]
    }
  ],
  "options": {
    "temperature": 0.2,
    "max_output_tokens": 1200
  }
}
```

Successful response:

```json
{
  "scope_id": "scp_01...",
  "request_id": "req_01...",
  "status": "completed",
  "output": {
    "role": "assistant",
    "content": [{"type": "text", "text": "Restored response..."}]
  },
  "privacy": {
    "path": "sanitized",
    "scope_privacy_mode": "sanitized_locked",
    "policy_version": "2026-09-01.1",
    "actions": {
      "PASS": 2,
      "TOKENIZE": 3,
      "LOCAL_ANALYZE_TO_SANITIZED_TEXT": 1
    },
    "withheld_item_ids": ["identity-1"]
  }
}
```

Do not expose finding values, token mappings, OCR text, or sensitive reason details in the API response.

### 8.3 Error behavior

Use stable machine-readable error codes:

| HTTP | Code | Meaning |
|---:|---|---|
| 400 | `INVALID_REQUEST` | Invalid manifest or unsupported combination |
| 404 | `SCOPE_NOT_FOUND` | Scope does not exist for this tenant |
| 409 | `SCOPE_CLOSED` | Scope is closed or expired |
| 401/403 | `UNAUTHORIZED` | Caller or purpose not allowed |
| 413 | `PAYLOAD_TOO_LARGE` | Size/count limit exceeded before parsing |
| 413 | `SCOPE_LIMIT_EXCEEDED` | Turn, file, page, byte, or mapping limit exceeded |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Cannot safely inspect this type |
| 422 | `CONTENT_BLOCKED` | Policy intentionally blocked the request/item |
| 424 | `INSPECTION_FAILED_CLOSED` | Parser, OCR, detector, policy, or vault failed |
| 502 | `EXTERNAL_PROVIDER_ERROR` | Provider failed after safe preprocessing |
| 504 | `REQUEST_DEADLINE_EXCEEDED` | End-to-end deadline expired |

Errors must not echo original content.

### 8.4 Operational endpoints

```text
GET /health/live      Process is running
GET /health/ready     Policy, vault, required detectors, and adapters are usable
GET /metrics          Protected Prometheus endpoint; no high-cardinality IDs
```

`/health/ready` must fail when the current policy cannot be loaded, vault encryption is unavailable, required local inspection is unavailable, or migrations are incomplete.

---

## 9. Policy engine

### 9.1 Responsibilities

The policy engine accepts normalized request context plus findings and returns deterministic decisions. It must not call an LLM.

Inputs should include:

- tenant and caller class;
- declared purpose;
- content item type and MIME type;
- entity type;
- finding source and confidence;
- document/image classification;
- policy version;
- jurisdiction or data boundary, when configured.

### 9.2 Example YAML policy

```yaml
version: "2026-09-01.1"
defaults:
  unknown_entity: BLOCK
  unsupported_content: BLOCK
  detector_error: BLOCK

entities:
  ID_CARD:
    action: TOKENIZE
    minimum_confidence: 0.50
  PERSON:
    action: TOKENIZE
    minimum_confidence: 0.75
  PHONE:
    action: TOKENIZE
    minimum_confidence: 0.60
  BANK_CARD:
    action: TOKENIZE
    minimum_confidence: 0.60
  EMAIL:
    action: TOKENIZE
    minimum_confidence: 0.70
  ADDRESS_DETAILED:
    action: TOKENIZE
    minimum_confidence: 0.75
  VEHICLE_PLATE:
    action: TOKENIZE
    minimum_confidence: 0.75
  MEDICAL_DATA:
    action: BLOCK
  FACE:
    action: PASS
  UNKNOWN_SENSITIVE:
    action: BLOCK

content_classes:
  ORDINARY_IMAGE:
    action: PASS
  ID_DOCUMENT_IMAGE:
    action: LOCAL_ANALYZE_TO_SANITIZED_TEXT
  SENSITIVE_IMAGE:
    action: LOCAL_ANALYZE_TO_SANITIZED_TEXT
  UNKNOWN_IMAGE:
    action: BLOCK

purpose_overrides:
  medical_report_analysis:
    MEDICAL_DATA:
      action: PASS

limits:
  max_request_bytes: 52428800
  max_file_bytes: 20971520
  max_scope_bytes: 209715200
  max_scope_turns: 50
  max_scope_files: 20
  max_scope_pages: 200
  max_scope_mappings: 5000
  max_ocr_pixels: 40000000
```

The example policy is a starting point, not a legal determination. The organization responsible for the deployment must approve the final policy.

### 9.3 Evaluation rules

1. Validate policy YAML against a strict schema during startup and CI.
2. Reject unknown keys to catch misspellings.
3. Pin a policy version when the scope is created and use it for the scope lifetime.
4. Apply the most specific matching rule: tenant/purpose override, content rule, entity rule, then default.
5. When multiple actions overlap, choose the most restrictive effective action.
6. `BLOCK` on any non-separable required content blocks the request.
7. `LOCAL_ONLY` on a separable attachment withholds that attachment while safe items continue.
8. Low-confidence or unknown findings follow an explicit uncertainty rule; never silently drop them.
9. Emit reason codes and policy version without emitting private values.

### 9.4 Hot reload

Do not hot-reload policy in the first release. Load and validate at process startup, then deploy a new version through the normal release process. This prevents different workers from silently evaluating the same request under different configurations.

---

## 10. Detection pipeline

### 10.1 Stages

Run detection in this order:

1. Parse and normalize locally.
2. Apply deterministic regex, checksum, and contextual keyword rules.
3. Classify document/image type locally.
4. Run OCR when the policy or classifier requires textual inspection.
5. Send parsed text, and sensitive images when local image understanding is required, only to the trusted local open-source model endpoint.
6. Validate local-model output against a strict JSON schema.
7. Verify every returned span against the exact normalized input.
8. Merge duplicates and overlaps.
9. Evaluate policy.

### 10.2 Deterministic rules

Use code for identifiers with recognizable structure:

- National ID numbers: regex, length, date components, checksum when applicable.
- Phone numbers: normalized country/area rules and contextual evidence.
- Bank cards: candidate regex plus Luhn checksum.
- Email addresses: conservative syntax validation.
- Vehicle plates: jurisdiction-specific pattern plus nearby labels.
- Field labels such as `Name`, `ID number`, `Phone`, `Address`, `Patient`, `Insured`, or localized equivalents.

Each rule must return an ID, span, entity type, confidence, and evidence category. Avoid one giant regex. Maintain rules as individually tested units.

### 10.3 Local open-source model

Use a small instruction-following model served locally through an OpenAI-compatible endpoint. A Qwen-family instruct model is a reasonable initial candidate, but keep the client model-agnostic. Select model size after measuring the server's GPU memory and latency.

Treat endpoint compatibility as a deployment probe rather than a product decision. The local-model adapter should:

- query `/v1/models` when supported and otherwise use the configured model name;
- use native `json_schema` structured output when supported;
- fall back to prompt-constrained JSON followed by the same strict gateway-side validation when native schema output is unavailable;
- isolate the endpoint-specific image input format behind the adapter;
- never send `reasoning_effort` in the MVP;
- fail readiness or dependent requests when required capabilities are absent.

The model performs semantic assistance for:

- person names in context;
- detailed addresses without rigid formatting;
- role-bearing names such as patient, insured person, driver, or contact;
- document type hints;
- ambiguous sensitive fields;
- structured extraction needed for local classification.

It does not determine `PASS`, `TOKENIZE`, `LOCAL_ONLY`, or `BLOCK`.

Suggested prompt contract:

```text
SYSTEM:
You are a local privacy entity detector. Identify spans only. Do not analyze the case.
Return JSON matching the supplied schema and no other text.
Never invent text. Every start/end span must exactly match the input.

ENTITY TYPES:
PERSON, ADDRESS_DETAILED, ORGANIZATION, MEDICAL_DATA, UNKNOWN_SENSITIVE

USER:
<document_type>{{document_type}}</document_type>
<text>{{normalized_text}}</text>
```

Expected response:

```json
{
  "entities": [
    {
      "start": 12,
      "end": 20,
      "text": "Example Name",
      "type": "PERSON",
      "confidence": 0.94
    }
  ]
}
```

Treat the local model's text field as untrusted. Accept a result only when:

- JSON schema validation succeeds;
- entity type is allowlisted;
- offsets are within bounds;
- `input[start:end]` exactly equals the returned text after the documented normalization rule;
- entity count and output size are below limits;
- no extra fields or prose are present.

Malformed output, timeout, or unavailable model must trigger the configured fail-closed behavior for content that depends on that detector.

### 10.4 Evidence merging and overlap

Recommended precedence:

```text
validated checksum rule
  > high-specificity deterministic rule
  > contextual keyword rule
  > local-model-only finding
```

For overlapping spans:

- preserve the finding with stronger evidence;
- if entity types conflict and policy actions differ, use the stricter action;
- prefer the longest correct direct-identifier span;
- record all contributing source IDs for audit metrics;
- never rewrite the same character range twice.

Replace text spans from the end of the string toward the beginning so offsets remain stable.

### 10.5 Entity normalization within a scope

The MVP performs deterministic format normalization only. Examples include Unicode normalization, surrounding whitespace, configured punctuation handling, and removal of phone-number separators. The same canonical value reuses the same token inside one scope.

Do not automatically merge semantic aliases or pronouns. For example, `Zhang San`, `Mr. Zhang`, `the patient`, and `the driver` remain separate unless their normalized source values are exactly equal. A future version may accept an explicit internal `subject_id` from the business system, but local-model-inferred coreference is outside the MVP. Incorrectly merging two people is more dangerous than assigning two tokens to one person.

---

## 11. Document handling

### 11.1 Supported MVP formats

| Type | Local processing | External representation |
|---|---|---|
| Direct text | Normalize and detect | Original or tokenized text |
| PDF | Parse text; render/OCR pages when needed; inspect supported metadata and objects | Original file only when completely inspected and safe; otherwise sanitized structured text |
| DOCX | Inspect paragraphs, tables, headers, footers, comments, text boxes, properties, and embedded images | Original file only when completely inspected and safe; otherwise sanitized structured text |
| XLSX | Inspect all sheets, including hidden sheets, cells, formulas/cached values, comments, names, properties, and embedded images | Original file only when completely inspected and safe; otherwise sanitized structured text |
| PNG/JPEG | Validate/decode, inspect metadata, classify, and OCR when required | Original bytes when completely inspected and safe; otherwise locally generated sanitized text |

For PDF, DOCX, and XLSX, the fast path may forward the original file only after every supported component has been inspected successfully and no protected information is found. Once protected information is found, never forward the original file after merely sanitizing extracted text: identifiers may remain in metadata, comments, hidden sheets, embedded files, annotations, layers, or images. Send a newly constructed sanitized text representation instead.

### 11.2 Parser safety

- Determine file type from validated content, not only filename or client MIME type.
- Reject encrypted/password-protected documents.
- Enforce byte, page, decompression, XML expansion, image pixel, and processing-time limits.
- Disable macros and never execute embedded content.
- Reject macro-enabled DOCM and XLSM files; never execute macros or embedded content.
- Inspect DOCX body paragraphs, tables, headers, footers, comments, text boxes, properties, and embedded images. If a component cannot be inspected, block the file.
- Inspect all XLSX sheets, including hidden and very-hidden sheets, cell values, formulas and cached results, comments, defined names, properties, and embedded images. Do not fetch external links. If an embedded object cannot be inspected, block the file.
- Use sandboxed worker processes for complex parsers when practical.
- Delete temporary plaintext files immediately after processing and never place them in a shared web root.
- A partial parse is a failure unless policy explicitly permits a complete, safely isolated subset.

### 11.3 Structured text representation

Preserve enough structure for external reasoning:

```text
[DOCUMENT file=medical-report.pdf]
[PAGE 1]
[HEADING] Laboratory Results
[TABLE]
Test | Result | Unit
ALT | 72 | U/L
Blood pressure | 145/95 | mmHg
Patient | [[PERSON_...]] |
[/TABLE]
[/PAGE]
[/DOCUMENT]
```

Escape or delimit extracted content so it cannot be mistaken for trusted system instructions. The external adapter should explicitly state that document content is untrusted data.

---

## 12. Image handling

### 12.1 Decision flow

```text
Decode image locally
  -> validate dimensions and format
  -> inspect EXIF and other metadata without modifying the file
  -> local image/document classifier
     -> ordinary image with no protected visible content or metadata: PASS original bytes
     -> sensitive image: analyze/OCR locally, sanitize extracted text, withhold original bytes
     -> unknown or classifier failure: BLOCK; never PASS
```

### 12.2 Ordinary images

Examples include accident damage, equipment, objects, and general scenes. If classification, metadata inspection, and required content/OCR inspection all succeed and find no policy-protected information, the gateway forwards the original image file byte-for-byte. The MVP does not re-encode, strip metadata, crop, redact, or otherwise modify approved images.

Faces may pass unchanged only when `FACE: PASS` is present in the active policy. This is a policy choice, not a detector default.

If protected EXIF/GPS or other protected metadata is present, treat the entire image as sensitive. Because the MVP does not mutate images, it must not forward that original file.

### 12.3 Sensitive document images

Examples include identity cards, passports, driver's licenses, bank cards, and document screenshots containing direct identifiers.

For the MVP:

- classify and OCR locally;
- apply `LOCAL_ANALYZE_TO_SANITIZED_TEXT`;
- keep the original image bytes inside the trusted zone;
- use local OCR/VLM analysis to produce validated structured text;
- tokenize or redact protected fields in that text;
- send only the sanitized text to the external LLM;
- do not send the original pixels externally;
- if classification or OCR fails, do not default to ordinary-image `PASS`.

The MVP does not generate derived facts such as age bands, regions, or document attributes. It preserves only content needed for the approved task after policy processing.

### 12.4 Future image transformation

Pixel-level redaction or image transformation is outside the MVP. If added later, it requires:

- layout-aware bounding boxes;
- conservative padding around detected regions;
- an explicitly approved transformation and output format;
- checks that no original metadata or layer survives;
- automated visual regression fixtures;
- a fallback to `LOCAL_ONLY` on uncertain coverage.

---

## 13. Tokenization and vault

### 13.1 Token format

Use high-entropy opaque placeholders that are unlikely to occur naturally:

```text
[[PGW_V1_PERSON_K7M4Q2Z9F8N3]]
[[PGW_V1_PHONE_D5T8R1C6L0W2]]
```

Requirements:

- Generate the suffix with a cryptographically secure random generator.
- Include only a coarse entity type, never part of the original value.
- Make tokens unique per tenant and scope.
- Preserve consistent references within one scope: the same deterministically canonicalized value maps to the same token.
- Reuse mappings across turns in the same active scope, but never across scopes.
- Escape token-like strings already present in user content to prevent collisions.

### 13.2 Scope and mapping records

```python
class ScopeRecord(BaseModel):
    tenant_id: str
    scope_id: str
    status: Literal["ACTIVE", "CLOSED", "EXPIRED"]
    privacy_mode: Literal["CLEAN", "SANITIZED_LOCKED"]
    policy_version: str
    turn_count: int
    file_count: int
    cumulative_bytes: int
    cumulative_pages: int
    mapping_count: int
    created_at: datetime
    last_active_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
```

```python
class TokenMapping(BaseModel):
    tenant_id: str
    scope_id: str
    created_by_request_id: str
    token: str
    entity_type: EntityType
    encrypted_original: bytes
    canonical_value_hmac: str
    created_at: datetime
    expires_at: datetime
```

Use a keyed HMAC for scope-local deduplication, not an unsalted raw hash of identifiers.

PostgreSQL should enforce uniqueness on `(tenant_id, scope_id)` for scopes, `(tenant_id, scope_id, token)` for mappings, and `(tenant_id, scope_id, entity_type, canonical_value_hmac)` for deterministic same-scope reuse. Updating counters, inserting new mappings, and changing `privacy_mode` to `SANITIZED_LOCKED` must occur in one database transaction before the external call.

### 13.3 Vault security

- Encrypt every original value before persistence using an authenticated encryption mode such as AES-256-GCM.
- Keep the master key outside source control and outside the database.
- Prefer a cloud KMS or hardware-backed key service in production; use a development-only local key for local work.
- Bind ciphertext to tenant, scope, token, entity type, and policy version as authenticated additional data.
- Enforce TTL at read time and with periodic deletion.
- Restrict vault access to the gateway service identity.
- Never expose a bulk list or search-by-plaintext API.
- Do not log mappings, encryption keys, decrypted values, or restoration substitutions.

### 13.4 Restoration algorithm

1. Scan only provider response fields explicitly declared as text.
2. Extract strings matching the exact gateway token grammar.
3. Fetch mappings using `(tenant_id, scope_id, token)`.
4. Restore only exact tokens that exist, are unexpired, and authenticate successfully.
5. Leave unknown or malformed tokens unchanged and increment a security metric.
6. Apply output length and substitution-count limits.
7. Never interpret external-model instructions to query arbitrary vault entries.

This prevents an external model from inventing a token that retrieves data from another scope or tenant.

### 13.5 Streaming

Disable streaming in the MVP. Safe restoration across chunk boundaries requires buffering or a stateful token scanner, and partial un-restored output complicates failure handling. Add streaming only after non-streaming behavior is stable.

---

## 14. External LLM/VLM adapter

Define a provider-neutral interface, but implement exactly one external provider in the MVP:

```python
class ExternalModelAdapter(Protocol):
    async def complete(
        self,
        request: SanitizedModelRequest,
        deadline: Deadline,
    ) -> ExternalModelResponse: ...
```

Adapter responsibilities:

- convert the internal canonical request to provider format;
- maintain message and attachment ordering;
- attach only items approved for external transfer;
- enforce the configured provider and allowed model list;
- set connection, read, and total timeouts;
- retry only safe transient failures with bounded exponential backoff;
- reuse the same idempotency key when the provider supports it;
- validate response size and structure;
- map provider errors to gateway error codes;
- never log request or response bodies.

The adapter must receive a typed `OriginalApprovedRequest` for the fast path or a `SanitizedModelRequest` for the privacy path. It must not accept arbitrary raw internal request objects. This makes bypasses harder. Do not implement provider selection, fallback, cost routing, load balancing, or cross-provider migration in the MVP.

### 14.1 Fast-path invariant

“Original” in the fast path means the user's semantic text, message order, approved document files, and approved image bytes are not privacy-redacted, tokenized, re-encoded, or otherwise modified. It does not exempt the request from authentication, complete local inspection, size limits, or provider-format envelope conversion.

The original request may be forwarded only if all of the following are true:

- every item completed all required inspection stages;
- the policy engine returned `PASS` for every item/finding;
- no detector reported protected or unknown-sensitive content;
- the scope privacy mode is `CLEAN`, not `SANITIZED_LOCKED`;
- there was no parser, OCR, detector, classifier, policy, or vault error;
- the external destination, model, and purpose are allowlisted.

Create a single guard method such as `assert_original_forward_allowed(decision_bundle)` and test it aggressively. Do not reproduce the guard logic in multiple routes.

---

## 15. Fail-closed behavior

### 15.1 Failure matrix

| Failure | Required behavior |
|---|---|
| Unsupported file type | Reject; do not forward |
| File type mismatch | Reject; do not forward |
| Parser timeout/crash/partial parse | `INSPECTION_FAILED_CLOSED` |
| OCR unavailable when required | Withhold item or fail request; never pass original |
| Image classifier timeout/unknown | `BLOCK`; never classify as ordinary |
| Local-model unavailable when required | Fail closed for dependent content |
| Invalid local-model JSON/spans | Fail closed for dependent content |
| Policy missing/invalid/unknown entity | Not ready or `BLOCK` |
| Vault write failure | Do not call external provider |
| Sanitization span conflict unresolved | Do not call external provider |
| External provider timeout | Return provider error; do not retry indefinitely |
| Vault read/decrypt failure during restore | Do not return a partially restored success |
| End-to-end deadline exceeded | Cancel downstream work and return 504 |

### 15.2 Transaction boundary

Do not call the external provider until:

1. every item has a final policy decision;
2. all transformations have completed;
3. the sanitized request passes a final invariant check;
4. all required token mappings are durably stored;
5. no blocked item is present in the outbound payload.

If a failure occurs after the external call but before restoration completes, return an error and retain mappings only for the short configured recovery/audit TTL. Never return a partially restored response as success.

---

## 16. Orchestrator pseudocode

```python
async def process_gateway_request(raw_request, principal):
    scope = await scope_service.require_active(raw_request.scope_id, principal.tenant_id)
    ctx = create_request_context(raw_request, principal, scope)
    enforce_request_limits(ctx)

    items = await normalizer.normalize(raw_request, ctx.deadline)
    inspection_results = []

    for item in items:
        parsed = await parser_registry.parse(item, ctx.deadline)
        findings = await detector_pipeline.inspect(parsed, ctx)
        inspection_results.append(
            InspectionResult(item=item, parsed=parsed, findings=findings)
        )

    decisions = policy_engine.evaluate(ctx, inspection_results)
    assert_complete_decision_coverage(items, decisions)

    if decisions.blocks_required_request_content():
        raise ContentBlocked(decisions.public_summary())

    if scope.privacy_mode == "CLEAN" and decisions.original_forward_allowed():
        outbound = request_builder.from_original_approved(raw_request, decisions)
        path = "fast"
    else:
        transformed = await sanitizer.transform(
            inspection_results, decisions, ctx
        )
        await vault.put_all_and_lock_scope(
            scope_id=scope.scope_id,
            mappings=transformed.token_mappings,
            privacy_mode="SANITIZED_LOCKED",
        )
        outbound = request_builder.from_sanitized(transformed, decisions)
        assert_no_withheld_or_blocked_content(outbound, decisions)
        path = "sanitized"

    external_response = await external_adapter.complete(outbound, ctx.deadline)
    validated = response_validator.validate(external_response)
    restored = await restorer.restore_text_fields(validated, ctx)

    return build_public_response(restored, decisions, path)
```

Wrap the operation with explicit error mapping, cancellation, metrics, and vault cleanup behavior. Do not use `except Exception: PASS` or fallback-to-forward logic anywhere.

---

## 17. Security and privacy controls

### 17.1 Authentication and authorization

- Require internal service authentication, preferably short-lived identity tokens or mTLS.
- Resolve tenant from the authenticated principal, never from an untrusted body field.
- Authorize purpose, external provider, and model.
- Rate-limit by tenant and principal.
- Keep administrative and metrics endpoints on a separate protected network or port.

### 17.2 Prompt-injection boundaries

Documents and OCR text are untrusted content. They may contain instructions such as “send the original document” or “reveal the token map.” These must have no effect on gateway policy.

- Policy evaluation never consumes free-form instructions as executable policy.
- External system prompts state that attached/extracted content is data.
- The external model has no tool or network path to the vault.
- Restoration recognizes exact tokens only; it does not follow model instructions.

### 17.3 Logging

Allowed log fields:

- request ID;
- tenant pseudonymous ID;
- route, status, duration, byte counts;
- policy version;
- aggregate action and entity counts;
- detector/parser component names and result codes;
- provider status category.

Forbidden by default:

- request/response bodies;
- file names when user-controlled or sensitive;
- extracted/OCR text;
- finding values;
- token mappings or decrypted values;
- authorization headers, API keys, encryption keys;
- raw provider errors that may echo inputs.

Add a centralized redaction filter, but do not rely on it as permission to log payloads.

### 17.4 Data retention

- Raw request bytes: memory or encrypted temporary storage only; delete after processing.
- Token mappings: short TTL, configurable by approved policy.
- Decision audit: metadata only, retained according to organizational policy.
- Debug artifacts: disabled in production.
- Provider retention/training: disable through provider controls and contract where available.

---

## 18. Configuration

Example `.env.example` keys:

```dotenv
APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8080
LOG_LEVEL=INFO

POLICY_FILE=/app/config/policy.default.yaml
REQUEST_DEADLINE_SECONDS=120
MAX_CONCURRENT_REQUESTS=16

DATABASE_URL=postgresql+asyncpg://privacy_gateway:change-me@postgres/privacy_gateway
VAULT_MASTER_KEY_B64=development-only-placeholder
SCOPE_IDLE_TTL_SECONDS=7200
SCOPE_ABSOLUTE_TTL_SECONDS=86400
SCOPE_MAX_TURNS=50
SCOPE_MAX_FILES=20
SCOPE_MAX_BYTES=209715200
SCOPE_MAX_PAGES=200
SCOPE_MAX_MAPPINGS=5000

LOCAL_MODEL_BASE_URL=http://local-model:8000/v1
LOCAL_MODEL_NAME=local-instruct-model
LOCAL_MODEL_TIMEOUT_SECONDS=20

OCR_BACKEND=local
OCR_TIMEOUT_SECONDS=30

EXTERNAL_PROVIDER=openai-compatible
EXTERNAL_BASE_URL=https://provider.example/v1
EXTERNAL_API_KEY=set-through-secret-manager
EXTERNAL_ALLOWED_MODELS=model-a,model-b
EXTERNAL_TIMEOUT_SECONDS=60

ENABLE_STREAMING=false
ENABLE_PAYLOAD_LOGGING=false
```

Production must refuse to start with placeholder keys, development secrets, wildcard provider hosts, or payload logging enabled.

---

## 19. Testing strategy

### 19.1 Unit tests

- Every regex and checksum with positive, negative, boundary, Unicode, and adversarial cases.
- Policy schema validation and rule precedence.
- Unknown entity/content defaults.
- Span validation, overlap resolution, and reverse-order replacement.
- Deterministic canonicalization and same-scope token consistency across turns.
- Token grammar, collision handling, TTL, encryption authentication, and tenant/scope isolation.
- Exact restoration and unknown-token behavior.
- Scope creation, explicit close, idle/absolute expiry, limit enforcement, and `SANITIZED_LOCKED` transitions.
- Fast-path guard invariants.
- Log filtering and public error serialization.

### 19.2 Parser and image tests

- Text PDF, scanned PDF, mixed PDF, malformed PDF, encrypted PDF, oversized PDF.
- DOCX headers, footers, tables, comments/embedded-content edge cases.
- XLSX hidden sheets, formulas, comments, external links, malformed archives.
- Image with EXIF, renamed MIME type, oversized dimensions, truncated bytes.
- Ordinary scene, accident image, ID card, passport, screenshot of a form, ambiguous image.
- OCR success, low-confidence OCR, timeout, and crash.

### 19.3 Integration tests with fake model services

Create deterministic fake local-model and external-provider servers. Test:

1. Safe text takes the original fast path.
2. Name and phone are tokenized; unrelated text is unchanged.
3. Medical values pass while direct identifiers are tokenized.
4. Ordinary approved image reaches the fake VLM byte-for-byte without re-encoding.
5. ID document image is withheld and never appears in outbound captured bytes.
6. Mixed request forwards safe/sanitized items in correct order.
7. External response tokens restore correctly.
8. Invented, malformed, expired, cross-scope, and cross-tenant tokens do not restore.
9. Vault failure prevents the external request.
10. Parser/OCR/classifier/model/policy failure never activates the fast path.
11. Provider retry does not duplicate unsafe side effects.
12. Timeout cancellation stops pending downstream work.
13. Tokenization in one turn locks the scope so later turns cannot use the original fast path.
14. Explicitly closed, idle-expired, and absolute-expired scopes cannot restore or accept messages.
15. Scope turn/file/byte/page/mapping limits fail before unsafe forwarding.

### 19.4 Security tests

- Prompt injection asking for original values or vault access.
- Token-like user strings and placeholder collision attempts.
- Zip/XML bombs and decompression limits.
- Path traversal in filenames and multipart metadata.
- MIME spoofing and polyglot files.
- Authorization and tenant-isolation tests.
- Log-capture assertion that known fixture identifiers never appear.
- Outbound-capture assertion that blocked bytes never leave the gateway.
- Fuzz parsers and token scanner with bounded inputs.

### 19.5 Failure-injection tests

Every dependency must have tests for timeout, unavailable, malformed output, partial output, and cancellation. The central assertion is:

> When inspection or protection is incomplete, the external-provider fake receives zero unsafe bytes.

### 19.6 Evaluation dataset

Maintain a versioned, access-controlled evaluation set with synthetic or approved data. Measure:

- recall by protected entity type;
- false-positive rate;
- document/image classification recall, especially sensitive documents;
- fast-path eligibility accuracy;
- percentage of unnecessary transformations;
- p50/p95/p99 latency by path;
- fail-closed and provider error rates.

Optimize first for recall on high-risk direct identifiers. A false negative can disclose data; a false positive usually costs utility or latency.

---

## 20. Local development

### 20.1 Prerequisites

- Docker Engine with Compose v2.
- Python 3.12 for editor tooling and optional non-container tests.
- At least 16 GB RAM; more if running a local model on CPU.
- Optional NVIDIA GPU, current driver, and NVIDIA Container Toolkit.

### 20.2 Developer workflow

The coding agent should provide these commands through the `Makefile`:

```text
make bootstrap       Create local config and development secrets
make up              Start gateway, PostgreSQL, fake provider, and optional local model
make migrate         Apply database migrations
make test            Run unit and integration tests
make test-security   Run security and failure-injection tests
make lint            Run formatting, linting, and type checks
make smoke           Exercise safe, sanitized, withheld-image, and fail-closed paths
make down             Stop local services
```

Default local development should use fake model/provider services so tests are deterministic and do not send data to the internet. Real external-provider tests must require an explicit opt-in environment profile.

### 20.3 Manual smoke cases

1. Safe general question: verify `privacy.path == "fast"`.
2. Text containing a synthetic name and phone: verify sanitized path and restored response.
3. Synthetic medical report: verify medical results remain and identifiers become tokens outbound.
4. Ordinary synthetic image: verify the exact permitted original bytes reach the fake VLM.
5. Synthetic ID card image: verify it is withheld.
6. Stop OCR/local model: verify dependent request fails closed.
7. Stop vault: verify no external call occurs.

Never use real personal data for smoke testing.

---

## 21. Docker design

### 21.1 Services

```text
gateway          FastAPI application
postgres         Encrypted token mappings and migrations
local-model      Local OpenAI-compatible inference server
ocr-worker       Optional isolated OCR/parser worker
fake-external    Development/test-only provider
```

### 21.2 Dockerfile requirements

- Multi-stage build.
- Pin Python packages with hashes or a lock file.
- Run as a non-root UID/GID.
- Read-only root filesystem where practical.
- Writable temporary volume with size limits.
- No compiler, package manager cache, test fixtures, or development keys in the runtime image.
- Health check against `/health/live`; orchestration readiness uses `/health/ready`.
- Set resource requests/limits at deployment time.
- Produce an SBOM and scan the image in CI.

### 21.3 Compose profiles

- `dev`: gateway, PostgreSQL, and fake provider.
- `cpu-model`: add a small CPU-compatible local model.
- `gpu-model`: add the GPU inference service and device reservation.
- `real-provider`: never enabled by default; reads secret through the approved mechanism.

Keep the external provider off in automated tests. Capture outbound fake-provider requests for assertions, then delete their bodies at test completion.

---

## 22. Server deployment checklist

### 22.1 Before deployment

- [ ] Confirm GPU model, VRAM, driver, CUDA/container runtime compatibility, RAM, CPU, disk, and network limits.
- [ ] Benchmark candidate local models and OCR on representative synthetic documents.
- [ ] Approve policy categories, actions, purposes, and provider/model allowlist.
- [ ] Confirm external provider data-use, retention, and regional routing settings.
- [ ] Deploy PostgreSQL on the separate database server agreed for production.
- [ ] Permit PostgreSQL access only from the gateway over the private network; do not expose it publicly.
- [ ] Require TLS, a least-privilege gateway account, migrations, encrypted backups, and tested recovery.
- [ ] Verify sensitive mapping values are encrypted by the gateway before database insertion, so PostgreSQL and its backups contain ciphertext rather than plaintext identifiers.
- [ ] Configure KMS/secret manager; do not place production secrets in `.env` files or images.
- [ ] Restrict outbound traffic to approved provider endpoints and required infrastructure.
- [ ] Restrict inbound traffic to internal clients/load balancers.
- [ ] Issue TLS certificates and service identity credentials.
- [ ] Configure encrypted disks and secure temporary storage.
- [ ] Run dependency, container, secret, and vulnerability scans.
- [ ] Complete privacy/security review using evaluation results.

### 22.2 Deployment

- [ ] Pin application image, local-model image, model artifact digest, and policy version.
- [ ] Verify model artifact checksum before serving.
- [ ] Apply migrations before marking the gateway ready.
- [ ] Start dependencies, local model/OCR, then gateway.
- [ ] Confirm readiness fails when each required dependency is unavailable.
- [ ] Run synthetic smoke tests for fast, sanitized, local-only, and fail-closed paths.
- [ ] Capture an outbound request at the controlled fake endpoint and verify no protected fixture content crossed the boundary.
- [ ] Set concurrency according to measured GPU/CPU memory, not optimistic defaults.
- [ ] Configure graceful shutdown to stop intake, finish/cancel requests, and clear temporary data.

### 22.3 Monitoring and alerts

- [ ] Latency and throughput by fast/sanitized path.
- [ ] Parser, OCR, detector, classifier, policy, vault, and provider error rates.
- [ ] Block/local-only/unknown-sensitive counts without values.
- [ ] Local-model GPU memory, utilization, queue depth, and out-of-memory events.
- [ ] Vault expiry backlog and decrypt/authentication failures.
- [ ] Unexpected increase in fast-path ratio or fall in detection counts.
- [ ] External egress destination violations.
- [ ] Disk/temp-volume utilization.

### 22.4 Rollback

- [ ] Retain the previous application image, model digest, and policy version.
- [ ] Make database migrations backward-compatible for at least one release.
- [ ] Roll back application and policy together when their schemas are coupled.
- [ ] Do not roll back to a policy with weaker protection without explicit approval.
- [ ] Verify vault decryptability and expiry behavior after rollback.

---

## 23. Phased implementation roadmap

### Phase 0 — Skeleton and security invariants

Deliver:

- repository structure and typed domain models;
- configuration validation;
- authentication placeholder suitable for replacement;
- policy schema/loader/engine;
- gateway-managed scope creation/close, lifecycle limits, and `SANITIZED_LOCKED` state;
- fake external provider;
- central no-bypass fast-path guard;
- health endpoints, safe logging, CI, Docker Compose.

Exit criteria: an unsupported or uninspected item can never reach the fake external provider.

### Phase 1 — Text-only vertical slice

Deliver:

- text API path;
- deterministic ID/phone/email/bank-card rules;
- local-model semantic detector interface and fake;
- evidence merger;
- scope-scoped tokenization, encrypted PostgreSQL vault, exact restoration across turns;
- safe and sanitized end-to-end tests.

Exit criteria: synthetic direct identifiers are absent from captured outbound requests and correctly restored from known tokens.

### Phase 2 — Documents

Deliver:

- PDF, DOCX, and XLSX local parsing;
- OCR for scanned PDFs;
- safe structured-text reconstruction;
- parser isolation and resource limits;
- malformed/encrypted/partial-parse fail-closed tests.

Exit criteria: supported documents retain useful structure, while unsupported or partially inspected content is never forwarded.

### Phase 3 — Images and multimodal routing

Deliver:

- image validation plus visible-content and metadata inspection without modifying the file;
- local ordinary/sensitive/unknown classifier;
- local OCR for document images;
- byte-for-byte original image pass for approved safe images;
- local analysis to sanitized text for sensitive images, with original bytes withheld;
- mixed-request item-level assembly.

Exit criteria: ordinary permitted images reach the fake VLM; synthetic ID document pixels do not.

### Phase 4 — Production hardening

Deliver:

- production identity and authorization;
- KMS integration and key rotation design;
- network egress controls;
- observability dashboards and alerts;
- load, soak, chaos, and recovery tests;
- provider contract tests;
- operational runbooks and release/rollback process.

Exit criteria: security/privacy sign-off and deployment checklist completed with evidence.

### Later phases

- policy administration with approvals and version history;
- human review workflow, only after the deferred attribution and long-tail-risk questions are separately defined;
- safe streaming restoration;
- verified pixel-level redaction;
- more document formats and languages;
- multi-provider routing;
- privacy-preserving evaluation and drift monitoring.

---

## 24. AI coding agent work order

The coding agent should implement in small, reviewable vertical slices. For each slice, it must add tests before proceeding to the next one.

### Work order

1. Scaffold the repository and pin dependencies.
2. Implement domain models, configuration, error types, and safe logging.
3. Implement gateway-managed scope creation/close, lifecycle enforcement, limits, and PostgreSQL schema.
4. Implement and test strict policy schema, loader, evaluation, and action precedence.
5. Implement the single fake external provider and captured-outbound test harness.
6. Implement text normalization and deterministic rules.
7. Add the local-model adapter/capability probe, strict JSON validation, and fake implementation.
8. Implement evidence merge and complete-decision coverage assertions.
9. Implement scope-scoped tokenizer, encrypted PostgreSQL vault, and exact restorer.
10. Implement the text-only orchestrator and message API vertical slice.
11. Add PDF/DOCX/XLSX parsers with resource limits and structured reconstruction.
12. Add local OCR and image classification protocols, then original-image/sanitized-text routing.
13. Add mixed multimodal request assembly and item-level routing.
14. Add failure injection, security tests, metrics, deadlines, cancellation, and readiness.
15. Add production database connectivity, migrations, Docker hardening, and deployment documentation.

### Rules for the coding agent

- Do not invent a permissive fallback to keep a demo working.
- Do not call the external provider from parser or detector modules.
- Do not let the local model return policy actions.
- Do not log payloads or add debug prints containing content.
- Do not persist plaintext token mappings.
- Do not forward original complex document files after only sanitizing extracted text.
- Do not re-encode, strip metadata from, crop, or redact approved images in the MVP; either send the fully inspected original bytes or withhold them and send sanitized local text.
- Do not implement Redis, derived facts, or multiple external providers in the MVP.
- Do not implement streaming in the MVP.
- Do not weaken tests when a fail-closed assertion fails.
- Keep provider/model/OCR implementations behind protocols with deterministic fakes.
- Record important assumptions in Architecture Decision Records under `docs/adr/`.

---

## 25. Definition of done for the MVP

The MVP is complete only when all of the following are true:

- Safe fully inspected requests use the original fast path.
- Protected text is minimally sanitized according to versioned policy.
- Medical/health analytical content remains usable when policy permits it.
- Faces and ordinary images pass only under explicit policy and successful inspection.
- Approved ordinary images are forwarded byte-for-byte without re-encoding only after complete successful inspection.
- Sensitive images keep their original bytes local and produce only validated, sanitized text for the external LLM.
- Mixed requests route at item level.
- External text responses restore exact current-scope tokens across turns.
- Cross-scope, cross-tenant, expired, malformed, and invented tokens cannot reveal values.
- Explicit close, two-hour idle expiry, 24-hour absolute expiry, and scope limits are enforced.
- Parser, OCR, local-model, classifier, policy, and vault failures are demonstrably fail-closed.
- Automated tests prove that protected fixture bytes never reach the fake external provider.
- Normal logs contain no fixture identifiers or payload bodies.
- Docker-based local setup and server deployment instructions work from a clean machine.
- The production policy, provider, retention settings, and security controls have owner approval.

---

## 26. Final architectural position

This design is appropriate for an MVP because it separates probabilistic detection from deterministic authorization:

```text
Rules + local model + OCR/classifiers
                -> evidence

Policy engine
                -> authoritative action

Gateway sanitizer/router
                -> permitted external request

External LLM/VLM
                -> reasoning

Scope-scoped vault/restorer
                -> user-facing response
```

The main engineering risk is not model quality alone; it is accidental bypass when inspection is incomplete. Build the no-bypass and fail-closed invariants first, then add formats and model sophistication incrementally.
