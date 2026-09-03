# Privacy-Preserving LLM Gateway

A gateway that sits between internal applications and an external LLM/VLM. It
inspects every request locally, lets a policy engine decide what may leave, sends
only what is permitted, and restores its own tokens in the reply.

Implementation of `privacy_preserving_llm_gateway_mvp_development_guide.md`.

---

## The routing rule

```
                          ┌─────────────────────────────────────────┐
  client ──▶ normalize ──▶│ parse · OCR · rules · local model       │
                          │           ↓ evidence                     │
                          │      policy engine  ← authoritative      │
                          └───────────────┬─────────────────────────┘
                                          │
                 nothing detected,        │        anything detected,
                 everything inspected     │        or inspection incomplete
                                          │
            ┌─────────────────────────────┴──────────────────────────────┐
            ▼                                                            ▼
     FAST PATH                                                  SANITIZED PATH
  original text and                                    tokenize · redact · withhold
  original image bytes,                                per item, then persist the
  byte-for-byte                                        mappings and lock the scope
            │                                                            │
            └──────────────────────┬─────────────────────────────────────┘
                                   ▼
                        ══════ trust boundary ══════
                                   ▼
                          external LLM / VLM
                                   ▼
                     validate response, restore exact
                     tokens for this tenant + scope
```

Three properties hold everywhere:

1. **Policy is authoritative.** Detectors produce evidence; only the policy
   engine produces actions, and it never calls a model.
2. **No implicit pass.** Absence of a successful inspection is not evidence of
   safety. A parser, OCR, detector, classifier, policy or vault failure ends the
   request; it never becomes permission to forward.
3. **Item-level routing.** One sensitive attachment does not discard the safe
   ones.

---

## Quick start

```bash
cp .env.example .env
make bootstrap          # dependencies + development vault keys
make up                 # gateway + PostgreSQL + recording fake provider
make migrate
make smoke              # safe / sanitized / blocked / closed-scope paths
```

`make up` starts the fake provider, not a real one. Real provider access is a
separate profile that is never enabled by default, so a local run cannot send
data to the internet by accident.

With a GPU available:

```bash
make up-gpu             # adds a vLLM-served local detection model
```

### Talking to it

```bash
SCOPE=$(curl -s -XPOST localhost:8080/v1/scopes \
          -H 'Authorization: Bearer dev-token-1' -d '{}' | jq -r .scope_id)

curl -s -XPOST localhost:8080/v1/scopes/$SCOPE/messages \
  -H 'Authorization: Bearer dev-token-1' \
  -F 'manifest={"purpose":"general","model":"model-a","messages":[
        {"role":"user","content":[
          {"type":"text","item_id":"p1","text":"Patient: Wei Zhang, phone 13812345678."}]}]}'
```

The response carries the restored text plus a non-sensitive `privacy` block:
which path was taken, the policy version, action counts, and any withheld item
ids. It never carries finding values, token mappings or OCR text.

---

## Layout

| Path | Responsibility |
|---|---|
| `app/core/` | config gate, enums, errors, safe logging, deadlines |
| `app/domain/` | typed models — no FastAPI, DB, OCR or provider imports |
| `app/parsers/` | content sniffing, PDF/DOCX/XLSX/image inspection, resource limits |
| `app/detectors/` | regex + checksum rules, field labels, local model, image classifier |
| `app/policy/` | strict schema, loader, the authoritative engine |
| `app/sanitization/` | tokenizer, span rewriter, item router |
| `app/vault/` | AES-256-GCM encryption, Postgres and in-memory stores |
| `app/gateway/` | normalizer, evidence merger, **fast-path guard**, orchestrator |
| `app/external/` | the single provider adapter, retry, response validation |
| `app/restore/` | exact-token scanner and restorer |

Two files carry more weight than the rest:

* `app/gateway/request_builder.py` — `assert_original_forward_allowed` is the
  **only** place that decides whether original content may be forwarded. Its six
  conditions come from guide §14.1 and each has a test that flips exactly that
  condition.
* `app/policy/engine.py` — the only place an action is chosen.

---

## Tokens

```
[[PGW_V1_PERSON_K7M4Q2Z9F8N3]]
```

The suffix is cryptographically random and carries no part of the original value.
Tokens are unique per tenant and scope and are meaningless outside them. Within
one scope the same deterministically canonicalized value reuses the same token,
so the model can follow "the same person" across turns.

Canonicalization is **format-level only**. `Zhang San`, `Mr. Zhang` and
`the patient` stay separate values with separate tokens. See
[ADR 0003](docs/adr/0003-deterministic-entity-normalization.md): splitting one
person costs answer quality, merging two people is an incident.

Restoration accepts the exact grammar and nothing else. An invented, malformed,
expired, cross-scope or cross-tenant token is returned to the caller unchanged
and counted in `gateway_unknown_tokens_total`.

---

## Scopes

The gateway generates `scope_id`; the business system stores and replays it.

```
POST /v1/scopes                     → ACTIVE / CLEAN
first tokenization                  → ACTIVE / SANITIZED_LOCKED   (one-way)
close, 2h idle, or 24h absolute     → CLOSED, mappings deleted
```

`SANITIZED_LOCKED` is permanent for the scope's life. A later "clean" turn in a
conversation that already tokenized something must not ship the original of what
an earlier turn protected.

Limits (50 turns, 20 files, 200 MB, 200 pages, 5,000 mappings) are enforced on
admission, before any parsing or model time is spent.

---

## The local detection model

The gateway needs a local instruction model to find entities that have no shape —
names, addresses, organisations. It talks to any OpenAI-compatible endpoint:

```dotenv
LOCAL_MODEL_BASE_URL=http://your-host/vllm/v1   # mind the path prefix
LOCAL_MODEL_NAME=Qwen3.8                        # case-sensitive
LOCAL_MODEL_API_KEY=...                         # in .env, never in .env.example
LOCAL_MODEL_DISABLE_THINKING=true
```

Verify the endpoint before wiring it in:

```bash
make check-model
```

That checks reachability, the exact model id, native `json_schema` support,
whether the reasoning switch is honoured, and runs a real detection call whose
spans are validated the way the gateway validates them.

Two things measurement on a live Qwen3.8 changed in this codebase:

* **Reasoning models return `content: null` while they think.** Detection gains
  nothing from deliberation and a truncated answer means an incomplete entity
  list, so thinking is turned off through the chat template, and both `null`
  content and `finish_reason: "length"` are treated as detector failures rather
  than as "nothing found".
* **The model identifies entities well and counts characters badly.** Its `text`
  is treated as a claim and located in the document by the gateway; its offsets
  are only a hint. See
  [ADR 0005](docs/adr/0005-locate-model-spans-in-the-document.md) — on the
  measured sample this moved recall from 1/6 to 6/6 with no hallucination
  accepted.

**This endpoint sits inside the trust boundary.** It receives unsanitized content
— OCR text, document bodies, identifiers in the clear — because the whole
sanitization chain runs after it. Keep it on a private network.

---

## The external model

```dotenv
EXTERNAL_BASE_URL=https://provider.example/v1   # include the API path prefix
EXTERNAL_API_KEY=...                            # secret manager in production
EXTERNAL_ALLOWED_MODELS=model-a,model-b         # allow-list, not a default
EXTERNAL_TIMEOUT_SECONDS=60
```

```bash
make check-external
```

`EXTERNAL_ALLOWED_MODELS` is an allow-list: a manifest naming a model outside it
is refused, and the check runs twice — once at the route, once inside the adapter
immediately before bytes leave the process.

Two things measurement against a live provider changed here:

* **A base URL missing its API path prefix does not fail loudly.** The host's web
  console answers `200` with an HTML page, so `raise_for_status` passes and the
  JSON decode error used to escape as a generic 500. The adapter now checks the
  content type and names the likely cause.
* **The output budget covers reasoning too.** A reasoning provider spends it
  before writing a word — an 800-token budget was consumed entirely on
  deliberation, returning empty content, which is indistinguishable from "the
  model had nothing to say". The default is now 4000 and an exhausted budget
  says so.

Token fidelity is the property the restoration path depends on, and
`make check-external` tests it directly: a synthetic probe that forces the model
to refer to entities, checked for markers returned byte-for-byte, invented, or
rewritten.

### Reasoning

`EXTERNAL_REASONING=provider_default|disabled`. The default leaves the provider
alone, because the external model is the reasoning engine and its analysis is the
product.

`disabled` is worth evaluating. Measured against deepseek-v4-flash on a
cross-material claims question (n=6 with reasoning, n=5 without):

| | reasoning on | reasoning off |
|---|---|---|
| latency | 2.4–6.3 s | 1.3–2.1 s |
| completion tokens | 181–617 | 117–138 |
| replies with markers intact | 4 of 6 | 5 of 5 |

The fidelity gap has a plausible mechanism: during a long deliberation the model
paraphrases entities into "甲/乙" and writes its answer from that paraphrase,
losing the markers. A lost marker is a utility problem rather than a leak —
restoration tolerates absence — but a reply saying "the driver" instead of a
token cannot be attributed to anyone.

The default was left unchanged because analytical quality on hard cases was
assessed by reading a handful of answers, not measured. Settle it with the Phase
2 evaluation set. The parameter name is provider-specific and several providers
ignore an unrecognised one silently — deepseek-v4-flash treats
`reasoning_effort: "minimal"` as no instruction and reasons *more* — so
`make check-external` reports the reasoning-token count and warns when the switch
appears to be ignored.

---

## Chinese-language operation

The corpus is Chinese insurance and medical paperwork, and several things behave
differently there than they do on English fixtures. Each of the following was
measured against the deployed Qwen3.8 endpoint and real-shaped Chinese documents.

**The model's character offsets are wrong essentially always.** On a Chinese
claims note it named 13 of 13 entities correctly and got 0 of 13 offsets right —
against 1 of 6 correct on English text. Locating the claimed string ourselves
([ADR 0005](docs/adr/0005-locate-model-spans-in-the-document.md)) is therefore not
an optimisation here: without it the local detector contributes nothing at all in
Chinese.

**The detection prompt is Chinese** (`entity_detection_zh_v1`, selectable through
`LOCAL_MODEL_PROMPT`). It uses 597 completion tokens against 785 for the English
prompt on the same document, and it stops the model labelling plates, phone
numbers and ID numbers as `UNKNOWN_SENSITIVE` — which the policy blocks on, so
the English prompt was turning routine claims into blocked requests. The prompt
tells the model that identifiers with deterministic rules are not its job, but
that *other* document numbers — 护照, 港澳通行证, 台胞证, 社保卡号, 病历号 —
still are, so the safety net stays in place.

**Forms align fields with spaces, not colons.** `姓名　张伟` and
`被保险人  张伟` carry no delimiter, so the label rules accept whitespace as a
separator and stop the value at a two-space column gap.

**Deterministic rules cover the Chinese identifier set**: 18- and 15-digit
national IDs, 统一社会信用代码 (with its GB 32100 check character, as the new
`ORG_ID` entity type), 护照 / 港澳通行证 / 台胞证, landlines written with an
area-code separator, plates with a full-width interpunct, and street-level
addresses anchored on 路/街/号 with the Chinese preposition in front trimmed off.

**OCR spacing inside a name no longer splits its token.** Chinese has no word
spacing, so a space inside 「张 伟」 is layout noise; canonicalization removes
whitespace between CJK characters. Left in, the same person would receive two
tokens and coreference would break across materials in one scope — the external
model would see two people where the file has one. This is still deterministic
normalization, not alias merging: 「张伟」 and 「张先生」 remain separate.

---

## Configuration

`.env.example` documents every key. Production refuses to start when any of these
hold — the check is in `Settings.validate_for_environment`, and the process stays
un-ready rather than serving:

* placeholder or missing vault keys;
* `ENABLE_PAYLOAD_LOGGING=true`;
* `DEV_STATIC_TOKENS` still configured;
* `STORAGE_BACKEND=memory`;
* a non-HTTPS provider URL, or a wildcard provider host;
* an unreadable or invalid policy file.

Policy is loaded and validated once at startup. There is no hot reload: different
workers evaluating one conversation under different policies is worse than a
restart.

---

## Seeing the pipeline

```bash
make trace-ui        # http://127.0.0.1:8090
```

A local page that runs a request through the real gateway and shows every stage:
text and attachments (PDF, DOCX, XLSX, PNG, JPEG) can be dropped straight in, and
each is shown with the parser that handled it, the text it yielded and the
findings against it —
what arrived, what each detector found and on what evidence, what policy decided
and under which rule, what actually crossed the boundary, what came back, and
what restoration produced. Two dashed lines mark the trust boundary so the
outbound payload is unmistakable.

It is useful for the questions that are hard to answer from logs: why a request
did not take the fast path, why a name was missed, whether the model or a rule
found something, whether the tokens survived the round trip.

One thing it is good at showing: a DOCX comment, a document's `creator`
property, or a very-hidden XLSX sheet is content like any other. Drop in a
workbook whose hidden sheet names a different payer and the external model will
report the contradiction — which is only possible because the parser read the
sheet nobody opens.

**Development only, and it refuses to start otherwise.** The page shows original
text, matched finding values and the decrypted token mapping table — exactly what
this service exists to keep inside. It is a script rather than a route in `app/`
so that it cannot be switched on in a deployed service by flipping a flag, it
binds to loopback, and `tests/unit/test_trace_hook.py` fails if anything in
`app/` ever constructs a recorder.

The trace comes from the real orchestrator through an opt-in hook, not from a
parallel implementation. A debugging view that quietly diverges from the code is
worse than none: it builds confidence in behaviour that is not there.

---

## Testing

```bash
make test            # unit, integration, contract
make test-security   # security and failure injection
make lint            # ruff, mypy, policy validation
```

The suite is organised around the assertions that matter rather than around
modules:

* `tests/unit/test_fast_path_guard.py` — every guard condition, flipped one at a
  time.
* `tests/security/test_no_leakage.py` — no synthetic identifier appears in the
  captured outbound request or in the logs.
* `tests/failure_injection/test_fail_closed.py` — break one dependency, assert
  the request fails **and** the provider received zero bytes.
* `tests/security/test_layer_isolation.py` — source-level checks that detectors
  cannot import the provider or the policy engine, and that no route
  reimplements the fast-path guard.

All fixtures are synthetic. The national-ID values carry valid checksums because
detector confidence depends on them; the numbers belong to nobody.

---

## What is and is not implemented

| Area | State |
|---|---|
| Scope lifecycle, limits, `SANITIZED_LOCKED` | implemented |
| Policy schema, loader, engine, precedence | implemented |
| Deterministic rules + checksums + field labels | implemented |
| Local-model detector, strict validation, span verification | implemented |
| Evidence merging, overlap resolution | implemented |
| Tokenizer, encrypted vault, exact restoration | implemented |
| Text, DOCX, XLSX inspection | implemented; standard library only |
| PNG/JPEG inspection and routing | implemented; OCR needs `pip install ".[ocr]"` |
| PDF, including scanned pages | implemented; needs `pip install ".[documents]"` |
| Production principal verifier (mTLS / short-lived identity) | **not implemented** — `StaticTokenVerifier` is a development stand-in and readiness fails in production |
| Streaming | deliberately absent (guide §13.5) |
| Pixel-level image redaction | deliberately absent ([ADR 0002](docs/adr/0002-no-image-mutation.md)) |
| Derived facts, multi-provider routing, Redis | deliberately absent |

The one remaining gap fails closed rather than degrading quietly: a production
deployment reports not-ready until a real principal verifier is wired.

A scanned PDF page — one with no text layer — is rendered with PDFium and read by
OCR. Where that cannot be done legibly within the pixel budget, or where the
render or OCR fails, the page stays uninspected and the file is blocked. That
matters more than it sounds: an unreadable render returns no text, and no text is
indistinguishable from a clean page, so the failure has to be loud rather than
empty.

---

## Deployment

`docs/` holds the architecture decisions. Before a production deployment, work
through §22 of the development guide — in particular:

* PostgreSQL on the separate database server, reachable only from the gateway;
* KMS or secret manager for `VAULT_MASTER_KEY_B64` and `VAULT_HMAC_KEY_B64`
  (never `.env`, never the image);
* egress restricted to the approved provider endpoint;
* a captured outbound request from the fake endpoint, verified to contain no
  protected fixture content;
* policy, provider, retention settings and security controls signed off by their
  owner.

The example policy in `config/policy.default.yaml` is a starting point, **not a
legal determination**. The organisation responsible for the deployment must
review and approve the final policy.

---

## Known limits

Detection is not perfect and this design does not claim otherwise. What it does
claim is that a *failure* of detection cannot silently become a forward: the fast
path opens only when every inspection stage completed and found nothing, and
every other route is explicit about what it removed.

Two consequences worth stating plainly:

* A false positive costs utility — an unnecessary token or a withheld
  attachment. A false negative discloses data. The rules and thresholds are
  tuned for recall on high-risk direct identifiers accordingly.
* The gateway protects identifiers it can recognise. Content that identifies a
  person without containing any identifier — a rare diagnosis plus a small
  region, an unusual combination of ordinary facts — is out of scope for the
  MVP, and the guide defers it deliberately rather than pretending otherwise.
