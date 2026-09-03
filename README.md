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
| Text, DOCX, XLSX, PNG/JPEG inspection | implemented |
| Image classification, byte-for-byte pass, local-analysis routing | implemented |
| PDF text extraction | implemented; needs `pip install ".[documents]"` |
| PDF page rasterisation for scanned pages | **not implemented** — a scanned page fails closed until a `PageRenderer` is supplied |
| Production principal verifier (mTLS / short-lived identity) | **not implemented** — `StaticTokenVerifier` is a development stand-in and readiness fails in production |
| Streaming | deliberately absent (guide §13.5) |
| Pixel-level image redaction | deliberately absent ([ADR 0002](docs/adr/0002-no-image-mutation.md)) |
| Derived facts, multi-provider routing, Redis | deliberately absent |

Both "not implemented" rows fail closed rather than degrading quietly: a scanned
PDF page is blocked, and a production deployment reports not-ready until a real
verifier is wired.

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
