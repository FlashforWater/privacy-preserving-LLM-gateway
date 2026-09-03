"""Exact-token restoration (guide §13.4).

The algorithm, in order:

1. scan only fields explicitly declared as text;
2. extract strings matching the exact gateway token grammar;
3. fetch mappings by ``(tenant_id, scope_id, token)``;
4. restore only tokens that exist, are unexpired and authenticate;
5. leave unknown or malformed tokens **unchanged** and count them;
6. apply output length and substitution-count limits.

Step 5 is the important one. An external model that invents
``[[PGW_V1_PERSON_AAAAAAAAAAAA]]`` gets that string back verbatim — the lookup is
keyed by tenant and scope, so an invented token cannot reach another scope's data,
and a failed lookup is never an error the model can use as an oracle. It is
counted instead, because a rise in unknown tokens is a security signal.

Nothing here interprets instructions found in the response. There is no path from
model text to a vault query beyond the exact-token lookup.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.errors import ExternalProviderError
from app.domain.requests import RequestContext
from app.domain.responses import (
    ExternalModelResponse,
    ExternalTextField,
    ExternalToolCall,
    RestorationStats,
)
from app.vault.base import Vault

from .token_scanner import MAX_OUTPUT_CHARS, MAX_SUBSTITUTIONS, scan, unique_tokens


@dataclass(slots=True)
class RestorationOutcome:
    response: ExternalModelResponse
    stats: RestorationStats = field(default_factory=RestorationStats)


class Restorer:
    def __init__(self, vault: Vault) -> None:
        self._vault = vault

    async def restore_text_fields(
        self, response: ExternalModelResponse, context: RequestContext
    ) -> RestorationOutcome:
        if response.total_text_length() > MAX_OUTPUT_CHARS:
            raise ExternalProviderError(
                "provider response exceeded the restoration size limit",
                public_detail="external provider returned an unexpected response",
            )

        # One lookup per distinct token across the whole response, not per
        # occurrence: a repeated token must not multiply vault reads.
        distinct: dict[str, str | None] = {}
        # Tool arguments are model-written text like any other, and a token left
        # unresolved in them is worse than one left in prose: the caller feeds
        # arguments to a real function, and "[[PGW_V1_PERSON_K7M4Q2Z9F8N3]]" is
        # not a filename anyone can open.
        for text in [f.text for f in response.text_fields] + [
            c.arguments for c in response.tool_calls
        ]:
            for token in unique_tokens(text):
                distinct.setdefault(token, None)

        for token in list(distinct):
            distinct[token] = await self._vault.resolve(
                tenant_id=context.tenant_id,
                scope_id=context.scope.scope_id,
                token=token,
            )

        restored_fields: list[ExternalTextField] = []
        restored_calls: list[ExternalToolCall] = []
        seen = restored = unknown = substitutions = 0

        def substitute(text: str) -> str:
            nonlocal seen, restored, unknown, substitutions
            occurrences = scan(text)
            seen += len(occurrences)
            result = text
            for occurrence in sorted(occurrences, key=lambda o: o.start, reverse=True):
                original = distinct.get(occurrence.token)
                if original is None:
                    unknown += 1
                    continue
                if substitutions >= MAX_SUBSTITUTIONS:
                    raise ExternalProviderError(
                        "provider response exceeded the substitution limit",
                        public_detail="external provider returned an unexpected response",
                    )
                result = result[: occurrence.start] + original + result[occurrence.end :]
                substitutions += 1
                restored += 1
            return result

        for field_ in response.text_fields:
            occurrences = scan(field_.text)
            seen += len(occurrences)
            text = field_.text
            # Replace back to front so earlier offsets stay valid.
            for occurrence in sorted(occurrences, key=lambda o: o.start, reverse=True):
                original = distinct.get(occurrence.token)
                if original is None:
                    unknown += 1
                    continue  # leave the token untouched
                if substitutions >= MAX_SUBSTITUTIONS:
                    raise ExternalProviderError(
                        "provider response exceeded the substitution limit",
                        public_detail="external provider returned an unexpected response",
                    )
                text = text[: occurrence.start] + original + text[occurrence.end :]
                substitutions += 1
                restored += 1
            restored_fields.append(ExternalTextField(path=field_.path, text=text))

        for call in response.tool_calls:
            restored_calls.append(
                ExternalToolCall(
                    id=call.id, name=call.name, arguments=substitute(call.arguments)
                )
            )

        return RestorationOutcome(
            response=ExternalModelResponse(
                model=response.model,
                text_fields=restored_fields,
                tool_calls=restored_calls,
                finish_reason=response.finish_reason,
                usage=response.usage,
            ),
            stats=RestorationStats(
                tokens_seen=seen,
                tokens_restored=restored,
                unknown_tokens=unknown,
                substitutions=substitutions,
            ),
        )
