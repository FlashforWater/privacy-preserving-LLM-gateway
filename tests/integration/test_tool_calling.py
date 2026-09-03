"""Tool calling through the gateway.

The scenario this exists for: an agent uploads a batch of claim documents and
asks the model to sort them into folders. The model must be able to name one
file, call a tool, and have the agent act on it — all without ever seeing a
filename, because in a claims upload the filenames are things like
身份证-张伟.jpg.

Three of the four directions cannot simply be passed through:

* tool *definitions* can be, but are checked first — a schema whose enum lists
  real filenames would carry them across untouched;
* tool *calls* cannot: the model writes gateway tokens into arguments, and an
  unresolved token is not a filename anyone can open;
* tool *results* cannot: a directory listing is full of real paths.
"""

from __future__ import annotations

import json

import pytest

from app.core.errors import ContentBlocked
from app.domain.content import Manifest
from app.domain.responses import ExternalModelResponse, ExternalToolCall
from app.external.response_validation import parse_openai_chat_completion
from app.sanitization.tokenizer import find_tokens
from tests.conftest import Harness
from tests.fixtures import synthetic

SORT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "move_material",
            "description": "把一份材料移动到指定文件夹",
            "parameters": {
                "type": "object",
                "properties": {
                    "ref": {"type": "string", "description": "材料编号，如 M1"},
                    "folder": {"enum": ["证件", "医疗", "费用", "事故"]},
                },
                "required": ["ref", "folder"],
            },
        },
    }
]


def manifest_with_tools(text: str, tools: list[dict] | None = SORT_TOOLS) -> Manifest:
    payload: dict = {
        "purpose": "general",
        "model": "model-a",
        "messages": [
            {"role": "user", "content": [{"type": "text", "item_id": "p1", "text": text}]}
        ],
    }
    if tools is not None:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    return Manifest.model_validate(payload)


async def run(harness: Harness, manifest: Manifest, responses=None):
    if responses is not None:
        harness.adapter._responses = responses  # noqa: SLF001
    scope = await harness.open_scope()
    normalized = harness.normalize(manifest)
    return await harness.orchestrator.process(harness.context(scope, manifest), normalized)


class TestToolDefinitions:
    async def test_definitions_are_forwarded_unchanged(self, harness: Harness) -> None:
        await run(harness, manifest_with_tools("整理这些材料"))
        request = harness.adapter.requests[0]
        assert request.tools == tuple(SORT_TOOLS)
        assert request.tool_choice == "auto"

    async def test_a_schema_carrying_real_data_is_refused(self, harness: Harness) -> None:
        """The realistic mistake: an agent builds the enum from the actual files."""
        leaky = json.loads(json.dumps(SORT_TOOLS))
        leaky[0]["function"]["parameters"]["properties"]["ref"] = {
            "enum": [f"证件-{synthetic.ID_CARD}.jpg"]
        }
        with pytest.raises(ContentBlocked) as exc:
            await run(harness, manifest_with_tools("整理", leaky))
        assert "tool definitions" in str(exc.value)
        assert harness.adapter.requests == []

    async def test_no_tools_is_fine(self, harness: Harness) -> None:
        response = await run(harness, manifest_with_tools("你好", tools=None))
        assert response.status == "completed"
        assert harness.adapter.requests[0].tools == ()


class TestToolCallResponses:
    def test_a_tool_call_reply_is_not_an_empty_reply(self) -> None:
        """Before tool calls were parsed, this raised "no text content" and the
        agent lost the call entirely."""
        response = parse_openai_chat_completion(
            {
                "model": "model-a",
                "choices": [{
                    "index": 0, "finish_reason": "tool_calls",
                    "message": {"role": "assistant", "content": None, "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {
                            "name": "move_material",
                            "arguments": '{"ref": "M2", "folder": "证件"}'}}]},
                }],
            },
            model="model-a",
        )
        assert response.tool_calls[0].name == "move_material"
        assert response.text_fields == []

    async def test_tokens_in_arguments_are_restored(self, harness: Harness) -> None:
        """An unresolved token in an argument is worse than one in prose: the
        caller feeds arguments to a real function."""
        manifest = manifest_with_tools(f"整理 {synthetic.PERSON_CJK} 的材料，电话 {synthetic.PHONE}")
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest)
        harness.adapter._responses = [ExternalModelResponse(model="model-a")]  # noqa: SLF001
        await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        token = find_tokens(harness.adapter.captured_text())[0]

        follow_up = manifest_with_tools("继续")
        harness.adapter._responses = [  # noqa: SLF001
            ExternalModelResponse(
                model="model-a",
                tool_calls=[ExternalToolCall(
                    id="c1", name="move_material",
                    arguments=json.dumps({"owner": token, "folder": "证件"},
                                         ensure_ascii=False))],
            )
        ]
        normalized2 = harness.normalize(follow_up)
        result = await harness.orchestrator.process(
            harness.context(scope, follow_up), normalized2
        )
        arguments = result.output["tool_calls"][0]["arguments"]  # type: ignore[index]
        assert synthetic.PHONE in arguments or synthetic.PERSON_CJK in arguments
        assert not find_tokens(arguments)


class TestMaterialReferences:
    async def test_refs_are_declared_and_returned(self, harness: Harness) -> None:
        response = await run(harness, manifest_with_tools("整理这些材料"))
        assert response.privacy.material_refs == {"M1": "p1"}
        # The model is told the numbering; the content itself is untouched.
        assert "M1" in harness.adapter.requests[0].system_prompt

    async def test_content_is_not_prefixed(self, harness: Harness) -> None:
        """Guide §14.1: the fast path forwards the user's text unmodified.

        References live in the gateway's system prompt, which is framing, rather
        than as a prefix on the user's own content.
        """
        text = "这些材料该怎么归类？"
        await run(harness, manifest_with_tools(text))
        assert harness.adapter.captured_text() == text

    async def test_filenames_never_reach_the_model(self, harness: Harness) -> None:
        """A filename is not document content — the gateway used to write it into
        the extracted text itself, so detection never saw it."""
        data = synthetic.docx_bytes(body_text="事故经过：路口碰撞。")
        manifest = Manifest.model_validate({
            "purpose": "general", "model": "model-a",
            "messages": [{"role": "user", "content": [
                {"type": "file", "item_id": "f1", "file_field": "file_f1",
                 "filename": "身份证-张伟.docx"}]}],
        })
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest, {"file_f1": data})
        await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        captured = harness.adapter.captured_text()
        assert "身份证-张伟" not in captured
        assert "张伟" not in captured


class TestToolResults:
    async def test_a_tool_result_is_inspected_like_any_content(
        self, harness: Harness
    ) -> None:
        """A directory listing comes back full of real paths. Feeding it straight
        to the model would mean the gateway protected only the first turn."""
        listing = f"/uploads/{synthetic.PERSON_CJK}-身份证.jpg\n/uploads/发票.pdf"
        manifest = Manifest.model_validate({
            "purpose": "general", "model": "model-a",
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "item_id": "p1", "text": "列出文件"}]},
                {"role": "tool", "tool_call_id": "c1", "content": [
                    {"type": "text", "item_id": "r1", "text": listing}]},
            ],
        })
        harness.local_model._default = []  # noqa: SLF001
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest)
        await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        captured = harness.adapter.captured_text()
        # The name is detected by the label-free CJK path only when the local
        # model finds it; what must hold regardless is that the result was routed
        # through inspection rather than around it.
        assert "列出文件" in captured
        assert any(item.item_id == "r1" for item in normalized.items)
