"""The tracing hook must be inert unless a caller opts in.

``app/gateway/trace.py`` holds original text, matched finding values and token
mappings. That is the point of it, and it is why nothing inside ``app/``
constructs one. These tests pin both halves: the hook changes nothing when it is
absent, and no production code path switches it on.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.gateway.trace import TraceRecorder

APP = Path(__file__).resolve().parents[2] / "app"


class TestRecorder:
    def test_stages_are_ordered_and_timed(self) -> None:
        recorder = TraceRecorder()
        recorder.begin("inspect")
        recorder.record(items=[1, 2])
        recorder.end()
        recorder.begin("policy")
        recorder.record(policy_version="v1")
        recorder.end()

        stages = recorder.to_json_obj()
        assert [s["name"] for s in stages] == ["inspect", "policy"]
        assert all(isinstance(s["duration_ms"], float) for s in stages)
        assert stages[0]["data"] == {"items": [1, 2]}

    def test_record_without_begin_does_not_raise(self) -> None:
        """A debug tool that crashes while explaining a crash is useless."""
        recorder = TraceRecorder()
        recorder.record(note="orphan")
        assert recorder.to_json_obj()[0]["data"] == {"note": "orphan"}


class TestHookIsOptIn:
    def test_process_defaults_to_no_trace(self) -> None:
        import inspect

        from app.gateway.orchestrator import Orchestrator

        signature = inspect.signature(Orchestrator.process)
        assert signature.parameters["trace"].default is None

    def test_nothing_in_app_constructs_a_recorder(self) -> None:
        """Only scripts/trace_ui.py may build one, and it refuses to run in
        production. If this ever fails, a service is one config flag away from
        capturing payloads."""
        for source_file in APP.rglob("*.py"):
            if source_file.name == "trace.py":
                continue
            tree = ast.parse(source_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    assert node.func.id != "TraceRecorder", (
                        f"{source_file.relative_to(APP)} constructs a TraceRecorder"
                    )

    def test_trace_module_is_not_imported_by_the_api_layer(self) -> None:
        """Checked by import, not by substring: a comment mentioning a stack
        trace is not an import, and a test that cannot tell the difference gets
        deleted the first time it cries wolf."""
        for source_file in (APP / "api").glob("*.py"):
            tree = ast.parse(source_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                for module in modules:
                    assert not module.endswith("gateway.trace"), source_file.name


class TestInspectorRefusesProduction:
    def test_script_checks_the_environment(self) -> None:
        source = (
            Path(__file__).resolve().parents[2] / "scripts" / "trace_ui.py"
        ).read_text(encoding="utf-8")
        assert "is_production" in source
        assert "SystemExit" in source
        # Loopback only: the page shows unredacted content by design.
        assert '"127.0.0.1"' in source
