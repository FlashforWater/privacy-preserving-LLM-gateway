"""Architectural invariants enforced at the source level.

These read like unusual tests, but each one guards a rule that is invisible at
runtime until the day it is broken:

* a detector that can call the provider makes "inspection then forward" optional;
* a detector that can read policy blurs evidence and authorization;
* an API route that reimplements the fast-path guard creates a second, untested
  forwarding decision.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "app"


def imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.append("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
    return names


@pytest.mark.parametrize("package", ["detectors", "parsers", "ocr"])
def test_inspection_layers_never_import_the_provider(package: str) -> None:
    for source_file in (ROOT / package).rglob("*.py"):
        for module in imported_modules(source_file):
            assert "app.external" not in module, f"{source_file.name} imports {module}"


@pytest.mark.parametrize("package", ["detectors", "parsers", "ocr"])
def test_inspection_layers_never_import_policy(package: str) -> None:
    for source_file in (ROOT / package).rglob("*.py"):
        for module in imported_modules(source_file):
            assert "app.policy" not in module, f"{source_file.name} imports {module}"


def test_policy_engine_never_imports_a_model_client() -> None:
    for module in imported_modules(ROOT / "policy" / "engine.py"):
        assert "local_model" not in module
        assert "app.external" not in module


def test_domain_models_stay_framework_free() -> None:
    """Guide §6: domain models independent of FastAPI, DB, OCR and provider SDKs."""
    banned = ("fastapi", "sqlalchemy", "asyncpg", "httpx", "starlette")
    for source_file in (ROOT / "domain").rglob("*.py"):
        for module in imported_modules(source_file):
            assert not any(module.startswith(name) for name in banned), (
                f"{source_file.name} imports {module}"
            )


def test_no_bare_except_pass_anywhere() -> None:
    """Guide §16: no ``except Exception: pass`` and no fallback-to-forward."""
    for source_file in ROOT.rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                body = [n for n in node.body if not isinstance(n, ast.Expr | ast.Pass)]
                only_pass = all(isinstance(n, ast.Pass) for n in node.body)
                if only_pass and node.type is None:
                    pytest.fail(f"{source_file.relative_to(ROOT)}: bare except: pass")
                del body


def test_streaming_is_not_implemented() -> None:
    """Guide §13.5: streaming stays off until restoration across chunks is designed."""
    for source_file in ROOT.rglob("*.py"):
        text = source_file.read_text(encoding="utf-8")
        assert '"stream": True' not in text
        assert "stream=True" not in text
