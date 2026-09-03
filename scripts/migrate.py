#!/usr/bin/env python3
"""Apply SQL migrations in filename order.

Plain SQL rather than a migration framework: the schema is two tables whose
constraints *are* the security design, and a reviewer should be able to read them
without knowing a DSL. Applied migrations are recorded so re-running is a no-op.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import get_settings

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"

_LEDGER = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


async def main() -> int:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    applied: set[str] = set()

    async with engine.begin() as connection:
        await connection.execute(text(_LEDGER))
        rows = await connection.execute(text("SELECT filename FROM schema_migrations"))
        applied = {row[0] for row in rows}

    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.name in applied:
            print(f"skip   {path.name}")
            continue
        print(f"apply  {path.name}")
        sql = path.read_text(encoding="utf-8")
        async with engine.begin() as connection:
            await connection.exec_driver_sql(sql)
            await connection.execute(
                text("INSERT INTO schema_migrations (filename) VALUES (:name)"),
                {"name": path.name},
            )
    await engine.dispose()
    print("migrations complete")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
