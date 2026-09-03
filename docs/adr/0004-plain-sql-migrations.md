# ADR 0004 — Plain SQL migrations, applied by a small runner

**Status:** accepted

## Context

The schema is two tables. Their constraints are not incidental — the unique index
on `(tenant_id, scope_id, entity_type, canonical_value_hmac)` is what makes
"the same value gets the same token inside one scope" a database guarantee rather
than an application convention, and the foreign key with `ON DELETE CASCADE` is
what makes closing a scope actually remove its mappings.

## Decision

Migrations are numbered `.sql` files in `migrations/`, applied in filename order
by `scripts/migrate.py`, which records applied filenames in `schema_migrations`.

## Consequences

* A reviewer reads the constraints directly, with no framework in between.
* No autogeneration, so a schema change is always a deliberate, written statement.
* Down-migrations are not provided. Rollback is handled by keeping migrations
  backward-compatible for at least one release (guide §22.4), which is the
  safer property for a table holding encrypted material.
