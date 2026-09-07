# SQL proxy

> **Status: planned.** This page describes an upcoming feature, not shipped
> behavior.

## What it is

A SQL-over-HTTP proxy in front of a customer's own Postgres (Supabase, Neon, RDS,
self-hosted). The client sends a query; Maskura executes it against the backing
database, runs the result set through the privacy layer, and returns masked JSON
rows.

It is the same promise Maskura makes for objects, applied to rows:

> raw in Postgres, scrubbed in the JSON response.

## Why

AI agents already reach production databases. Fine-grained access control is the
blocker, and Postgres's native answer — roles, column grants, RLS, views — does not
scale to many agents.

Maskura takes the opposite approach: the agent can run whatever `SELECT` it wants,
but the only thing it can ever *observe* is the masked projection. Masking is
post-query and server-side, so the raw column never leaves Maskura.

## Scope (day one)

- **Read-only** — writes are rejected.
- **BYO Postgres** — Maskura fronts the customer's database using the same
  encrypted-credential + routing machinery as the S3 backend.
- **Schema-aware masking** — column-level policy (`users.email` is always masked),
  with type-aware transforms (bucketing numbers, coarse-graining dates).
- **Reuse** — masking runs through the same sandboxed wasm pipeline and
  `binary_reductor` claim model.

## See also

- [Binary adapters](binary-adapters.md)
- [MCP](mcp.md)
