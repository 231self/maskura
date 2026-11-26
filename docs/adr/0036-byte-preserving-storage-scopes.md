# ADR 0036: Byte-preserving storage scopes for external table catalogs

- Status: Accepted
- Date: 2026-11-26

## Context

Apache Polaris (an Iceberg REST catalog) uses S3 as its object store. On
`CREATE TABLE` it writes `metadata/00000-<uuid>.metadata.json` before the table
exists. The Iceberg table-format adapter (ADR 0028) classifies that key as a
table-root document, so:

- with the default gate closed, `v0.7.34`/`v0.7.35` returned S3
  `501 NotImplemented` for the write;
- with `MASKURA_ENABLE_ICEBERG=true`, `v0.7.35` returned HTTP 400 because the
  adapter expects the current metadata of an existing table and walks it to
  commit a new version.

The failure depends on the key classification, not on the payload: the same
body under an ordinary key succeeds, whether signed fixed-length or AWS
SigV4 chunked. A catalog that owns its commit lifecycle must be able to store
individual objects, byte-for-byte, without Maskura treating them as a table to
transform.

Two approaches were considered:

1. **Teach the Iceberg adapter to create initial tables.** This helps a future
   table-processing workflow, but it couples object storage to the catalog's
   table lifecycle and still needs separate handling for partial writes,
   commits, and reads.
2. **An explicitly configured byte-preserving storage scope.** The operator
   declares that a bucket or key prefix is external-catalog storage. Covered
   operations store and serve the bytes unchanged; the catalog owns commits.
   Everything outside the scope keeps its current behavior.

## Decision

Add an operator-only, default-empty scope list:

```
MASKURA_BYTE_PRESERVING_SCOPES=warehouse,catalogs/polaris
```

Each entry is `bucket` or `bucket/prefix`. The list is parsed and validated at
startup. The scope is resolved from **server configuration plus the
authenticated request's bucket** — a key suffix, HTTP header, query parameter,
or body shape can never select it. The control-plane grant still has to admit
the operation; the scope grants nothing by itself.

### Request behavior

- **No resolution substitute by key in the resolver interface.** The pipeline
  resolver has no key parameter, so covered requests bypass `Gateway::resolve`
  in the handlers and execute a synthetic explicit-passthrough resolution
  (`revision: byte-preserving-scope-v1`, empty chain) instead. The resolution
  is bound into the usage authorization like any other.
- **Writes:** skip Iceberg table classification, the Lance/Avro adapters, and
  the record decoder. The body is streamed through the existing signature,
  chunked-framing, checksum, size-limit, and transaction paths and stored
  exactly as written, with the supplied `Content-Type`, `Content-Encoding`,
  user metadata, and tags. `Format::Binary` is forced.
- **Reads:** resolve to the explicit passthrough assignment. `GET`, `HEAD`
  (including `Range`) serve the stored bytes and metadata.
- **Multipart:** create/upload/complete store and publish the exact part
  bytes; the table-unit rejection and format adapters do not apply.
- **LIST/DELETE/bucket operations:** unchanged.

### Configuration rules

Startup fails closed when one write could be assigned both storage modes:

- a scope entry whose bucket is a managed service bucket
  (`MASKURA_SERVICE_BUCKETS`), or
- a scope entry whose bucket has a bucket-scoped `write`/`read` assignment in
  the signed pipeline file (`buckets.*` or `workspaces.*.buckets.*`), or
- malformed, duplicate, or overlapping entries.

At request time, a covered key whose resolved destination is managed storage
fails closed with a named configuration error instead of silently degrading to
a transformed write.

The global plugin catalog is not a bucket-scoped assignment. A covered request
therefore **overrides** it: the scope is the more specific, operator-authored
assignment. This is deliberate — the reported local FileStore deployment ships
a default plugin component, and rejecting that combination would make the
feature unusable where it is needed.

## Consequences

- Data in a byte-preserving scope is **unfiltered**. No Wasm plugin runs on it.
  Operators must treat such buckets as catalog storage, not protected customer
  data; the docs and the security chapter state this plainly.
- The scope bypasses the local appliance's "passthrough only to the file
  backend" guard for the buckets the operator named. That is an explicit
  operator choice, not a default.
- **Self-hosted scope only for now.** In a policy-enforced deployment the
  synthetic revision does not match a signed `EffectiveState` route, so the
  policy gate denies covered requests. Teaching the hosted control plane about
  the scope (per-principal/assignment resolution, a signed route) is separate
  work in the private repository and is not claimed here.
- Conditional writes (`If-Match` / `If-None-Match`) are honored in and out of
  the scope by ADR 0037, so a catalog can guard a first commit.
- No default changes: an empty setting preserves every existing behavior.
