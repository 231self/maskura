# ADR 0028: Iceberg table-format adapter

- Status: Proposed (sequenced after the Parquet adapter; accepted when the table walker and its policy coverage land)
- Date: 2026-10-23

## Context

Maskura's policy boundary is the object: every data-plane operation targets
one S3 object and one stored representation. Apache Iceberg is not an object
format — it is a **table format**: a metadata tree (table metadata JSON →
snapshot → manifest list → manifests → data files) laid out across many
objects, with the data files usually Parquet and the manifests Avro. The
formats roadmap reserved a "later layer" for table formats (originally framed
as Hive tables); Iceberg is that layer's modern shape, and it is where
analytics tables on object storage increasingly live.

Applying per-object transforms to Iceberg files is unsafe by construction,
because of three properties of the format:

1. **Manifests carry plaintext column statistics** — `lower_bounds`,
   `upper_bounds`, `value_counts`, `null_value_counts`, `column_sizes` per
   data file. Copying them into a rewritten table leaks plaintext bounds.
2. **Files cross-reference**: manifest entries pin data-file paths, sizes,
   row counts, and split offsets. Transforming one data file desynchronizes
   the table and breaks readers.
3. **Paths and partition values encode data**: Hive-style partition paths
   (`/date=2024-01-01/`) and manifest `partition` entries carry plaintext
   values, and retained snapshots reference old files whose plaintext would
   survive any partial rewrite.

Three approaches were considered:

1. **A table-aware layer over the file codecs** — the unit of a processed
   operation is a table root; the walker transforms every data file with the
   Parquet codec ([ADR 0027](0027-parquet-format-adapter.md)), rewrites the
   manifest layer with the Avro codec, and commits atomically.
2. **Per-object file adapters** — process each Iceberg file as an independent
   object. It composes trivially but corrupts table consistency and leaks
   manifest statistics; made honest, it collapses into approach 1's first
   phase.
3. **Detection and fail-closed only** — recognize Iceberg, reject processed
   operations, defer the table layer. Cheapest, and defers all the value.

## Decision

1. **The adapter is a table-aware layer over the file codecs** (approach 1),
   implemented after the Parquet adapter it composes. Manifest Avro files are
   *read* with the shipped Avro codec but **rewritten by the Iceberg layer**.
2. **Detection is structural and conservative**: the table-metadata JSON
   shape (`format-version`, `schemas`, `current-snapshot-id`, `metadata-log`),
   the `metadata/` layout, `version-hint.text`, `*.metadata.json` naming, and
   the manifest-list/manifest Avro schema fingerprint. Conflicting signals
   reject per `merge_signal`; unknown table layouts (Delta `_delta_log`, Hive)
   fail closed — never guess.
3. **Unit of work: the table root.** The walker runs metadata JSON →
   snapshot's manifest list → manifests → data files. A processed operation
   on anything smaller than a table root — a single data file, a manifest —
   fails closed with a named `unsupported.table_operation` error. No
   half-transformed table state is reachable.
4. **Statistics discipline.** Rewritten manifests recompute
   `lower_bounds`/`upper_bounds`/`value_counts`/`null_value_counts`/
   `column_sizes` from transformed values or drop them (Iceberg permits null
   bounds); plaintext statistics are never copied. Parquet footer statistics
   are re-derived under ADR 0027's output-grammar rule.
5. **Path and partition discipline.** Output data files use content-hash
   paths with no value-derived path components; manifest `partition` values
   are transformed as data, not metadata. Consequence: partition pruning
   degrades to scan on transformed tables (correctness preserved; documented
   cost).
6. **Commits and snapshots map to object versions.** An Iceberg atomic commit
   (new metadata JSON + `version-hint`) becomes a new snapshot produced by a
   Maskura transform; the prior snapshot is never mutated and snapshot
   isolation is preserved. In v1 the operation must cover **every data file
   referenced by every retained snapshot** or fail closed — otherwise the old
   snapshot's plaintext files survive as a leak. Snapshot expiry is an
   explicit prior step, never an implicit side effect.
7. **Feature gate and policy coverage land with the codec**, per the policy
   approval contract ([ADR 0022](0022-policy-approval-and-execution-trust-boundary.md)):
   default-off `MASKURA_ENABLE_ICEBERG` (→ `features.enable_iceberg`,
   `binary_iceberg_enabled` lifecycle state), an `EffectiveState` entry for
   the table-walk and commit path, and enforced-path matrix rows: table-root
   processed write (gate-closed = 501 before body read, nothing stored),
   table-root processed read (complete-output staging, no raw fallback,
   Range/part-number rejected), raw per-object GET/HEAD/byte-range marked
   *unprocessed* passthrough, and fail-closed rows for partial processed
   operations inside a table root. Pipeline evidence and metering reuse the
   binary-adapter rows.
8. **Testing before acceptance**: golden tables written by pyiceberg (v1/v2
   format versions, partitioned, multi-snapshot), walker and scrub unit
   tests, commit-atomicity tests, the enforced-path matrix rows, and pyiceberg
   interop reading the transformed table end to end.
9. **Non-goals for v1**: ORC data files, Delta Lake, Hive tables, catalog
   service integration (v1 operates on object layout only), and merge-on-read
   delete files — a table carrying delete files fails closed.

## Consequences

- Transformed-table reads lose partition pruning (paths no longer encode
  partition values) and pay full-scan cost until a future layout-preserving
  increment. Tables with merge-on-read deletes are rejected in v1.
- Every transform is a full table walk and rewrite: write amplification is
  proportional to retained snapshots and data files. This is the honest cost
  of consistency at the table layer.
- No partially transformed table can become visible, and the manifest layer
  cannot leak plaintext statistics — the two failure modes that per-object
  processing would have introduced are structurally unreachable.
- The formats roadmap now covers the object formats (Avro, Lance, Parquet)
  and the table layer (Iceberg) under one policy-approval contract. Delta
  Lake remains unapproved scope.

## Implementation notes (2026-10-23)

The table layer landed as `crates/gateway/src/iceberg/` (detection, metadata,
manifest rewrite, walker, commit) with the HTTP surface in
`crates/gateway/src/server/iceberg.rs`, the default-off
`MASKURA_ENABLE_ICEBERG` gate (`features.enable_iceberg` → the runtime
`binary_iceberg_enabled` state), the `EffectiveState` route entry for the
table-walk/commit path, and the enforced-path matrix rows. Mechanics this
implementation fixed, for the record:

- **The data-file transform is a named fail-closed seam**
  (`DataFileTransform`), implemented by the Parquet codec ([ADR
  0027](0027-parquet-format-adapter.md)) when it lands; until then
  `UnsupportedDataFileTransform` fails every data file closed with
  `unsupported.format`, so only zero-data-file tables can be processed end to
  end. Wiring note: replace the stub at the two `walk_and_prepare` call sites
  in `server/iceberg.rs` with the Parquet-backed transform. Pyiceberg interop
  reading a transformed table end to end (§8) stays an acceptance item for
  that follow-on.
- **Processed write contract**: `PutObject` of the *current* table metadata
  document to the next zero-padded version key (`0000N-token.metadata.json`).
  The request body is the state the walk transforms (compare-and-swap against
  the committed document); creating a table root through this path fails
  closed because there is no committed state to transform.
- **Processed read contract**: a complete-output staging of the document a
  commit would produce — a preview, marked `x-maskura-iceberg-preview`, with
  nothing stored and no raw fallback. `Range`/`partNumber` are rejected
  before any walk.
- **Partial-operation rejection is gate-independent.** The named
  `unsupported.table_operation` failure applies to processed operations on
  strict sub-units (and multipart of any table unit) whether or not
  `MASKURA_ENABLE_ICEBERG` is open; the gate governs only table-root
  processing. This ordering is pinned by the matrix rows.
- **Hive-layout rejection uses two signals**: a `field=value` path shape plus
  a table-claiming content type. A `_delta_log` marker alone always fails
  closed for processed operations; a Hive-looking path alone is an ordinary
  object (never guessed as a table, and never rejected on shape alone).
- **Backends**: table operations require direct object IO (file, memory,
  S3-compatible). Managed service storage and presigned proxies fail closed
  with `unsupported.table_operation` — their placement/authority machinery has
  no multi-object transactional shape for a commit yet.
- **Commit fencing** is the `version-hint` compare-and-swap plus
  write-new-objects-only ordering; the streaming workspace lease and write
  intents are not yet integrated for the table path (v1, direct-IO backends
  only). Post-swap cleanup of replaced plaintext objects is best-effort and
  audited (`cleanup_failures`), matching the "no plaintext survives" intent.
