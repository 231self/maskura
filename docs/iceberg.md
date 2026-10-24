# Iceberg table-format adapter (default-off, table-aware)

Apache Iceberg is not an object format — it is a **table format**: a metadata
tree (table metadata JSON → snapshot → manifest list → manifests → data files)
laid out across many objects, with data files usually Parquet and manifests
Avro. Applying per-object transforms to Iceberg files is unsafe by
construction: manifests carry plaintext column statistics, files
cross-reference each other, and paths and partition values encode data. The
table-aware adapter ([ADR 0028](adr/0028-iceberg-table-format-adapter.md))
makes the **table root** the unit of work instead.

Status: the table walker, manifest rewrite, and atomic commit ship behind the
default-off `MASKURA_ENABLE_ICEBERG` gate. The data-file transform runs
through the Parquet codec seam ([ADR 0027](adr/0027-parquet-format-adapter.md)),
which fails closed until that codec is wired — a table carrying data files
cannot be processed end to end until then.

## What it does

- **Detection is structural and conservative** — the table-metadata JSON shape
  (`format-version`, `schemas`, `snapshots`, `location`), the `metadata/`
  layout, `version-hint.text`, `*.metadata.json` naming, and the manifest
  Avro schema fingerprint. Conflicting signals are rejected, never guessed.
  Delta (`_delta_log`) and Hive table layouts fail closed as
  `unsupported.format`.
- **Unit of work: the table root.** A processed write of a table metadata
  document (`<root>/metadata/<version>-*.metadata.json`) walks every data file
  referenced by **every retained snapshot** and commits one new snapshot. A
  processed operation on anything smaller — one data file, one manifest, the
  version pointer — fails closed with the named `unsupported.table_operation`
  error, whether or not the gate is open. No half-transformed table state is
  reachable.
- **Statistics discipline.** Rewritten manifests drop
  `lower_bounds`/`upper_bounds`/`value_counts`/`null_value_counts`/
  `column_sizes` (Iceberg permits null bounds); plaintext statistics are never
  copied into a rewritten manifest, and snapshot summaries are scrubbed to
  their `operation`.
- **Path and partition discipline.** Output data files use content-hash paths
  with no value-derived path components; manifest `partition` values are
  transformed as data. Consequence: partition pruning degrades to full scan on
  transformed tables — a documented cost until a layout-preserving increment.
- **Atomic commit.** New metadata JSON plus one `version-hint.text` pointer
  swap is the commit point; a concurrent commit is never silently clobbered
  (compare-and-swap on the pointer). The prior snapshot is never mutated, and
  the replaced plaintext objects are deleted after the swap. Snapshot expiry
  is always an explicit prior step.

## Operations

- **Table-root processed write** — `PutObject` of the *current* table metadata
  document to the next version's key. With the gate closed the request is
  rejected 501 before the body is read and nothing is stored.
- **Table-root processed read** — `x-maskura-process: read` `GetObject` of the
  current metadata document stages the complete transformed output (the
  document a commit would produce; a preview — nothing is stored). `Range` and
  `partNumber` are rejected; failures never fall back to the raw bytes.
- **Raw per-object GET/HEAD/byte-range** over any table file is *unprocessed*
  passthrough over the stored representation, regardless of the gate.
- **Multipart** is single-object-only for table units: multipart
  create/completion of a table-root document or sub-unit fails closed.

v1 requires a backend with direct object IO (local file, in-memory, or
S3-compatible). Managed service storage and presigned-URL backends fail closed
for table operations. v1 non-goals, each fail-closed: ORC data files, Delta
Lake, Hive tables, REST catalog integration, merge-on-read delete files, and
table statistics files.

## Feature gate

`MASKURA_ENABLE_ICEBERG=true` (or `features.enable_iceberg = true`) opens the
table-root write/read surface. Default off. The named partial-operation
rejection does not depend on the gate.

## Verification

The adapter is covered by golden pyiceberg tables (v1/v2, partitioned,
multi-snapshot, delete-file, and zero-snapshot fixtures under
`crates/gateway/tests/fixtures/iceberg/`), walker/scrub/commit unit tests,
commit-atomicity and snapshot-coverage tests, and the enforced-path matrix
rows in the S3 front-door suite. Fixtures are regenerable with
`crates/gateway/tests/fixtures/iceberg/generate_fixtures.py`.
