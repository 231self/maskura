# External catalog storage (Polaris, Iceberg REST)

Maskura can store the objects of an external table catalog byte-for-byte while
the catalog keeps owning its commits. This is the operator setup and a manual
reproducible probe. The design is [ADR 0036](adr/0036-byte-preserving-storage-scopes.md).

## When to use it

Use a byte-preserving scope when a catalog (for example Apache Polaris) writes
Iceberg metadata, manifests, and data files itself and manages its own table
lifecycle. Maskura must not treat those objects as a table to transform.

Do **not** use a scope for protected customer data: no plugin, encryption, or
format transform runs inside it, so the stored bytes are unfiltered.

## Operator setup

1. Run the gateway with an explicit scope list and, if you need conditional
   commits, a backend that can enforce them (FileStore, in-memory, or an
   S3-compatible backend):

   ```bash
   MASKURA_BYTE_PRESERVING_SCOPES=warehouse,catalogs/polaris
   MASKURA_ENABLE_ICEBERG=false        # the scope does not need the adapter
   MASKURA_MULTIPART_MODE=staged       # if the catalog uses multipart uploads
   ```

   Entries are `bucket` or `bucket/prefix`. Startup fails if an entry overlaps
   a managed service bucket or a bucket-scoped pipeline assignment.

2. Point the catalog at the gateway's S3 endpoint and give it credentials
   whose workspace is authorized for the bucket. The scope is resolved from
   the configuration and the authenticated bucket; nothing in the request can
   select it.

3. Data in the scope is unfiltered. Keep it out of protected assignments.

## Manual probe (Polaris 1.8.0 + Trino 484)

This probe is not part of CI; run it against a disposable deployment.

1. Start Maskura in local mode with an empty warehouse bucket and the settings
   above:

   ```bash
   MASKURA_STORAGE_MODE=local \
   MASKURA_LOCAL_STORAGE_DIR=/tmp/maskura-warehouse \
   MASKURA_SINGLE_TENANT=true \
   MASKURA_BYTE_PRESERVING_SCOPES=warehouse \
   MASKURA_MULTIPART_MODE=staged \
   maskura-gateway
   ```

2. Configure Polaris to use the gateway with its path-style S3 endpoint and
   bucket `warehouse`.
3. Connect Trino to the Polaris Iceberg REST catalog.
4. Run:

   ```sql
   CREATE SCHEMA iceberg.probe;
   CREATE TABLE iceberg.probe.sample (x integer);
   INSERT INTO iceberg.probe.sample VALUES (1), (2), (3);
   SELECT * FROM iceberg.probe.sample ORDER BY x;
   ```

   Expect `1`, `2`, `3`. The `CREATE TABLE` path writes
   `metadata/00000-<uuid>.metadata.json` before the table exists — the write
   that previously failed with `501` or `400`.

5. Verify the snapshot advanced: query `iceberg.probe."sample$snapshots"` (or
   read the current metadata document) and confirm a new snapshot id after the
   insert.
6. Restart the gateway over the same storage directory and repeat the
   `SELECT`; the metadata and data must survive the restart.

## Verified probe (2026-11-26)

Ran `scripts/probe-polaris-trino.sh` against this revision: Apache Polaris
1.8.0 (in-memory metastore, static S3 credentials, path-style) and Trino 484
(Iceberg REST connector) against the gateway with a local FileStore and
`MASKURA_BYTE_PRESERVING_SCOPES=warehouse`.

- `CREATE SCHEMA iceberg.probe`, `CREATE TABLE iceberg.probe.sample
  (x integer)`, `INSERT` of three rows, and `SELECT` returned `1, 2, 3`;
- the Iceberg snapshot count advanced after the insert;
- restarting the gateway over the same FileStore returned the same rows.

The run disables credential vending
(`iceberg.rest-catalog.vended-credentials-enabled=false`); Polaris and Trino
use static S3 credentials, and the scope stores every catalog object
unchanged. Reproduce with:

```bash
MASKURA_GATEWAY_BIN=target/debug/maskura-gateway bash scripts/probe-polaris-trino.sh
```

Docker must have `apache/polaris:1.8.0`, `trinodb/trino:484`, and `postgres`
is not required for Polaris's in-memory mode.

## In-repo coverage

The automated tests cover the same shapes without Polaris or Trino:

- `crates/gateway/tests/s3_frontdoor_test/byte_preserving.rs` — first metadata
  JSON write (fixed-length, `aws-chunked`, and per-chunk-signed SigV4 PUTs),
  manifest and data-file media types, exact byte/metadata readback, `HEAD`,
  scope selection boundaries, gate-closed/gate-open verdicts outside the scope,
  signature and checksum rejection, and conditional writes.
- `crates/gateway/tests/byte_preserving_filestore.rs` — the FileStore backend
  with staged multipart, a failed conditional write, and survival across a
  FileStore restart.
- `crates/gateway/src/byte_preserving.rs` and the startup tests in
  `crates/gateway/src/server/lifecycle.rs` — scope parsing, matching,
  overlap/ambiguity rejection, and the synthetic resolution.
