# ADR 0027: Parquet format adapter

- Status: Proposed (sequenced after the Lance adapter per the formats roadmap; accepted when the codec and its policy coverage land)
- Date: 2026-10-23

## Context

Maskura's format adapters give schema-aware filtering and envelope encryption
to structured object formats through one contract: detect → decode → filter →
restore → encode → validate (see [Binary adapters](../binary-adapters.md)).
Avro ships today ([Avro gate](../avro.md)); Lance is in development
([ADR 0026](0026-lance-format-adapter.md)); the formats roadmap approves
Parquet next. Parquet is the dominant on-disk table format for
analytics pipelines, so it is where a large share of the tabular data that
needs the policy boundary lives.

Three codec approaches were considered:

1. **The `parquet` crate (parquet-rs)** — the official Apache implementation:
   every page encoding, the common compression codecs, nested
   definition/repetition levels, and the logical-type system at codec quality.
2. **Hand-rolled, as Lance was** — zero new dependencies, maximum
   auditability, but Parquet is far more complex than Lance: a Thrift
   `FileMetaData` footer, fourteen page encodings, five compression codecs,
   and the def/rep repetition model. Lance was hand-rolled only because no
   Rust implementation exists.
3. **Hybrid: `parquet` for decode, own encoder** — keeps the heavy
   dependency while hand-rolling the writer surface.

Per AGENTS.md's "prefer specialized libraries" rule and the Avro precedent
(`apache-avro` with its snappy/zstandard features), the specialized library is
the house answer when a maintained one exists.

Parquet is also friendlier to detection than Lance: the format carries both a
head magic (`PAR1`) and a tail magic, so the conservative two-sided validation
Lance had to reconstruct from footer structure is native here.

## Decision

1. **Codec: the `parquet` crate** (Apache-2.0), approach 1. Supply-chain
   weight is managed by the existing `cargo-deny`/`cargo-audit` gates; the
   alternative is months of format work with more risk of subtle decode bugs.
2. **Detection is two-sided and conservative**: `PAR1` head magic plus the
   8-byte tail (4-byte little-endian `FileMetaData` length + `PAR1`), with
   footer-length sanity and a successful `FileMetaData` parse. Conflicting
   signals (override, content type, extension, magic) reject per the existing
   `merge_signal` logic. Truncated files, non-`PAR1` tails, and over-long
   footer lengths fail closed as `unsupported.format`/`invalid.format`.
3. **Feature gate** `MASKURA_ENABLE_PARQUET` (→ `features.enable_parquet`,
   `binary_parquet_enabled` lifecycle state), default-off, mirroring Avro and
   Lance.
4. **Decode scope**: all encodings and logical types the crate supports, full
   nested def/rep. Compression codecs enabled: **snappy, gzip, zstd**. LZ4
   and BROTLI pages fail closed as `unsupported.format` in v1. **Parquet
   column encryption (modular encryption) fails closed** — encrypted files
   never pass through the transform.
5. **Transform** reuses the existing `CommonTypeBinaryReductor` +
   `EnvelopeBinaryTransform` pump with `CompleteOutputRequired`
   (non-prefix-safe first cut): a processed `x-s4-process: read` GET stages
   the complete filtered output before responding; raw GET/HEAD/byte-range
   semantics over the stored representation are unchanged.
6. **One documented output grammar** (the Lance lesson): data-page V1,
   writer-version V1, PLAIN + RLE_DICTIONARY, SNAPPY column chunks. The
   output is a newly written file; row-group boundaries and physical layout
   are re-derived, never preserved from the input. Round trips are verified
   against the reference implementation (pyarrow) in both directions before
   acceptance.
7. **Policy coverage lands with the codec**, per the policy-approval contract
   ([ADR 0022](0022-policy-approval-and-execution-trust-boundary.md)):
   an `EffectiveState` entry for the `parquet` adapter keyed to the gate, and
   enforced-path matrix rows for `streaming_parquet_single_put` (gate-closed
   = 501 before body read, nothing stored), `complete_staged_parquet_multipart`
   (frozen policy verdicts cover the completion path),
   `parquet_transformed_read_response` (complete-output staging, no raw
   fallback, Range/part-number rejected), with raw GET/HEAD/byte-range
   explicitly marked *unprocessed* passthrough. Pipeline evidence and metering
   reuse the existing binary-adapter rows; no new metering route. The codec
   does not merge without its coverage.
8. **Testing** before acceptance: golden fixtures written by pyarrow (v1/v2
   writer versions, nested schemas, dictionary-encoded columns, each enabled
   compression variant), unit tests at the codec edge, gate-closed behavior
   rows mirroring the Avro gate, the enforced-path matrix rows, and
   filter/encrypt round-trip properties through the pump.

## Consequences

- The `parquet` crate (and its dependency tree) joins the gateway. The audit
  and deny gates police it like every other dependency; the crate's breadth
  (encodings, compression, nesting) is exactly what buying it buys.
- v1 rejects real-world files that use LZ4/BROTLI compression or column
  encryption. That is deliberate fail-closed behavior, and each is a bounded
  later increment (a feature flag away for compression codecs).
- Processed reads remain non-prefix-safe (complete-output staging), so large
  Parquet objects pay spool cost on processed GETs — the same trade Avro and
  Lance make, and the same future work: streaming processed reads across all
  three adapters rather than per-format.
- Layout is not preserved: a processed write produces a physically different
  (but semantically equal) Parquet file. Consumers that byte-compare objects
  or depend on row-group placement must treat processed objects as new files.
- With Avro, Lance, and Parquet, every mainstream structured object format in
  the roadmap sits behind one detect → decode → filter → restore → encode →
  validate contract and one policy-approval coverage pattern.
