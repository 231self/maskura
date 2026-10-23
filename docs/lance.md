# Lance format

Apache Lance — the columnar table format built for ML workloads (random-access
scans, embeddings, dataset versioning) — is the next format adapter in
Maskura, prioritized ahead of Parquet (owner decision 2026-10-22; tracked in
issue [#235](https://github.com/231self/maskura/issues/235), decided in
[ADR 0026](adr/0026-lance-format-adapter.md)).

Maskura processes Apache Lance columnar table files (the `.lance` data files
of Lance datasets) through the same schema-aware pipeline that serves Avro:
detection, decode to the normalized schema/value contract, filter and envelope
transform, restore, encode, and validate. Lance support is **off by default**;
set `MASKURA_ENABLE_LANCE=true` (or `features.enable_lance = true`) to opt in.
Requests carrying Lance content while the gate is closed are rejected before
the body is read and nothing is stored.

Status: the codec and its policy coverage land together — the format
adapter's `EffectiveState` entry and enforced-path matrix rows ship in the
same change, per the policy-approval contract (ADR 0022): uncovered
format-adapter paths fail closed.

## Why Lance first

ML pipelines storing embeddings and training data in object stores are
exactly the customer data that needs the policy boundary; Lance is where that
data increasingly lives. Parquet remains approved scope and follows.

## Detection

Lance files have **no head magic**: a data file begins directly with page
buffers. Conservative detection therefore validates the trailing `LANC` magic,
the recognized major/minor version pair in the fixed 40-byte footer, and the
footer's offset-table structure. Conflicting or partial signals are rejected
rather than guessed, matching the `Obj\x01` / `PAR1` conventions of the other
binary formats. The legacy v1 container is recognized as Lance and rejected
before decoding.

Media types: `application/vnd.apache.lance` (canonical), `application/x-lance`,
`application/vnd.lance`; extension `.lance`.

## What the codec reads and writes

The codec edge is `crates/gateway/src/lance.rs`. Page encodings are
self-describing; the codec implements two documented subsets and fails closed
on everything else (dictionaries, FSST, RLE, bitpacked and general-compressed
pages, blob and planar 2.3 layouts, and unknown type URLs all produce a named
`unsupported.format` error):

* **Legacy v2.0 array encodings** (`lance.encodings`): `Flat`, `Nullable`,
  `Binary`, `List`, `FixedSizeList`, and `SimpleStruct` — decoded, so uploads
  produced by `data_storage_version="2.0"` tooling can be processed.
* **Structural v2.1/v2.2 pages** (`lance.encodings21`): mini-block pages with
  flat/variable value compression, constant pages (inline or serialized
  constant values, all-null pages), and full-zip pages without control words —
  decoded **and** encoded. All output is written in the v2.2 structural
  grammar (mini-block pages), because the legacy grammar cannot represent
  nullable structs, which envelope encryption produces.

Lance maps onto the normalized IR as: primitives and logical types (date,
time, timestamp, decimal) to their IR nodes, `list`/`list.struct` to arrays,
and `struct` to records. Maps have no Lance column type and are rejected, as
are UUIDs and custom reductor types. Nesting, nullability, and the standard
field limits follow the shared IR contract.

## Read semantics

Lance is not prefix-safe in the first release: a processed
`x-maskura-process: read` GET stages the complete filtered output in the
encrypted read spool before any response body is disclosed, exactly like Avro
and Parquet. Raw GET, HEAD, and byte-range semantics over the stored
representation are unchanged — those paths are unprocessed passthrough.
Processed reads never fall back to raw bytes; `Range` and `partNumber` are
rejected for processed reads.

## Dataset versions

A Lance dataset revision is opaque bytes within one object version. The codec
processes one self-contained file per request; it never maps dataset versions
onto object versions and never performs cross-file (time-travel) reads. Any
future mapping would be an ADR revision with its own policy analysis.

## Policy coverage

Per ADR 0022 the adapter's policy surface is pinned alongside the codec:

* An `EffectiveState` route entry for the `lance` adapter (`format: "lance"`)
  pins the adapter implementation (`adapter_sha256`) and is keyed to the
  `MASKURA_ENABLE_LANCE` gate (`features.enable_lance` /
  `binary_lance_enabled`).
* The enforced-path matrix rows cover single PUT
  (`streaming_lance_single_put`), staged multipart completion
  (`complete_staged_lance_multipart`, under the frozen create-time verdict),
  processed GET (`lance_transformed_read_response`: complete-output staging,
  no raw fallback, `Range`/`partNumber` rejected), and mark raw
  GET/HEAD/byte-range as *unprocessed* passthrough.
* Pipeline evidence and receipt metering for Lance reuse the existing
  binary-adapter rows (`CommonTypeBinaryReductor` + envelope); there is no
  Lance-specific metering route.

## Interoperability

The codec was verified against the reference implementation (`pylance`, the
`lance` Python bindings) in both directions: reference-written v2.0 and v2.2
files decode to the expected values (checked in as test fixtures under
`crates/gateway/tests/fixtures/lance/`), and files written by the codec —
including lists with null/empty rows, lists of structs with null elements,
nullable structs (the envelope shape), nested lists, dates, timestamps,
decimals, and binary columns — are read back by the reference reader with
exact values.
