# Lance format (in development)

Apache Lance — the columnar table format built for ML workloads (random-access
scans, embeddings, dataset versioning) — is the next format adapter in
Maskura, prioritized ahead of Parquet (owner decision 2026-10-22; tracked in
issue [#235](https://github.com/231self/maskura/issues/235), decided in
[ADR 0026](adr/0026-lance-format-adapter.md)).

Status: **in development**. The codec and its policy coverage land together;
this page documents the committed shape and will be completed as the adapter
ships.

## What it will do

Schema-aware PII filtering and per-field envelope encryption over Lance
datasets, through the same detect → decode → filter → restore → encode →
validate flow as the other typed formats (see
[Binary adapters](binary-adapters.md)):

- **Conservative detection** — the Lance head/tail magic and manifest structure
  are validated; conflicting or partial signals are rejected, never guessed.
- **Non-prefix-safe first cut** — a processed `x-s4-process: read` GET stages
  the complete filtered output before responding (as Avro and Parquet do).
  Raw GET/HEAD/byte-range semantics over the stored representation are
  unchanged.
- **Default-off feature gate** — `MASKURA_ENABLE_LANCE`, mirroring
  `MASKURA_ENABLE_AVRO`.
- **Policy coverage ships with the codec** — the format adapter's
  `EffectiveState` entry lands in the same change, per the policy-approval
  contract (ADR 0022): uncovered format-adapter paths fail closed.
- **Dataset versions are opaque within object versions** — a Lance dataset
  revision is bytes inside one object version; Maskura's object versioning
  remains the durability and policy boundary. Cross-revision reads (time
  travel across objects) are out of scope for v1 and would need an ADR
  revision.

## Why Lance first

ML pipelines storing embeddings and training data in object stores are
exactly the customer data that needs the policy boundary; Lance is where that
data increasingly lives. Parquet remains approved scope and follows.
