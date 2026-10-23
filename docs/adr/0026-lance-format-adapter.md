# ADR 0026: Apache Lance format adapter

- Status: Proposed (owner-prioritized 2026-10-23 ahead of Parquet; accepted when the codec and its policy coverage land)

## Context

Maskura's format adapters give schema-aware filtering and envelope encryption
to structured object formats. Avro Object Container Files ship today and
Parquet was the queued successor (`docs/plans` formats scope in the s4 private
plans: `2026-08-16-formats.md`). Apache Lance — a columnar table format built
for ML workloads (random-access scans, embeddings, dataset versioning) — is
where regulated training and embedding data increasingly lives, and that data
is exactly what customers need behind the policy boundary. On owner decision
2026-10-22/23, Lance is re-prioritized ahead of Parquet (public issue
`maskura#235`).

Constraints that any new format must satisfy:

- ADR 0022 (policy approval and the execution trust boundary) requires that a
  format adapter's `EffectiveState` coverage land **with** the codec — the
  enforced-path contract rejects uncovered format-adapter paths, so a codec
  without coverage would silently widen the unenforced surface.
- The formats architecture separates codec-edge concerns (markers, framing)
  from the normalized schema/value contract used by the filter pipeline; new
  formats must not leak format-specific types past that contract.
- The gateway's read semantics (`docs/plans` formats contract) do not assume
  prefix-safe decode: processed reads may require complete-object staging.

## Decision

1. **Lance is a format adapter in the existing registry/codec flow** — detect,
   decode, filter/transform, restore, encode, validate — reusing the
   normalized schema/value contract. No Lance-specific types cross the codec
   edge.
2. **Detection is conservative**: the Lance magic/version footer and manifest
   structure are validated; conflicting or partial signals are rejected rather
   than guessed, matching the Avro `Obj\x01` / Parquet `PAR1` convention.
3. **Not prefix-safe in the first cut**: a processed `x-s4-process: read` GET
   stages the complete filtered output before responding, as Avro and Parquet
   do. Raw GET/HEAD/byte-range semantics over the stored representation are
   unchanged.
4. **Default-off feature gate**: `MASKURA_ENABLE_LANCE` (mirroring
   `MASKURA_ENABLE_AVRO`), so operators opt in explicitly.
5. **Policy coverage ships in the same change**: the adapter's
   `EffectiveState` entry and the enforced-path matrix coverage land with the
   codec, per ADR 0022. Uncovered paths continue to fail closed.
6. **Lance dataset versions are not mapped onto object versions (v1)**: a
   given Lance dataset revision is opaque bytes within one object version;
   Maskura's object versioning remains the durability and policy boundary.
   Cross-revision dataset reads (time travel across objects) are out of scope
   for v1 and would need their own ADR revision.
7. **Ordering**: Lance lands before Parquet (owner decision). Parquet remains
   approved scope and follows.

## Consequences

- The public engine gains the Lance codec and marker detection behind the
  feature gate; the hosted control plane gains the adapter's policy coverage
  in the same change series, keeping the ADR 0022 contract intact.
- ML pipelines storing embeddings/training data in Lance gain PII filtering
  and envelope encryption without changing their storage layout.
- The non-prefix-safe first cut means processed Lance reads buffer whole
  outputs; large-dataset streaming processing stays a future concern shared
  with Avro/Parquet, not a Lance-specific one.
- The dataset-version boundary keeps v1 honest: time-travel semantics are
  explicitly deferred rather than half-covered, and any later mapping is an
  ADR revision with its own policy analysis.
- Implementation work can proceed in parallel with the policy-enrollment
  operationalization slice (different surfaces: engine format adapter vs
  hosted rollout); the only sequencing rule is intra-change — codec and
  coverage land together.
