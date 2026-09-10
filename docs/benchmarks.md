# Gateway Filter Pipeline Benchmarks

Measured per-object cost of routing writes through Maskura's Wasm plugin
pipeline. Each number below is the median over a self-tuned run on the Wasm
runtime micro-benchmark; **fuel** is Wasmtime's deterministic instruction
counter (the reproducible cross-machine metric), and wall-clock time is
indicative for one Apple Silicon machine.

## Run it

```bash
just bench-filters
```

This builds the filter components and prints the full sweep. It writes machine
readable results to `target/benchmarks.csv` and run provenance to
`target/benchmarks.metadata` (UTC timestamp, source revision/change, dirty
state, OS, architecture, processor, Rust, and Cargo versions). It drives
`FilterEngine` directly—no network or storage—so it isolates plugin cost. The
sweep is 7 components x 3 record sizes (1 KB / 64 KB / 1 MB) x 4 requested PII
counts (0 / 1 / 10 / 100).

The reference tables below were recorded on 2026-09-10 using an Apple M4 Pro
(arm64), macOS 26.6.2, Rust/Cargo 1.98.1, and the production release profile.
Wall-clock results will move with hardware and system load; fuel should be the
comparison metric across machines.

## What each metric means

- **fuel** — Wasmtime fuel consumed per object (Wasm instruction count proxy).
  Deterministic across machines for the same component and payload.
- **fuel/byte** — marginal scan cost; the fixed per-object overhead is small
  relative to 1 MB records, so large records expose the true per-byte cost.
- **ms/object** — median wall-clock per object (machine-dependent).
- **MiB/s** — effective single-object throughput.
- **expansion** — output bytes / input bytes (crypto envelopes inflate output).

## Results

### 1. Fixed per-object overhead (`noop`)

A `noop` filter still pays one fresh Wasm store, `begin`, one `transform`, and
`finish` per object. Fuel is flat regardless of size:

| size | fuel | ms/object | MiB/s |
|------|-----:|----------:|------:|
| 1 KB | 18,396 | 0.052 | 18 |
| 64 KB | 18,592 | 0.084 | 730 |
| 1 MB | 18,592 | 0.567 | 1683 |

### 2. PII scan cost (redaction filters, 1 MB, 0 PII)

Detection/redaction scans every byte; cost is linear in size:

| plugin | fuel/byte | ms/object | MiB/s |
|--------|----------:|----------:|------:|
| pii-default (email+card+ssn) | 49.5 | 2.48 | 385 |
| email-detect | 41.5 | 2.31 | 413 |
| ssn-detect | 45.5 | 2.17 | 440 |
| card-detect | 45.5 | 2.10 | 454 |

### 3. Envelope encryption (hybrid X25519 + ML-KEM-768 + AES-256-GCM)

Cost is dominated by one hybrid key encapsulation per detected field, ~35M fuel
per field (down from ~52M for the RSA-2048 OAEP wrap it replaced). The
encapsulation is larger — 1120 B per field vs 256 B — so expansion grows for
dense records:

| record | fields | fuel | ms/object | MiB/s | expansion |
|--------|-------:|-----:|----------:|------:|----------:|
| 1 KB | 1 | 35.1M | 0.92 | 1.0 | 5.86x |
| 1 MB | 100 | 3.42G | 86.7 | 11.0 | 1.49x |

### 4. Stable (deterministic) encryption (AES-SIV)

This filter parses and re-serializes the whole JSON record (serde), so cost
scales with record size, plus ~170K fuel per encrypted field:

| record | fields | fuel | ms/object | MiB/s |
|--------|-------:|-----:|----------:|------:|
| 1 MB | 0 | 1.02M | 0.59 | 1609 |
| 1 MB | 1 | 29.6M | 1.50 | 637 |
| 1 MB | 100 | 46.8M | 1.97 | 483 |

## Cost summary (multiplier vs. `noop`, 1 MB)

| plugin | fuel/byte | vs noop (fuel) | MiB/s |
|--------|----------:|---------------:|------:|
| noop | ~0.02 | 1x | 1683 |
| stable-encrypt (0 fields) | ~1.0 | ~55x | 1609 |
| envelope-encrypt (0 fields) | 28.6 | ~1540x | 563 |
| email-detect | 41.5 | ~2230x | 413 |
| ssn-detect | 45.5 | ~2450x | 440 |
| card-detect | 45.5 | ~2450x | 454 |
| pii-default | 49.5 | ~2660x | 385 |

The `vs noop` column is absolute fuel; for a fixed per-object budget the
marginal per-byte figure (`fuel/byte`) is the number to plan capacity against.

## Caveats

- Built with the production `release` profile (`opt-level = "s"`, `lto`, 1 CU).
  A speed-optimized profile would lower wall-clock times; fuel is unaffected.
- Fuel budget for this sweep was raised to 1e10 to measure crypto work rather
  than the production 1e9 ceiling. At the default budget, `envelope-encrypt`
  exhausts fuel at roughly 27 encrypted fields per object.
- A text record is padded/truncated to the target size; a small record with a
  high requested PII count therefore carries fewer actual tokens (see the CSV
  for exact input bytes).
- `envelope-encrypt` numbers assume a valid hybrid X25519 + ML-KEM-768 public
  key in the session context and host-generated entropy; `stable-encrypt` uses a
  fixed 64-byte key and tagged fields.
