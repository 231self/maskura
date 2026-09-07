# Gateway Filter Pipeline Benchmarks

Measured per-object cost of routing writes through the `s4:filter` plugin
pipeline. Each number below is the median over a self-tuned run on the Wasm
runtime micro-benchmark; **fuel** is Wasmtime's deterministic instruction
counter (the reproducible cross-machine metric), and wall-clock time is
indicative for one Apple Silicon machine.

## Run it

```bash
just bench-filters
```

This builds the filter components and prints the full sweep plus a CSV at
`target/benchmarks.csv`. It drives `FilterEngine` directly (no network, no
storage), so it isolates pure plugin cost. The sweep is 7 components x 3 record
sizes (1 KB / 64 KB / 1 MB) x 4 PII counts (0 / 1 / 10 / 100).

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
| 1 KB | 18,396 | 0.062 | 15 |
| 64 KB | 18,592 | 0.109 | 560 |
| 1 MB | 18,592 | 0.772 | 1236 |

### 2. PII scan cost (redaction filters, 1 MB, 0 PII)

Detection/redaction scans every byte; cost is linear in size:

| plugin | fuel/byte | ms/object | MiB/s |
|--------|----------:|----------:|------:|
| pii-default (email+card+ssn) | 49.5 | 3.37 | 283 |
| email-detect | 41.5 | 2.76 | 346 |
| ssn-detect | 45.5 | 3.23 | 295 |
| card-detect | 45.5 | 3.14 | 303 |

### 3. Envelope encryption (RSA-2048 OAEP + AES-256-GCM)

Cost is dominated by one RSA-OAEP wrap per detected field, ~52M fuel per field:

| record | fields | fuel | ms/object | MiB/s | expansion |
|--------|-------:|-----:|----------:|------:|----------:|
| 1 KB | 1 | 52.3M | 2.27 | 0.4 | 2.38x |
| 1 MB | 100 | 5.24G | 178.6 | 5.3 | 1.14x |

### 4. Stable (deterministic) encryption (AES-SIV)

This filter parses and re-serializes the whole JSON record (serde), so cost
scales with record size, plus ~170K fuel per encrypted field:

| record | fields | fuel | ms/object | MiB/s |
|--------|-------:|-----:|----------:|------:|
| 1 MB | 0 | 1.02M | 0.93 | 1023 |
| 1 MB | 1 | 29.6M | 2.27 | 420 |
| 1 MB | 100 | 46.8M | 2.76 | 345 |

## Cost summary (multiplier vs. `noop`, 1 MB)

| plugin | fuel/byte | vs noop (fuel) | MiB/s |
|--------|----------:|---------------:|------:|
| noop | ~0.02 | 1x | 1236 |
| stable-encrypt (0 fields) | ~1.0 | ~55x | 1023 |
| envelope-encrypt (0 fields) | 27.7 | ~1490x | 275 |
| email-detect | 41.5 | ~2230x | 346 |
| ssn-detect | 45.5 | ~2450x | 295 |
| card-detect | 45.5 | ~2450x | 303 |
| pii-default | 49.5 | ~2660x | 283 |

The `vs noop` column is absolute fuel; for a fixed per-object budget the
marginal per-byte figure (`fuel/byte`) is the number to plan capacity against.

## Caveats

- Built with the production `release` profile (`opt-level = "s"`, `lto`, 1 CU).
  A speed-optimized profile would lower wall-clock times; fuel is unaffected.
- Fuel budget for this sweep was raised to 1e10 to measure crypto work rather
  than the production 1e9 ceiling. At the default budget, `envelope-encrypt`
  exhausts fuel at roughly 19 encrypted fields per object.
- A text record is padded/truncated to the target size; a small record with a
  high requested PII count therefore carries fewer actual tokens (see the CSV
  for exact input bytes).
- `envelope-encrypt` numbers assume a valid RSA-2048 public key in the session
  context and host-generated entropy; `stable-encrypt` uses a fixed 64-byte key
  and tagged fields.
