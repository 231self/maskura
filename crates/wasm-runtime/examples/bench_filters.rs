//! Tier-1 micro-benchmark for the `s4:filter` pipeline components.
//!
//! Measures per-object Wasm fuel, wall-clock time, and output expansion for
//! every built-in component across a record-size / PII-density sweep. Run
//! with `just bench-filters` (builds the components first) or directly with
//! `cargo run --release -p s4-wasm-runtime --example bench_filters`.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use s4_wasm_runtime::{FilterEngine, Operation, RuntimeLimits, Session, TransformOutcome};

const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmO5zDMFH3Ka2TpgJ1NSr\n\
yOYHyn4l7r+yTnOc5AGe4bEQmErHrAmalqYbSJkO8yHH3M0TKojjCIK0v0zxJHdW\n\
uFXLIwD9XpPBUAGPhDrcG1ljvEystFX/kIqJp8mUXLb5oLBkTJa7s7J0DO+P6lNb\n\
hl0YNUajEQTqFpXvRG/sFeVyvIte6K+dsLCw3JBVnfNG7dJyRXuT6y0McoWdq2Wg\n\
Nw5XL4h23bp2dvZjljUxJ3I43BZLQpymQjcvY2gCxFPb+n9Gix6x98WG3LzD8lwG\n\
G/PyrV2DNfpRmgm2z62yoorRnZie7XC47Q1ecIyWEIVuVEzHIMMOwlfjFALVlZn/\n\
MwIDAQAB\n\
-----END PUBLIC KEY-----";

const PII_EMAIL: &str = "alice@example.com";
const PII_SSN: &str = "123-45-6789";
const PII_CARD: &str = "4111111111111111";

const FILLER: &str =
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ";

const BENCH_FUEL: u64 = 10_000_000_000;

const SIZES: [usize; 3] = [1_000, 64_000, 1_000_000];
const PII_COUNTS: [usize; 4] = [0, 1, 10, 100];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Text,
    Jsonl,
}

#[derive(Clone, Copy, Debug)]
struct Component {
    name: &'static str,
    file: &'static str,
    format: Format,
    needs_public_key: bool,
    needs_stable: bool,
}

const COMPONENTS: [Component; 7] = [
    Component {
        name: "noop",
        file: "noop",
        format: Format::Text,
        needs_public_key: false,
        needs_stable: false,
    },
    Component {
        name: "pii-default",
        file: "pii-default",
        format: Format::Text,
        needs_public_key: false,
        needs_stable: false,
    },
    Component {
        name: "email-detect",
        file: "email-detect",
        format: Format::Text,
        needs_public_key: false,
        needs_stable: false,
    },
    Component {
        name: "ssn-detect",
        file: "ssn-detect",
        format: Format::Text,
        needs_public_key: false,
        needs_stable: false,
    },
    Component {
        name: "card-detect",
        file: "card-detect",
        format: Format::Text,
        needs_public_key: false,
        needs_stable: false,
    },
    Component {
        name: "envelope-encrypt",
        file: "envelope-encrypt",
        format: Format::Text,
        needs_public_key: true,
        needs_stable: false,
    },
    Component {
        name: "stable-encrypt",
        file: "stable-encrypt",
        format: Format::Jsonl,
        needs_public_key: false,
        needs_stable: true,
    },
];

struct Record {
    bytes: Vec<u8>,
    stable_fields: String,
}

fn components_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("components")
}

fn read_component(name: &str) -> Vec<u8> {
    let path = components_dir().join(format!("{name}.component.wasm"));
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}; run `just build-filters` first",
            path.display()
        )
    })
}

fn make_record(size: usize, pii: usize, format: Format) -> Record {
    match format {
        Format::Text => make_text(size, pii),
        Format::Jsonl => make_jsonl(size, pii),
    }
}

fn make_text(size: usize, pii: usize) -> Record {
    let mut body = String::with_capacity(size + pii * 64);
    for _ in 0..pii {
        body.push_str("Contact ");
        body.push_str(PII_EMAIL);
        body.push_str(" SSN ");
        body.push_str(PII_SSN);
        body.push_str(" card ");
        body.push_str(PII_CARD);
        body.push_str(". ");
    }
    while body.len() < size {
        body.push_str(FILLER);
    }
    body.truncate(size);
    Record {
        bytes: body.into_bytes(),
        stable_fields: String::new(),
    }
}

fn make_jsonl(size: usize, pii: usize) -> Record {
    let mut fields = Vec::with_capacity(pii);
    for i in 0..pii {
        fields.push((format!("f{i}"), PII_EMAIL));
    }

    let mut note = String::new();
    while note.len() < size.saturating_sub(pii * 40 + 64) {
        note.push_str(FILLER);
    }

    let mut body = String::with_capacity(size + 128);
    body.push('{');
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push('"');
        body.push_str(key);
        body.push_str("\":\"");
        body.push_str(value);
        body.push('"');
    }
    if !fields.is_empty() {
        body.push(',');
    }
    body.push_str("\"note\":\"");
    body.push_str(&note);
    body.push_str("\"}");

    let stable_fields = fields
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<Vec<_>>()
        .join(",");

    Record {
        bytes: body.into_bytes(),
        stable_fields,
    }
}

fn make_session(component: Component, format: Format, stable_fields: &str) -> Session {
    Session {
        format: match format {
            Format::Text => "text".to_string(),
            Format::Jsonl => "jsonl".to_string(),
        },
        content_type: match format {
            Format::Text => "text/plain".to_string(),
            Format::Jsonl => "application/x-ndjson".to_string(),
        },
        policy_version: 1,
        operation: Operation::Write,
        config_json: None,
        public_key_pem: component
            .needs_public_key
            .then(|| PUBLIC_KEY_PEM.to_string()),
        stable_key: component.needs_stable.then(|| vec![0x5a; 64]),
        stable_fields: component.needs_stable.then(|| stable_fields.to_string()),
    }
}

fn engine(component: Component) -> FilterEngine {
    FilterEngine::with_limits(
        &read_component(component.file),
        RuntimeLimits {
            cumulative_fuel: BENCH_FUEL,
            per_call_fuel: BENCH_FUEL,
            ..RuntimeLimits::default()
        },
    )
    .expect("component compiles")
}

struct Outcome {
    fuel: u64,
    output_bytes: usize,
}

fn run_once(engine: &FilterEngine, session: &Session, record: &[u8]) -> Outcome {
    let mut filter = engine.start_session(session).expect("start_session");
    let output = match filter.transform(record).expect("transform") {
        TransformOutcome::Emit(bytes) => bytes,
        TransformOutcome::Drop => Vec::new(),
    };
    let (tail, fuel) = filter.finish_with_fuel_limit(u64::MAX).expect("finish");
    Outcome {
        fuel,
        output_bytes: output.len() + tail.len(),
    }
}

fn median_duration(mut durations: Vec<Duration>) -> Duration {
    durations.sort_unstable();
    durations[durations.len() / 2]
}

fn bench(engine: &FilterEngine, session: &Session, record: &[u8]) -> (Outcome, Duration) {
    for _ in 0..2 {
        let _ = run_once(engine, session, record);
    }

    let (single_duration, outcome) = {
        let start = Instant::now();
        let outcome = run_once(engine, session, record);
        (start.elapsed(), outcome)
    };

    let target = Duration::from_millis(200).as_nanos().max(1);
    let iters = ((target / single_duration.as_nanos().max(1)) as usize).clamp(3, 5_000);

    let mut durations = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let outcome = run_once(engine, session, record);
        black_box(outcome.output_bytes);
        durations.push(start.elapsed());
    }

    (outcome, median_duration(durations))
}

struct Row {
    plugin: &'static str,
    bytes: usize,
    pii: usize,
    fuel: u64,
    output_bytes: usize,
    median: Duration,
}

fn main() {
    let mut rows: Vec<Row> = Vec::new();

    for component in COMPONENTS.iter() {
        let component_engine = engine(*component);
        for &pii in &PII_COUNTS {
            for &size in &SIZES {
                let record = make_record(size, pii, component.format);
                let session = make_session(*component, component.format, &record.stable_fields);
                let (outcome, median) = bench(&component_engine, &session, &record.bytes);
                rows.push(Row {
                    plugin: component.name,
                    bytes: record.bytes.len(),
                    pii,
                    fuel: outcome.fuel,
                    output_bytes: outcome.output_bytes,
                    median,
                });
            }
        }
    }

    print_report(&rows);
    write_csv(&rows);
}

fn print_report(rows: &[Row]) {
    println!(
        "{:<16} {:>9} {:>5} {:>14} {:>12} {:>12} {:>10} {:>10}",
        "plugin", "bytes", "pii", "fuel", "fuel/byte", "ms/object", "MiB/s", "expansion"
    );
    for row in rows {
        let fuel_per_byte = row.fuel as f64 / row.bytes.max(1) as f64;
        let secs = row.median.as_secs_f64().max(1e-9);
        let mib_s = (row.bytes as f64 / (1024.0 * 1024.0)) / secs;
        let expansion = row.output_bytes as f64 / row.bytes.max(1) as f64;
        println!(
            "{:<16} {:>9} {:>5} {:>14} {:>12.4} {:>12.3} {:>10.2} {:>10.3}",
            row.plugin,
            row.bytes,
            row.pii,
            row.fuel,
            fuel_per_byte,
            secs * 1000.0,
            mib_s,
            expansion
        );
    }
}

fn write_csv(rows: &[Row]) {
    let path = components_dir().parent().unwrap().join("benchmarks.csv");
    let mut csv = String::from("plugin,bytes,pii,fuel,fuel_per_byte,ms_per_object,expansion\n");
    for row in rows {
        let fuel_per_byte = row.fuel as f64 / row.bytes.max(1) as f64;
        let ms = row.median.as_secs_f64() * 1000.0;
        let expansion = row.output_bytes as f64 / row.bytes.max(1) as f64;
        csv.push_str(&format!(
            "{},{},{},{},{:.4},{:.3},{:.3}\n",
            row.plugin, row.bytes, row.pii, row.fuel, fuel_per_byte, ms, expansion
        ));
    }
    std::fs::write(&path, csv).expect("write benchmarks.csv");
    eprintln!("wrote {}", path.display());
}
