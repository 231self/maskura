# Maskura plugins

Plugins are WebAssembly components that transform object data in an ordered
pipeline. A plugin can filter, redact, encrypt, validate, normalize, convert,
or perform another deterministic byte transformation. The output of one plugin
is the input of the next.

## Contract ownership

The public [`maskura-plugin-sdk`](../crates/plugin-sdk/) crate owns the
canonical WIT contract and thin Rust bindings. Both the gateway host and every
in-tree transformer consume that same source:

```wit
package maskura:plugin@0.1.0;
world transformer { /* begin, transform, finish */ }
```

Purpose is metadata, not ABI. A plugin under `plugins/crypto/` and one under
`plugins/filters/` implement the same `transformer` world, so new capability
families do not require new protocols.

| Function | Called | Purpose |
|---|---|---|
| `begin(context)` | once per object | Receive format, operation, policy, bounded config, and explicitly granted sensitive inputs |
| `transform(payload)` | once per record | Return `emit(bytes)`, `drop`, or `reject(reason)` |
| `finish()` | once at the end | Flush bounded trailing output |

The sandbox provides bounded memory, tables, stack, time, and fuel. It does not
inherit the host filesystem, environment, network, stdout, or stderr.

## Write a Rust plugin

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
maskura-plugin-sdk = { git = "https://github.com/231self/maskura", tag = "v0.7.2" }
```

```rust
use maskura_plugin_sdk::{Context, Decision, Guest, export_plugin};

struct Normalize;

impl Guest for Normalize {
    fn begin(_context: Context) -> Result<(), String> {
        Ok(())
    }

    fn transform(payload: Vec<u8>) -> Result<Decision, String> {
        Ok(Decision::Emit(payload))
    }

    fn finish() -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

export_plugin!(Normalize);
```

Build it as a WASI reactor and lift it to a component with the pinned adapter,
as demonstrated by [`scripts/build-plugins.sh`](../scripts/build-plugins.sh).
The minimal in-tree example is [`plugins/transforms/noop`](../plugins/transforms/noop/).

## Official plugin layout

Maskura keeps one contribution surface until external contribution volume
justifies another repository:

```text
plugins/
  filters/       content selection and redaction
  crypto/        encryption and deterministic protection
  transforms/    general-purpose byte transformations
  shared/        internal libraries, not loadable components
```

Each loadable plugin has a `plugin.toml` with its stable ID, category, status,
world, version, and requested capabilities. `official` means maintained and
released by Maskura; `experimental` means the API or behavior may still change.
The label does not weaken sandboxing or validation.

Do not add an empty category to advertise a roadmap. Add a category when its
first useful plugin lands. If outside contributions eventually need independent
ownership or release cadence, the SDK keeps a future community repository from
forking the ABI.

## Load a component

Self-hosted gateways support runtime import without rebuilding the server:

```bash
maskura plugin upload my-plugin.component.wasm
maskura plugin list
maskura plugin reorder my-plugin pii-default
maskura plugin disable <id>
maskura plugin delete <id>
```

Or auto-load every `.wasm` component in a directory at startup:

```bash
MASKURA_PLUGINS_DIR=./components ./target/debug/maskura-gateway
```

`MASKURA_DEFAULT_PLUGIN` selects the initial component; local images use the
official `pii-default` artifact. `just proof plugin` verifies runtime import
against the published container and observes a transformation produced only by
the imported component.

Hosted workspaces persist immutable plugin versions, installations, ordered
pipeline revisions, assignments, grants, and validation results. Uploads use
the same world identifier:

```bash
maskura hosted upload ./my-plugin.component.wasm \
  --slug my-plugin --display-name "My Plugin" --version 1.0.0 \
  --world maskura:plugin/transformer@0.1.0 --wit-version 0.1.0
```

Only workspace owners mutate hosted plugin state. Sensitive context is passed
only after an explicit capability grant. Empty pipelines require explicit
pass-through, and failed read transforms never disclose unprocessed fallback
data.

Typed binary formats can additionally use the `binary-reductor` world from the
same WIT package. See [Binary adapters](binary-adapters.md).
