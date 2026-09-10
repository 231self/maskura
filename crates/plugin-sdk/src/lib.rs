//! Rust bindings for the versioned Maskura WebAssembly plugin contract.
//!
//! Plugin authors implement [`Guest`] and call [`export_plugin!`]. The WIT in
//! this crate is the canonical contract consumed by both plugins and Maskura's
//! host runtime.

extern crate self as maskura_plugin_sdk;

#[doc(hidden)]
pub mod bindings {
    wit_bindgen::generate!({
        world: "transformer",
        path: "wit",
        pub_export_macro: true,
        export_macro_name: "export_plugin",
        default_bindings_module: "maskura_plugin_sdk::bindings",
    });
}

pub use bindings::{Context, Decision, Guest, Operation, export_plugin};
