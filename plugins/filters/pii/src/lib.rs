//! Combined PII redaction filter. Re-exports the detection logic from
//! `pii-shared` so the default one-click filter and its tests stay put
//! while `email-detect` / `ssn-detect` / `card-detect` expose the same
//! detection one kind at a time.

pub use maskura_plugin_pii_core::{
    is_valid_card, is_valid_email, is_valid_ssn, is_valid_ssn_format, redact_cards, redact_emails,
    redact_pii, redact_ssns,
};

#[cfg(target_arch = "wasm32")]
mod guest {
    use crate::redact_pii;
    use maskura_plugin_sdk::{Context, Decision, Guest, export_plugin};

    struct PiiFilter;

    impl Guest for PiiFilter {
        fn begin(_context: Context) -> Result<(), String> {
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            let text = std::str::from_utf8(&payload).map_err(|e| e.to_string())?;
            let result = redact_pii(text);
            Ok(Decision::Emit(result.into_bytes()))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export_plugin!(PiiFilter);
}
