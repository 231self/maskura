//! Stateless demo endpoints and their bounded pipeline templates.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

pub(crate) const DEMO_MAX_RECORDS: usize = 10;
pub(crate) const DEMO_MAX_INPUT_BYTES: usize = 64 * 1024;
pub(crate) const DEMO_MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub(crate) const DEMO_MAX_RAW_BODY_BYTES: usize = 512 * 1024;
pub(crate) const DEMO_MAX_CONCURRENCY: usize = 4;
pub(crate) const DEMO_MAX_STARTS_PER_MINUTE: usize = 30;
pub(crate) const DEMO_MAX_CUMULATIVE_FUEL: u64 = 50_000_000;
pub(crate) const DEMO_MAX_WALL_TIME: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(crate) struct DemoPipelines {
    pub(crate) safe: PipelineSnapshot,
    pub(crate) join: Option<PipelineSnapshot>,
}

pub(crate) struct DemoPipelineTemplate {
    pub(crate) registry: PluginRegistry,
    pub(crate) pii_id: String,
    pub(crate) stable_id: Option<String>,
}

impl DemoPipelineTemplate {
    pub(crate) fn instantiate(&self) -> anyhow::Result<DemoPipelines> {
        let registry = self.registry.isolated_clone()?;
        if let Some(stable_id) = &self.stable_id {
            registry.set_enabled(stable_id, false);
        }
        let safe = registry.snapshot().constrained(demo_pipeline_limits())?;
        let join = if let Some(stable_id) = &self.stable_id {
            registry.set_enabled(stable_id, true);
            registry.reorder(vec![stable_id.clone(), self.pii_id.clone()]);
            Some(registry.snapshot().constrained(demo_pipeline_limits())?)
        } else {
            None
        };
        Ok(DemoPipelines { safe, join })
    }
}

/// The process's single `AppState` shares this anonymous admission policy across
/// all router clones and both processing routes. A noisy anonymous client can
/// exhaust the shared allowance; edge or identity-aware limiting is the
/// follow-up availability control.
pub(crate) struct DemoLimiter {
    pub(crate) concurrency: Arc<tokio::sync::Semaphore>,
    pub(crate) starts: Mutex<VecDeque<Instant>>,
    pub(crate) max_starts: usize,
    pub(crate) window: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemoLimitError {
    Concurrent,
    Rate,
}

impl DemoLimiter {
    pub(crate) fn new() -> Self {
        Self::with_limits(
            DEMO_MAX_CONCURRENCY,
            DEMO_MAX_STARTS_PER_MINUTE,
            Duration::from_secs(60),
        )
    }

    pub(crate) fn with_limits(concurrency: usize, max_starts: usize, window: Duration) -> Self {
        Self {
            concurrency: Arc::new(tokio::sync::Semaphore::new(concurrency)),
            starts: Mutex::new(VecDeque::with_capacity(max_starts)),
            max_starts,
            window,
        }
    }

    pub(crate) fn try_start(&self) -> Result<tokio::sync::OwnedSemaphorePermit, DemoLimitError> {
        let permit = self
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| DemoLimitError::Concurrent)?;
        let now = Instant::now();
        let mut starts = self.starts.lock().unwrap();
        starts.retain(|started| now.saturating_duration_since(*started) < self.window);
        if starts.len() >= self.max_starts {
            return Err(DemoLimitError::Rate);
        }
        starts.push_back(now);
        Ok(permit)
    }
}

pub(crate) fn demo_pipeline_limits() -> PipelineLimits {
    PipelineLimits {
        max_intermediate_record_bytes: DEMO_MAX_OUTPUT_BYTES,
        max_plugin_finish_bytes: DEMO_MAX_OUTPUT_BYTES,
        max_input_bytes: DEMO_MAX_INPUT_BYTES as u64,
        max_output_bytes: DEMO_MAX_OUTPUT_BYTES as u64,
        max_expansion_factor: 8,
        max_expansion_slack_bytes: 1024,
        max_plugins: 2,
        max_cumulative_fuel: DEMO_MAX_CUMULATIVE_FUEL,
        max_wall_time: DEMO_MAX_WALL_TIME,
    }
}

pub(crate) fn build_demo_pipeline_template(
    pii_component: &[u8],
    stable_component: Option<&[u8]>,
    engine_fuel: u64,
) -> anyhow::Result<DemoPipelineTemplate> {
    let registry = PluginRegistry::with_fuel(engine_fuel);
    let pii = registry.import("pii-default", pii_component)?;
    let stable_id = if let Some(component) = stable_component {
        let stable = match registry.import("stable-encrypt", component) {
            Ok(stable) => stable,
            Err(_) => {
                warn!(
                    error_category = "plugin",
                    "stable-encrypt unavailable for the stateless demo"
                );
                return Ok(DemoPipelineTemplate {
                    registry,
                    pii_id: pii.id,
                    stable_id: None,
                });
            }
        };
        registry.reorder(vec![stable.id.clone(), pii.id.clone()]);
        Some(stable.id)
    } else {
        None
    };
    Ok(DemoPipelineTemplate {
        registry,
        pii_id: pii.id,
        stable_id,
    })
}

#[cfg(test)]
pub(crate) fn build_demo_pipelines(
    pii_component: &[u8],
    stable_component: Option<&[u8]>,
    engine_fuel: u64,
) -> anyhow::Result<DemoPipelines> {
    build_demo_pipeline_template(pii_component, stable_component, engine_fuel)?.instantiate()
}

/// Interactive demo: run the WASM PII pipeline over the submitted text and
/// return the redacted output without writing request data to storage.
#[derive(Deserialize, ToSchema)]
pub(crate) struct DemoRedactRequest {
    pub(crate) text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DemoMode {
    Safe,
    Join,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DemoProcessRequest {
    pub(crate) records: Vec<serde_json::Value>,
    pub(crate) mode: DemoMode,
}

#[derive(Serialize)]
pub(crate) struct DemoProcessedRecord {
    pub(crate) record: usize,
    pub(crate) body: String,
}

#[derive(Serialize)]
pub(crate) struct DemoProcessResponse {
    pub(crate) mode: DemoMode,
    pub(crate) records: Vec<DemoProcessedRecord>,
}

#[derive(Serialize)]
pub(crate) struct DemoErrorResponse {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

pub(crate) fn harden_demo_response(
    mut response: axum::response::Response,
) -> axum::response::Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "private, no-store".parse().expect("static cache control"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        "nosniff".parse().expect("static content type option"),
    );
    response
}

pub(crate) struct BoundedDemoJsonWriter {
    pub(crate) bytes: Vec<u8>,
    pub(crate) exceeded: bool,
}

impl BoundedDemoJsonWriter {
    pub(crate) fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(DEMO_MAX_OUTPUT_BYTES),
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedDemoJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > DEMO_MAX_OUTPUT_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("demo JSON response exceeds limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn bounded_demo_json<T: Serialize>(value: &T) -> axum::response::Response {
    let mut writer = BoundedDemoJsonWriter::new();
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => {
            let mut response = axum::response::Response::new(axum::body::Body::from(writer.bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                "application/json".parse().expect("static content type"),
            );
            harden_demo_response(response)
        }
        Err(_) if writer.exceeded => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "output_too_large",
            "Demo output exceeds 64 KiB",
        ),
        Err(_) => demo_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_failed",
            "Demo processing failed",
        ),
    }
}

pub(crate) fn demo_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> axum::response::Response {
    harden_demo_response((status, Json(DemoErrorResponse { code, message })).into_response())
}

pub(crate) fn demo_limit_response(error: DemoLimitError) -> axum::response::Response {
    match error {
        DemoLimitError::Concurrent => demo_error(
            StatusCode::TOO_MANY_REQUESTS,
            "demo_busy",
            "Too many demo operations are running",
        ),
        DemoLimitError::Rate => demo_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Demo rate limit exceeded",
        ),
    }
}

pub(crate) fn start_demo_operation(
    state: &AppState,
) -> Result<tokio::sync::OwnedSemaphorePermit, DemoLimitError> {
    state.demo_limiter.try_start()
}

pub(crate) fn demo_pipeline(state: &AppState, mode: DemoMode) -> Option<PipelineSnapshot> {
    match mode {
        DemoMode::Safe => Some(state.demo_pipelines.safe.clone()),
        DemoMode::Join => state.demo_pipelines.join.clone(),
    }
}

pub(crate) fn demo_request_stable_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 64]);
    OsRng.fill_bytes(key.as_mut_slice());
    key
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemoBodyError {
    Invalid,
    TooLarge,
    Deadline,
}

pub(crate) fn demo_body_error(error: DemoBodyError) -> axum::response::Response {
    match error {
        DemoBodyError::Invalid => demo_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid demo request",
        ),
        DemoBodyError::TooLarge => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "input_too_large",
            "Demo request body is too large",
        ),
        DemoBodyError::Deadline => demo_error(
            StatusCode::REQUEST_TIMEOUT,
            "demo_timeout",
            "Demo operation timed out",
        ),
    }
}

pub(crate) async fn decode_demo_json<T: DeserializeOwned>(
    request: Request,
    deadline: Instant,
) -> Result<T, DemoBodyError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| value == "application/json" || value.ends_with("+json"));
    if content_type.is_none() {
        return Err(DemoBodyError::Invalid);
    }

    let mut body = request.into_body();
    let mut bytes = Vec::new();
    loop {
        let frame = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), body.frame())
            .await
            .map_err(|_| DemoBodyError::Deadline)?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(|_| DemoBodyError::Invalid)?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > DEMO_MAX_RAW_BODY_BYTES {
                return Err(DemoBodyError::TooLarge);
            }
            bytes.extend_from_slice(data);
        }
    }
    let decoded = serde_json::from_slice(&bytes).map_err(|_| DemoBodyError::Invalid)?;
    if Instant::now() >= deadline {
        return Err(DemoBodyError::Deadline);
    }
    Ok(decoded)
}

pub(crate) fn demo_pipeline_error(error: &maskura_error::MaskuraError) -> axum::response::Response {
    match error.code() {
        maskura_error::codes::LIMIT_INPUT_BYTES | maskura_error::codes::RECORD_TOO_LARGE => {
            demo_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "input_too_large",
                "Demo input exceeds 64 KiB",
            )
        }
        maskura_error::codes::LIMIT_OUTPUT_BYTES
        | maskura_error::codes::LIMIT_EXPANSION
        | maskura_error::codes::LIMIT_INTERMEDIATE_BYTES
        | maskura_error::codes::LIMIT_FINISH_BYTES => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "output_too_large",
            "Demo output exceeds 64 KiB",
        ),
        maskura_error::codes::WASM_DEADLINE | maskura_error::codes::WASM_CANCELLED => demo_error(
            StatusCode::REQUEST_TIMEOUT,
            "demo_timeout",
            "Demo operation timed out",
        ),
        _ => demo_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_failed",
            "Demo processing failed",
        ),
    }
}

pub(crate) fn demo_deadline_error() -> maskura_error::MaskuraError {
    maskura_error::MaskuraError::new(
        maskura_error::codes::WASM_DEADLINE,
        "demo operation deadline exceeded",
    )
}

pub(crate) async fn execute_demo_records(
    snapshot: PipelineSnapshot,
    session: maskura_wasm_runtime::Session,
    records: Vec<crate::record::Record>,
    deadline: Instant,
) -> Result<(Vec<crate::record::Record>, Vec<crate::record::Record>), maskura_error::MaskuraError> {
    let cancellation = trusted_wasm_cancellation();
    let mut pipeline = snapshot
        .start_streaming_session_with_deadline(session, cancellation, deadline)
        .await?;
    let mut output = Vec::with_capacity(records.len());
    for record in records {
        if Instant::now() >= deadline {
            let _ = pipeline.cancel_and_wait().await;
            return Err(demo_deadline_error());
        }
        match pipeline.process(record).await {
            Ok(Some(record)) => output.push(record),
            Ok(None) => {
                let _ = pipeline.cancel_and_wait().await;
                return Err(maskura_error::MaskuraError::new(
                    maskura_error::codes::WASM_REJECT,
                    "demo pipeline dropped a record",
                ));
            }
            Err(error) => {
                let _ = pipeline.cancel_and_wait().await;
                return Err(error);
            }
        }
    }
    let (trailing, _fuel) = pipeline.finish().await?;
    Ok((output, trailing))
}

pub(crate) fn append_demo_output(
    output: &mut Vec<u8>,
    record: crate::record::Record,
    max_output_bytes: Option<usize>,
) -> Result<(), maskura_error::MaskuraError> {
    let added = record.payload.len().saturating_add(record.separator.len());
    if max_output_bytes.is_some_and(|limit| output.len().saturating_add(added) > limit) {
        return Err(maskura_error::MaskuraError::new(
            maskura_error::codes::LIMIT_OUTPUT_BYTES,
            "demo output exceeds limit",
        ));
    }
    output.extend_from_slice(&record.payload);
    output.extend_from_slice(&record.separator);
    Ok(())
}

pub(crate) async fn demo_redact(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    let _permit = match start_demo_operation(&state) {
        Ok(permit) => permit,
        Err(error) => return demo_limit_response(error),
    };
    let deadline = Instant::now() + DEMO_MAX_WALL_TIME;
    let body: DemoRedactRequest = match decode_demo_json(request, deadline).await {
        Ok(body) => body,
        Err(error) => return demo_body_error(error),
    };
    if body.text.len() > DEMO_MAX_INPUT_BYTES {
        return demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "input_too_large",
            "Demo input exceeds 64 KiB",
        );
    }
    let limits = crate::record::DecoderLimits::default();
    let mut decoder = match crate::record::RecordDecoder::new(Format::Text, limits) {
        Ok(decoder) => decoder,
        Err(error) => return demo_pipeline_error(&error),
    };
    if let Err(error) = decoder.push(body.text.as_bytes()) {
        return demo_pipeline_error(&error);
    }
    let mut records = Vec::new();
    loop {
        match decoder.next_record() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(error) => return demo_pipeline_error(&error),
        }
    }
    if let Err(error) = decoder.finish() {
        return demo_pipeline_error(&error);
    }
    loop {
        match decoder.next_record() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(error) => return demo_pipeline_error(&error),
        }
    }
    let records_processed = records.len();
    let session = maskura_wasm_runtime::Session {
        format: Format::Text.as_str().to_string(),
        content_type: "text/plain".to_string(),
        policy_version: 0,
        operation: maskura_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: None,
        stable_key: None,
        stable_fields: None,
    };
    match execute_demo_records(
        state.demo_pipelines.safe.clone(),
        session,
        records,
        deadline,
    )
    .await
    {
        Ok((records, trailing)) => {
            let mut bytes = Vec::new();
            for record in records.into_iter().chain(trailing) {
                if let Err(error) =
                    append_demo_output(&mut bytes, record, Some(DEMO_MAX_OUTPUT_BYTES))
                {
                    return demo_pipeline_error(&error);
                }
            }
            if Instant::now() >= deadline {
                return demo_pipeline_error(&demo_deadline_error());
            }
            bounded_demo_json(&serde_json::json!({
                "redacted": String::from_utf8_lossy(&bytes),
                "records_processed": records_processed,
            }))
        }
        Err(error) => demo_pipeline_error(&error),
    }
}

pub(crate) async fn demo_process(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    let _permit = match start_demo_operation(&state) {
        Ok(permit) => permit,
        Err(error) => return demo_limit_response(error),
    };
    let deadline = Instant::now() + DEMO_MAX_WALL_TIME;
    let DemoProcessRequest { records, mode } = match decode_demo_json(request, deadline).await {
        Ok(body) => body,
        Err(error) => return demo_body_error(error),
    };
    if records.is_empty() || records.len() > DEMO_MAX_RECORDS {
        return demo_error(
            StatusCode::BAD_REQUEST,
            "invalid_record_count",
            "Demo requests require 1-10 records",
        );
    }

    let mut canonical_records = Vec::with_capacity(records.len());
    let mut input_bytes = 0usize;
    for record in &records {
        if Instant::now() >= deadline {
            return demo_pipeline_error(&demo_deadline_error());
        }
        let canonical = match serde_json::to_vec(record) {
            Ok(canonical) => canonical,
            Err(_) => {
                return demo_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid demo request",
                );
            }
        };
        input_bytes = input_bytes.saturating_add(canonical.len());
        if input_bytes > DEMO_MAX_INPUT_BYTES {
            return demo_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "input_too_large",
                "Demo input exceeds 64 KiB",
            );
        }
        // Demo records are returned as independent values rather than one
        // concatenated JSON document. Model that framing explicitly as JSONL
        // while the pipeline runs, then strip the known separator below.
        canonical_records.push(crate::record::Record::new(
            canonical,
            bytes::Bytes::from_static(b"\n"),
        ));
    }

    let snapshot = match demo_pipeline(&state, mode) {
        Some(snapshot) => snapshot,
        None => {
            return demo_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "join_unavailable",
                "Join demo mode is unavailable",
            );
        }
    };
    let stable_key = match mode {
        DemoMode::Safe => None,
        DemoMode::Join => Some(demo_request_stable_key()),
    };
    let session = maskura_wasm_runtime::Session {
        format: Format::Jsonl.as_str().to_string(),
        content_type: "application/x-ndjson".to_string(),
        policy_version: 0,
        operation: maskura_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: None,
        stable_key: stable_key.as_ref().map(|key| key.as_slice().to_vec()),
        stable_fields: matches!(mode, DemoMode::Join).then(|| "email".to_string()),
    };
    let (output, trailing) =
        match execute_demo_records(snapshot, session, canonical_records, deadline).await {
            Ok(output) => output,
            Err(error) => return demo_pipeline_error(&error),
        };
    if !trailing.is_empty() {
        return demo_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_failed",
            "Demo processing failed",
        );
    }
    let mut output_bytes = 0usize;
    let mut processed = Vec::with_capacity(output.len());
    for (index, record) in output.into_iter().enumerate() {
        if record.separator.as_ref() != b"\n" {
            return demo_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "pipeline_failed",
                "Demo processing failed",
            );
        }
        output_bytes = output_bytes.saturating_add(record.payload.len());
        if output_bytes > DEMO_MAX_OUTPUT_BYTES {
            return demo_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "output_too_large",
                "Demo output exceeds 64 KiB",
            );
        }
        let body = match String::from_utf8(record.payload.to_vec()) {
            Ok(body) => body,
            Err(_) => {
                return demo_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "pipeline_failed",
                    "Demo processing failed",
                );
            }
        };
        processed.push(DemoProcessedRecord {
            record: index + 1,
            body,
        });
    }
    if Instant::now() >= deadline {
        return demo_pipeline_error(&demo_deadline_error());
    }
    bounded_demo_json(&DemoProcessResponse {
        mode,
        records: processed,
    })
}

pub(crate) async fn legacy_demo_gone() -> axum::response::Response {
    harden_demo_response(StatusCode::GONE.into_response())
}
