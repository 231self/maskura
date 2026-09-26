//! Streaming `PutObject` execution: single put, AVRO, and body verification.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;
use maskura_pipeline_config::PolicyOperation;

use crate::policy_gate::{PolicyRequest, enforce_policy, policy_error_response};

#[derive(Debug)]
pub(crate) enum StreamingPutError {
    Integrity(IntegrityError),
    Pipeline(maskura_error::MaskuraError),
    Transaction(TransactionError),
    InputTooLarge,
    SourceFrameTooLarge,
    Transport,
    InvalidRequest(String),
    Unsupported(String),
    PreserveReservation(Box<StreamingPutError>),
}

impl StreamingPutError {
    pub(crate) fn preserves_reservation(&self) -> bool {
        matches!(self, Self::PreserveReservation(_))
    }
}

impl From<maskura_error::MaskuraError> for StreamingPutError {
    fn from(error: maskura_error::MaskuraError) -> Self {
        Self::Pipeline(error)
    }
}

impl From<TransactionError> for StreamingPutError {
    fn from(error: TransactionError) -> Self {
        Self::Transaction(error)
    }
}

pub(crate) fn streaming_put_error_response(
    key: &str,
    error: StreamingPutError,
) -> axum::response::Response {
    match error {
        StreamingPutError::PreserveReservation(error) => streaming_put_error_response(key, *error),
        StreamingPutError::Integrity(
            IntegrityError::PayloadHashMismatch | IntegrityError::SignatureMismatch,
        ) => s3_error::signature_mismatch(key),
        StreamingPutError::Integrity(
            error @ (IntegrityError::InvalidChecksum(_)
            | IntegrityError::MissingChecksum
            | IntegrityError::DecodedLengthMismatch),
        ) => s3_error::bad_digest(key, &error.to_string()),
        StreamingPutError::Integrity(error) => s3_error::invalid_request(key, &error.to_string()),
        StreamingPutError::Pipeline(error) => pipeline_error_response(key, &error),
        StreamingPutError::Transaction(
            TransactionError::CapacityExceeded | TransactionError::TooManyParts,
        ) => s3_error::entity_too_large(key),
        StreamingPutError::Transaction(TransactionError::Spool(detail)) => {
            s3_error::internal_error(key, &detail)
        }
        StreamingPutError::Transaction(TransactionError::Backend(error))
            if error.kind == BackendErrorKind::Definitive =>
        {
            s3_error::service_unavailable(key, "The destination rejected the write request.")
        }
        StreamingPutError::Transaction(error) => s3_error::internal_error(key, &error.to_string()),
        StreamingPutError::InputTooLarge | StreamingPutError::SourceFrameTooLarge => {
            s3_error::entity_too_large(key)
        }
        StreamingPutError::Transport => {
            s3_error::invalid_request(key, "request body stream failed")
        }
        StreamingPutError::InvalidRequest(detail) => s3_error::invalid_request(key, &detail),
        StreamingPutError::Unsupported(detail) => {
            drop(detail);
            warn!(error_category = "unsupported", "streaming PUT rejected");
            s3_error::not_implemented(key)
        }
    }
}

pub(crate) fn pipeline_error_response(
    key: &str,
    error: &maskura_error::MaskuraError,
) -> axum::response::Response {
    match error.code() {
        maskura_error::codes::WASM_ADMISSION => s3_error::slow_down(key),
        maskura_error::codes::LIMIT_INPUT_BYTES
        | maskura_error::codes::LIMIT_OUTPUT_BYTES
        | maskura_error::codes::LIMIT_EXPANSION
        | maskura_error::codes::LIMIT_INTERMEDIATE_BYTES
        | maskura_error::codes::LIMIT_FINISH_BYTES
        | maskura_error::codes::RECORD_TOO_LARGE => s3_error::entity_too_large(key),
        maskura_error::codes::DECODE_JSON
        | maskura_error::codes::DECODE_JSONL
        | maskura_error::codes::DECODE_CSV
        | maskura_error::codes::DECODE_ENCODING
        | maskura_error::codes::WASM_REJECT
        | maskura_error::codes::UNSUPPORTED_FORMAT
        | maskura_error::codes::CONFIG_INVALID
        | maskura_error::codes::POLICY_EXPIRED
        | maskura_error::codes::POLICY_TAMPERED => {
            s3_error::invalid_request(key, "The processing pipeline rejected the request.")
        }
        _ => s3_error::internal_error(key, error.code()),
    }
}

pub(crate) async fn streaming_put_failure_response(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    error: StreamingPutError,
) -> axum::response::Response {
    let preserve_reservation = error.preserves_reservation();
    let response = streaming_put_error_response(key, error);
    if preserve_reservation {
        response
    } else {
        release_failure(control, context, grant, key, response).await
    }
}

pub(crate) fn streaming_format(headers: &HeaderMap) -> Result<(Format, String), StreamingPutError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| StreamingPutError::InvalidRequest("invalid Content-Type".to_string()))
        })
        .transpose()?
        .unwrap_or("application/octet-stream");
    streaming_format_content_type(content_type)
}

pub(crate) fn streaming_format_content_type(
    content_type: &str,
) -> Result<(Format, String), StreamingPutError> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let format = match media_type.as_str() {
        "text/plain" => Format::Text,
        "application/x-ndjson" | "application/jsonlines" => Format::Jsonl,
        "application/json" => Format::Json,
        "text/csv" => Format::Csv,
        "text/tab-separated-values" => Format::Tsv,
        "application/octet-stream" | "binary/octet-stream" => Format::Binary,
        _ => {
            return Err(StreamingPutError::Unsupported(format!(
                "unsupported streaming Content-Type {media_type:?}"
            )));
        }
    };
    Ok((format, media_type))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn streaming_single_put(
    state: &AppState,
    mut authentication: HeaderAuthentication,
    backend: ResolvedBackend,
    usage: AuthorizedUsage<'_>,
    snapshot: PipelineSnapshot,
    headers: &HeaderMap,
    mut body: axum::body::Body,
    key: &str,
) -> Result<
    (
        Auth,
        StoredObjectMeta,
        u64,
        u64,
        Option<crate::control::PipelineEvidence>,
    ),
    StreamingPutError,
> {
    use http_body_util::BodyExt as _;
    use sha2::Digest as _;
    let grant = usage.grant;

    if authentication.body_verifier.is_none() && headers.contains_key(header::CONTENT_ENCODING) {
        return Err(StreamingPutError::InvalidRequest(
            "Content-Encoding is unsupported for transformed streaming".to_string(),
        ));
    }
    if is_avro_content_type(headers) {
        if !state.binary_avro_enabled {
            return Err(StreamingPutError::Unsupported(
                "Avro processing is disabled; set MASKURA_ENABLE_AVRO=true".to_string(),
            ));
        }
        return streaming_avro_single_put(
            state,
            authentication,
            backend,
            usage,
            headers,
            body,
            key,
        )
        .await;
    }
    let (format, content_type) = streaming_format(headers)?;
    let mut content_md5 =
        ContentMd5Verifier::from_headers(headers).map_err(StreamingPutError::Integrity)?;
    let sink = begin_streaming_sink(
        state,
        backend,
        AuthorizedOperation {
            auth: &authentication.auth,
            grant,
        },
        grant.operation_id(),
        grant.bucket(),
        key,
        &content_type,
        None,
        Some(single_put_stored_metadata(headers)),
    )
    .await?;
    let mut sink_guard = SinkAbortGuard::new(sink);
    let sink = Arc::clone(&sink_guard.sink);

    let stable_fields = customer_headers::validated(headers, customer_headers::STABLE_FIELDS)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let session = maskura_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type: content_type.clone(),
        policy_version: 0,
        operation: maskura_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: authentication.auth.public_key_pem.clone(),
        stable_key: authentication.auth.stable_key.clone(),
        stable_fields,
    };
    let cancellation = trusted_wasm_cancellation();
    let pipeline_started = std::time::Instant::now();
    let mut pipeline = match snapshot
        .clone()
        .start_streaming_session(session, cancellation.clone())
        .await
    {
        Ok(pipeline) => Some(pipeline),
        Err(error) => {
            let _ = sink.lock().await.abort().await;
            sink_guard.disarm();
            return Err(error.into());
        }
    };
    let decoder_limits = crate::record::DecoderLimits {
        max_source_frame_bytes: state.source_body_limits.max_frame_bytes,
        ..crate::record::DecoderLimits::default()
    };
    let mut decoder = crate::record::RecordDecoder::new(format, decoder_limits)?;
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut output_hasher = sha2::Sha256::new();

    let processing = async {
        while let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|_| StreamingPutError::Transport)?
        {
            let data = frame.into_data().map_err(|frame| {
                if frame.into_trailers().is_ok() {
                    StreamingPutError::Integrity(IntegrityError::Framing(
                        "HTTP trailers are not valid outside aws-chunked framing",
                    ))
                } else {
                    StreamingPutError::Transport
                }
            })?;
            if data.len() > state.source_body_limits.max_frame_bytes {
                return Err(StreamingPutError::SourceFrameTooLarge);
            }
            let decoded = if let Some(verifier) = &mut authentication.body_verifier {
                verifier.push(&data).map_err(StreamingPutError::Integrity)?
            } else {
                vec![data]
            };
            for chunk in decoded {
                if let Some(verifier) = &mut content_md5 {
                    verifier.update(&chunk);
                }
                input_bytes = input_bytes
                    .checked_add(chunk.len() as u64)
                    .ok_or(StreamingPutError::InputTooLarge)?;
                if input_bytes > state.source_body_limits.max_bytes {
                    return Err(StreamingPutError::InputTooLarge);
                }
                decoder.push(&chunk)?;
                while let Some(record) = decoder.next_record()? {
                    if let Some(record) = pipeline
                        .as_mut()
                        .expect("pipeline remains available until finish")
                        .process(record)
                        .await?
                    {
                        write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes)
                            .await?;
                    }
                }
            }
        }
        if let Some(verifier) = authentication.body_verifier.take() {
            let verified = verifier.finish().map_err(StreamingPutError::Integrity)?;
            if verified != input_bytes {
                return Err(StreamingPutError::Integrity(
                    IntegrityError::DecodedLengthMismatch,
                ));
            }
        }
        if let Some(verifier) = content_md5.take() {
            verifier.finish().map_err(StreamingPutError::Integrity)?;
        }
        decoder.finish()?;
        while let Some(record) = decoder.next_record()? {
            if let Some(record) = pipeline
                .as_mut()
                .expect("pipeline remains available until finish")
                .process(record)
                .await?
            {
                write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes).await?;
            }
        }
        let finishing = pipeline
            .take()
            .expect("pipeline remains available until finish");
        let (records, pipeline_fuel) = finishing.finish().await?;
        for record in records {
            write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes).await?;
        }
        let pipeline_evidence = snapshot.pipeline_evidence(
            pipeline_fuel,
            pipeline_started.elapsed().as_millis() as u64,
            "none",
        );
        let output_digest = hex::encode(output_hasher.finalize());
        let mut sink = sink.lock().await;
        sink.verify_output(output_bytes, &output_digest).await?;
        let mut usage_event = UsageEvent::from_grant(grant, input_bytes, output_bytes);
        if let Some(evidence) = &pipeline_evidence {
            usage_event = usage_event.with_pipeline_evidence(evidence.clone());
        }
        persist_transaction_usage_evidence(
            state.operation_journal.as_ref(),
            sink.usage_journal_operation_id(),
            &usage_event,
        )
        .await
        .map_err(TransactionError::from)?;
        sink.record_usage_evidence(&usage_event).await?;
        let stored = sink.complete(DestinationCommitAuthority::SinglePut).await?;
        Ok((stored, output_bytes, pipeline_evidence))
    }
    .await;

    match processing {
        Ok((stored, output_bytes, pipeline_evidence)) => {
            sink_guard.disarm();
            Ok((
                authentication.auth,
                stored,
                input_bytes,
                output_bytes,
                pipeline_evidence,
            ))
        }
        Err(error) => {
            cancellation.cancel();
            if let Some(pipeline) = pipeline.take() {
                let _ = pipeline.cancel_and_wait().await;
            }
            let preserve_reservation = sink.lock().await.commit_state().preserves_reservation();
            if !preserve_reservation && sink.lock().await.abort().await.is_err() {
                warn!(
                    operation_id = %grant.operation_id(),
                    error_category = "abort",
                    "streaming sink abort failed"
                );
            }
            sink_guard.disarm();
            if preserve_reservation {
                Err(StreamingPutError::PreserveReservation(Box::new(error)))
            } else {
                Err(error)
            }
        }
    }
}

pub(crate) fn avro_media_type(content_type: &str) -> Option<String> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/avro" | "application/x-avro" | "application/vnd.apache.avro+binary"
    )
    .then_some(media_type)
}

pub(crate) fn is_avro_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(avro_media_type)
        .is_some()
}

pub(crate) fn avro_pump(
    auth: &Auth,
    headers: &HeaderMap,
    limits: crate::avro::AvroLimits,
) -> Result<
    crate::binary_pump::BinaryPump<
        crate::binary_reductor::CommonTypeBinaryReductor,
        crate::binary_pump::EnvelopeBinaryTransform,
    >,
    maskura_error::MaskuraError,
> {
    let targets = customer_headers::validated(headers, customer_headers::ENCRYPT_FIELDS)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| {
                    maskura_error::MaskuraError::new(
                        maskura_error::codes::CONFIG_INVALID,
                        "invalid x-maskura-encrypt-fields",
                    )
                })
                .and_then(crate::binary_pump::parse_envelope_targets)
        })
        .transpose()?
        .unwrap_or_default();
    let transform =
        crate::binary_pump::EnvelopeBinaryTransform::new(targets, auth.public_key_pem.as_deref())?;
    Ok(crate::binary_pump::BinaryPump::new(
        crate::binary_reductor::CommonTypeBinaryReductor::default(),
        transform,
        limits.ir,
    ))
}

pub(crate) async fn streaming_avro_single_put(
    state: &AppState,
    mut authentication: HeaderAuthentication,
    backend: ResolvedBackend,
    usage: AuthorizedUsage<'_>,
    headers: &HeaderMap,
    mut body: axum::body::Body,
    key: &str,
) -> Result<
    (
        Auth,
        StoredObjectMeta,
        u64,
        u64,
        Option<crate::control::PipelineEvidence>,
    ),
    StreamingPutError,
> {
    use http_body_util::BodyExt as _;
    use sha2::Digest as _;
    let grant = usage.grant;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| StreamingPutError::InvalidRequest("Content-Type is required".to_string()))?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let mut content_md5 =
        ContentMd5Verifier::from_headers(headers).map_err(StreamingPutError::Integrity)?;
    let sink = begin_streaming_sink(
        state,
        backend,
        AuthorizedOperation {
            auth: &authentication.auth,
            grant,
        },
        grant.operation_id(),
        grant.bucket(),
        key,
        &content_type,
        None,
        None,
    )
    .await?;
    let mut sink_guard = SinkAbortGuard::new(sink);
    let processing = async {
        let mut input = Vec::new();
        let mut input_bytes = 0_u64;
        while let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|_| StreamingPutError::Transport)?
        {
            let data = frame
                .into_data()
                .map_err(|_| StreamingPutError::Transport)?;
            if data.len() > state.source_body_limits.max_frame_bytes {
                return Err(StreamingPutError::SourceFrameTooLarge);
            }
            let decoded = if let Some(verifier) = &mut authentication.body_verifier {
                verifier.push(&data).map_err(StreamingPutError::Integrity)?
            } else {
                vec![data]
            };
            for chunk in decoded {
                if let Some(verifier) = &mut content_md5 {
                    verifier.update(&chunk);
                }
                input_bytes = input_bytes
                    .checked_add(chunk.len() as u64)
                    .ok_or(StreamingPutError::InputTooLarge)?;
                if input_bytes > state.source_body_limits.max_bytes {
                    return Err(StreamingPutError::InputTooLarge);
                }
                input.extend_from_slice(&chunk);
            }
        }
        if let Some(verifier) = authentication.body_verifier.take() {
            let verified = verifier.finish().map_err(StreamingPutError::Integrity)?;
            if verified != input_bytes {
                return Err(StreamingPutError::Integrity(
                    IntegrityError::DecodedLengthMismatch,
                ));
            }
        }
        if let Some(verifier) = content_md5.take() {
            verifier.finish().map_err(StreamingPutError::Integrity)?;
        }

        let limits = crate::avro::AvroLimits {
            max_source_bytes: state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize,
            ..crate::avro::AvroLimits::default()
        };
        let mut pump = avro_pump(&authentication.auth, headers, limits)?;
        let output = crate::avro::process_ocf(input.as_slice(), limits, &mut pump)?;
        let output_bytes =
            u64::try_from(output.len()).map_err(|_| StreamingPutError::InputTooLarge)?;
        let digest = hex::encode(sha2::Sha256::digest(&output));
        let stored = {
            let mut sink = sink_guard.sink.lock().await;
            sink.write(bytes::Bytes::from(output)).await?;
            sink.verify_output(output_bytes, &digest).await?;
            let usage_event = UsageEvent::from_grant(grant, input_bytes, output_bytes);
            persist_transaction_usage_evidence(
                state.operation_journal.as_ref(),
                sink.usage_journal_operation_id(),
                &usage_event,
            )
            .await
            .map_err(TransactionError::from)?;
            sink.record_usage_evidence(&usage_event).await?;
            sink.complete(DestinationCommitAuthority::SinglePut).await?
        };
        Ok((stored, input_bytes, output_bytes))
    }
    .await;

    match processing {
        Ok((stored, input_bytes, output_bytes)) => {
            sink_guard.disarm();
            Ok((authentication.auth, stored, input_bytes, output_bytes, None))
        }
        Err(error) => {
            let preserve_reservation = sink_guard
                .sink
                .lock()
                .await
                .commit_state()
                .preserves_reservation();
            if !preserve_reservation {
                let _ = sink_guard.sink.lock().await.abort().await;
            }
            sink_guard.disarm();
            if preserve_reservation {
                Err(StreamingPutError::PreserveReservation(Box::new(error)))
            } else {
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum VerifiedBodyError {
    Integrity(IntegrityError),
    TooLarge,
    Transport,
}

pub(crate) async fn read_verified_body(
    mut authentication: HeaderAuthentication,
    mut body: axum::body::Body,
    max_decoded_bytes: usize,
) -> Result<(Auth, bytes::Bytes), VerifiedBodyError> {
    let mut decoded = bytes::BytesMut::new();
    while let Some(frame) = body
        .frame()
        .await
        .transpose()
        .map_err(|_| VerifiedBodyError::Transport)?
    {
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if frame.into_trailers().is_ok() {
                    return Err(VerifiedBodyError::Integrity(IntegrityError::Framing(
                        "HTTP trailers are not valid outside aws-chunked framing",
                    )));
                }
                continue;
            }
        };
        if data.len() > max_decoded_bytes {
            return Err(VerifiedBodyError::TooLarge);
        }
        let chunks = if let Some(verifier) = &mut authentication.body_verifier {
            verifier.push(&data).map_err(VerifiedBodyError::Integrity)?
        } else {
            vec![data]
        };
        for chunk in chunks {
            if decoded.len().saturating_add(chunk.len()) > max_decoded_bytes {
                return Err(VerifiedBodyError::TooLarge);
            }
            decoded.extend_from_slice(&chunk);
        }
    }
    if let Some(verifier) = authentication.body_verifier.take() {
        verifier.finish().map_err(VerifiedBodyError::Integrity)?;
    }
    Ok((authentication.auth, decoded.freeze()))
}

pub(crate) async fn s3_put(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    request: Request,
) -> impl IntoResponse {
    if params.part_number.is_some() || params.upload_id.is_some() {
        return s3_upload_part(state, bucket, key, params, request).await;
    }
    let (parts, request_body) = request.into_parts();
    let header_auth = match authenticate_headers(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &state.keys,
        &state,
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(error) => return authentication_error_response(&key, error),
    };
    let auth = &header_auth.auth;
    let auth_context = auth.context.clone();
    if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
        return response;
    }
    let operation = request_operation_identity();
    let resolution_started = Instant::now();
    let resolution = match state
        .gateway
        .resolve(
            auth.workspace_id().as_str(),
            &bucket,
            crate::pipeline::PipelineDirection::Write,
        )
        .await
    {
        Ok(resolution) => resolution,
        Err(error) => {
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth.context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Write,
                None,
                error.code(),
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
            return pipeline_error_response(&key, &error);
        }
    };
    let authorization = operation.pipeline_authorization(
        &bucket,
        UsageRoute::PutObject,
        RequestKind::Write,
        object_max_processed_bytes(&state),
        &resolution,
    );
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let snapshot = match state.gateway.snapshot_for(&resolution).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth.context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Write,
                Some(&resolution),
                error.code(),
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                pipeline_error_response(&key, &error),
            )
            .await;
        }
    };
    let backend = match resolve_backend(&state, auth, &parts.headers, StorageOperation::Put).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth_context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    let _policy = match enforce_policy(
        state.policy_gate.as_ref(),
        PolicyRequest {
            workspace_id: auth.workspace_id().as_str(),
            operation: PolicyOperation::Put,
            bucket: &bucket,
            key: &key,
            resolution: Some(&resolution),
            destination: &backend,
            direction: crate::pipeline::PipelineDirection::Write,
        },
    )
    .await
    {
        Ok(policy) => policy,
        Err(error) => {
            return release_failure(
                state.control.as_ref(),
                &auth_context,
                &grant,
                &key,
                policy_error_response(&key, &error),
            )
            .await;
        }
    };
    if let Some(response) = require_file_bucket(&backend, &bucket).await {
        return release_failure(
            state.control.as_ref(),
            &auth_context,
            &grant,
            &key,
            response,
        )
        .await;
    }
    if let Err(error) = validate_streaming_backend(&state, &backend) {
        let response = streaming_put_error_response(&key, error);
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            response,
        )
        .await;
    }
    if let ResolvedBackend::Managed(storage) = &backend {
        match storage.managed_mode() {
            ManagedStreamingMode::Observe => {
                let response = s3_error::service_unavailable(
                    &key,
                    "managed mutations are disabled in observe mode",
                );
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            ManagedStreamingMode::Off | ManagedStreamingMode::Enforce => {}
        }
    }
    match streaming_single_put(
        &state,
        header_auth,
        backend,
        AuthorizedUsage { grant: &grant },
        snapshot,
        &parts.headers,
        request_body,
        &key,
    )
    .await
    {
        Ok((auth, stored, source_bytes, output_bytes, pipeline_evidence)) => {
            let usage = OperationUsage {
                grant: &grant,
                source_bytes,
                output_bytes,
            };
            let event = match pipeline_evidence {
                Some(evidence) => usage.event().with_pipeline_evidence(evidence),
                None => usage.event(),
            };
            if let Err(response) =
                record_operation_with_event(state.control.clone(), &auth.context, event, &key).await
            {
                return response;
            }
            info!(
                operation_id = %grant.operation_id(),
                receipt_id = %grant.receipt_id(),
                output_bytes,
                "streaming PUT committed"
            );
            let mut response = axum::response::Response::builder().status(StatusCode::OK);
            if let Some(etag) = stored.etag {
                response = response.header(header::ETAG, etag);
            }
            if let Some(version_id) = stored.version_id {
                response = response.header("x-amz-version-id", version_id);
            }
            response.body(axum::body::Body::empty()).unwrap()
        }
        Err(error) => {
            let error_code = match &error {
                StreamingPutError::Pipeline(error) => error.code(),
                StreamingPutError::PreserveReservation(error) => match error.as_ref() {
                    StreamingPutError::Pipeline(error) => error.code(),
                    _ => maskura_error::codes::INTERNAL,
                },
                _ => maskura_error::codes::INTERNAL,
            };
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth_context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Write,
                Some(&resolution),
                error_code,
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
            streaming_put_failure_response(
                state.control.as_ref(),
                &auth_context,
                &grant,
                &key,
                error,
            )
            .await
        }
    }
}
