//! HTTP server: `/health`, `/bootstrap`, `/prove/shasta`,
//! `/prove/shasta-aggregate`.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info};

use crate::{
    Config, ServeOpts, aggregation, bootstrap as bootstrap_module, l2_client::L2Client, proposal,
    protocol::{
        BootstrapResponse, ProofError, ProofResponse, ProofResult, ProofStatus,
        RETH_TDX_PROOF_RESPONSE_SCHEMA, RETH_TDX_SHASTA_AGGREGATE_REQUEST_SCHEMA,
        RETH_TDX_SHASTA_REQUEST_SCHEMA, ShastaAggregateRequest, ShastaProveRequest,
    },
};

/// Maximum accepted request body. Aggregation batches with many sub-proofs
/// can grow, but reth-tdx's payload is L1-only fields so this is generous.
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Shared state passed to every handler.
#[derive(Clone)]
pub struct AppState {
    /// Prover configuration (chain id, verifier, instance id, etc.).
    pub config: Arc<Config>,
    /// Local Nethermind RPC client.
    pub l2: L2Client,
}

/// Run the HTTP proving server until the process is signalled to shut down.
///
/// # Errors
///
/// Returns an error if binding the socket fails or the axum server propagates
/// an error.
pub async fn run(config: Config, opts: ServeOpts, l2: L2Client) -> Result<()> {
    let state = AppState {
        config: Arc::new(config),
        l2,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/bootstrap", get(bootstrap_handler))
        .route("/prove/shasta", post(prove_shasta))
        .route("/prove/shasta-aggregate", post(prove_shasta_aggregate))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .with_state(state);

    let listener = TcpListener::bind(opts.bind)
        .await
        .with_context(|| format!("failed to bind {}", opts.bind))?;
    info!("reth-tdx HTTP server listening on {}", opts.bind);

    axum::serve(listener, app).await.context("axum server error")
}

// ─────────────────────────── Handlers ───────────────────────────

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn bootstrap_handler(
    State(state): State<AppState>,
) -> Result<Json<BootstrapResponse>, (StatusCode, String)> {
    bootstrap_module::load_bootstrap_response(state.config.home.as_deref())
        .map(Json)
        .map_err(|err| {
            error!(error = %err, "GET /bootstrap failed");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        })
}

async fn prove_shasta(
    State(state): State<AppState>,
    Json(request): Json<ShastaProveRequest>,
) -> (StatusCode, Json<ProofResponse>) {
    if request.schema != RETH_TDX_SHASTA_REQUEST_SCHEMA {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_schema",
            format!("expected {RETH_TDX_SHASTA_REQUEST_SCHEMA}, got {}", request.schema),
        );
    }

    match proposal::sign_proposal(&state.config, &state.l2, request.payload).await {
        Ok(signed) => success_response(signed.into()),
        Err(err) => {
            error!(error = %err, "POST /prove/shasta failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "prove_failed",
                err.to_string(),
            )
        }
    }
}

async fn prove_shasta_aggregate(
    State(state): State<AppState>,
    Json(request): Json<ShastaAggregateRequest>,
) -> (StatusCode, Json<ProofResponse>) {
    if request.schema != RETH_TDX_SHASTA_AGGREGATE_REQUEST_SCHEMA {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_schema",
            format!(
                "expected {RETH_TDX_SHASTA_AGGREGATE_REQUEST_SCHEMA}, got {}",
                request.schema
            ),
        );
    }

    match aggregation::sign_aggregation(&state.config, &state.l2, request.payload.proofs).await {
        Ok(signed) => success_response(signed.into()),
        Err(err) => {
            error!(error = %err, "POST /prove/shasta-aggregate failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "aggregate_failed",
                err.to_string(),
            )
        }
    }
}

// ─────────────────────────── Response helpers ───────────────────────────

fn success_response(result: ProofResult) -> (StatusCode, Json<ProofResponse>) {
    (
        StatusCode::OK,
        Json(ProofResponse {
            schema: RETH_TDX_PROOF_RESPONSE_SCHEMA.to_string(),
            status: ProofStatus::Ok,
            result: Some(result),
            error: None,
        }),
    )
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: String,
) -> (StatusCode, Json<ProofResponse>) {
    (
        status,
        Json(ProofResponse {
            schema: RETH_TDX_PROOF_RESPONSE_SCHEMA.to_string(),
            status: ProofStatus::Error,
            result: None,
            error: Some(ProofError {
                code: code.to_string(),
                message,
            }),
        }),
    )
}
