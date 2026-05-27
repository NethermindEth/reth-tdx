//! tdxs attestation-daemon client.
//!
//! Speaks the tdxs daemon's JSON-over-Unix-socket protocol: connect, write a
//! single JSON request, half-close, read the response to EOF. The daemon
//! abstracts over the underlying issuer (`tdx` / `azure` / `gcp` / `simulator`)
//! so reth-tdx is identical across deployment targets.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Generic JSON-RPC-like request envelope.
#[derive(Debug, Serialize)]
pub struct Request<T> {
    /// Method name.
    pub method: String,
    /// Method-specific payload.
    pub data: T,
}

/// Payload for the `issue` method (request an attestation quote).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueRequestData {
    /// Hex-encoded user data (typically the address or signing hash) embedded
    /// in the attestation quote's report.
    pub user_data: String,
    /// Hex-encoded 32-byte random nonce; binds the quote to a fresh request.
    pub nonce: String,
}

/// Payload for the `metadata` method (no fields).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataRequestData {}

/// Generic response envelope — exactly one of `data` or `error` is set.
#[derive(Debug, Deserialize)]
pub struct Response<T> {
    /// Method-specific success payload.
    pub data: Option<T>,
    /// Error message if the daemon rejected the request.
    pub error: Option<String>,
}

/// Response from the `issue` method.
pub type IssueResponse = Response<IssueResponseData>;

/// Response from the `metadata` method.
pub type MetadataResponse = Response<MetadataResponseData>;

/// Hex-encoded attestation document returned by the daemon.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueResponseData {
    /// Hex-encoded attestation document.
    pub document: String,
}

/// Attestation metadata returned by the daemon.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct MetadataResponseData {
    /// One of `tdx`, `azure`, `gcp`, `simulator`.
    pub issuer_type: String,
    /// Hex-encoded user data from the most recent attestation (when applicable).
    pub user_data: String,
    /// Hex-encoded nonce from the most recent attestation (when applicable).
    pub nonce: String,
    /// Issuer-specific metadata (e.g. Azure PCRs).
    pub metadata: serde_json::Value,
}

impl<T> Response<T> {
    fn into_result(self) -> Result<T> {
        match (self.data, self.error) {
            (Some(data), None) => Ok(data),
            (None, Some(error)) => Err(anyhow!("Attestation service error: {error}")),
            (None, None) => Err(anyhow!("Invalid response: neither data nor error")),
            (Some(_), Some(error)) => Err(anyhow!(
                "Invalid response: both data and error present. Error: {error}"
            )),
        }
    }
}

/// Issue a TDX attestation quote for the given user data and nonce.
///
/// Returns the raw attestation document bytes.
///
/// # Errors
///
/// Returns an error if the daemon is unreachable or returns an error.
pub async fn issue_attestation(
    socket_path: &str,
    user_data: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let issue_data = IssueRequestData {
        user_data: hex::encode(user_data),
        nonce: hex::encode(nonce),
    };
    let request = Request {
        method: "issue".to_string(),
        data: serde_json::to_value(issue_data)?,
    };
    let request_json = serde_json::to_string(&request).context("Failed to serialize request")?;
    let socket_path = socket_path.to_owned();

    let response_buf =
        tokio::task::spawn_blocking(move || send_request_blocking(&socket_path, &request_json))
            .await
            .context("attestation blocking task panicked")??;

    let response: IssueResponse = serde_json::from_slice(&response_buf)
        .context("Failed to parse attestation service response")?;
    let data = response.into_result()?;
    hex::decode(&data.document).context("Failed to decode attestation document from hex")
}

/// Fetch metadata from the tdxs daemon (issuer type, etc.).
///
/// # Errors
///
/// Returns an error if the daemon is unreachable or returns an error.
pub async fn metadata(socket_path: &str) -> Result<MetadataResponseData> {
    let request = Request {
        method: "metadata".to_string(),
        data: serde_json::to_value(MetadataRequestData {})?,
    };
    let request_json = serde_json::to_string(&request).context("Failed to serialize request")?;
    let socket_path = socket_path.to_owned();

    let response_buf =
        tokio::task::spawn_blocking(move || send_request_blocking(&socket_path, &request_json))
            .await
            .context("attestation blocking task panicked")??;

    let response: MetadataResponse = serde_json::from_slice(&response_buf)
        .context("Failed to parse attestation service response")?;
    response.into_result()
}

/// Blocking Unix-socket round trip: connect → write → shutdown(write) → read all.
fn send_request_blocking(socket_path: &str, request_json: &str) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to attestation service at {socket_path}"))?;

    stream
        .write_all(request_json.as_bytes())
        .context("Failed to write request to socket")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("Failed to shutdown write side of socket")?;

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .context("Failed to read response from socket")?;

    Ok(response_buf)
}
