//! Top-level subcommand handlers wired up in `main.rs`.

use anyhow::{Context, Result};
use tracing::info;

use crate::{
    Config, ServeOpts,
    bootstrap as bootstrap_module,
    l2_client::L2Client,
    persistence,
    protocol::BootstrapResponse,
    server,
};

/// Bootstrap the TDX prover key + attestation quote (idempotent), persist
/// them, and return the bootstrap record.
///
/// # Errors
///
/// Returns an error when key generation, attestation, or disk I/O fails.
pub async fn bootstrap(config: &Config) -> Result<BootstrapResponse> {
    bootstrap_module::bootstrap(config.home.as_deref(), &config.tdxs_socket).await
}

/// Smoke-test the dependencies reth-tdx will rely on at request time without
/// producing any proofs:
///
/// - the tdxs daemon socket responds to a `metadata` request
/// - the local L2 RPC responds to `eth_blockNumber`
/// - if a bootstrap record exists, the on-disk private key recovers to the
///   address recorded in `bootstrap.json`
///
/// # Errors
///
/// Returns an error on the first failed dependency check.
pub async fn check(config: &Config) -> Result<()> {
    info!("reth-tdx check: pinging tdxs daemon...");
    bootstrap_module::ping_attestation(&config.tdxs_socket)
        .await
        .context("tdxs daemon check failed")?;

    info!(
        "reth-tdx check: probing local L2 RPC at {}",
        crate::config::LOCAL_L2_RPC_URL
    );
    let l2 = L2Client::local()?;
    let block_number = l2
        .probe()
        .await
        .context("local L2 RPC check failed")?;
    info!("local L2 reachable, head block = {block_number}");

    if persistence::bootstrap_exists(config.home.as_deref())? {
        info!("reth-tdx check: verifying bootstrap key/address consistency...");
        bootstrap_module::verify_disk_consistency(config.home.as_deref())
            .context("bootstrap disk consistency check failed")?;
        info!("bootstrap key matches recorded address ✓");
    } else {
        info!("no bootstrap record on disk yet — run `reth-tdx bootstrap` to initialise");
    }

    info!("reth-tdx check: OK");
    Ok(())
}

/// Run the HTTP proving server.
///
/// Eagerly bootstraps if no record exists so the first incoming `POST
/// /prove/shasta` doesn't pay the tdxs-quote round-trip on top of the L2
/// fetch latency.
///
/// # Errors
///
/// Returns an error when bootstrap, socket bind, or the HTTP server itself
/// fails.
pub async fn serve(config: Config, opts: ServeOpts) -> Result<()> {
    bootstrap_module::bootstrap(config.home.as_deref(), &config.tdxs_socket)
        .await
        .context("eager bootstrap before serving failed")?;
    let l2 = L2Client::local()?;
    server::run(config, opts, l2).await
}
