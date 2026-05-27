//! CLI entrypoint for the reth-tdx remote TDX prover.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use reth_tdx::{Config, ServeOpts, bootstrap, check, serve};

#[derive(Debug, Parser)]
#[command(name = "reth-tdx")]
#[command(about = "Remote TDX TEE prover for taiko-mono / raiko2 (Shasta).")]
struct App {
    #[command(flatten)]
    config: Config,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate (or reuse) the TDX prover key, fetch a TDX attestation quote, and
    /// emit the bootstrap record (quote, public key, nonce, metadata) to stdout.
    Bootstrap,
    /// Verify that reth-tdx can talk to its dependencies (tdxs daemon socket,
    /// local Nethermind L2 RPC) without producing any proofs.
    Check,
    /// Run the HTTP proving server.
    Serve(ServeOpts),
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let app = App::parse();
    match app.command {
        Command::Bootstrap => {
            let data = bootstrap(&app.config).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
            Ok(())
        }
        Command::Check => check(&app.config).await,
        Command::Serve(opts) => serve(app.config, opts).await,
    }
}

fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_ansi(false))
        .init();
}
