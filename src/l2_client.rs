//! Local Nethermind L2 JSON-RPC client.
//!
//! Hardcoded to [`crate::config::LOCAL_L2_RPC_URL`] — never operator-overridable.
//! reth-tdx's whole reason to exist is that L2 state comes from the trusted
//! co-resident node inside the TDX VM; allowing an arbitrary L2 URL would defeat
//! the attestation guarantee.

use std::time::Duration;

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::eth::BlockTransactionsKind;
use alloy_primitives::B256;
use anyhow::{Context, Result, anyhow};

/// Read-only client over the local L2 JSON-RPC endpoint.
#[derive(Clone)]
pub struct L2Client {
    provider: DynProvider,
}

/// Minimal block header view sourced from the local L2 node.
///
/// reth-tdx only needs the fields that go into the Shasta `Checkpoint` plus the
/// parent hash for chain continuity, so we project early instead of moving the
/// full `alloy_rpc_types_eth::Block` around.
#[derive(Debug, Clone, Copy)]
pub struct L2BlockHeader {
    /// Block number.
    pub number: u64,
    /// Block hash.
    pub hash: B256,
    /// Parent block hash.
    pub parent_hash: B256,
    /// State root after executing this block.
    pub state_root: B256,
}

impl L2Client {
    /// Build a client over the hardcoded local L2 RPC URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the hardcoded URL fails to parse (compile-time
    /// invariant — this should never happen in practice) or the HTTP transport
    /// cannot be constructed.
    pub fn local() -> Result<Self> {
        Self::with_url(crate::config::LOCAL_L2_RPC_URL)
    }

    fn with_url(url: &str) -> Result<Self> {
        let parsed = url
            .parse()
            .with_context(|| format!("invalid L2 RPC URL {url:?}"))?;
        let provider = ProviderBuilder::new().connect_http(parsed).erased();
        Ok(Self { provider })
    }

    /// Fetch the block at `block_number` from the local L2 node.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC call fails, the block is missing, or the
    /// header lacks a hash (only possible for unsealed / in-flight blocks).
    pub async fn fetch_block_header(&self, block_number: u64) -> Result<L2BlockHeader> {
        let block = self
            .provider
            .get_block_by_number(block_number.into())
            .kind(BlockTransactionsKind::Hashes)
            .await
            .with_context(|| format!("local L2 eth_getBlockByNumber({block_number}) failed"))?
            .ok_or_else(|| {
                anyhow!(
                    "local L2 has no block at number {block_number} \
                     — has Nethermind synced past the proposal yet?"
                )
            })?;

        let header = block.header.inner;
        Ok(L2BlockHeader {
            number: header.number,
            hash: block.header.hash,
            parent_hash: header.parent_hash,
            state_root: header.state_root,
        })
    }

    /// Quick reachability probe used by `reth-tdx check`. Reads
    /// `eth_blockNumber` and returns the latest block height.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC call fails.
    pub async fn probe(&self) -> Result<u64> {
        // 1 second is plenty for localhost; on cold-start the node may still be
        // syncing so probe() is best-effort — callers decide what to do with
        // failures.
        let block_number = tokio::time::timeout(
            Duration::from_secs(5),
            self.provider.get_block_number(),
        )
        .await
        .context("local L2 eth_blockNumber timed out")?
        .context("local L2 eth_blockNumber failed")?;
        Ok(block_number)
    }
}
