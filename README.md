# reth-tdx

Remote TDX TEE prover for [taiko-mono](https://github.com/taikoxyz/taiko-mono) /
[raiko2](https://github.com/taikoxyz/raiko2) (Shasta).

`reth-tdx` runs **inside** the Intel-TDX–protected VM produced by
[nethermind-tdx](https://github.com/NethermindEth/nethermind-tdx), alongside a
trusted local Nethermind L2 client. An external `raiko2` instance (running on
operator-controlled infrastructure) calls reth-tdx over HTTP to obtain a TDX
attestation-backed proof for a Shasta proposal.

## Why a separate binary

In the previous design, the full `raiko2` ran inside the TDX VM and produced
TDX proofs in-process. That gave the operator the freedom to point `raiko2` at
any L2 RPC — but it also meant the attestation quote did not actually constrain
where the proven blocks came from. A malicious operator could direct the
in-VM `raiko2` to read blocks from an untrusted RPC and still emit a
TEE-signed proof.

`reth-tdx` closes that gap by making the trust boundary explicit:

1. The caller (`raiko2`) sends **only L1-derived proposal data** —
   `proposal_id`, `proposal_hash`, `parent_proposal_hash`, `actual_prover`,
   `transition (proposer + timestamp)`.
2. `reth-tdx` fetches the L2 block at `proposal_id` (1:1 with L2 block number
   in Shasta) from the **locally co-resident, hardcoded** Nethermind RPC
   (`http://127.0.0.1:8547`). Operators cannot override this — the L2 endpoint
   is baked in at image-build time.
3. `reth-tdx` builds the full `ProofCarryData` (including the checkpoint
   `blockNumber` / `blockHash` / `stateRoot` derived from the local block),
   computes the Shasta signing hash, and ECDSA-signs it with the TDX-bound
   bootstrap key.
4. The 89-byte proof (`instance_id || address || signature`) is returned to the
   caller, wire-compatible with the legacy `SgxVerifier` ABI.

The on-chain Shasta verifier cross-checks the L1-derived fields against L1
state at submission time, so it is safe for reth-tdx to trust those without
its own L1 RPC. The L2 fields (where TDX is the source of truth) are sourced
locally and never accepted from the caller.

## HTTP API

| Method | Path                       | Purpose                                                 |
| ------ | -------------------------- | ------------------------------------------------------- |
| GET    | `/health`                  | Liveness probe.                                         |
| GET    | `/bootstrap`               | Bootstrap record (quote, public key, nonce, metadata).  |
| POST   | `/prove/shasta`            | Sign one Shasta proposal's `proof_carry_data`.          |
| POST   | `/prove/shasta-aggregate`  | Aggregate a batch of previously-signed sub-proofs.      |

Request/response schemas are defined in [`src/protocol.rs`](src/protocol.rs)
(`reth-tdx-shasta-request-v1`, `reth-tdx-shasta-aggregate-request-v1`,
`reth-tdx-proof-v1`).

## CLI

```
reth-tdx bootstrap     # generate the key + attestation quote, print the record
reth-tdx check         # smoke-test tdxs socket + local L2 RPC
reth-tdx serve         # run the HTTP server on $RETH_TDX_BIND (default 0.0.0.0:8080)
```

## Build

```
cargo build --release
```

Targets are tracked against the
[`feat/tdx-prover`](https://github.com/taikoxyz/raiko2/tree/feat/tdx-prover)
branch of raiko2 (for the Shasta primitives reused here). Once that PR lands,
the git dependency in `Cargo.toml` will be pinned to a specific commit.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
