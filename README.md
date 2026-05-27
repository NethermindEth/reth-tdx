# reth-tdx

Remote TDX TEE prover for [taiko-mono](https://github.com/taikoxyz/taiko-mono) /
[raiko2](https://github.com/taikoxyz/raiko2) (Shasta).

`reth-tdx` runs **inside** an Intel-TDX–protected VM produced by
[nethermind-tdx](https://github.com/NethermindEth/nethermind-tdx), alongside a
trusted local Nethermind L2 client. An external `raiko2` instance calls
`reth-tdx` over HTTP to obtain a TDX-attestation-backed proof for a Shasta
proposal.

## How it works

`reth-tdx` is the only component in the proving stack that:

- Holds the prover's signing key. The key is generated inside the TEE on first
  boot, sealed to disk at `~/.config/reth-tdx/secrets/priv.key` (mode 0600), and
  never leaves the VM. A TDX attestation quote binds that key to the running
  image's measurements (`mrTd`, `mrSeam`, PCRs).
- Reads L2 state. The L2 JSON-RPC endpoint is **hardcoded** to the
  co-resident Nethermind on `http://127.0.0.1:8547` and is not operator-
  overridable — that's what makes the attestation quote a useful constraint
  on where the proven blocks came from.

The caller sends only **L1-derived proposal data**: `proposal_id`,
`proposal_hash`, `parent_proposal_hash`, `actual_prover`, and
`transition (proposer + timestamp)`. For each request, `reth-tdx`:

1. Fetches the L2 block at `proposal_id` (1:1 with the L2 block number in
   Shasta) from the local Nethermind RPC.
2. Builds the full Shasta `ProofCarryData` by combining the caller's L1 fields
   with the L2 block's `parent_hash`, `blockHash`, `stateRoot`, and
   `blockNumber`.
3. Computes the Shasta signing hash
   (`shasta_aggregation_output(commitment, chain_id, verifier, instance)`)
   and ECDSA-signs it with the TDX-bound key.
4. Issues a fresh TDX attestation quote over the same signing hash via the
   `tdxs` daemon socket.
5. Returns the canonical 89-byte proof
   (`instance_id(4) || address(20) || signature(65)`) plus the quote.

The on-chain Shasta verifier cross-checks the L1-derived fields against L1
state at proof-submission time, so `reth-tdx` does not need its own L1 RPC.
L2 fields are always sourced locally from the in-VM Nethermind — never from
the caller.

## HTTP API

| Method | Path                       | Purpose                                                  |
| ------ | -------------------------- | -------------------------------------------------------- |
| GET    | `/health`                  | Liveness probe.                                          |
| GET    | `/bootstrap`               | Bootstrap record (quote, public key, nonce, metadata).   |
| POST   | `/prove/shasta`            | Sign one Shasta proposal's `proof_carry_data`.           |
| POST   | `/prove/shasta-aggregate`  | Aggregate a batch of previously-signed sub-proofs.       |

Request/response schemas live in [`src/protocol.rs`](src/protocol.rs):
`reth-tdx-shasta-request-v1`, `reth-tdx-shasta-aggregate-request-v1`,
`reth-tdx-proof-v1`. Each request carries an explicit schema discriminator so
version mismatches fail fast.

## CLI

```
reth-tdx bootstrap     # generate the key + attestation quote, print the record
reth-tdx check         # smoke-test the tdxs socket + local L2 RPC
reth-tdx serve         # run the HTTP server on $RETH_TDX_BIND (default 0.0.0.0:8080)
```

Configuration is via CLI flags or matching environment variables
(`RETH_TDX_*`). The `serve` subcommand eagerly runs bootstrap if no record
exists on disk, so the first incoming `/prove/shasta` does not pay the
attestation round-trip on top of the L2 fetch latency.

## Build

```
cargo build --release
```

`reth-tdx` reuses a small number of Shasta primitives from raiko2 (commitment
build, aggregation hash, `ProofCarryData` / `ShastaTransitionInput` types) via
a git dependency declared in [`Cargo.toml`](Cargo.toml).

## License

Dual-licensed under MIT or Apache-2.0, at your option.
