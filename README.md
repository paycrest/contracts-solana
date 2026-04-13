# contracts-solana

Solana smart contracts for the Paycrest gateway protocol.

## Description

This repository contains the Solana implementation of the Paycrest Gateway order lifecycle.
It mirrors the core behavior from the EVM implementation in `paycrest/contracts`:

- owner-managed protocol configuration (treasury, aggregator, token support, token fee settings)
- order creation with deterministic order IDs and escrowed token vaults
- settlement flows for local and FX transfers (`settle_out`)
- onramp settlement flow (`settle_in`)
- sender fee splitting and protocol fee collection
- refund flow with capped fee deduction
- pause/unpause controls

## Project structure

- `programs/gateway/src/lib.rs`: Anchor program implementation
- `tests/gateway.spec.ts`: parity-oriented test cases for order/fee logic
- `Cargo.toml`: Rust workspace
- `Anchor.toml`: Anchor configuration

## Requirements

- Rust (latest stable recommended)
- Node.js 20+ and npm
- Solana CLI
- Anchor CLI

## Install dependencies

```bash
npm install
```

## Build

```bash
npm run build:program
```

## Test

Runs Rust unit tests and TypeScript parity tests:

```bash
npm test
```

## Deployment

### 1) Configure your Solana cluster

```bash
solana config set --url <RPC_URL>
solana config set --keypair <PATH_TO_KEYPAIR_JSON>
```

Examples:

- Localnet: `http://127.0.0.1:8899`
- Devnet: `https://api.devnet.solana.com`
- Mainnet: your production RPC endpoint

### 2) Set program ID

Update `declare_id!` in `programs/gateway/src/lib.rs` and `Anchor.toml` (`[programs.<cluster>]`) to the target program ID before deploying to non-local environments.

### 3) Build and deploy

```bash
anchor build
anchor deploy --provider.cluster <localnet|devnet|mainnet>
```

For local development:

```bash
solana-test-validator
anchor deploy --provider.cluster localnet
```

### 4) Initialize program configuration

After deployment, call `initialize` with:

- `treasury` (pubkey)
- `aggregator` (pubkey)
- `chain_id` (u64 identifier used in deterministic order ID derivation)

Then configure:

- supported token mints via `setting_manager_bool`
- fee settings per token via `set_token_fee_settings`
- optional protocol address updates via `update_protocol_address`

## Operational notes

- `MAX_BPS` is `100_000` (basis-point precision used by the EVM implementation).
- local transfer mode is triggered when `rate == 100` and requires `sender_fee > 0`.
- FX mode (`rate != 100`) requires `provider_to_aggregator_fx > 0` in token settings.
- settlement supports split fills via `settle_percent` in `settle_out`.
- rebates are applied from protocol fee during settlement using `rebate_percent`.
- `settle_in` finalizes orders atomically by collecting liquidity from provider, transferring recipient payout, and splitting sender/protocol fees.

## License

[Affero General Public License v3.0](https://choosealicense.com/licenses/agpl-3.0/)
