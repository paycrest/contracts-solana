# Solana Gateway — Paycrest Payment Protocol

Anchor-based Solana port of the Paycrest Gateway (EVM/Cairo).

## Architecture

- **Shared vault per mint** — all orders for a given SPL token share one vault token account
- **PDA-based order accounts** — seeded by `[ORDER_SEED, sender, nonce_le_bytes]`
- **Event-only settle_in** — on-ramp orders emit events without persistent state
- **Cairo stored-fee drawdown** — `remaining_protocol_fee` tracks proportional fee consumption

## Instructions

| Instruction | Access | Description |
|-------------|--------|-------------|
| `initialize` | Deployer only | One-time setup of Config + vault authority |
| `set_token_support` | Owner | Enable/disable token mint (SPL Token only, no Token-2022) |
| `set_token_fee_settings` | Owner | Configure per-token fee BPS |
| `update_protocol_address` | Owner | Change treasury or aggregator address |
| `pause` / `unpause` | Owner | Emergency pause (blocks create_order + settle_in) |
| `create_order` | Any sender | Escrow tokens, create order PDA |
| `settle_out` | Aggregator | Partial/full settlement to LP |
| `settle_in` | Any caller | On-ramp (event-only, no persistent state) |
| `refund` | Aggregator | Return escrowed funds minus fee |
| `close_order` | Aggregator | Reclaim rent from terminal orders |

## Deployment

### Deployer Address

The `initialize` instruction is gated to a hardcoded deployer address defined in `src/constants.rs`:

```rust
pub const DEPLOYER: &str = "YamaVRSB27oMRP9DeaCtRoykrQ2Ho3iygfZCwoU3w2j";
```

**Before mainnet deployment**, verify this matches the wallet that will call `initialize`. The deployer becomes the initial `owner` of the protocol.

### Steps

1. `anchor build`
2. `solana program deploy target/deploy/solana_gateway.so`
3. Call `initialize` from the deployer wallet — sets owner, aggregator, treasury
4. Call `set_token_support` for each stablecoin mint
5. Call `set_token_fee_settings` for each supported mint

### Security Notes

- **Token-2022 mints with transfer-fee extension are rejected** by `set_token_support`. Only classic SPL Token mints are allowed to prevent vault accounting issues.
- **settle_in is permissionless** — off-chain indexers MUST deduplicate events by `tx signature` (not `order_id`) and cross-check amounts. The `order_id` field is caller-controlled.
- **close_order returns rent to aggregator** (not sender). This is by design — aggregator bears the operational cost of order lifecycle management.
- **No ownership transfer mechanism exists.** If the owner key is lost, admin functions are permanently locked. Consider multisig for the owner wallet.
- **Vault invariant:** `vault_balance >= sum(current_amount) + sum(sender_fee - distributed_sender_fee)` for all Pending orders of that mint. Violation indicates an accounting bug.

## Building & Testing

```bash
anchor build
anchor test
```

## Fee Model

| Parameter | FX Mode | Local Mode |
|-----------|---------|------------|
| `provider_to_aggregator_fx` | % of amount → protocol fee (stored at creation) | Not used |
| `sender_to_aggregator` | % of sender_fee → treasury | Not used |
| `sender_to_provider` | Not used | % of sender_fee → provider |
| `provider_to_aggregator` | Not used | % of provider's share → treasury |

MAX_BPS = 100,000. All fee calculations use u128 intermediate precision with checked arithmetic.



git add ./Anchor.toml \
        ./Cargo.toml \
        ./package.json \
        ./tsconfig.json \
        ./README.md \
        ./programs/ \
        ./tests/
