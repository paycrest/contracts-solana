# Paycrest Gateway — Solana Port

**Target repo:** `paycrest/contracts-solana`
**Status:** Plan only. No implementation.
**Ported from:** `contracts/` (Solidity, EVM + Tron) and `contracts-starknet/` (Cairo).
**EVM alignment:** Decision log revised after a grill session aimed at Gateway.sol behavioral parity (tombstones, shared id space, keccak payout ids, pause/fee/event semantics). Aggregator integration remains a separate workstream; §4 is notes only.

**Rev 3 — cost and correctness pass.** Removed the per-sender nonce counter PDA (redundant given tombstones; costly given single-use receive addresses). Tombstone reduced from full-field to flags-only after confirming no on-chain reader of terminal order state. `Config.chain_id` made write-once. Transaction budget recosted against the real account list — `create_order` requires a v0 tx + Address Lookup Table.

---

## 0. What we're porting

The existing gateway is four state-changing entry points plus a settings layer:

| Entry point | Caller | Behaviour |
|---|---|---|
| `createOrder` | anyone | Escrows `amount + senderFee`, records an order, emits `OrderCreated` with the encrypted recipient blob |
| `settleOut` | aggregator only | Partial settlement by decrementing `currentBPS`; pays LP, splits treasury fee with a rebate carve-out |
| `settleIn` | permissionless | LP pushes tokens in; they flow straight out to the recipient, order is fulfilled immediately |
| `refund` | aggregator only | `fee <= protocolFee`; returns principal + sender fee to `refundAddress` |

Settings: `Ownable2Step` owner, `aggregatorAddress`, `treasuryAddress`, per-token supported flag, per-token `{senderToTreasury, providerToTreasury}` BPS, `MAX_BPS = 100_000`, pausable, upgradeable.

**Pause scope (EVM-exact):** `createOrder` and `settleIn` are blocked when paused; `settleOut` and `refund` remain available to the aggregator.

The Solana port keeps all of this. The decisions below are where Solana forces a different shape — or where we deliberately chose Gateway parity over an earlier Solana-only shortcut.

---

## 1. Decision log

Every decision, what it buys, and what it costs.

### D1 — Framework: **native Rust + Pinocchio**

Zero-dependency, zero-copy, minimal CU and binary size.

**Cost accepted:** no IDL generation, no `emit!`, no `#[derive(Accounts)]`. Every owner check, signer check, discriminator check, and rent-exemption check is hand-written code that a reviewer must verify by eye. This raises the value of structural containment and of external-boundary tests (see D13), and it makes the CU measurement in D13 load-bearing — Pinocchio's entire justification is CU efficiency, and unmeasured efficiency is a claim, not a fact.

### D2 — Events: **`sol_log_data`, Anchor-compatible wire format; six core events only**

8-byte discriminator + Borsh body, byte-identical to `emit!`. A hand-maintained `idl/gateway.json` is checked into the repo.

**Core events (required):** `OrderCreated`, `SettleOut`, `SettleIn`, `OrderRefunded`, `SenderFeeTransferred`, `TransferFeeSplit` — same field *semantics* as live `Gateway.sol` emits (types narrowed). Setting-manager / Ownable admin events are **not** required for v1; ops can read account state.

**`OrderCreated` quirk (EVM-exact):** the first address field is named `sender` in `IGateway.sol` but Gateway actually emits **`_refundAddress`**. Solana emits the same: first pubkey = `refund_address`. Do not “fix” this on Solana alone.

**Why:** every Solana indexer already understands the Anchor log shape; cross-chain decoders stay aligned with what Gateway *does*.

**Cost accepted:** program logs can be truncated by the runtime under CU pressure. Mitigation is to keep event payloads small and to keep total CU well under budget — tracked as a Mollusk assertion, not a hope.

### D3 — Order identity: **EVM-shaped payout ids; explicit pay-in ids; shared Order PDA**

**Payout (`create_order`):** mirror Gateway's id *algorithm*, not its counter storage.

- `order_id = keccak256(abi.encode(uint256(pubkey), uint256(nonce), uint256(chain_id)))` — 96-byte ABI-style preimage (pubkey as `uint256`, not a 20-byte address).
- `nonce` is supplied in **instruction data**. There is **no on-chain nonce counter PDA** (see below).
- Client derives the Order PDA before signing and passes it in the account list; program recomputes the keccak from the signer, the supplied nonce, and Config `chain_id`, then asserts the passed Order PDA equals `find_program_address(["order", computed_id])`.
- `order_id` therefore does **not** occupy instruction data on `create_order` — it is implied by the PDA and re-derived.
- Hash function: **keccak256** (not sha256) for Gateway algorithm parity. Cost is ~133 CU (85 base + ~1 CU per 2 bytes over a 96-byte preimage) — negligible, not a budget concern.

**Why no nonce counter PDA (supersedes the earlier per-sender counter):**

1. *It is redundant.* Tombstones (D8) keep the Order PDA permanently occupied, so reusing a `(sender, nonce)` pair reproduces the same `order_id`, hits an existing account, and fails init. Uniqueness is enforced by PDA occupancy — exactly what `require(order[orderId].sender == address(0))` does on EVM. The counter only adds *monotonicity*, which nothing consumes; EVM itself carries both as belt-and-braces.
2. *It is expensive and useless in this deployment.* The aggregator mints a **fresh receive address per payment order** (`controllers/sender/sender.go:678`), and that receive address is the `create_order` signer. Every order would therefore create a brand-new counter PDA whose value is **always 1** — 18 bytes → **1,016,160 lamports (~0.001016 SOL) locked permanently, per order**, for a counter that never counts.
3. *It costs transaction budget.* Removing it returns a 32-byte account key to the D6 budget and drops a system-program CPI.

Direct integrators reusing a single wallet track their own nonce client-side, exactly as they track EVM nonces today.

**Pay-in (`settle_in`):** explicit 32-byte `order_id` supplied by the caller — same as EVM `settleIn(bytes32 _orderId, ...)`.

**`Order` PDA:** seeds `["order", order_id]` — **one shared namespace** for both directions (D4).

**Synthetic `chain_id` — write-once, consensus-critical.** Stored in Config at `initialize`. Reserved Paycrest band: `900_001` (mainnet-beta) / `900_002` (devnet). Must not collide with EVM, Tron, or Starknet `SN_MAIN`.

It is not cosmetic — it namespaces `gateway_id` between mainnet and devnet rows in a single aggregator DB. But because it sits inside the keccak preimage, **it must have no setter**: `update_protocol_address` must not reach it and no admin instruction may mutate it. An owner who changes `chain_id` post-deploy invalidates every client-side id derivation and bricks `create_order` on that network until the aggregator is repointed. Equally, the Config value and the aggregator's network row must be identical — a mismatch fails every `create_order` at id verification.

**Identity binding (EIP-7702 analogue):** `order.sender` and the keccak preimage bind to the **token-authority signer** (depositor). Fee payer may be a separate sponsor (aggregator), matching EVM where the keeper pays gas and the user’s delegated EOA is Gateway `msg.sender`.

### D4 — Shared order-id namespace (EVM-exact)

One seed prefix: `["order", order_id]`. A payout id and a pay-in id share occupancy — `create_order` and `settle_in` cannot both succeed for the same id, matching EVM’s single `order` mapping.

**Supersedes** the earlier “split `order_out` / `order_in`” idea. Split namespaces were attractive when full PDA close allowed reuse; with permanent tombstones (D8), shared space is the Gateway-aligned choice.

### D5 — Order-id squatting: **accepted risk, mirror EVM**

`settle_in` stays permissionless. An already-initialized Order PDA (live or tombstone) fails init — analogue of `require(order[_orderId].sender == address(0))` on EVM, implemented as “account must not already exist” / reject if present.

**Risk carried:** pay-in ids remain predictable off-chain; anyone who occupies the PDA first permanently blocks that id (tombstone keeps it occupied). Pre-existing EVM property; ops runbook still required.

### D6 — Encrypted recipient blob: **X25519 hybrid; raw bytes on-chain**

Replace the 256-byte RSA-2048-wrapped AES key with a 32-byte X25519 ephemeral public key.

**Why this is forced, with the arithmetic.** Solana's hard transaction cap is 1232 bytes, total. Costed against the *actual* `create_order` account list in §2.2 (11 accounts, sponsor fee payer + depositor both signing), not an idealised one:

| Component | Legacy tx | + ALT |
|---|---|---|
| 2 signatures + count | 129 | 129 |
| Message header | 3 | 3 |
| Account keys (11 × 32 legacy; 6 hoisted into a lookup table) | 353 | 207 |
| Recent blockhash | 32 | 32 |
| Instruction framing | 16 | 16 |
| Fixed args (nonce 8, amount 8, rate 16, sender_fee 8, two pubkeys 64, discriminator, length prefix) | 109 | 109 |
| **Remaining for the blob** | **590** | **736** |

Today's blob is `4 (keylen) + 256 (RSA-wrapped key) + 12 (nonce) + plaintext + 16 (GCM tag)`. At the configured `MESSAGE_HASH_MAX_SIZE=500` that is **788 raw bytes** — and 1,051 once base64'd. It does not fit in either column.

With X25519: `32 + 12 + 500 + 16 = **560 bytes**`.

**This requires a v0 transaction with an Address Lookup Table.** In a legacy transaction the blob leaves only 30 bytes of headroom, and a ComputeBudget priority-fee instruction costs ~42 (its program key plus framing) — so the legacy path overflows at maximum payload. With an ALT hoisting the six accounts that are constant per mint (token program, system program, config PDA, token config PDA, vault ATA, mint), headroom is ~176 before ComputeBudget and ~134 after. That is the shipping configuration.

*Alternative if you want to avoid ALTs:* make the depositor its own fee payer (one signature, one fewer account key, +96 bytes) and legacy fits with ~85 bytes spare. That costs the sponsored-gas model — every receive address would need to be pre-funded with SOL — so the ALT is the better trade.

**On-chain representation:** raw `Vec<u8>` / byte array in ix + `OrderCreated` — semantic parity with EVM’s `messageHash` field, not identical string/base64 encoding.

**Cost accepted:** aggregator must hold, rotate, and publish an X25519 keypair for integrators.

### D7 — Custody: **one global vault ATA per mint, authority = program PDA**

Direct analogue of the EVM contract balance.

**Contention is a non-issue at your volume:** Solana's per-account write-lock cap is 12M CU per block; at ~40k CU per instruction that is ~300 orders/block, ~750/sec.

**Cost accepted:** all orders share one pot, so a bug in any path can reach funds belonging to every other order. With Pinocchio there is no framework guard behind that. This is the single largest reason the audit and the differential test suite matter.

**Dust:** no owner sweep (EVM parity). Truncation residuals stay in the vault forever.

### D8 — Rent: **shrink Order PDA to a flags-only tombstone; reclaim excess to aggregator**

**Not** full close. Closing broke permanent `OrderAlreadyExists`. The tombstone keeps the PDA occupied forever, so replay protection is identical to EVM's never-cleared mapping slot.

**Terminalization:** shared helper used by:

- final `settle_out` (`current_bps == 0`)
- `refund`
- `settle_in` (terminal on arrival — allocate directly at tombstone size, no realloc; see D16)

**Tombstone layout (16 bytes):** distinct account tag `TAG_ORDER_TOMBSTONE`, `version`, `bump`, `is_fulfilled`, `is_refunded`, `reserved[4]`.

The distinct tag is load-bearing under Pinocchio: without it a 16-byte tombstone could be mis-deserialized as a 204-byte live `Order`, reading whatever follows in the account. Every reader must dispatch on the tag before interpreting bytes.

**Why flags-only rather than retaining the full EVM field set** (supersedes the earlier full-field tombstone), at 6,960 lamports/byte + 128-byte account overhead:

| Variant | Data bytes | Rent (lamports) | Reclaimed | % of live rent |
|---|---|---|---|---|
| Order, live | 204 | 2,310,720 | — | — |
| Full-field tombstone | 172 | 2,088,000 | 222,720 | **7%** |
| **Flags-only tombstone** | **16** | **1,002,240** | **1,308,480** | **57%** |

A full-field tombstone shrinks only the 32 bytes of `reserved` padding — ~4.5¢ per order at $200/SOL, which does not pay for the realloc machinery. Its sole justification was keeping `get_order_info` Gateway-shaped after terminal state, and that has **no consumer**: the single caller in the codebase, `services/order/tron.go:385`, reads `Amount` *before* refunding — a pre-terminal read. Nothing reads a terminal order on-chain.

Terminal order data remains fully recoverable from `SettleOut` / `SettleIn` / `OrderRefunded` events, which is how the indexer reconstructs state on every chain already.

**No per-order `rent_payer` field.** Excess lamports on shrink go to the current `Config.aggregator`.

**Who funds rent at create:** the fee payer sponsors Order PDA rent — typically the aggregator. Round-trip: sponsor 2,310,720 at create → reclaim 1,308,480 at terminalization → **1,002,240 lamports (~0.001 SOL, ~$0.20) locked permanently per order**.

Combined with dropping the nonce counter PDA (D3), per-order permanent rent falls from 0.0031 SOL to 0.0010 SOL — at 1,000 orders/day, ~1.0 SOL/day instead of ~3.1.

**Cost accepted:** terminal orders are no longer readable on-chain in Gateway shape; ops and the indexer rely on events. Tombstone minimum rent is still locked forever and grows without bound.

### D9 — Token standard: **legacy SPL Token only, program id hard-pinned**

Pinned to `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`. Covers USDC and USDT, which is the actual volume.

**Why pinning matters here specifically:** it removes an entire class of program-substitution attack, and with Pinocchio that check is hand-written anyway — so pinning a constant is strictly safer than validating a variable.

**Cost accepted:** onboarding a Token-2022 stablecoin later requires a program upgrade, not a config change.

### D10 — Destination token accounts: **off-chain validation; on-chain refund ATA assert at `create_order` only**

On EVM `safeTransfer` reaches any address. SPL requires an initialized token account.

**Program:**

- `create_order`: pass `refund_address` ATA read-only; assert exists, correct mint, correct owner. Refuse to escrow if refund can never succeed.
- No in-program ATA creation.
- `settle_in` recipient (and other payees): **not** asserted on-chain beyond CPI failure if missing. Callers / off-chain validation must ensure ATAs exist before submit.

**Cost accepted:** onramp to a wallet without a mint ATA fails at CPI. Provisioning is outside this contract — callers validate off-chain and, where the recipient is new, prepend an ATA `create_idempotent` to the same transaction (O1). The program stays unaware of either.

### D11 — Governance: **single keypair in KMS/HSM**, mirroring the EVM owner EOA

Both the program upgrade authority and the config owner.

**Risk carried:** on Solana that one key can push arbitrary new program bytecode with no delay and no proxy-admin separation. A single compromise is total, and it is strictly more dangerous than the equivalent EVM key.

**Migration path (this is reversible):** upgrade authority can be transferred to a Squads V4 multisig at any time via `solana program set-upgrade-authority` — no redeploy, no downtime. Recommend scheduling that as a post-launch hardening item rather than treating this as permanent.

The **aggregator** role is a separate hot key that can only call `settle_out` and `refund`, so its blast radius stays bounded.

### D12 — Indexing: **`getSignaturesForAddress` + batched `getTransaction`, at `finalized`**

Solana has no `eth_getLogs`; there is no way to request every event from a program between two slots in one call.

Walk the program's signature history with a persisted last-seen signature and slot as cursor, then fetch and decode in batches. Closest analogue to the Etherscan address-history fallback the indexer already runs, works on any RPC provider, no vendor lock-in.

**`finalized`, not `confirmed`:** ~13s and ~32 slots of latency, in exchange for never acting on a slot that could be dropped. The right trade when the event triggers a fiat payout.

**Cost accepted:** one `getTransaction` per signature is chatty and needs batching plus rate-limit handling. Push-based ingestion (Helius/Geyser) is a later latency optimisation layered *on top of* this, never instead of it.

*Note: indexing is aggregator-side; listed here because it constrains event payload size and finality assumptions for the program.*

### D13 — Testing: **Rust (Mollusk + LiteSVM) and TypeScript, both**

They do different jobs and both are required:

- **Rust / Mollusk** — per-instruction correctness plus **CU budgets asserted in CI** (including keccak on `create_order`). This is what makes the Pinocchio decision verifiable rather than assumed.
- **Rust / LiteSVM** — multi-instruction end-to-end flows, in-process, millisecond speed.
- **TypeScript** — proves the hand-written wire format is decodable **from outside the program**. The TS client encoder must be written independently against the IDL spec, not generated from the Rust types.
- **Parity vectors** ported from the existing suites (`contracts-starknet/tests/test_gateway.cairo`; `contracts/test/gateway/*.test.js`) as differential tests — fee math, pause scope, settle_in field writes, OrderCreated refund-address quirk, live-vs-frozen fees.
- **Local validator smoke suite** for real SPL Token and ATA interactions that mocks cannot prove.

### D14 — Fee math: **strict bit-exact parity with the Solidity implementation**

`u128` intermediates with checked arithmetic; replicate EVM operation ordering and truncation.

**Settings timing (EVM-exact):**

- `create_order`: store `protocol_fee = amount * provider_to_treasury / MAX_BPS` from settings **at create** — used later as **refund fee cap** only.
- `settle_out`: recompute treasury cut from **live** `TokenConfig` at settle time on each `liquidity_provider_amount` (not from stored `protocol_fee`).
- Sender-fee split on final settle: uses **live** `sender_to_treasury` at that moment.
- `settle_in`: same live `provider_to_treasury` / rebate pattern as Gateway `_bookSettleInAndPayFees`.

### D15 — Scope: **full parity v1, staged rollout behind config caps**

All four instructions plus the settings layer, audited once.

De-risking at rollout: `max_order_amount` and `global_escrow_cap` in Config, owner-tunable. Devnet → mainnet with caps → lift caps (set to `u64::MAX` ≈ EVM mode). Deliberate Solana-only divergence for blast-radius control.

### D16 — `settle_in` Order field write: **EVM `_bookSettleInAndPayFees` exact**

EVM's booking semantics are preserved exactly in **ordering and arithmetic**; the difference is where the result lands.

`_bookSettleInAndPayFees` writes, in this order, *before* any outbound transfer:

- `sender = recipient` (not the LP signer)
- `token`, `senderFeeRecipient`, `senderFee` from calldata
- `protocolFee = grossTreasuryFee`
- `isFulfilled = true`, `isRefunded = false`
- `amount = amountToSettle` (net after treasury)
- `refundAddress` / `currentBPS` left unset

**On Solana:** a pay-in order is terminal the moment it exists, so the Order PDA is **allocated directly at tombstone size (16 bytes)** — no full-size write followed by a realloc in the same instruction. The PDA is created and marked `is_fulfilled = true` *before* the treasury, rebate, and recipient transfers, preserving EVM's checks-effects-interactions ordering and arming the `OrderAlreadyExists` guard against double-settlement.

The field values above are still computed identically and are carried in the **`SettleIn` event** (`recipient`, `amount_to_settle`, `mint`, `gross_treasury_fee`, `rate`, `rebate_percent`) rather than persisted to the account. No consumer reads them from storage (D8).

**No `direction` field** on Order — EVM `Order` has none; lifecycle/flags imply payout vs payin.

**Note — Cairo diverges here.** `contracts-starknet/src/contracts/Gateway.cairo:366` sets `refund_address: caller` and `current_bps: 0` on `settle_in`, where Solidity leaves both zero. Solana follows Solidity. If three-way consistency is wanted, that is a separate Starknet ticket, not a Solana change.

---

## 2. Program architecture

### 2.1 Accounts

**`Config` PDA** — seeds `["config"]`

| Field | Type | Notes |
|---|---|---|
| tag | `[u8; 8]` | account discriminator |
| version | `u8` | layout version — Solana upgrades do **not** migrate account data |
| bump | `u8` | |
| paused | `u8` | |
| owner | `Pubkey` | |
| pending_owner | `Pubkey` | preserves `Ownable2Step` semantics |
| aggregator | `Pubkey` | settle/refund authority; rent reclaim destination |
| treasury | `Pubkey` | |
| chain_id | `u64` | synthetic; in the payout order-id keccak preimage. **Write-once at `initialize` — no setter, no admin mutation path** (D3) |
| max_bps | `u64` | 100_000 |
| max_order_amount | `u64` | rollout cap (D15) |
| global_escrow_cap | `u64` | rollout cap (D15) |
| reserved | `[u8; 64]` | **there is no `__gap` equivalent — reserve at v1 or never add a field** |

**`TokenConfig` PDA** — seeds `["token", mint]`

`tag`, `version`, `bump`, `is_supported`, `mint`, `sender_to_treasury: u64`, `provider_to_treasury: u64`, `reserved: [u8; 32]`.

Splitting per-mint settings into their own PDA keeps `Config` read-only on the hot path where possible.

**No `Nonce` PDA.** The payout nonce is supplied in instruction data; uniqueness is enforced by permanent Order PDA occupancy (D3).

**`Order` PDA** — seeds `["order", order_id]`

EVM-mirrored logical fields only (no `direction`, no `rent_payer`):

| Field | Type | Maps from Solidity |
|---|---|---|
| tag (`TAG_ORDER_LIVE`), version, bump | `u8`×3 | — |
| is_fulfilled, is_refunded | `u8`×2 | `isFulfilled`, `isRefunded` |
| sender | `Pubkey` | `sender` |
| mint | `Pubkey` | `token` |
| sender_fee_recipient | `Pubkey` | `senderFeeRecipient` |
| refund_address | `Pubkey` | `refundAddress` |
| amount | `u64` | `amount` (u256 → u64) |
| sender_fee | `u64` | `senderFee` |
| protocol_fee | `u64` | `protocolFee` |
| current_bps | `u64` | `currentBPS` |
| reserved | `[u8; 32]` | |

Live layout is 204 data bytes (2,310,720 lamports). On terminalization the account is realloc'd down to the 16-byte `TAG_ORDER_TOMBSTONE` layout (1,002,240 lamports) and the 1,308,480-lamport excess is transferred to `Config.aggregator` (D8). Readers **must** dispatch on the tag — a tombstone deserialized as a live `Order` reads past its own data.

`settle_in` allocates directly at tombstone size and never holds the live layout (D16).

**Vault** — one ATA per supported mint, authority = PDA `["vault_authority"]`.

### 2.2 Instructions

Admin: `initialize`, `set_token_support`, `set_token_fee_settings`, `update_protocol_address`, `transfer_ownership`, `accept_ownership`, `pause`, `unpause`, `set_caps`.

**No instruction may write `Config.chain_id` after `initialize`** — `update_protocol_address` handles treasury and aggregator only (D3).

Core: `create_order`, `settle_out`, `settle_in`, `refund`.

**Pause:** only `create_order` and `settle_in` check `paused`; `settle_out` / `refund` do not.

**`create_order` (sketch):** fee payer (writable, sponsors rent) + depositor token-authority signer + depositor source ATA + Order PDA + vault ATA + config + token config + mint + refund ATA (read-only, D10) + token program + system program.

Ix data: `nonce`, rate, amount, sender fee, refund/fee-recipient pubkeys, message-hash bytes. `order_id` is **not** in ix data — the program recomputes `keccak(depositor, nonce, chain_id)` and asserts the passed Order PDA derives from it.

### 2.3 Events

Six core events — §1 D2. Types narrowed: `u256 → u64`, `address → Pubkey`, `bytes32 → [u8; 32]`, `string messageHash → Vec<u8>`. `OrderCreated` first pubkey = `refund_address`.

---

## 3. Cross-chain divergence summary

| Concern | EVM / Tron / Starknet | Solana | Why |
|---|---|---|---|
| Pay-out order id | `keccak256(abi.encode(msg.sender, nonce, chainid))` | Same algorithm with pubkey-as-uint256 + Config `chain_id`; client pre-derives PDA | PDA must be known pre-signature (D3) |
| Nonce storage | per-sender counter in contract storage | **none** — nonce in ix data; uniqueness from permanent PDA occupancy | counter is redundant given tombstones, and costs 0.001 SOL/order under single-use receive addresses (D3) |
| Order namespaces | one shared mapping | one shared `["order", id]` PDA | EVM alignment (D4) |
| Order storage lifetime | permanent full slot | permanent 16-byte flags-only tombstone | id occupancy preserved; terminal fields live in events, which have no on-chain reader (D8) |
| Terminal order readability | `getOrderInfo` returns full struct | events only | no consumer reads terminal state (D8) |
| Transaction assembly | single tx, no size ceiling | **v0 tx + Address Lookup Table required** | 1232-byte cap vs 560-byte blob (D6) |
| Replay guard | on-chain, permanent | on-chain, permanent (tombstone occupies PDA) | D8 |
| Blob encryption | RSA-2048 hybrid | X25519 hybrid | 1232-byte tx cap (D6) |
| Blob encoding on chain | base64 string | raw bytes | size (D6) |
| Destination addresses | any address | refund ATA asserted at create; others off-chain / CPI | SPL model (D10) |
| Rollout caps | none | `max_order_amount`, escrow cap | staged launch (D15) |
| Gasless / sponsored flow | EIP-7702 keeper pays gas; user is `msg.sender` | native fee payer ≠ token authority; authority is `sender` | D3 identity binding |
| Pause | create + settleIn blocked; settleOut/refund ok | same | §0 |
| Fee settings timing | live at settle; create `protocolFee` caps refund | same | D14 |
| `OrderCreated` first address | emits refund address (natspec says sender) | same | D2 |
| Dust | stuck forever, no sweep | same | D7 |
| Upgrade mechanism | transparent proxy / class-hash replace | BPF loader upgrade | **does not migrate account data** — hence `reserved` padding |

---

## 4. Aggregator (Go) workstream — out of scope for this plan

Contract plan only. Aggregator work is a **separate** stream; listed so program choices stay implementable:

1. X25519 crypto path and publication of the public key.
2. Payout id precompute (`keccak` + ABI encode + Config `chain_id`) and nonce selection off-chain for PDA derivation — trivial for API-born orders, where the single-use receive address means `nonce == 1` always.
2b. Address Lookup Table provisioning and maintenance per mint (D6) — `create_order` does not fit a legacy transaction.
3. `services/indexer/solana.go` — signature-cursor polling at `finalized` (D12).
4. `services/order/solana.go` — tx build, fee-payer sponsorship, priority fees, confirmation.
5. Pay-in id encoding for Solana addresses + synthetic `chain_id` (`900_001` / `900_002`).
6. Network row using those synthetic chain ids.
7. Off-chain ATA validation / provisioning for `settle_in` recipients (D10).

Tombstones mean on-chain replay protection no longer depends on a new DB `gateway_id` unique constraint for Solana correctness (that may still be desirable ops hygiene, but it is not a contract hard dependency the way full PDA close was).

---

## 5. Repo layout

Mirrors `contracts-starknet/` where sensible, including the `script/` tooling shape (`deploy`, `setSupportedTokens`, `setTokenFeeSettings`, `updateProtocolAddresses`, `upgrade`, `checkStatus`).

```
contracts-solana/
├── Cargo.toml                  # workspace
├── program/src/
│   ├── lib.rs                  # entrypoint + dispatch
│   ├── instructions/           # one file per instruction
│   ├── state/                  # config.rs, token_config.rs, order.rs (live + tombstone)
│   ├── events.rs
│   ├── errors.rs
│   └── math.rs                 # BPS math, u128 intermediates, keccak id helper
├── tests/
│   ├── mollusk/                # per-instruction + CU budget assertions
│   ├── litesvm/                # end-to-end flows
│   └── vectors/                # parity vectors ported from Solidity/Cairo
├── ts/
│   ├── src/                    # INDEPENDENT client encoder (D13)
│   └── tests/                  # litesvm-ts / bankrun
├── idl/gateway.json            # hand-maintained
├── script/                     # deploy + settings tooling
└── .github/workflows/          # build, test, CU regression, solana-verify
```

---

## 6. Phasing

**Phase 0 — Foundations.** Repo scaffold, CI, IDL spec frozen, account layouts frozen (live + tombstone layouts, account tags, `reserved` padding, write-once Config `chain_id`), parity vectors extracted from the Cairo and JS suites.

**Phase 1 — State and admin.** `Config`/`TokenConfig` PDAs, ownership two-step, pause (create/settle_in only), token registration, fee settings, caps. Mollusk coverage.

**Phase 2 — Pay-out path.** Keccak id verify, `create_order`, `refund`, vault, refund ATA assert, shrink-to-tombstone on refund, ALT provisioning.

**Phase 3 — Settlement.** `settle_out` (partial BPS, live fees, rebate, shrink on final), `settle_in` (direct tombstone-size allocation, CEI ordering, event carries booked values).

**Phase 4 — Aggregator integration.** Separate workstream (§4), in parallel where possible.

**Phase 5 — Hardening.** Audit, CU budgets (incl. keccak), fuzz/property tests on BPS math, `solana-verify`, devnet soak.

**Phase 6 — Staged mainnet.** Deploy with caps → monitor → lift caps → hand upgrade authority to a multisig (D11).

---

## 7. Open items

| # | Item | Status / why it matters |
|---|---|---|
| **O1** | `settle_in` recipient ATA | **Resolved — off-contract.** The program performs no ATA creation and asserts nothing beyond CPI failure; existence is validated off-chain before submit. Recommended mechanism: the caller prepends an ATA `create_idempotent` as instruction 0 of the **same** `settle_in` transaction (no program change; `settle_in` carries no blob so budget is ample). A validation-only check leaves onramp to a first-time recipient rejected rather than completed — creating in-transaction is what makes it complete, and matches standard Solana sender behaviour. |
| **O2** | Synthetic `chain_id` | **Decided:** write-once Config field, no setter; `900_001` mainnet-beta / `900_002` devnet. **The aggregator network row must carry the identical value** — it is inside the order-id keccak preimage, so any divergence fails every `create_order` at id verification. Confirm before deploy, not after. |
| **O3** | Vault dust sweep | **Decided:** no sweep (EVM parity). |
| **O4** | Priority-fee strategy and retry policy | Aggregator-only; not a contract concern. |
| **O5** | Audit firm and slot | Book before Phase 3 completes. |
| **O6** | X25519 key rotation procedure | Aggregator key-management; overlap window for in-flight orders. |
| **O7** | Vault ATA creation path | Confirm whether vault ATA is created in `set_token_support` / `initialize` and who pays that rent (likely aggregator/owner). |
| **O8** | Exact tombstone realloc size | **Decided:** 16 bytes (`TAG_ORDER_TOMBSTONE`, version, bump, two flags, 4 reserved) → 1,002,240 lamports; reclaim 1,308,480. Mollusk asserts the exact reclaim amount so a layout change cannot silently alter it. |
| **O9** | Address Lookup Table lifecycle | `create_order` requires a v0 tx + ALT (D6). Who creates the table per mint, who pays its rent, and how it is rolled if an entry changes. Blocks Phase 2. |

## 8. Accepted risks (carried deliberately)

- **R1 (D5)** — pay-in order ids are predictable and squattable; tombstone makes occupation permanent. Ops runbook required.
- **R2 (D7)** — single shared vault per mint; a bug in any path can reach every order's funds.
- **R3 (D8)** — id occupancy stays on-chain via tombstone, so replay protection matches EVM. Residual: 1,002,240 lamports (~0.001 SOL) locked forever per order, unbounded growth — ~1.0 SOL/day at 1,000 orders/day. Revisit if volume makes that material.
- **R4 (D11)** — a single key holds both upgrade authority and config ownership; total compromise on loss. Reversible via `set-upgrade-authority`.
- **R5 (D1)** — no framework guardrails; correctness of every account check rests on review and tests.
- **R7 (D14)** — mid-flight token fee changes alter settle math (same as EVM); refund cap stays at create-time `protocol_fee`.
- **R8 (D8)** — a tombstone mis-read as a live `Order` would deserialize past its own 16 bytes. Every reader must dispatch on the account tag; this is hand-written under Pinocchio and belongs in the audit scope.
- **R9 (D6)** — `create_order` depends on an Address Lookup Table being present and correct. A missing or stale ALT breaks order creation on Solana entirely (see O9).

**Retired:** ~~R6 (D3), keccak CU cost~~ — the syscall is ~133 CU for a 96-byte preimage (85 base + ~1 CU per 2 bytes), 0.07% of the default 200k budget.
