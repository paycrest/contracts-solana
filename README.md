# contracts-solana

Solana port of the Paycrest Gateway (see `contracts/` and `contracts-starknet/`
in the main Paycrest monorepo for the Solidity and Cairo originals).

Native Rust + [Pinocchio](https://github.com/anza-xyz/pinocchio), no Anchor.
Design rationale, decision log, and open items: [`docs/PLAN.md`](docs/PLAN.md).

## Status

Program logic for all four core instructions (`create_order`, `settle_out`,
`settle_in`, `refund`) plus the full admin/settings surface is implemented
and compiles cleanly to a deployable `.so`. Verified so far:

- `cargo check` / `cargo test` — 25 native unit tests: BPS fee-math parity
  vectors (bit-exact against `Gateway.sol`'s arithmetic), account
  (de)serialization round trips, PDA derivation, event wire-format encoding.
- `cargo build-sbf` — clean release build, ~79 KB `.so`.
- Mollusk end-to-end smoke tests (`tests/mollusk`) driving the *compiled*
  binary — proves the entrypoint, dispatch, System Program CPI, and
  byte-level state layout actually work, not just that the source compiles.
- `script/` — a TypeScript deploy + admin CLI (`@solana/web3.js`, mirroring
  `contracts-starknet/script/*.ts`'s structure and npm-script names) with
  its own hand-written instruction encoders and state decoders, independent
  of the Rust program's own (de)serializers per D13. `npx tsc --noEmit`
  passes clean, and `getDeployerInfo`/`checkStatus` have been run against
  live devnet RPC to confirm the runtime logic works, not just the types.

**Not yet done** (see `docs/PLAN.md` §6 "Phasing" and §7 "Open items"):
Mollusk/LiteSVM coverage for `create_order`/`settle_out`/`settle_in`/`refund`
against real SPL Token accounts; parity vectors ported from the existing
Cairo (`contracts-starknet/tests/test_gateway.cairo`) and JS
(`contracts/test/gateway/*.test.js`) suites; the independent TypeScript
*client SDK* for the four core instructions (`ts/` — `script/` only covers
admin/settings, not `create_order`'s Address Lookup Table handling per
D6/O9); the hand-maintained `idl/gateway.json`; CU budget assertions in CI;
audit.

## Layout

```
program/          the on-chain program (Pinocchio, no_std)
tests/mollusk/     Mollusk-driven tests against the compiled .so
tests/litesvm/     (planned) multi-instruction end-to-end flows
tests/vectors/     (planned) parity vectors ported from Cairo/JS suites
script/            deploy + admin CLI (TypeScript, @solana/web3.js)
ts/                (planned) independent client SDK for core instructions
idl/               (planned) hand-maintained gateway.json
docs/PLAN.md       decision log and design rationale
```

## Building

```bash
cargo check                              # fast native type-check
cargo test --workspace                   # native unit tests + Mollusk smoke tests
cargo-build-sbf --manifest-path program/Cargo.toml   # deployable .so
```
