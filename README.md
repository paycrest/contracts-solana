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
- **Deployed and verified on devnet.** Program id
  `BoSMnjq5yfEbGYDAm9QMDwYS1SU2avudcc7JqBKNw77U`, deployed and initialized
  via `script/deploy.ts`, then confirmed with the full `update-addresses` /
  `set-tokens` / `set-fee-settings` / `check-status` pipeline against real
  devnet RPC. Reproducibly built and hash-verified twice (once pre-
  `security.txt`, once after) against `solana-verify`, including a
  from-scratch clone of the pushed GitHub commit (not just the local
  working copy):

  ```bash
  solana-verify verify-from-repo -u https://api.devnet.solana.com \
    --program-id BoSMnjq5yfEbGYDAm9QMDwYS1SU2avudcc7JqBKNw77U \
    https://github.com/paycrest/contracts-solana \
    --library-name paycrest_gateway \
    --base-image solanafoundation/solana-verifiable-build:4.0.3 \
    --commit-hash 3f06dcf595d4fffef46817aca0c1400515b644e6
  # Executable Program Hash from repo: 1df7285ee108e9300da2a9d95fd35bc74433dcd6fb8a32c89ba8d26d91164b3c
  # On-chain Program Hash:            1df7285ee108e9300da2a9d95fd35bc74433dcd6fb8a32c89ba8d26d91164b3c
  # Program hash matches ✅
  ```

  An on-chain verify PDA recording this (git URL, commit, build args) is
  publicly queryable: `solana-verify list-program-pdas --program-id
  BoSMnjq5yfEbGYDAm9QMDwYS1SU2avudcc7JqBKNw77U -u
  https://api.devnet.solana.com`. Note that OtterSec's *remote* verification
  service — the thing that actually populates Explorer's green "Verified"
  checkmark — only processes **mainnet** programs; there is no equivalent
  badge for devnet, regardless of how the program was built. The PDA above
  is the real, checkable evidence for a devnet deployment.

  The program also embeds `security.txt` (contact:
  `engineering@paycrest.io`) — confirmed present in the compiled `.so` via
  `strings`, not just asserted from source.

  Things worth knowing if you reproduce this:
  - `solana-verify build`'s **default** base image (auto-selected as
    "Solana version 3.0.1") bundles a Solana-tools rustc too old for
    Pinocchio's MSRV (`pinocchio`/`pinocchio-token`/etc. require rustc
    1.89+). Pass `--base-image solanafoundation/solana-verifiable-build:4.0.3`
    (or a comparably recent tag) explicitly.
  - `Cargo.lock` pins `zeroize` to `1.8.1`, not whatever your local
    toolchain would otherwise resolve. A locally newer rustc (this repo
    was built with 1.97.1) will happily resolve `zeroize 1.9.0`, which
    requires `edition2024` — unsupported by the verifiable-build image's
    older bundled cargo. Don't `cargo update -p zeroize` without checking
    this still holds.
  - `solana-verify get-program-hash` (and even a raw `solana program dump`)
    can return stale results for a few seconds right after an upgrade on
    the public devnet RPC — a mismatch immediately post-upgrade isn't
    necessarily real; the transaction's own status (`solana confirm -v
    <sig>`) is the authoritative check, and the hash caught up on retry.
  - Confirmed empirically, not just asserted: after redeploying the
    reproducible binary via `script/upgrade.ts` **twice**, `Config`/
    `TokenConfig` state (owner, treasury, aggregator, chain_id, token
    support) was unaffected both times — matching D11's claim that
    upgrades don't touch account data.

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
