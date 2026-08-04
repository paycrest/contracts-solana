use pinocchio::address::Address;

/// PDA seed prefixes.
pub const SEED_CONFIG: &[u8] = b"config";
pub const SEED_TOKEN_CONFIG: &[u8] = b"token";
pub const SEED_ORDER: &[u8] = b"order";
pub const SEED_VAULT_AUTHORITY: &[u8] = b"vault_authority";

/// Account discriminators (tags). 8 bytes, matching the Anchor account
/// discriminator formula `sha256("account:<Name>")[..8]` so the hand
/// maintained `idl/gateway.json` and any Anchor-aware indexer agree with
/// what's on chain, even though this program has no Anchor derive to
/// generate them. See `idl/gateway.json` for the source names.
pub const TAG_CONFIG: [u8; 8] = [0x9b, 0x0c, 0xaa, 0xe0, 0x1e, 0xfa, 0xcc, 0x82];
pub const TAG_TOKEN_CONFIG: [u8; 8] = [0x5c, 0x49, 0xff, 0x2b, 0x6b, 0x33, 0x75, 0x65];
pub const TAG_ORDER_LIVE: [u8; 8] = [0x86, 0xad, 0xdf, 0xb9, 0x4d, 0x56, 0x1c, 0x33];
pub const TAG_ORDER_TOMBSTONE: [u8; 8] = [0x08, 0x98, 0xc4, 0xac, 0xc6, 0xd3, 0x9c, 0x95];

/// Event discriminators, `sha256("event:<Name>")[..8]` — the exact Anchor
/// `emit!` formula, so `sol_log_data` output decodes with an off-the-shelf
/// Anchor event parser (D2).
pub const EVT_ORDER_CREATED: [u8; 8] = [0xe0, 0x01, 0xe5, 0x3f, 0xfe, 0x3c, 0xbe, 0x9f];
pub const EVT_SETTLE_OUT: [u8; 8] = [0x40, 0xee, 0xea, 0xbe, 0x03, 0x10, 0x74, 0x8b];
pub const EVT_SETTLE_IN: [u8; 8] = [0x3d, 0xb4, 0x0a, 0xdd, 0x7b, 0xb7, 0x89, 0xa2];
pub const EVT_ORDER_REFUNDED: [u8; 8] = [0x78, 0x9b, 0x0a, 0xa9, 0x07, 0x62, 0xca, 0xbb];
pub const EVT_SENDER_FEE_TRANSFERRED: [u8; 8] = [0x93, 0xd4, 0x28, 0xc5, 0x2e, 0xe4, 0xeb, 0xcf];
pub const EVT_TRANSFER_FEE_SPLIT: [u8; 8] = [0x50, 0xa6, 0xbd, 0x4e, 0xa0, 0xa1, 0x64, 0xfa];

/// Layout version for all account types. Bumped whenever a field is added
/// out of `reserved` padding.
pub const LAYOUT_VERSION: u8 = 1;

/// `MAX_BPS` from `GatewaySettingManager.sol` — 100% in basis points.
pub const MAX_BPS: u64 = 100_000;

/// D9 — legacy SPL Token program only, hard-pinned. Using
/// `pinocchio_token::TokenProgram::ID` (re-exported below) directly avoids
/// hand-transcribing this base58 string a second time.
pub use pinocchio_token::ID as TOKEN_PROGRAM_ID;

/// System program id, re-exported from `pinocchio_system` rather than
/// hand-transcribed.
pub use pinocchio_system::ID as SYSTEM_PROGRAM_ID;

/// A zeroed address, used the way EVM code checks `address(0)`.
pub const ZERO_ADDRESS: Address = Address::new_from_array([0u8; 32]);
