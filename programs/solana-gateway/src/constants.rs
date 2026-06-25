/// Maximum basis points (100_000) — same as EVM/Cairo MAX_BPS.
pub const MAX_BPS: u64 = 100_000;

// ─── PDA Seeds ────────────────────────────────────────────────────────────────

/// Seed for the singleton Config account.
pub const CONFIG_SEED: &[u8] = b"config";

/// Seed for per-token TokenConfig accounts: ["token", mint].
pub const TOKEN_CONFIG_SEED: &[u8] = b"token";

/// Seed for the vault authority PDA (signs token transfers out).
pub const VAULT_AUTHORITY_SEED: &[u8] = b"vault_authority";

/// Seed for per-mint vault token accounts: ["vault", mint].
pub const VAULT_SEED: &[u8] = b"vault";

/// Seed for per-sender nonce state: ["nonce", sender].
pub const SENDER_STATE_SEED: &[u8] = b"nonce";

/// Seed for order accounts: ["order", sender, nonce_le_bytes].
pub const ORDER_SEED: &[u8] = b"order";
