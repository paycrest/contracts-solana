use anchor_lang::prelude::*;

/// Protocol configuration account (singleton, PDA seeded by "config").
#[account]
#[derive(InitSpace)]
pub struct Config {
    pub owner: Pubkey,
    pub aggregator: Pubkey,
    pub treasury: Pubkey,
    pub paused: bool,
    pub bump: u8,
    pub vault_authority_bump: u8,
}

/// Per-token configuration (PDA seeded by ["token", mint]).
#[account]
#[derive(InitSpace)]
pub struct TokenConfig {
    pub mint: Pubkey,
    pub is_supported: u8,
    pub sender_to_provider: u64,
    pub provider_to_aggregator: u64,
    pub sender_to_aggregator: u64,
    pub provider_to_aggregator_fx: u64,
    pub bump: u8,
}

/// Per-sender nonce counter (PDA seeded by ["nonce", sender]).
#[account]
#[derive(InitSpace)]
pub struct SenderState {
    pub sender: Pubkey,
    pub nonce: u64,
    pub bump: u8,
}

/// Order lifecycle status.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum OrderStatus {
    Pending,
    Fulfilled,
    Refunded,
}

/// Payment order account.
/// PDA seeded by ["order", sender, nonce_le_bytes] — deterministic, front-run resistant.
#[account]
#[derive(InitSpace)]
pub struct Order {
    /// Unique 32-byte order identifier: hash(sender, nonce, program_id).
    pub order_id: [u8; 32],
    /// The sender who created the order.
    pub sender: Pubkey,
    /// SPL token mint.
    pub token: Pubkey,
    /// Address to receive sender fee.
    pub sender_fee_recipient: Pubkey,
    /// Sender fee amount (in token decimals).
    pub sender_fee: u64,
    /// Amount of sender_fee already distributed in partial settlements (Local mode).
    pub distributed_sender_fee: u64,
    /// Protocol fee (precomputed at creation, immutable snapshot).
    pub protocol_fee: u64,
    /// Remaining protocol fee (decremented on each partial settle — Cairo drawdown model).
    pub remaining_protocol_fee: u64,
    /// Current lifecycle status.
    pub status: OrderStatus,
    /// Address to refund to if order is cancelled/refunded.
    pub refund_address: Pubkey,
    /// Current basis points remaining (starts at MAX_BPS, decremented on partial settle).
    pub current_bps: u64,
    /// Original escrowed token amount (immutable after creation).
    pub initial_amount: u64,
    /// Remaining escrowed token amount (decremented on partial settle).
    pub current_amount: u64,
    /// Rate at which the sender intends to sell.
    pub rate: u64,
    /// Unix timestamp at which the order was created.
    pub created_at: i64,
    /// Whether this is a local transfer (rate == 100).
    pub is_local: bool,
    /// The nonce used when creating this order (for PDA derivation).
    pub nonce: u64,
    /// Bump seed for this PDA.
    pub bump: u8,
}
