use anchor_lang::prelude::*;

#[error_code]
pub enum GatewayError {
    // ─── Access Control ───────────────────────────────────────────────
    #[msg("Only the aggregator authority can call this instruction")]
    OnlyAggregator,

    #[msg("Only the owner can call this instruction")]
    OnlyOwner,

    #[msg("Caller is not the pending owner")]
    NotPendingOwner,

    // ─── Pause ────────────────────────────────────────────────────────
    #[msg("Protocol is paused")]
    ProtocolPaused,

    #[msg("Protocol is not paused")]
    ProtocolNotPaused,

    // ─── Token Validation ─────────────────────────────────────────────
    #[msg("Token is not supported")]
    TokenNotSupported,

    #[msg("Invalid token support status (must be 1 or 2)")]
    InvalidTokenStatus,

    #[msg("Token fee settings not configured for this mint")]
    TokenFeeSettingsNotConfigured,

    // ─── Order Creation ───────────────────────────────────────────────
    #[msg("Amount must be greater than zero")]
    AmountIsZero,

    #[msg("Refund address must not be the zero/default pubkey")]
    ZeroRefundAddress,

    #[msg("Sender fee recipient must not be the zero/default pubkey when sender fee > 0")]
    InvalidSenderFeeRecipient,

    #[msg("Message hash must not be empty")]
    InvalidMessageHash,

    #[msg("An order with this ID already exists")]
    OrderAlreadyExists,

    #[msg("Sender fee is required for local transfers (rate = 100)")]
    SenderFeeIsZero,

    // ─── Settlement ───────────────────────────────────────────────────
    #[msg("Order has already been fulfilled")]
    OrderFulfilled,

    #[msg("Order has already been refunded")]
    OrderRefunded,

    #[msg("Settle percent must be > 0 and <= current BPS")]
    InvalidSettlePercent,

    #[msg("Rebate percent must be <= MAX_BPS")]
    InvalidRebatePercent,

    // ─── Refund ───────────────────────────────────────────────────────
    #[msg("Fee exceeds the stored protocol fee")]
    FeeExceedsProtocolFee,

    // ─── Fee Settings ─────────────────────────────────────────────────
    #[msg("Fee percentage exceeds MAX_BPS")]
    FeeExceedsMaxBps,

    // ─── Math ─────────────────────────────────────────────────────────
    #[msg("Arithmetic overflow")]
    MathOverflow,

    // ─── Misc ─────────────────────────────────────────────────────────
    #[msg("Invalid protocol address type")]
    InvalidProtocolAddressType,

    #[msg("Address is already set to this value")]
    AddressAlreadySet,

    #[msg("Recipient must not be the zero/default pubkey")]
    ZeroRecipientAddress,

    #[msg("Address must not be the zero/default pubkey")]
    ZeroAddress,

    #[msg("Treasury token account owner does not match config.treasury")]
    InvalidTreasuryAccount,

    #[msg("Mint does not match the order's token")]
    MintMismatch,

    #[msg("Refund token account owner does not match order.refund_address")]
    InvalidRefundAddress,

    #[msg("Nonce does not match expected next nonce")]
    InvalidNonce,

    #[msg("Recipient token account owner does not match expected recipient")]
    InvalidRecipientAccount,

    #[msg("Order is not in a terminal state (must be Fulfilled or Refunded)")]
    OrderNotTerminal,

    #[msg("Token-2022 mints with transfer-fee extension are not supported")]
    Token2022NotSupported,
}
