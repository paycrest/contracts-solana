use anchor_lang::prelude::*;

/// Emitted when a new payment order is created.
/// Includes both sender (wallet) and refund_address for off-chain indexer flexibility.
#[event]
pub struct OrderCreated {
    /// The wallet that created the order (tx signer).
    pub sender: Pubkey,
    /// The refund address (where funds go on refund — may differ from sender).
    pub refund_address: Pubkey,
    /// SPL token mint.
    pub token: Pubkey,
    /// Escrowed amount.
    pub amount: u64,
    /// Precomputed protocol fee.
    pub protocol_fee: u64,
    /// Unique 32-byte order identifier.
    pub order_id: [u8; 32],
    /// Exchange rate.
    pub rate: u64,
    /// Off-chain message hash / recipient details.
    pub message_hash: [u8; 32],
}

/// Emitted when the aggregator settles an order (partial or full) to a liquidity provider.
/// Mirrors EVM: SettleOut(splitOrderId, orderId, liquidityProvider, settlePercent, rebatePercent)
#[event]
pub struct OrderSettledOut {
    /// Split order identifier (for partial settlements).
    pub split_order_id: [u8; 32],
    /// The parent order ID.
    pub order_id: [u8; 32],
    /// Liquidity provider receiving funds.
    pub liquidity_provider: Pubkey,
    /// BPS settled in this call.
    pub settle_percent: u64,
    /// Rebate percent given back to LP from aggregator fee.
    pub rebate_percent: u64,
}

/// Emitted when a settle-in (on-ramp) order is processed.
/// Mirrors EVM: SettleIn(orderId, liquidityProvider, recipient, amount, token, aggregatorFee, rate)
#[event]
pub struct OrderSettledIn {
    /// Unique order identifier.
    pub order_id: [u8; 32],
    /// The liquidity provider / caller.
    pub liquidity_provider: Pubkey,
    /// Recipient of the tokens.
    pub recipient: Pubkey,
    /// Amount settled to recipient.
    pub amount: u64,
    /// SPL token mint.
    pub token: Pubkey,
    /// Aggregator fee deducted.
    pub aggregator_fee: u64,
    /// Exchange rate.
    pub rate: u64,
}

/// Emitted when an order is refunded.
/// Mirrors EVM: OrderRefunded(fee, orderId)
#[event]
pub struct OrderRefunded {
    /// Fee deducted from the refund (sent to treasury).
    pub fee: u64,
    /// The order that was refunded.
    pub order_id: [u8; 32],
}

/// Emitted when sender fee is transferred.
/// Mirrors EVM: SenderFeeTransferred(orderId, sender, amount)
#[event]
pub struct SenderFeeTransferred {
    /// Order ID.
    pub order_id: [u8; 32],
    /// Recipient of the sender fee.
    pub recipient: Pubkey,
    /// Amount transferred.
    pub amount: u64,
}

/// Emitted when a local transfer fee is split among participants.
/// Mirrors EVM: LocalTransferFeeSplit(orderId, senderAmount, providerAmount, aggregatorAmount)
#[event]
pub struct LocalTransferFeeSplit {
    /// Order ID.
    pub order_id: [u8; 32],
    /// Amount going to sender fee recipient.
    pub sender_amount: u64,
    /// Amount going to liquidity provider.
    pub provider_amount: u64,
    /// Amount going to treasury (aggregator).
    pub aggregator_amount: u64,
}

/// Emitted when an FX transfer fee is split.
/// Mirrors EVM: FxTransferFeeSplit(orderId, senderAmount, aggregatorAmount)
#[event]
pub struct FxTransferFeeSplit {
    /// Order ID.
    pub order_id: [u8; 32],
    /// Amount going to sender fee recipient.
    pub sender_amount: u64,
    /// Amount going to treasury (aggregator).
    pub aggregator_amount: u64,
}
