use pinocchio::error::ProgramError;

/// Mirrors the require()/assert() strings in Gateway.sol and Gateway.cairo.
/// Ordering is append-only — these values are returned to clients as
/// `Custom(n)` and a renumber would change every existing error's meaning.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayError {
    TokenNotSupported = 0,
    AmountIsZero = 1,
    ZeroRefundAddress = 2,
    InvalidSenderFeeRecipient = 3,
    InvalidMessageHash = 4,
    OrderAlreadyExists = 5,
    OrderFulfilled = 6,
    OrderRefunded = 7,
    InvalidRebatePercent = 8,
    InvalidSettlePercent = 9,
    FeeExceedsProtocolFee = 10,
    OnlyAggregator = 11,
    OnlyOwner = 12,
    OnlyPendingOwner = 13,
    ContractPaused = 14,
    ZeroAddress = 15,
    TreasuryAlreadySet = 16,
    AggregatorAlreadySet = 17,
    InvalidStatus = 18,
    MathOverflow = 19,
    InvalidAccountTag = 20,
    InvalidPda = 21,
    MissingRefundTokenAccount = 22,
    InvalidTokenProgram = 23,
    InvalidMint = 24,
    AmountExceedsCap = 25,
    EscrowCapExceeded = 26,
    AlreadyInitialized = 27,
    InvalidOwner = 28,
    MissingSignature = 29,
    InvalidTokenAccountOwner = 30,
}

impl From<GatewayError> for ProgramError {
    fn from(e: GatewayError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
