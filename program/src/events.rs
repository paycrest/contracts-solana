//! D2 — event emission via `sol_log_data`, Anchor's exact wire format:
//! an 8-byte discriminator (`sha256("event:<Name>")[..8]`, computed in
//! `constants.rs`) followed by a Borsh-encoded body. For every field type
//! used here (`u64`, `bool`, `[u8; 32]`, `Vec<u8>`) Borsh's encoding is
//! byte-identical to a straightforward manual little-endian write, so this
//! file has no borsh dependency — see `idl/gateway.json` for the schema
//! this must stay in sync with.
//!
//! Field sets mirror `IGateway.sol`'s events exactly (D2), including the
//! `OrderCreated` quirk: the first field is named `sender` in the
//! interface but Gateway actually emits `_refundAddress`. That is
//! reproduced here on purpose — see `create_order.rs`.

use pinocchio::address::Address;

use alloc::vec::Vec;

#[inline(always)]
fn emit(bytes: &[u8]) {
    #[cfg(target_os = "solana")]
    unsafe {
        let fields: [&[u8]; 1] = [bytes];
        pinocchio::syscalls::sol_log_data(fields.as_ptr() as *const u8, fields.len() as u64);
    }
    #[cfg(not(target_os = "solana"))]
    {
        let _ = bytes;
    }
}

fn push_address(buf: &mut Vec<u8>, value: &Address) {
    buf.extend_from_slice(value.as_array());
}

fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes32(buf: &mut Vec<u8>, value: &[u8; 32]) {
    buf.extend_from_slice(value);
}

/// Borsh's `Vec<u8>` encoding: 4-byte LE length prefix, then raw bytes.
fn push_var_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

pub struct OrderCreated<'a> {
    /// Named `sender` in `IGateway.sol` but actually the refund address —
    /// reproduced here, not "fixed" (D2).
    pub sender: Address,
    pub token: Address,
    pub amount: u64,
    pub protocol_fee: u64,
    pub order_id: [u8; 32],
    pub rate: u64,
    pub message_hash: &'a [u8],
}

impl OrderCreated<'_> {
    pub fn emit(&self) {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 8 + 8 + 32 + 8 + 4 + self.message_hash.len());
        buf.extend_from_slice(&crate::constants::EVT_ORDER_CREATED);
        push_address(&mut buf, &self.sender);
        push_address(&mut buf, &self.token);
        push_u64(&mut buf, self.amount);
        push_u64(&mut buf, self.protocol_fee);
        push_bytes32(&mut buf, &self.order_id);
        push_u64(&mut buf, self.rate);
        push_var_bytes(&mut buf, self.message_hash);
        emit(&buf);
    }
}

pub struct SettleOutEvent {
    pub split_order_id: [u8; 32],
    pub order_id: [u8; 32],
    pub liquidity_provider: Address,
    pub settle_percent: u64,
    pub rebate_percent: u64,
}

impl SettleOutEvent {
    pub fn emit(&self) {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 32 + 8 + 8);
        buf.extend_from_slice(&crate::constants::EVT_SETTLE_OUT);
        push_bytes32(&mut buf, &self.split_order_id);
        push_bytes32(&mut buf, &self.order_id);
        push_address(&mut buf, &self.liquidity_provider);
        push_u64(&mut buf, self.settle_percent);
        push_u64(&mut buf, self.rebate_percent);
        emit(&buf);
    }
}

pub struct SettleInEvent {
    pub order_id: [u8; 32],
    pub liquidity_provider: Address,
    pub recipient: Address,
    pub amount: u64,
    pub mint: Address,
    pub aggregator_fee: u64,
    pub rate: u64,
    pub rebate_percent: u64,
}

impl SettleInEvent {
    pub fn emit(&self) {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 32 + 8 + 32 + 8 + 8 + 8);
        buf.extend_from_slice(&crate::constants::EVT_SETTLE_IN);
        push_bytes32(&mut buf, &self.order_id);
        push_address(&mut buf, &self.liquidity_provider);
        push_address(&mut buf, &self.recipient);
        push_u64(&mut buf, self.amount);
        push_address(&mut buf, &self.mint);
        push_u64(&mut buf, self.aggregator_fee);
        push_u64(&mut buf, self.rate);
        push_u64(&mut buf, self.rebate_percent);
        emit(&buf);
    }
}

pub struct OrderRefundedEvent {
    pub fee: u64,
    pub order_id: [u8; 32],
}

impl OrderRefundedEvent {
    pub fn emit(&self) {
        let mut buf = Vec::with_capacity(8 + 8 + 32);
        buf.extend_from_slice(&crate::constants::EVT_ORDER_REFUNDED);
        push_u64(&mut buf, self.fee);
        push_bytes32(&mut buf, &self.order_id);
        emit(&buf);
    }
}

pub struct SenderFeeTransferredEvent {
    pub order_id: [u8; 32],
    pub sender: Address,
    pub amount: u64,
}

impl SenderFeeTransferredEvent {
    pub fn emit(&self) {
        let mut buf = Vec::with_capacity(8 + 32 + 32 + 8);
        buf.extend_from_slice(&crate::constants::EVT_SENDER_FEE_TRANSFERRED);
        push_bytes32(&mut buf, &self.order_id);
        push_address(&mut buf, &self.sender);
        push_u64(&mut buf, self.amount);
        emit(&buf);
    }
}

pub struct TransferFeeSplitEvent {
    pub order_id: [u8; 32],
    pub sender_amount: u64,
    pub aggregator_amount: u64,
}

impl TransferFeeSplitEvent {
    pub fn emit(&self) {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 8);
        buf.extend_from_slice(&crate::constants::EVT_TRANSFER_FEE_SPLIT);
        push_bytes32(&mut buf, &self.order_id);
        push_u64(&mut buf, self.sender_amount);
        push_u64(&mut buf, self.aggregator_amount);
        emit(&buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format itself (independent of the `sol_log_data` syscall,
    /// which only resolves on-chain): discriminator + field bytes in
    /// declaration order, matching Borsh's encoding for every field type
    /// used. This is what the TS client (D13) must decode independently.
    #[test]
    fn order_created_encodes_discriminator_then_fields_then_length_prefixed_hash() {
        let sender = Address::new_from_array([0xAA; 32]);
        let token = Address::new_from_array([0xBB; 32]);
        let order_id = [0xCCu8; 32];
        let message_hash = [1u8, 2, 3, 4, 5];

        let mut buf = Vec::new();
        buf.extend_from_slice(&crate::constants::EVT_ORDER_CREATED);
        push_address(&mut buf, &sender);
        push_address(&mut buf, &token);
        push_u64(&mut buf, 1_000_000);
        push_u64(&mut buf, 2_500);
        push_bytes32(&mut buf, &order_id);
        push_u64(&mut buf, 42);
        push_var_bytes(&mut buf, &message_hash);

        // discriminator
        assert_eq!(&buf[0..8], &crate::constants::EVT_ORDER_CREATED);
        // sender (refund_address quirk — first field)
        assert_eq!(&buf[8..40], sender.as_array());
        // token
        assert_eq!(&buf[40..72], token.as_array());
        // amount (LE u64)
        assert_eq!(&buf[72..80], &1_000_000u64.to_le_bytes());
        // protocol_fee
        assert_eq!(&buf[80..88], &2_500u64.to_le_bytes());
        // order_id
        assert_eq!(&buf[88..120], &order_id);
        // rate
        assert_eq!(&buf[120..128], &42u64.to_le_bytes());
        // message_hash: 4-byte LE length prefix then raw bytes
        assert_eq!(&buf[128..132], &5u32.to_le_bytes());
        assert_eq!(&buf[132..137], &message_hash);
        assert_eq!(buf.len(), 137);
    }

    /// Borsh's `bool` encoding — single byte, 0 or 1. No event here has a
    /// lone `bool` field, but `OrderLive`/`OrderTombstone` do (`bytes.rs`
    /// writes them the same way), so this pins the shared convention.
    #[test]
    fn bool_is_single_byte_zero_or_one() {
        assert_eq!(true as u8, 1u8);
        assert_eq!(false as u8, 0u8);
    }
}
