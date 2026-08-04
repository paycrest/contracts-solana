//! Fixed-offset byte packing for on-chain account state.
//!
//! No borsh/serde: every field here is a primitive (`u8`, `u64`, 32-byte
//! address) whose little-endian byte layout is identical to what Borsh
//! would produce, so this is byte-compatible with the event encoding in
//! `events.rs` without adding a serialization dependency (D1 — Pinocchio's
//! zero-dependency premise extends to account state, not just CPI).

use pinocchio::address::Address;

#[inline(always)]
pub fn read_u8(data: &[u8], offset: usize) -> u8 {
    data[offset]
}

#[inline(always)]
pub fn write_u8(data: &mut [u8], offset: usize, value: u8) {
    data[offset] = value;
}

#[inline(always)]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

#[inline(always)]
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[inline(always)]
pub fn read_address(data: &[u8], offset: usize) -> Address {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[offset..offset + 32]);
    Address::new_from_array(buf)
}

#[inline(always)]
pub fn write_address(data: &mut [u8], offset: usize, value: &Address) {
    data[offset..offset + 32].copy_from_slice(value.as_array());
}

#[inline(always)]
pub fn read_tag(data: &[u8]) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[0..8]);
    buf
}
