use pinocchio::address::Address;

use crate::{
    bytes::{read_address, read_tag, read_u64, read_u8, write_address, write_u64, write_u8},
    constants::{LAYOUT_VERSION, TAG_ORDER_LIVE, TAG_ORDER_TOMBSTONE},
    errors::GatewayError,
};

/// Live `Order` — EVM-mirrored fields (§2.1). 204 bytes: `(128 + 204) *
/// 6960 = 2,310,720` lamports, matching the plan's rent table exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderLive {
    pub version: u8,
    pub bump: u8,
    pub is_fulfilled: bool,
    pub is_refunded: bool,
    pub sender: Address,
    pub mint: Address,
    pub sender_fee_recipient: Address,
    pub refund_address: Address,
    pub amount: u64,
    pub sender_fee: u64,
    pub protocol_fee: u64,
    pub current_bps: u64,
}

impl OrderLive {
    pub const LEN: usize = 204;

    const OFF_VERSION: usize = 8;
    const OFF_BUMP: usize = 9;
    const OFF_IS_FULFILLED: usize = 10;
    const OFF_IS_REFUNDED: usize = 11;
    const OFF_SENDER: usize = 12;
    const OFF_MINT: usize = 44;
    const OFF_SENDER_FEE_RECIPIENT: usize = 76;
    const OFF_REFUND_ADDRESS: usize = 108;
    const OFF_AMOUNT: usize = 140;
    const OFF_SENDER_FEE: usize = 148;
    const OFF_PROTOCOL_FEE: usize = 156;
    const OFF_CURRENT_BPS: usize = 164;
    // 172..204 reserved (32 bytes).

    pub fn read_from(data: &[u8]) -> Result<Self, GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        if read_tag(data) != TAG_ORDER_LIVE {
            return Err(GatewayError::InvalidAccountTag);
        }
        let version = read_u8(data, Self::OFF_VERSION);
        if version != LAYOUT_VERSION {
            return Err(GatewayError::InvalidAccountTag);
        }
        Ok(Self {
            version,
            bump: read_u8(data, Self::OFF_BUMP),
            is_fulfilled: read_u8(data, Self::OFF_IS_FULFILLED) != 0,
            is_refunded: read_u8(data, Self::OFF_IS_REFUNDED) != 0,
            sender: read_address(data, Self::OFF_SENDER),
            mint: read_address(data, Self::OFF_MINT),
            sender_fee_recipient: read_address(data, Self::OFF_SENDER_FEE_RECIPIENT),
            refund_address: read_address(data, Self::OFF_REFUND_ADDRESS),
            amount: read_u64(data, Self::OFF_AMOUNT),
            sender_fee: read_u64(data, Self::OFF_SENDER_FEE),
            protocol_fee: read_u64(data, Self::OFF_PROTOCOL_FEE),
            current_bps: read_u64(data, Self::OFF_CURRENT_BPS),
        })
    }

    pub fn write_to(&self, data: &mut [u8]) -> Result<(), GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        data[0..8].copy_from_slice(&TAG_ORDER_LIVE);
        write_u8(data, Self::OFF_VERSION, self.version);
        write_u8(data, Self::OFF_BUMP, self.bump);
        write_u8(data, Self::OFF_IS_FULFILLED, self.is_fulfilled as u8);
        write_u8(data, Self::OFF_IS_REFUNDED, self.is_refunded as u8);
        write_address(data, Self::OFF_SENDER, &self.sender);
        write_address(data, Self::OFF_MINT, &self.mint);
        write_address(data, Self::OFF_SENDER_FEE_RECIPIENT, &self.sender_fee_recipient);
        write_address(data, Self::OFF_REFUND_ADDRESS, &self.refund_address);
        write_u64(data, Self::OFF_AMOUNT, self.amount);
        write_u64(data, Self::OFF_SENDER_FEE, self.sender_fee);
        write_u64(data, Self::OFF_PROTOCOL_FEE, self.protocol_fee);
        write_u64(data, Self::OFF_CURRENT_BPS, self.current_bps);
        Ok(())
    }
}

/// Terminal `Order` state (D8). 16 bytes: `(128 + 16) * 6960 = 1,002,240`
/// lamports. Deliberately carries only the two flags — every other EVM
/// field is recoverable from the `SettleOut`/`SettleIn`/`OrderRefunded`
/// event that caused the terminalization, which has no on-chain reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderTombstone {
    pub version: u8,
    pub bump: u8,
    pub is_fulfilled: bool,
    pub is_refunded: bool,
}

impl OrderTombstone {
    pub const LEN: usize = 16;

    const OFF_VERSION: usize = 8;
    const OFF_BUMP: usize = 9;
    const OFF_IS_FULFILLED: usize = 10;
    const OFF_IS_REFUNDED: usize = 11;
    // 12..16 reserved (4 bytes).

    pub fn read_from(data: &[u8]) -> Result<Self, GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        if read_tag(data) != TAG_ORDER_TOMBSTONE {
            return Err(GatewayError::InvalidAccountTag);
        }
        let version = read_u8(data, Self::OFF_VERSION);
        if version != LAYOUT_VERSION {
            return Err(GatewayError::InvalidAccountTag);
        }
        Ok(Self {
            version,
            bump: read_u8(data, Self::OFF_BUMP),
            is_fulfilled: read_u8(data, Self::OFF_IS_FULFILLED) != 0,
            is_refunded: read_u8(data, Self::OFF_IS_REFUNDED) != 0,
        })
    }

    pub fn write_to(&self, data: &mut [u8]) -> Result<(), GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        data[0..8].copy_from_slice(&TAG_ORDER_TOMBSTONE);
        write_u8(data, Self::OFF_VERSION, self.version);
        write_u8(data, Self::OFF_BUMP, self.bump);
        write_u8(data, Self::OFF_IS_FULFILLED, self.is_fulfilled as u8);
        write_u8(data, Self::OFF_IS_REFUNDED, self.is_refunded as u8);
        Ok(())
    }

    pub fn new(bump: u8, is_fulfilled: bool, is_refunded: bool) -> Self {
        Self {
            version: LAYOUT_VERSION,
            bump,
            is_fulfilled,
            is_refunded,
        }
    }
}

/// R8 mitigation: the *only* sanctioned way to interpret an `Order`
/// account's bytes. Every instruction that reads an existing Order PDA
/// must go through this dispatcher rather than reading `OrderLive`/
/// `OrderTombstone` directly, so a tombstone can never be misread as a
/// live order (which would read 188 bytes past the end of its own data).
pub enum OrderAccount {
    Live(OrderLive),
    Tombstone(OrderTombstone),
}

impl OrderAccount {
    pub fn load(data: &[u8]) -> Result<Self, GatewayError> {
        match data.len() {
            OrderLive::LEN => Ok(Self::Live(OrderLive::read_from(data)?)),
            OrderTombstone::LEN => Ok(Self::Tombstone(OrderTombstone::read_from(data)?)),
            _ => Err(GatewayError::InvalidAccountTag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_live() -> OrderLive {
        OrderLive {
            version: LAYOUT_VERSION,
            bump: 253,
            is_fulfilled: false,
            is_refunded: false,
            sender: Address::new_from_array([1u8; 32]),
            mint: Address::new_from_array([2u8; 32]),
            sender_fee_recipient: Address::new_from_array([3u8; 32]),
            refund_address: Address::new_from_array([4u8; 32]),
            amount: 1_000_000,
            sender_fee: 5_000,
            protocol_fee: 500,
            current_bps: 100_000,
        }
    }

    #[test]
    fn live_round_trip_preserves_all_fields() {
        let order = sample_live();
        let mut buf = [0u8; OrderLive::LEN];
        order.write_to(&mut buf).unwrap();
        let reloaded = OrderLive::read_from(&buf).unwrap();
        assert_eq!(order, reloaded);
    }

    #[test]
    fn tombstone_round_trip_preserves_flags() {
        let tomb = OrderTombstone::new(253, true, false);
        let mut buf = [0u8; OrderTombstone::LEN];
        tomb.write_to(&mut buf).unwrap();
        let reloaded = OrderTombstone::read_from(&buf).unwrap();
        assert_eq!(tomb, reloaded);
    }

    /// R8 — the dispatcher must route by length+tag, never let a
    /// tombstone's 16 bytes be interpreted as a 204-byte live order.
    #[test]
    fn dispatcher_routes_by_length_and_tag() {
        let live = sample_live();
        let mut live_buf = [0u8; OrderLive::LEN];
        live.write_to(&mut live_buf).unwrap();
        match OrderAccount::load(&live_buf).unwrap() {
            OrderAccount::Live(l) => assert_eq!(l, live),
            OrderAccount::Tombstone(_) => panic!("misrouted live order as tombstone"),
        }

        let tomb = OrderTombstone::new(253, true, false);
        let mut tomb_buf = [0u8; OrderTombstone::LEN];
        tomb.write_to(&mut tomb_buf).unwrap();
        match OrderAccount::load(&tomb_buf).unwrap() {
            OrderAccount::Tombstone(t) => assert_eq!(t, tomb),
            OrderAccount::Live(_) => panic!("misrouted tombstone as live order"),
        }
    }

    #[test]
    fn dispatcher_rejects_wrong_tag_for_length() {
        // Right length for a live order, but tombstone tag bytes at the
        // front — must not be silently accepted as either variant.
        let mut buf = [0u8; OrderLive::LEN];
        buf[0..8].copy_from_slice(&TAG_ORDER_TOMBSTONE);
        assert!(OrderAccount::load(&buf).is_err());
    }

    #[test]
    fn dispatcher_rejects_unknown_length() {
        let buf = [0u8; 50];
        assert!(OrderAccount::load(&buf).is_err());
    }

    #[test]
    fn lens_match_planned_rent() {
        assert_eq!(OrderLive::LEN, 204);
        assert_eq!(OrderTombstone::LEN, 16);
        assert_eq!((128 + OrderLive::LEN as u64) * 6960, 2_310_720);
        assert_eq!((128 + OrderTombstone::LEN as u64) * 6960, 1_002_240);
        // Reclaim on terminalization (D8).
        assert_eq!(2_310_720 - 1_002_240, 1_308_480);
    }
}
