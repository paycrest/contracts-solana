use pinocchio::address::Address;

use crate::{
    bytes::{read_address, read_tag, read_u64, read_u8, write_address, write_u64, write_u8},
    constants::{LAYOUT_VERSION, TAG_CONFIG},
    errors::GatewayError,
};

/// `Config` PDA — seeds `["config"]`. §2.1 of the plan.
///
/// `chain_id` is write-once: set at `initialize`, never touched by any
/// other instruction (D3). It sits inside the payout order-id keccak
/// preimage, so mutating it post-launch would invalidate every
/// already-computed client-side id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub version: u8,
    pub bump: u8,
    pub paused: bool,
    pub owner: Address,
    pub pending_owner: Address,
    pub aggregator: Address,
    pub treasury: Address,
    pub chain_id: u64,
    pub max_bps: u64,
    pub max_order_amount: u64,
    pub global_escrow_cap: u64,
}

impl Config {
    pub const LEN: usize = 235;

    const OFF_VERSION: usize = 8;
    const OFF_BUMP: usize = 9;
    const OFF_PAUSED: usize = 10;
    const OFF_OWNER: usize = 11;
    const OFF_PENDING_OWNER: usize = 43;
    const OFF_AGGREGATOR: usize = 75;
    const OFF_TREASURY: usize = 107;
    const OFF_CHAIN_ID: usize = 139;
    const OFF_MAX_BPS: usize = 147;
    const OFF_MAX_ORDER_AMOUNT: usize = 155;
    const OFF_GLOBAL_ESCROW_CAP: usize = 163;
    // 171..235 reserved (64 bytes).

    pub fn read_from(data: &[u8]) -> Result<Self, GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        if read_tag(data) != TAG_CONFIG {
            return Err(GatewayError::InvalidAccountTag);
        }
        Ok(Self {
            version: read_u8(data, Self::OFF_VERSION),
            bump: read_u8(data, Self::OFF_BUMP),
            paused: read_u8(data, Self::OFF_PAUSED) != 0,
            owner: read_address(data, Self::OFF_OWNER),
            pending_owner: read_address(data, Self::OFF_PENDING_OWNER),
            aggregator: read_address(data, Self::OFF_AGGREGATOR),
            treasury: read_address(data, Self::OFF_TREASURY),
            chain_id: read_u64(data, Self::OFF_CHAIN_ID),
            max_bps: read_u64(data, Self::OFF_MAX_BPS),
            max_order_amount: read_u64(data, Self::OFF_MAX_ORDER_AMOUNT),
            global_escrow_cap: read_u64(data, Self::OFF_GLOBAL_ESCROW_CAP),
        })
    }

    pub fn write_to(&self, data: &mut [u8]) -> Result<(), GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        data[0..8].copy_from_slice(&TAG_CONFIG);
        write_u8(data, Self::OFF_VERSION, self.version);
        write_u8(data, Self::OFF_BUMP, self.bump);
        write_u8(data, Self::OFF_PAUSED, self.paused as u8);
        write_address(data, Self::OFF_OWNER, &self.owner);
        write_address(data, Self::OFF_PENDING_OWNER, &self.pending_owner);
        write_address(data, Self::OFF_AGGREGATOR, &self.aggregator);
        write_address(data, Self::OFF_TREASURY, &self.treasury);
        write_u64(data, Self::OFF_CHAIN_ID, self.chain_id);
        write_u64(data, Self::OFF_MAX_BPS, self.max_bps);
        write_u64(data, Self::OFF_MAX_ORDER_AMOUNT, self.max_order_amount);
        write_u64(data, Self::OFF_GLOBAL_ESCROW_CAP, self.global_escrow_cap);
        // reserved[64] left zeroed by the caller's fresh allocation.
        Ok(())
    }

    pub fn new_initial(
        bump: u8,
        owner: Address,
        aggregator: Address,
        treasury: Address,
        chain_id: u64,
    ) -> Self {
        Self {
            version: LAYOUT_VERSION,
            bump,
            paused: false,
            owner,
            pending_owner: Address::new_from_array([0u8; 32]),
            aggregator,
            treasury,
            chain_id,
            max_bps: crate::constants::MAX_BPS,
            max_order_amount: 0,
            global_escrow_cap: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_all_fields() {
        let cfg = Config::new_initial(
            255,
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
            Address::new_from_array([3u8; 32]),
            900_001,
        );
        let mut buf = [0u8; Config::LEN];
        cfg.write_to(&mut buf).unwrap();
        let reloaded = Config::read_from(&buf).unwrap();
        assert_eq!(cfg, reloaded);
    }

    #[test]
    fn rejects_wrong_tag() {
        let buf = [0u8; Config::LEN];
        assert_eq!(
            Config::read_from(&buf).unwrap_err(),
            GatewayError::InvalidAccountTag
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let buf = [0u8; Config::LEN - 1];
        assert_eq!(
            Config::read_from(&buf).unwrap_err(),
            GatewayError::InvalidAccountTag
        );
    }

    /// (128 + 235) * 6960 — see D8/§2.1 of the plan for the rent formula
    /// this must match.
    #[test]
    fn len_matches_planned_rent() {
        assert_eq!(Config::LEN, 235);
        let rent = (128 + Config::LEN as u64) * 6960;
        assert_eq!(rent, 2_526_480);
    }
}
