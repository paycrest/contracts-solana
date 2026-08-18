use pinocchio::address::Address;

use crate::{
    bytes::{read_address, read_tag, read_u64, read_u8, write_address, write_u64, write_u8},
    constants::{LAYOUT_VERSION, MAX_BPS, TAG_TOKEN_CONFIG},
    errors::GatewayError,
};

/// `TokenConfig` PDA — seeds `["token", mint]`. Mirrors
/// `GatewaySettingManager.sol`'s `TokenFeeSettings` (with the two
/// deprecated `senderToProvider`/`providerToAggregator` fields dropped —
/// nothing writes or reads them even on EVM).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenConfig {
    pub version: u8,
    pub bump: u8,
    pub is_supported: bool,
    pub mint: Address,
    pub sender_to_treasury: u64,
    pub provider_to_treasury: u64,
}

impl TokenConfig {
    pub const LEN: usize = 91;

    const OFF_VERSION: usize = 8;
    const OFF_BUMP: usize = 9;
    const OFF_IS_SUPPORTED: usize = 10;
    const OFF_MINT: usize = 11;
    const OFF_SENDER_TO_TREASURY: usize = 43;
    const OFF_PROVIDER_TO_TREASURY: usize = 51;
    // 59..91 reserved (32 bytes).

    pub fn read_from(data: &[u8]) -> Result<Self, GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        if read_tag(data) != TAG_TOKEN_CONFIG {
            return Err(GatewayError::InvalidAccountTag);
        }
        let version = read_u8(data, Self::OFF_VERSION);
        if version != LAYOUT_VERSION {
            return Err(GatewayError::InvalidAccountTag);
        }
        Ok(Self {
            version,
            bump: read_u8(data, Self::OFF_BUMP),
            is_supported: read_u8(data, Self::OFF_IS_SUPPORTED) != 0,
            mint: read_address(data, Self::OFF_MINT),
            sender_to_treasury: read_u64(data, Self::OFF_SENDER_TO_TREASURY),
            provider_to_treasury: read_u64(data, Self::OFF_PROVIDER_TO_TREASURY),
        })
    }

    pub fn write_to(&self, data: &mut [u8]) -> Result<(), GatewayError> {
        if data.len() != Self::LEN {
            return Err(GatewayError::InvalidAccountTag);
        }
        data[0..8].copy_from_slice(&TAG_TOKEN_CONFIG);
        write_u8(data, Self::OFF_VERSION, self.version);
        write_u8(data, Self::OFF_BUMP, self.bump);
        write_u8(data, Self::OFF_IS_SUPPORTED, self.is_supported as u8);
        write_address(data, Self::OFF_MINT, &self.mint);
        write_u64(data, Self::OFF_SENDER_TO_TREASURY, self.sender_to_treasury);
        write_u64(
            data,
            Self::OFF_PROVIDER_TO_TREASURY,
            self.provider_to_treasury,
        );
        Ok(())
    }

    pub fn new(bump: u8, mint: Address) -> Self {
        Self {
            version: LAYOUT_VERSION,
            bump,
            is_supported: true,
            mint,
            sender_to_treasury: 0,
            provider_to_treasury: 0,
        }
    }

    /// `setTokenFeeSettings`'s bounds check: both BPS values `<= MAX_BPS`.
    pub fn validate_bps(sender_to_treasury: u64, provider_to_treasury: u64) -> Result<(), GatewayError> {
        if sender_to_treasury > MAX_BPS || provider_to_treasury > MAX_BPS {
            return Err(GatewayError::InvalidStatus);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_all_fields() {
        let mut tc = TokenConfig::new(254, Address::new_from_array([9u8; 32]));
        tc.sender_to_treasury = 1_234;
        tc.provider_to_treasury = 5_678;

        let mut buf = [0u8; TokenConfig::LEN];
        tc.write_to(&mut buf).unwrap();
        let reloaded = TokenConfig::read_from(&buf).unwrap();
        assert_eq!(tc, reloaded);
    }

    #[test]
    fn validate_bps_rejects_over_max() {
        assert!(TokenConfig::validate_bps(MAX_BPS + 1, 0).is_err());
        assert!(TokenConfig::validate_bps(0, MAX_BPS + 1).is_err());
        assert!(TokenConfig::validate_bps(MAX_BPS, MAX_BPS).is_ok());
    }

    #[test]
    fn len_matches_plan() {
        assert_eq!(TokenConfig::LEN, 91);
    }
}
