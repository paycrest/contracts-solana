//! D14 — bit-exact parity with Gateway.sol's fee arithmetic.
//!
//! Solidity's `(a * b) / denom` on `uint256` becomes `u128` intermediates
//! here: `amount` and every BPS value are `u64`-narrowed (D-series decision
//! to drop `uint256`), so `a * b` can reach ~2^128 in the worst case and
//! must not be computed in `u64`. The result of a BPS division is always
//! `<= a` (since `denom >= b`... no — `denom` is `MAX_BPS` and `b <=
//! MAX_BPS` by construction, so `a*b/denom <= a`), so narrowing the
//! quotient back to `u64` is always safe once the `u128` division has run.

use crate::errors::GatewayError;

/// `(a * b) / denom`, truncating — the exact shape of every fee
/// computation in `Gateway.sol` and `GatewaySettingManager.sol`.
#[inline(always)]
pub fn mul_div_floor(a: u64, b: u64, denom: u64) -> Result<u64, GatewayError> {
    if denom == 0 {
        return Err(GatewayError::MathOverflow);
    }
    let product = (a as u128)
        .checked_mul(b as u128)
        .ok_or(GatewayError::MathOverflow)?;
    let quotient = product / (denom as u128);
    u64::try_from(quotient).map_err(|_| GatewayError::MathOverflow)
}

#[inline(always)]
pub fn checked_add(a: u64, b: u64) -> Result<u64, GatewayError> {
    a.checked_add(b).ok_or(GatewayError::MathOverflow)
}

#[inline(always)]
pub fn checked_sub(a: u64, b: u64) -> Result<u64, GatewayError> {
    a.checked_sub(b).ok_or(GatewayError::MathOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// createOrder's `protocolFee = (amount * providerToTreasury) / MAX_BPS`.
    #[test]
    fn mul_div_matches_solidity_truncation() {
        // 1_000_000 * 250 / 100_000 = 2500 exactly.
        assert_eq!(mul_div_floor(1_000_000, 250, 100_000).unwrap(), 2_500);
        // Truncating division: 999_999 * 1 / 100_000 = 9 (floor of 9.99999).
        assert_eq!(mul_div_floor(999_999, 1, 100_000).unwrap(), 9);
        // Zero bps -> zero fee, no division-by-zero.
        assert_eq!(mul_div_floor(1_000_000, 0, 100_000).unwrap(), 0);
    }

    #[test]
    fn mul_div_handles_u64_max_without_overflow() {
        // a * b would overflow u64 (and even u128 checked_mul guards it),
        // but u64::MAX * MAX_BPS fits in u128 comfortably.
        let result = mul_div_floor(u64::MAX, 100_000, 100_000).unwrap();
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn mul_div_rejects_zero_denominator() {
        assert_eq!(
            mul_div_floor(100, 1, 0).unwrap_err(),
            GatewayError::MathOverflow
        );
    }

    #[test]
    fn checked_add_sub_reject_overflow_underflow() {
        assert!(checked_add(u64::MAX, 1).is_err());
        assert!(checked_sub(0, 1).is_err());
        assert_eq!(checked_add(2, 3).unwrap(), 5);
        assert_eq!(checked_sub(5, 3).unwrap(), 2);
    }

    /// Differential vector mirroring `settleOut`'s treasury/rebate split in
    /// `Gateway.sol`: treasuryFee computed from `liquidityProviderAmount`,
    /// then a rebate carve-out taken from that same treasuryFee and added
    /// back to the LP amount.
    #[test]
    fn settle_out_treasury_rebate_split_vector() {
        let order_amount: u64 = 1_000_000;
        let settle_percent: u64 = 100_000; // full settle, 100%
        let current_bps: u64 = 100_000;
        let provider_to_treasury: u64 = 500; // 0.5%
        let rebate_percent: u64 = 20_000; // 20%

        let mut signer_amount = mul_div_floor(order_amount, settle_percent, current_bps).unwrap();
        assert_eq!(signer_amount, 1_000_000);

        let mut treasury_fee = mul_div_floor(signer_amount, provider_to_treasury, 100_000).unwrap();
        assert_eq!(treasury_fee, 5_000);
        signer_amount = checked_sub(signer_amount, treasury_fee).unwrap();

        let rebate_amount = mul_div_floor(treasury_fee, rebate_percent, 100_000).unwrap();
        assert_eq!(rebate_amount, 1_000);
        treasury_fee = checked_sub(treasury_fee, rebate_amount).unwrap();
        signer_amount = checked_add(signer_amount, rebate_amount).unwrap();

        assert_eq!(treasury_fee, 4_000);
        assert_eq!(signer_amount, 996_000);
        assert_eq!(signer_amount + treasury_fee, order_amount);
    }
}
