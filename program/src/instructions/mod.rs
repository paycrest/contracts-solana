pub mod admin;
pub mod create_order;
pub mod refund;
pub mod settle_in;
pub mod settle_out;

use pinocchio::{AccountView, Address};

use crate::errors::GatewayError;

/// Every instruction pulls its `Config` account and re-checks the caller
/// against `Config.owner`/`Config.aggregator` — there is no Anchor
/// `#[account(has_one = ...)]` to do this declaratively (D1/R5).
#[inline(always)]
pub fn require_signer(account: &AccountView) -> Result<(), GatewayError> {
    if !account.is_signer() {
        return Err(GatewayError::MissingSignature);
    }
    Ok(())
}

#[inline(always)]
pub fn require_owned_by_program(account: &AccountView, program_id: &Address) -> Result<(), GatewayError> {
    if !account.owned_by(program_id) {
        return Err(GatewayError::InvalidOwner);
    }
    Ok(())
}

#[inline(always)]
pub fn addresses_eq(a: &Address, b: &Address) -> bool {
    a.as_array() == b.as_array()
}

#[inline(always)]
pub fn is_zero_address(a: &Address) -> bool {
    a.as_array() == &[0u8; 32]
}
