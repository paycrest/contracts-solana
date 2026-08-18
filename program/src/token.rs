//! D9 — thin wrapper around `pinocchio_token::state::Account`.
//!
//! `Account::from_account_view` already rejects any account not owned by
//! the legacy SPL Token program (`pinocchio_token::ID`), which is the
//! hard-pin itself: a Token-2022 account has a different owner and is
//! rejected here before any of our own logic runs.

use pinocchio::{error::ProgramError, AccountView, Address};
use pinocchio_token::state::Account as SplTokenAccount;

use crate::errors::GatewayError;

pub struct TokenAccountInfo {
    pub mint: Address,
    pub owner: Address,
    pub amount: u64,
}

pub fn read_token_account(account: &AccountView) -> Result<TokenAccountInfo, GatewayError> {
    let data = SplTokenAccount::from_account_view(account)
        .map_err(|_: ProgramError| GatewayError::InvalidTokenAccountOwner)?;
    Ok(TokenAccountInfo {
        mint: *data.mint(),
        owner: *data.owner(),
        amount: data.amount(),
    })
}

/// D10 — `create_order` refuses to escrow funds unless `refund_address`
/// already has an initialized token account for `mint`. This is the check
/// alone; it does not create anything (no in-program ATA creation, per D10).
pub fn assert_existing_token_account_for(
    account: &AccountView,
    expected_mint: &Address,
    expected_owner: &Address,
) -> Result<(), GatewayError> {
    let info = read_token_account(account)?;
    if info.mint.as_array() != expected_mint.as_array() {
        return Err(GatewayError::InvalidMint);
    }
    if info.owner.as_array() != expected_owner.as_array() {
        return Err(GatewayError::InvalidTokenAccountOwner);
    }
    Ok(())
}
