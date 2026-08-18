pub mod admin;
pub mod create_order;
pub mod refund;
pub mod settle_in;
pub mod settle_out;

use pinocchio::{AccountView, Address};

use crate::{
    constants::{SEED_CONFIG, SEED_TOKEN_CONFIG, SEED_VAULT_AUTHORITY},
    errors::GatewayError,
    pda::verify_pda,
    state::{Config, TokenConfig},
};

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

/// Loads the canonical Config PDA and verifies its stored bump matches.
pub fn load_config(config_ai: &AccountView, program_id: &Address) -> Result<Config, GatewayError> {
    require_owned_by_program(config_ai, program_id)?;
    let data = config_ai.try_borrow().map_err(|_| GatewayError::InvalidAccountTag)?;
    let config = Config::read_from(&data)?;
    verify_pda(config_ai.address(), &[SEED_CONFIG], config.bump, program_id)?;
    Ok(config)
}

/// Loads the canonical TokenConfig PDA for `mint` and verifies its stored bump.
pub fn load_token_config(
    token_config_ai: &AccountView,
    mint: &Address,
    program_id: &Address,
) -> Result<TokenConfig, GatewayError> {
    require_owned_by_program(token_config_ai, program_id)?;
    let data = token_config_ai
        .try_borrow()
        .map_err(|_| GatewayError::InvalidAccountTag)?;
    let token_config = TokenConfig::read_from(&data)?;
    if !addresses_eq(&token_config.mint, mint) {
        return Err(GatewayError::InvalidMint);
    }
    verify_pda(
        token_config_ai.address(),
        &[SEED_TOKEN_CONFIG, mint.as_array()],
        token_config.bump,
        program_id,
    )?;
    Ok(token_config)
}

/// Derives and verifies the canonical vault-authority PDA for `vault_bump`.
pub fn load_vault_authority(
    vault_authority_ai: &AccountView,
    vault_bump: u8,
    program_id: &Address,
) -> Result<Address, GatewayError> {
    verify_pda(
        vault_authority_ai.address(),
        &[SEED_VAULT_AUTHORITY],
        vault_bump,
        program_id,
    )?;
    crate::pda::create_pda(&[SEED_VAULT_AUTHORITY], vault_bump, program_id)
}
