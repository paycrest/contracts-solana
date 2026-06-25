use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::error::GatewayError;
use crate::state::*;

#[derive(Accounts)]
pub struct SetTokenSupport<'info> {
    /// Protocol owner (admin).
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Config — verifies owner via has_one.
    #[account(
        has_one = owner,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,

    /// The SPL token mint to support/unsupport.
    pub mint: InterfaceAccount<'info, Mint>,

    /// Per-token config PDA — created on first call, updated on subsequent calls.
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + TokenConfig::INIT_SPACE,
        seeds = [TOKEN_CONFIG_SEED, mint.key().as_ref()],
        bump,
    )]
    pub token_config: Account<'info, TokenConfig>,

    /// Vault token account for this mint — created on first support.
    /// Authority = vault_authority PDA (pure PDA, no data account).
    #[account(
        init_if_needed,
        payer = owner,
        seeds = [VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    /// Vault authority PDA — pure PDA, only used as token authority.
    /// CHECK: validated by seeds constraint.
    #[account(
        seeds = [VAULT_AUTHORITY_SEED],
        bump = config.vault_authority_bump,
    )]
    pub vault_authority: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Sets or updates token support status (1 = supported, 2 = unsupported).
/// H-01 fix: Only classic SPL Token mints are allowed (no Token-2022 with transfer-fee).
pub fn handler(ctx: Context<SetTokenSupport>, status: u8) -> Result<()> {
    require!(status == 1 || status == 2, GatewayError::InvalidTokenStatus);

    // Reject Token-2022 mints to prevent fee-on-transfer accounting issues.
    // Classic SPL Token program ID = TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    if status == 1 {
        require!(
            ctx.accounts.mint.to_account_info().owner == &anchor_spl::token::ID,
            GatewayError::Token2022NotSupported
        );
    }

    let token_config = &mut ctx.accounts.token_config;
    token_config.mint = ctx.accounts.mint.key();
    token_config.is_supported = status;
    token_config.bump = ctx.bumps.token_config;

    Ok(())
}
