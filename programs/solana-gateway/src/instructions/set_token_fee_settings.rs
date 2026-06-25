use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::GatewayError;
use crate::state::*;

#[derive(Accounts)]
pub struct SetTokenFeeSettings<'info> {
    /// Protocol owner (admin).
    pub owner: Signer<'info>,

    /// Config — verifies owner.
    #[account(
        has_one = owner,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,

    /// The mint this config is for.
    /// CHECK: used only as seed reference.
    pub mint: UncheckedAccount<'info>,

    /// Per-token config to update.
    #[account(
        mut,
        seeds = [TOKEN_CONFIG_SEED, mint.key().as_ref()],
        bump = token_config.bump,
    )]
    pub token_config: Account<'info, TokenConfig>,
}

/// Updates fee settings for a supported token.
pub fn handler(
    ctx: Context<SetTokenFeeSettings>,
    sender_to_provider: u64,
    provider_to_aggregator: u64,
    sender_to_aggregator: u64,
    provider_to_aggregator_fx: u64,
) -> Result<()> {
    let token_config = &ctx.accounts.token_config;
    require!(token_config.is_supported == 1, GatewayError::TokenNotSupported);
    require!(sender_to_provider <= MAX_BPS, GatewayError::FeeExceedsMaxBps);
    require!(provider_to_aggregator <= MAX_BPS, GatewayError::FeeExceedsMaxBps);
    require!(sender_to_aggregator <= MAX_BPS, GatewayError::FeeExceedsMaxBps);
    require!(provider_to_aggregator_fx <= MAX_BPS, GatewayError::FeeExceedsMaxBps);

    let token_config = &mut ctx.accounts.token_config;
    token_config.sender_to_provider = sender_to_provider;
    token_config.provider_to_aggregator = provider_to_aggregator;
    token_config.sender_to_aggregator = sender_to_aggregator;
    token_config.provider_to_aggregator_fx = provider_to_aggregator_fx;

    Ok(())
}
