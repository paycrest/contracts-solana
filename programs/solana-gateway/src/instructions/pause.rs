use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::*;

#[derive(Accounts)]
pub struct Pause<'info> {
    /// Protocol owner.
    pub owner: Signer<'info>,

    /// Config — verifies owner, must not already be paused.
    #[account(
        mut,
        has_one = owner,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = !config.paused @ crate::error::GatewayError::ProtocolPaused,
    )]
    pub config: Account<'info, Config>,
}

/// Pauses the protocol — blocks create_order and settle_in.
pub fn handler(ctx: Context<Pause>) -> Result<()> {
    ctx.accounts.config.paused = true;
    Ok(())
}
