use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::*;

#[derive(Accounts)]
pub struct Unpause<'info> {
    /// Protocol owner.
    pub owner: Signer<'info>,

    /// Config — verifies owner, must be paused.
    #[account(
        mut,
        has_one = owner,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = config.paused @ crate::error::GatewayError::ProtocolNotPaused,
    )]
    pub config: Account<'info, Config>,
}

/// Unpauses the protocol.
pub fn handler(ctx: Context<Unpause>) -> Result<()> {
    ctx.accounts.config.paused = false;
    Ok(())
}
