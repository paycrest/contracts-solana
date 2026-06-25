use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::GatewayError;
use crate::state::*;

#[derive(Accounts)]
pub struct CloseOrder<'info> {
    /// Only the aggregator can close terminal orders and reclaim rent.
    #[account(mut)]
    pub aggregator: Signer<'info>,

    #[account(
        has_one = aggregator,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,

    /// Order must be in a terminal state (Fulfilled or Refunded).
    /// Anchor's `close` directive safely zeroes discriminator and drains lamports.
    #[account(
        mut,
        seeds = [ORDER_SEED, order.sender.as_ref(), order.nonce.to_le_bytes().as_ref()],
        bump = order.bump,
        constraint = order.status == OrderStatus::Fulfilled || order.status == OrderStatus::Refunded @ GatewayError::OrderNotTerminal,
        close = aggregator,
    )]
    pub order: Account<'info, Order>,
}

/// Closes a terminal order account and returns rent lamports to aggregator.
/// Must be called in a separate transaction after settle_out (final) or refund.
pub fn handler(_ctx: Context<CloseOrder>) -> Result<()> {
    // Anchor's `close = aggregator` handles everything:
    // 1. Zeroes discriminator (prevents re-init)
    // 2. Drains all lamports to aggregator
    // 3. Marks account for garbage collection
    Ok(())
}
