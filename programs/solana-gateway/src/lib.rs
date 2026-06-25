pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;
pub mod utils;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("BB1wme2YXxKDoiqWNn4P4Nxu5fiF4xfTccTZJTCEG1q4");

#[program]
pub mod solana_gateway {
    use super::*;

    // ─── Admin Instructions ───────────────────────────────────────────

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize::handler(ctx)
    }

    pub fn set_token_support(ctx: Context<SetTokenSupport>, status: u8) -> Result<()> {
        instructions::set_token_support::handler(ctx, status)
    }

    pub fn set_token_fee_settings(
        ctx: Context<SetTokenFeeSettings>,
        sender_to_provider: u64,
        provider_to_aggregator: u64,
        sender_to_aggregator: u64,
        provider_to_aggregator_fx: u64,
    ) -> Result<()> {
        instructions::set_token_fee_settings::handler(
            ctx, sender_to_provider, provider_to_aggregator,
            sender_to_aggregator, provider_to_aggregator_fx,
        )
    }

    pub fn update_protocol_address(
        ctx: Context<UpdateProtocolAddress>,
        address_type: ProtocolAddressType,
        new_address: Pubkey,
    ) -> Result<()> {
        instructions::update_protocol_address::handler(ctx, address_type, new_address)
    }

    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        instructions::pause::handler(ctx)
    }

    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        instructions::unpause::handler(ctx)
    }

    // ─── Core Instructions ────────────────────────────────────────────

    /// Create a payment order. order_id is computed inside (hash of sender+nonce+program).
    /// PDA = [ORDER_SEED, sender, nonce_le]. Client reads sender_state.nonce to derive PDA.
    pub fn create_order(
        ctx: Context<CreateOrder>,
        
        amount: u64,
        rate: u64,
        sender_fee: u64,
        message_hash: [u8; 32],
    ) -> Result<()> {
        instructions::create_order::handler(ctx, amount, rate, sender_fee, message_hash)
    }

    /// Settle an order (partial/full) to a liquidity provider. Aggregator-only.
    pub fn settle_out(
        ctx: Context<SettleOut>,
        split_order_id: [u8; 32],
        settle_percent: u64,
        rebate_percent: u64,
    ) -> Result<()> {
        instructions::settle_out::handler(ctx, split_order_id, settle_percent, rebate_percent)
    }

    /// Process settle-in (on-ramp). Open to any caller. Event-only (no persistent order state).
    pub fn settle_in(
        ctx: Context<SettleIn>,
        order_id: [u8; 32],
        amount: u64,
        sender_fee: u64,
        rate: u64,
        recipient_owner: Pubkey,
        fee_recipient_owner: Pubkey,
    ) -> Result<()> {
        instructions::settle_in::handler(ctx, order_id, amount, sender_fee, rate, recipient_owner, fee_recipient_owner)
    }

    /// Refund an order. Aggregator-only. Fee capped at remaining_protocol_fee.
    pub fn refund(ctx: Context<Refund>, fee: u64) -> Result<()> {
        instructions::refund::handler(ctx, fee)
    }

    /// Close a terminal order account (Fulfilled/Refunded) and reclaim rent.
    /// Must be called in a separate transaction after the terminal state is reached.
    pub fn close_order(ctx: Context<CloseOrder>) -> Result<()> {
        instructions::close_order::handler(ctx)
    }
}
