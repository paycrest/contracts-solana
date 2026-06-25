use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::error::GatewayError;
use crate::events::*;
use crate::state::*;
use crate::utils::transfer_from_vault;

#[derive(Accounts)]
#[event_cpi]
pub struct Refund<'info> {
    #[account(mut)]
    pub aggregator: Signer<'info>,

    #[account(
        has_one = aggregator,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [ORDER_SEED, order.sender.as_ref(), order.nonce.to_le_bytes().as_ref()],
        bump = order.bump,
        constraint = order.token == mint.key() @ GatewayError::MintMismatch,
    )]
    pub order: Box<Account<'info, Order>>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        seeds = [VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// CHECK: validated by seeds.
    #[account(
        seeds = [VAULT_AUTHORITY_SEED],
        bump = config.vault_authority_bump,
    )]
    pub vault_authority: UncheckedAccount<'info>,

    /// Refund destination — must be owned by order.refund_address.
    #[account(
        mut,
        token::mint = mint,
        constraint = refund_token_account.owner == order.refund_address @ GatewayError::InvalidRefundAddress,
    )]
    pub refund_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Treasury — must be owned by config.treasury.
    #[account(
        mut,
        token::mint = mint,
        constraint = treasury_token_account.owner == config.treasury @ GatewayError::InvalidTreasuryAccount,
    )]
    pub treasury_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Interface<'info, TokenInterface>,
}

/// Refunds an order: returns escrowed funds to refund_address minus fee.
/// Aggregator-only. Fee capped at remaining_protocol_fee.
/// Closes order account and returns rent to aggregator.
pub fn handler(ctx: Context<Refund>, fee: u64) -> Result<()> {
    let order = &ctx.accounts.order;
    let mint_decimals = ctx.accounts.mint.decimals;
    let vault_bump = ctx.accounts.config.vault_authority_bump;
    let token_program_key = ctx.accounts.token_program.key();
    let vault_info = ctx.accounts.vault.to_account_info();
    let vault_authority_info = ctx.accounts.vault_authority.to_account_info();
    let mint_info = ctx.accounts.mint.to_account_info();

    // ─── Step 1: Status checks ────────────────────────────────────────
    require!(order.status != OrderStatus::Fulfilled, GatewayError::OrderFulfilled);
    require!(order.status != OrderStatus::Refunded, GatewayError::OrderRefunded);
    require!(fee <= order.remaining_protocol_fee, GatewayError::FeeExceedsProtocolFee);

    // ─── Step 2: Transfer fee → treasury ──────────────────────────────
    transfer_from_vault(
        &vault_info, &ctx.accounts.treasury_token_account.to_account_info(),
        &vault_authority_info, &mint_info, &token_program_key,
        vault_bump, fee, mint_decimals,
    )?;

    // ─── Step 3: Transfer (current_amount - fee + remaining_sender_fee) → refund_address ─
    let remaining_sender_fee = order.sender_fee
        .checked_sub(order.distributed_sender_fee)
        .ok_or(GatewayError::MathOverflow)?;

    let refund_amount = order.current_amount
        .checked_sub(fee)
        .ok_or(GatewayError::MathOverflow)?
        .checked_add(remaining_sender_fee)
        .ok_or(GatewayError::MathOverflow)?;

    transfer_from_vault(
        &vault_info, &ctx.accounts.refund_token_account.to_account_info(),
        &vault_authority_info, &mint_info, &token_program_key,
        vault_bump, refund_amount, mint_decimals,
    )?;

    // ─── Step 4: Update order state ───────────────────────────────────
    let order = &mut ctx.accounts.order;
    order.status = OrderStatus::Refunded;
    order.current_bps = 0;
    order.current_amount = 0;
    order.remaining_protocol_fee = 0;

    // ─── Step 5: Emit event ───────────────────────────────────────────
    emit_cpi!(OrderRefunded {
        fee,
        order_id: order.order_id,
    });

    Ok(())
}
