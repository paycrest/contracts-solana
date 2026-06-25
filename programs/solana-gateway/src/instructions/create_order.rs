use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::error::GatewayError;
use crate::events::*;
use crate::state::*;
use crate::utils::transfer_to_vault;

#[derive(Accounts)]
#[event_cpi]

pub struct CreateOrder<'info> {
    #[account(mut)]
    pub sender: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = !config.paused @ GatewayError::ProtocolPaused,
    )]
    pub config: Box<Account<'info, Config>>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        seeds = [TOKEN_CONFIG_SEED, mint.key().as_ref()],
        bump = token_config.bump,
        constraint = token_config.is_supported == 1 @ GatewayError::TokenNotSupported,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = sender,
    )]
    pub sender_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: validated by seeds.
    #[account(
        seeds = [VAULT_AUTHORITY_SEED],
        bump = config.vault_authority_bump,
    )]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = sender,
        space = 8 + SenderState::INIT_SPACE,
        seeds = [SENDER_STATE_SEED, sender.key().as_ref()],
        bump,
    )]
    pub sender_state: Box<Account<'info, SenderState>>,

    /// Order PDA seeded by [ORDER_SEED, sender, nonce_le_bytes].
    /// Client reads sender_state.nonce off-chain, passes nonce+1, derives PDA.
    #[account(
        init,
        payer = sender,
        space = 8 + Order::INIT_SPACE,
        seeds = [ORDER_SEED, sender.key().as_ref(), sender_state.nonce.to_le_bytes().as_ref()],
        bump,
    )]
    pub order: Box<Account<'info, Order>>,

    /// CHECK: stored in order state; validated in handler if sender_fee > 0.
    pub sender_fee_recipient: UncheckedAccount<'info>,

    /// CHECK: stored in order state; validated in handler (non-zero).
    pub refund_address: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

pub fn handler(
    ctx: Context<CreateOrder>,
    amount: u64,
    rate: u64,
    sender_fee: u64,
    message_hash: [u8; 32],
) -> Result<()> {
    let token_config = &ctx.accounts.token_config;
    let refund_address = ctx.accounts.refund_address.key();
    let sender_fee_recipient = ctx.accounts.sender_fee_recipient.key();

    // ─── Step 1: Validations ──────────────────────────────────────────
    require!(amount > 0, GatewayError::AmountIsZero);
    require!(refund_address != Pubkey::default(), GatewayError::ZeroRefundAddress);
    require!(message_hash != [0u8; 32], GatewayError::InvalidMessageHash);
    if sender_fee > 0 {
        require!(sender_fee_recipient != Pubkey::default(), GatewayError::InvalidSenderFeeRecipient);
    }

    // ─── Step 2: Transfer tokens from sender → vault ──────────────────
    let total_transfer = amount.checked_add(sender_fee).ok_or(GatewayError::MathOverflow)?;
    let mint_decimals = ctx.accounts.mint.decimals;

    transfer_to_vault(
        &ctx.accounts.sender_token_account.to_account_info(),
        &ctx.accounts.vault.to_account_info(),
        &ctx.accounts.sender.to_account_info(),
        &ctx.accounts.mint.to_account_info(),
        &ctx.accounts.token_program.key(),
        total_transfer,
        mint_decimals,
    )?;

    // ─── Step 3: Record nonce used for PDA (= sender_state.nonce at time of init) ──
    let sender_state = &mut ctx.accounts.sender_state;
    if sender_state.sender == Pubkey::default() {
        sender_state.sender = ctx.accounts.sender.key();
        sender_state.bump = ctx.bumps.sender_state;
    }
    // PDA was derived with current nonce value; store it before incrementing
    let order_nonce = sender_state.nonce;
    sender_state.nonce = sender_state.nonce.checked_add(1).ok_or(GatewayError::MathOverflow)?;

    // ─── Step 4: Compute order_id (deterministic hash) ────────────────
    // order_id = sha256(sender || nonce_used || program_id)
    let order_id = solana_sha256_hasher::hashv(&[
        ctx.accounts.sender.key().as_ref(),
        &order_nonce.to_le_bytes(),
        ctx.program_id.as_ref(),
    ]).to_bytes();

    // ─── Step 5: Compute protocol fee ─────────────────────────────────
    let is_local = rate == 100;
    let protocol_fee: u64;

    if is_local {
        protocol_fee = 0;
        require!(sender_fee > 0, GatewayError::SenderFeeIsZero);
    } else {
        require!(token_config.provider_to_aggregator_fx > 0, GatewayError::TokenFeeSettingsNotConfigured);
        let fee_128 = (amount as u128)
            .checked_mul(token_config.provider_to_aggregator_fx as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(GatewayError::MathOverflow)?;
        protocol_fee = u64::try_from(fee_128).map_err(|_| GatewayError::MathOverflow)?;
    }

    // ─── Step 6: Populate order state ─────────────────────────────────
    let order = &mut ctx.accounts.order;
    let clock = Clock::get()?;

    order.order_id = order_id;
    order.sender = ctx.accounts.sender.key();
    order.token = ctx.accounts.mint.key();
    order.sender_fee_recipient = sender_fee_recipient;
    order.sender_fee = sender_fee;
    order.distributed_sender_fee = 0;
    order.protocol_fee = protocol_fee;
    order.remaining_protocol_fee = protocol_fee;
    order.status = OrderStatus::Pending;
    order.refund_address = refund_address;
    order.current_bps = MAX_BPS;
    order.initial_amount = amount;
    order.current_amount = amount;
    order.rate = rate;
    order.created_at = clock.unix_timestamp;
    order.is_local = is_local;
    order.nonce = order_nonce;
    order.bump = ctx.bumps.order;

    // ─── Step 7: Emit event ───────────────────────────────────────────
    emit_cpi!(OrderCreated {
        sender: ctx.accounts.sender.key(),
        refund_address,
        token: ctx.accounts.mint.key(),
        amount,
        protocol_fee,
        order_id,
        rate,
        message_hash,
    });

    Ok(())
}
