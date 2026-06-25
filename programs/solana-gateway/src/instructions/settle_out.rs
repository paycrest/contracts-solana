use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::error::GatewayError;
use crate::events::*;
use crate::state::*;
use crate::utils::transfer_from_vault;

#[derive(Accounts)]
#[event_cpi]
#[instruction(split_order_id: [u8; 32])]
pub struct SettleOut<'info> {
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
        seeds = [TOKEN_CONFIG_SEED, mint.key().as_ref()],
        bump = token_config.bump,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

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

    #[account(mut, token::mint = mint)]
    pub liquidity_provider_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = mint,
        constraint = treasury_token_account.owner == config.treasury @ GatewayError::InvalidTreasuryAccount,
    )]
    pub treasury_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = mint,
        constraint = sender_fee_recipient_token_account.owner == order.sender_fee_recipient @ GatewayError::InvalidSenderFeeRecipient,
    )]
    pub sender_fee_recipient_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Interface<'info, TokenInterface>,
}

pub fn handler(
    ctx: Context<SettleOut>,
    split_order_id: [u8; 32],
    settle_percent: u64,
    rebate_percent: u64,
) -> Result<()> {
    let order = &ctx.accounts.order;
    let token_config = &ctx.accounts.token_config;
    let mint_decimals = ctx.accounts.mint.decimals;
    let vault_bump = ctx.accounts.config.vault_authority_bump;
    let token_program_key = ctx.accounts.token_program.key();
    let vault_info = ctx.accounts.vault.to_account_info();
    let vault_authority_info = ctx.accounts.vault_authority.to_account_info();
    let mint_info = ctx.accounts.mint.to_account_info();

    // ─── Step 1: Status checks ────────────────────────────────────────
    require!(order.status == OrderStatus::Pending, GatewayError::OrderFulfilled);
    require!(rebate_percent <= MAX_BPS, GatewayError::InvalidRebatePercent);

    let current_bps = order.current_bps;
    require!(
        settle_percent > 0 && settle_percent <= current_bps,
        GatewayError::InvalidSettlePercent
    );

    // ─── Step 2: Compute new BPS ──────────────────────────────────────
    let new_bps = current_bps.checked_sub(settle_percent).ok_or(GatewayError::MathOverflow)?;

    // ─── Step 3: Compute base settle amount ───────────────────────────
    let lp_amount_128 = (order.current_amount as u128)
        .checked_mul(settle_percent as u128)
        .ok_or(GatewayError::MathOverflow)?
        .checked_div(current_bps as u128)
        .ok_or(GatewayError::MathOverflow)?;
    let base_settle_amount = u64::try_from(lp_amount_128).map_err(|_| GatewayError::MathOverflow)?;
    let mut lp_amount = base_settle_amount;

    let is_final = new_bps == 0;
    let is_local = order.is_local;

    // ─── Step 4: Final FX sender fee split ────────────────────────────
    if is_final && !is_local && order.sender_fee > 0 {
        let agg_share_128 = (order.sender_fee as u128)
            .checked_mul(token_config.sender_to_aggregator as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(GatewayError::MathOverflow)?;
        let agg_share = u64::try_from(agg_share_128).map_err(|_| GatewayError::MathOverflow)?;
        let sender_share = order.sender_fee.checked_sub(agg_share).ok_or(GatewayError::MathOverflow)?;

        transfer_from_vault(
            &vault_info, &ctx.accounts.sender_fee_recipient_token_account.to_account_info(),
            &vault_authority_info, &mint_info, &token_program_key,
            vault_bump, sender_share, mint_decimals,
        )?;
        transfer_from_vault(
            &vault_info, &ctx.accounts.treasury_token_account.to_account_info(),
            &vault_authority_info, &mint_info, &token_program_key,
            vault_bump, agg_share, mint_decimals,
        )?;

        emit_cpi!(FxTransferFeeSplit {
            order_id: order.order_id,
            sender_amount: sender_share,
            aggregator_amount: agg_share,
        });
        emit_cpi!(SenderFeeTransferred {
            order_id: order.order_id,
            recipient: order.sender_fee_recipient,
            amount: sender_share, // Fix #6: actual amount received, not total fee
        });
    }

    // ─── Step 5: Local sender fee split (per settle) ──────────────────
    if is_local && order.sender_fee > 0 {
        let provider_amount_128 = (order.sender_fee as u128)
            .checked_mul(token_config.sender_to_provider as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(GatewayError::MathOverflow)?;
        let provider_amount = u64::try_from(provider_amount_128).map_err(|_| GatewayError::MathOverflow)?;

        let current_provider_128 = (provider_amount as u128)
            .checked_mul(settle_percent as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(GatewayError::MathOverflow)?;
        let current_provider = u64::try_from(current_provider_128).map_err(|_| GatewayError::MathOverflow)?;

        let agg_amount_128 = (current_provider as u128)
            .checked_mul(token_config.provider_to_aggregator as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(GatewayError::MathOverflow)?;
        let agg_amount = u64::try_from(agg_amount_128).map_err(|_| GatewayError::MathOverflow)?;

        let net_provider = current_provider.checked_sub(agg_amount).ok_or(GatewayError::MathOverflow)?;
        let sender_recipient_amount = order.sender_fee.checked_sub(provider_amount).ok_or(GatewayError::MathOverflow)?;

        if is_final && sender_recipient_amount > 0 {
            transfer_from_vault(
                &vault_info, &ctx.accounts.sender_fee_recipient_token_account.to_account_info(),
                &vault_authority_info, &mint_info, &token_program_key,
                vault_bump, sender_recipient_amount, mint_decimals,
            )?;
        }
        transfer_from_vault(
            &vault_info, &ctx.accounts.treasury_token_account.to_account_info(),
            &vault_authority_info, &mint_info, &token_program_key,
            vault_bump, agg_amount, mint_decimals,
        )?;
        transfer_from_vault(
            &vault_info, &ctx.accounts.liquidity_provider_token_account.to_account_info(),
            &vault_authority_info, &mint_info, &token_program_key,
            vault_bump, net_provider, mint_decimals,
        )?;

        emit_cpi!(LocalTransferFeeSplit {
            order_id: order.order_id,
            sender_amount: sender_recipient_amount,
            provider_amount: net_provider,
            aggregator_amount: agg_amount,
        });
        emit_cpi!(SenderFeeTransferred {
            order_id: order.order_id,
            recipient: order.sender_fee_recipient,
            amount: sender_recipient_amount, // Fix #6: actual amount, not total
        });
    }

    // ─── Step 6: FX aggregator fee (Cairo stored-fee drawdown) ────────
    let mut aggregator_fee: u64;

    if !is_local {
        // Fix #1: Use remaining_protocol_fee for proportional drawdown
        // INVARIANT: remaining_protocol_fee ≤ current_amount always holds.
        // Proof: At creation, protocol_fee = floor(amount * fx / MAX_BPS) ≤ amount.
        // Each settle applies the same proportional function f(x) = x - floor(x*s/c)
        // with s ≤ c, which is monotonic on integers. Therefore:
        // floor(rpf * s / c) ≤ floor(ca * s / c), i.e. aggregator_fee ≤ base_settle_amount.
        let fee_128 = (order.remaining_protocol_fee as u128)
            .checked_mul(settle_percent as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(current_bps as u128)
            .ok_or(GatewayError::MathOverflow)?;
        aggregator_fee = u64::try_from(fee_128).map_err(|_| GatewayError::MathOverflow)?;
        lp_amount = lp_amount.checked_sub(aggregator_fee).ok_or(GatewayError::MathOverflow)?;

        // Rebate
        if rebate_percent > 0 {
            let rebate_128 = (aggregator_fee as u128)
                .checked_mul(rebate_percent as u128)
                .ok_or(GatewayError::MathOverflow)?
                .checked_div(MAX_BPS as u128)
                .ok_or(GatewayError::MathOverflow)?;
            let rebate_amount = u64::try_from(rebate_128).map_err(|_| GatewayError::MathOverflow)?;
            aggregator_fee = aggregator_fee.checked_sub(rebate_amount).ok_or(GatewayError::MathOverflow)?;
            lp_amount = lp_amount.checked_add(rebate_amount).ok_or(GatewayError::MathOverflow)?;
        }

        transfer_from_vault(
            &vault_info, &ctx.accounts.treasury_token_account.to_account_info(),
            &vault_authority_info, &mint_info, &token_program_key,
            vault_bump, aggregator_fee, mint_decimals,
        )?;
    }

    // LP gets their amount
    transfer_from_vault(
        &vault_info, &ctx.accounts.liquidity_provider_token_account.to_account_info(),
        &vault_authority_info, &mint_info, &token_program_key,
        vault_bump, lp_amount, mint_decimals,
    )?;

    // ─── Step 7: Update order state ───────────────────────────────────
    let order = &mut ctx.accounts.order;
    order.current_bps = new_bps;
    order.current_amount = order.current_amount
        .checked_sub(base_settle_amount)
        .ok_or(GatewayError::MathOverflow)?;

    // C-02 fix: Track distributed sender_fee for local orders
    if is_local && order.sender_fee > 0 {
        // current_provider was distributed this settle (to LP + treasury)
        // On final, sender_recipient_amount was also distributed
        let fee_out_this_settle = {
            let prov_128 = (order.sender_fee as u128)
                .saturating_mul(token_config.sender_to_provider as u128) / (MAX_BPS as u128);
            let prov = prov_128 as u64;
            let curr_prov = ((prov as u128).saturating_mul(settle_percent as u128) / (MAX_BPS as u128)) as u64;
            let sender_recip = order.sender_fee.saturating_sub(prov);
            if is_final { curr_prov.saturating_add(sender_recip) } else { curr_prov }
        };
        order.distributed_sender_fee = order.distributed_sender_fee
            .checked_add(fee_out_this_settle)
            .ok_or(GatewayError::MathOverflow)?;
    }

    // Fix #1: Decrement remaining_protocol_fee
    if !is_local {
        // aggregator_fee before rebate redistribution = fee drawn from protocol_fee pool
        let fee_drawn_128 = (order.remaining_protocol_fee as u128)
            .checked_mul(settle_percent as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(current_bps as u128)
            .ok_or(GatewayError::MathOverflow)?;
        let fee_drawn = u64::try_from(fee_drawn_128).map_err(|_| GatewayError::MathOverflow)?;
        order.remaining_protocol_fee = order.remaining_protocol_fee
            .checked_sub(fee_drawn)
            .ok_or(GatewayError::MathOverflow)?;
    }

    if is_final {
        order.status = OrderStatus::Fulfilled;
    }

    // ─── Step 8: Emit event ───────────────────────────────────────────
    emit_cpi!(OrderSettledOut {
        split_order_id,
        order_id: order.order_id,
        liquidity_provider: ctx.accounts.liquidity_provider_token_account.owner,
        settle_percent,
        rebate_percent,
    });

    Ok(())
}
