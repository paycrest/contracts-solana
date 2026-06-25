use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::error::GatewayError;
use crate::events::*;
use crate::state::*;
use crate::utils::{transfer_from_vault, transfer_to_vault};

#[derive(Accounts)]
#[event_cpi]
#[instruction(order_id: [u8; 32], amount: u64, sender_fee: u64, rate: u64, recipient_owner: Pubkey, fee_recipient_owner: Pubkey)]
pub struct SettleIn<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

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
        token::authority = caller,
    )]
    pub caller_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

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

    #[account(
        mut,
        token::mint = mint,
        constraint = recipient_token_account.owner == recipient_owner @ GatewayError::InvalidRecipientAccount,
    )]
    pub recipient_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = mint,
        constraint = treasury_token_account.owner == config.treasury @ GatewayError::InvalidTreasuryAccount,
    )]
    pub treasury_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = mint,
        constraint = sender_fee_recipient_token_account.owner == fee_recipient_owner @ GatewayError::InvalidSenderFeeRecipient,
    )]
    pub sender_fee_recipient_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Interface<'info, TokenInterface>,
}

/// Processes a settle-in (on-ramp) order.
/// No persistent Order account is created — all data is emitted via CPI events.
/// This eliminates zombie accounts and PDA reuse attack vectors.
pub fn handler(
    ctx: Context<SettleIn>,
    order_id: [u8; 32],
    amount: u64,
    sender_fee: u64,
    rate: u64,
    _recipient_owner: Pubkey,
    _fee_recipient_owner: Pubkey,
) -> Result<()> {
    let token_config = &ctx.accounts.token_config;
    let config = &ctx.accounts.config;
    let mint_decimals = ctx.accounts.mint.decimals;
    let vault_bump = config.vault_authority_bump;
    let token_program_key = ctx.accounts.token_program.key();
    let vault_info = ctx.accounts.vault.to_account_info();
    let vault_authority_info = ctx.accounts.vault_authority.to_account_info();
    let mint_info = ctx.accounts.mint.to_account_info();

    // ─── Step 1: Validations ──────────────────────────────────────────
    require!(amount > 0, GatewayError::AmountIsZero);

    // ─── Step 2: Fee Calculation (u128) ───────────────────────────────
    let is_local = rate == 100;
    let aggregator_fee: u64;

    if is_local {
        require!(sender_fee > 0, GatewayError::SenderFeeIsZero);
        aggregator_fee = 0;
    } else {
        require!(token_config.provider_to_aggregator_fx > 0, GatewayError::TokenFeeSettingsNotConfigured);
        let fee_128 = (amount as u128)
            .checked_mul(token_config.provider_to_aggregator_fx as u128)
            .ok_or(GatewayError::MathOverflow)?
            .checked_div(MAX_BPS as u128)
            .ok_or(GatewayError::MathOverflow)?;
        aggregator_fee = u64::try_from(fee_128).map_err(|_| GatewayError::MathOverflow)?;
    }

    let amount_to_settle = amount.checked_sub(aggregator_fee).ok_or(GatewayError::MathOverflow)?;

    // ─── Step 3: Pull total from caller → vault ───────────────────────
    let total_in = amount.checked_add(sender_fee).ok_or(GatewayError::MathOverflow)?;

    transfer_to_vault(
        &ctx.accounts.caller_token_account.to_account_info(),
        &vault_info,
        &ctx.accounts.caller.to_account_info(),
        &mint_info,
        &token_program_key,
        total_in,
        mint_decimals,
    )?;

    // ─── Step 4: Distribute from vault ────────────────────────────────
    transfer_from_vault(
        &vault_info, &ctx.accounts.recipient_token_account.to_account_info(),
        &vault_authority_info, &mint_info, &token_program_key,
        vault_bump, amount_to_settle, mint_decimals,
    )?;

    transfer_from_vault(
        &vault_info, &ctx.accounts.treasury_token_account.to_account_info(),
        &vault_authority_info, &mint_info, &token_program_key,
        vault_bump, aggregator_fee, mint_decimals,
    )?;

    // ─── Step 5: Sender Fee Splitting ─────────────────────────────────
    if sender_fee > 0 {
        if !is_local {
            // FX Mode
            let agg_share_128 = (sender_fee as u128)
                .checked_mul(token_config.sender_to_aggregator as u128)
                .ok_or(GatewayError::MathOverflow)?
                .checked_div(MAX_BPS as u128)
                .ok_or(GatewayError::MathOverflow)?;
            let agg_share = u64::try_from(agg_share_128).map_err(|_| GatewayError::MathOverflow)?;
            let sender_share = sender_fee.checked_sub(agg_share).ok_or(GatewayError::MathOverflow)?;

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

            emit_cpi!(FxTransferFeeSplit { order_id, sender_amount: sender_share, aggregator_amount: agg_share });

            emit_cpi!(SenderFeeTransferred {
                order_id,
                recipient: ctx.accounts.sender_fee_recipient_token_account.owner,
                amount: sender_share,
            });
        } else {
            // Local Mode
            let provider_amount_128 = (sender_fee as u128)
                .checked_mul(token_config.sender_to_provider as u128)
                .ok_or(GatewayError::MathOverflow)?
                .checked_div(MAX_BPS as u128)
                .ok_or(GatewayError::MathOverflow)?;
            let provider_amount = u64::try_from(provider_amount_128).map_err(|_| GatewayError::MathOverflow)?;

            let agg_amount_128 = (provider_amount as u128)
                .checked_mul(token_config.provider_to_aggregator as u128)
                .ok_or(GatewayError::MathOverflow)?
                .checked_div(MAX_BPS as u128)
                .ok_or(GatewayError::MathOverflow)?;
            let agg_amount = u64::try_from(agg_amount_128).map_err(|_| GatewayError::MathOverflow)?;

            let net_provider = provider_amount.checked_sub(agg_amount).ok_or(GatewayError::MathOverflow)?;
            let sender_recipient_amount = sender_fee.checked_sub(provider_amount).ok_or(GatewayError::MathOverflow)?;

            transfer_from_vault(
                &vault_info, &ctx.accounts.sender_fee_recipient_token_account.to_account_info(),
                &vault_authority_info, &mint_info, &token_program_key,
                vault_bump, sender_recipient_amount, mint_decimals,
            )?;
            transfer_from_vault(
                &vault_info, &ctx.accounts.treasury_token_account.to_account_info(),
                &vault_authority_info, &mint_info, &token_program_key,
                vault_bump, agg_amount, mint_decimals,
            )?;
            transfer_from_vault(
                &vault_info, &ctx.accounts.caller_token_account.to_account_info(),
                &vault_authority_info, &mint_info, &token_program_key,
                vault_bump, net_provider, mint_decimals,
            )?;

            emit_cpi!(LocalTransferFeeSplit { order_id, sender_amount: sender_recipient_amount, provider_amount: net_provider, aggregator_amount: agg_amount });

            emit_cpi!(SenderFeeTransferred {
                order_id,
                recipient: ctx.accounts.sender_fee_recipient_token_account.owner,
                amount: sender_recipient_amount,
            });
        }
    }

    // ─── Step 6: Emit Event (no persistent state — event-only) ────────
    emit_cpi!(OrderSettledIn {
        order_id,
        liquidity_provider: ctx.accounts.caller.key(),
        recipient: ctx.accounts.recipient_token_account.owner,
        amount: amount_to_settle,
        token: ctx.accounts.mint.key(),
        aggregator_fee,
        rate,
    });

    Ok(())
}
