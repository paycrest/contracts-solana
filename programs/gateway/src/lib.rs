use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWxTWqk6W2BeZ7FEfcYkgPqS4fSn");

const CONFIG_SEED: &[u8] = b"config";
const TOKEN_CONFIG_SEED: &[u8] = b"token-config";
const USER_NONCE_SEED: &[u8] = b"user-nonce";
const ORDER_SEED: &[u8] = b"order";
const VAULT_AUTHORITY_SEED: &[u8] = b"vault-authority";

const TOKEN_KEY: &[u8] = b"token";
const TREASURY_KEY: &[u8] = b"treasury";
const AGGREGATOR_KEY: &[u8] = b"aggregator";

#[program]
pub mod gateway {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        treasury: Pubkey,
        aggregator: Pubkey,
        chain_id: u64,
    ) -> Result<()> {
        require!(
            treasury != Pubkey::default(),
            GatewayError::ThrowZeroAddress
        );
        require!(
            aggregator != Pubkey::default(),
            GatewayError::ThrowZeroAddress
        );

        let config = &mut ctx.accounts.config;
        config.owner = ctx.accounts.owner.key();
        config.pending_owner = Pubkey::default();
        config.treasury = treasury;
        config.aggregator = aggregator;
        config.paused = false;
        config.max_bps = 100_000;
        config.chain_id = chain_id;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn transfer_ownership(ctx: Context<OnlyOwner>, new_owner: Pubkey) -> Result<()> {
        require!(
            new_owner != Pubkey::default(),
            GatewayError::ThrowZeroAddress
        );
        ctx.accounts.config.pending_owner = new_owner;
        emit!(OwnershipTransferStarted {
            current_owner: ctx.accounts.config.owner,
            pending_owner: new_owner,
        });
        Ok(())
    }

    pub fn accept_ownership(ctx: Context<AcceptOwnership>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(
            ctx.accounts.pending_owner.key() == config.pending_owner,
            GatewayError::UnauthorizedPendingOwner
        );
        let old_owner = config.owner;
        config.owner = ctx.accounts.pending_owner.key();
        config.pending_owner = Pubkey::default();
        emit!(OwnershipTransferred {
            old_owner,
            new_owner: config.owner,
        });
        Ok(())
    }

    pub fn pause(ctx: Context<OnlyOwner>) -> Result<()> {
        ctx.accounts.config.paused = true;
        emit!(PausedChanged { is_paused: true });
        Ok(())
    }

    pub fn unpause(ctx: Context<OnlyOwner>) -> Result<()> {
        ctx.accounts.config.paused = false;
        emit!(PausedChanged { is_paused: false });
        Ok(())
    }

    pub fn setting_manager_bool(
        ctx: Context<SettingManagerBool>,
        what: [u8; 32],
        status: u8,
    ) -> Result<()> {
        require!(status == 1 || status == 2, GatewayError::InvalidStatus);
        require!(matches_word(&what, TOKEN_KEY), GatewayError::InvalidWhat);

        let token_config = &mut ctx.accounts.token_config;
        token_config.mint = ctx.accounts.token_mint.key();
        token_config.status = status;
        token_config.bump = ctx.bumps.token_config;

        emit!(SettingManagerBoolEvent {
            what,
            value: ctx.accounts.token_mint.key(),
            status: status as u64,
        });
        Ok(())
    }

    pub fn update_protocol_address(
        ctx: Context<OnlyOwner>,
        what: [u8; 32],
        value: Pubkey,
    ) -> Result<()> {
        require!(value != Pubkey::default(), GatewayError::ThrowZeroAddress);
        let config = &mut ctx.accounts.config;

        if matches_word(&what, TREASURY_KEY) {
            require!(config.treasury != value, GatewayError::AddressAlreadySet);
            config.treasury = value;
        } else if matches_word(&what, AGGREGATOR_KEY) {
            require!(config.aggregator != value, GatewayError::AddressAlreadySet);
            config.aggregator = value;
        } else {
            return err!(GatewayError::InvalidWhat);
        }

        emit!(ProtocolAddressUpdated { what, value });
        Ok(())
    }

    pub fn set_token_fee_settings(
        ctx: Context<SetTokenFeeSettings>,
        sender_to_provider: u64,
        provider_to_aggregator: u64,
        sender_to_aggregator: u64,
        provider_to_aggregator_fx: u64,
    ) -> Result<()> {
        let max_bps = ctx.accounts.config.max_bps;
        let token_config = &mut ctx.accounts.token_config;

        require!(token_config.status == 1, GatewayError::TokenNotSupported);
        require!(
            sender_to_provider <= max_bps
                && provider_to_aggregator <= max_bps
                && sender_to_aggregator <= max_bps
                && provider_to_aggregator_fx <= max_bps,
            GatewayError::InvalidFeeBps
        );

        token_config.fee_settings = TokenFeeSettings {
            sender_to_provider,
            provider_to_aggregator,
            sender_to_aggregator,
            provider_to_aggregator_fx,
        };

        emit!(TokenFeeSettingsUpdated {
            token: token_config.mint,
            sender_to_provider,
            provider_to_aggregator,
            sender_to_aggregator,
            provider_to_aggregator_fx,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_order(
        ctx: Context<CreateOrder>,
        order_id: [u8; 32],
        amount: u64,
        rate: u64,
        sender_fee_recipient: Pubkey,
        sender_fee: u64,
        refund_address: Pubkey,
        message_hash: String,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(!config.paused, GatewayError::Paused);
        require!(
            ctx.accounts.token_config.status == 1,
            GatewayError::TokenNotSupported
        );
        require!(amount > 0, GatewayError::AmountIsZero);
        require!(
            refund_address != Pubkey::default(),
            GatewayError::ThrowZeroAddress
        );
        require!(!message_hash.is_empty(), GatewayError::InvalidMessageHash);
        if sender_fee > 0 {
            require!(
                sender_fee_recipient != Pubkey::default(),
                GatewayError::InvalidSenderFeeRecipient
            );
        }

        let nonce_account = &mut ctx.accounts.user_nonce;
        if nonce_account.user == Pubkey::default() {
            nonce_account.user = ctx.accounts.sender.key();
            nonce_account.nonce = 0;
            nonce_account.bump = ctx.bumps.user_nonce;
        } else {
            require!(
                nonce_account.user == ctx.accounts.sender.key(),
                GatewayError::NonceOwnerMismatch
            );
        }

        let next_nonce = nonce_account
            .nonce
            .checked_add(1)
            .ok_or(GatewayError::MathOverflow)?;
        let computed_order_id =
            compute_order_id(&ctx.accounts.sender.key(), next_nonce, config.chain_id);
        require!(computed_order_id == order_id, GatewayError::InvalidOrderId);
        nonce_account.nonce = next_nonce;

        let protocol_fee = if rate == 100 {
            require!(sender_fee > 0, GatewayError::SenderFeeIsZero);
            0
        } else {
            let provider_to_aggregator_fx = ctx
                .accounts
                .token_config
                .fee_settings
                .provider_to_aggregator_fx;
            require!(
                provider_to_aggregator_fx > 0,
                GatewayError::TokenFeeSettingsNotConfigured
            );
            mul_div_u64(amount, provider_to_aggregator_fx, config.max_bps)?
        };

        let total_amount = amount
            .checked_add(sender_fee)
            .ok_or(GatewayError::MathOverflow)?;

        let transfer_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.sender_token_account.to_account_info(),
                to: ctx.accounts.vault_token_account.to_account_info(),
                authority: ctx.accounts.sender.to_account_info(),
            },
        );
        token::transfer(transfer_ctx, total_amount)?;

        let order = &mut ctx.accounts.order;
        order.order_id = order_id;
        order.sender = ctx.accounts.sender.key();
        order.token = ctx.accounts.mint.key();
        order.sender_fee_recipient = sender_fee_recipient;
        order.sender_fee = sender_fee;
        order.protocol_fee = protocol_fee;
        order.is_fulfilled = false;
        order.is_refunded = false;
        order.refund_address = refund_address;
        order.current_bps = config.max_bps;
        order.amount = amount;
        order.bump = ctx.bumps.order;

        emit!(OrderCreated {
            sender: refund_address,
            token: order.token,
            amount,
            protocol_fee,
            order_id,
            rate,
            message_hash,
        });
        Ok(())
    }

    pub fn settle(
        ctx: Context<Settle>,
        split_order_id: [u8; 32],
        order_id: [u8; 32],
        settle_percent: u64,
        rebate_percent: u64,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(
            ctx.accounts.aggregator.key() == config.aggregator,
            GatewayError::OnlyAggregator
        );
        require!(
            rebate_percent <= config.max_bps,
            GatewayError::InvalidRebatePercent
        );

        let order = &mut ctx.accounts.order;
        require!(order.order_id == order_id, GatewayError::InvalidOrderId);
        require!(!order.is_fulfilled, GatewayError::OrderFulfilled);
        require!(!order.is_refunded, GatewayError::OrderRefunded);

        let current_order_bps = order.current_bps;
        require!(
            settle_percent > 0 && settle_percent <= current_order_bps,
            GatewayError::InvalidSettlePercent
        );
        order.current_bps = order
            .current_bps
            .checked_sub(settle_percent)
            .ok_or(GatewayError::MathOverflow)?;

        if order.current_bps == 0 {
            order.is_fulfilled = true;
            if order.sender_fee != 0 && order.protocol_fee != 0 {
                handle_fx_transfer_fee_splitting(
                    order,
                    &ctx.accounts.token_config.fee_settings,
                    config.max_bps,
                    &ctx.accounts.sender_fee_recipient_token_account,
                    &ctx.accounts.treasury_token_account,
                    &ctx.accounts.vault_token_account,
                    &ctx.accounts.vault_authority,
                    &ctx.accounts.token_program,
                    ctx.bumps.vault_authority,
                )?;
            }
        }

        if order.sender_fee != 0 && order.protocol_fee == 0 {
            handle_local_transfer_fee_splitting(
                order,
                settle_percent,
                &ctx.accounts.token_config.fee_settings,
                config.max_bps,
                &ctx.accounts.sender_fee_recipient_token_account,
                &ctx.accounts.liquidity_provider_token_account,
                &ctx.accounts.treasury_token_account,
                &ctx.accounts.vault_token_account,
                &ctx.accounts.vault_authority,
                &ctx.accounts.token_program,
                ctx.bumps.vault_authority,
            )?;
        }

        let mut liquidity_provider_amount =
            mul_div_u64(order.amount, settle_percent, current_order_bps)?;
        order.amount = order
            .amount
            .checked_sub(liquidity_provider_amount)
            .ok_or(GatewayError::MathOverflow)?;

        if order.protocol_fee != 0 {
            let mut protocol_fee = mul_div_u64(
                liquidity_provider_amount,
                ctx.accounts
                    .token_config
                    .fee_settings
                    .provider_to_aggregator_fx,
                config.max_bps,
            )?;
            liquidity_provider_amount = liquidity_provider_amount
                .checked_sub(protocol_fee)
                .ok_or(GatewayError::MathOverflow)?;

            if rebate_percent != 0 {
                let rebate_amount = mul_div_u64(protocol_fee, rebate_percent, config.max_bps)?;
                protocol_fee = protocol_fee
                    .checked_sub(rebate_amount)
                    .ok_or(GatewayError::MathOverflow)?;
                liquidity_provider_amount = liquidity_provider_amount
                    .checked_add(rebate_amount)
                    .ok_or(GatewayError::MathOverflow)?;
            }

            transfer_from_vault(
                protocol_fee,
                &ctx.accounts.vault_token_account,
                &ctx.accounts.treasury_token_account,
                &ctx.accounts.vault_authority,
                &ctx.accounts.token_program,
                ctx.bumps.vault_authority,
            )?;
        }

        transfer_from_vault(
            liquidity_provider_amount,
            &ctx.accounts.vault_token_account,
            &ctx.accounts.liquidity_provider_token_account,
            &ctx.accounts.vault_authority,
            &ctx.accounts.token_program,
            ctx.bumps.vault_authority,
        )?;

        emit!(OrderSettled {
            split_order_id,
            order_id,
            liquidity_provider: ctx.accounts.liquidity_provider.key(),
            settle_percent,
            rebate_percent,
        });
        Ok(())
    }

    pub fn refund(ctx: Context<Refund>, fee: u64, order_id: [u8; 32]) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(
            ctx.accounts.aggregator.key() == config.aggregator,
            GatewayError::OnlyAggregator
        );

        let order = &mut ctx.accounts.order;
        require!(order.order_id == order_id, GatewayError::InvalidOrderId);
        require!(!order.is_fulfilled, GatewayError::OrderFulfilled);
        require!(!order.is_refunded, GatewayError::OrderRefunded);
        require!(
            order.protocol_fee >= fee,
            GatewayError::FeeExceedsProtocolFee
        );

        if fee > 0 {
            transfer_from_vault(
                fee,
                &ctx.accounts.vault_token_account,
                &ctx.accounts.treasury_token_account,
                &ctx.accounts.vault_authority,
                &ctx.accounts.token_program,
                ctx.bumps.vault_authority,
            )?;
        }

        order.is_refunded = true;
        order.current_bps = 0;

        let refund_amount = order
            .amount
            .checked_sub(fee)
            .ok_or(GatewayError::MathOverflow)?;
        let total_refund = refund_amount
            .checked_add(order.sender_fee)
            .ok_or(GatewayError::MathOverflow)?;

        transfer_from_vault(
            total_refund,
            &ctx.accounts.vault_token_account,
            &ctx.accounts.refund_token_account,
            &ctx.accounts.vault_authority,
            &ctx.accounts.token_program,
            ctx.bumps.vault_authority,
        )?;

        emit!(OrderRefunded { fee, order_id });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + Config::LEN,
        seeds = [CONFIG_SEED],
        bump
    )]
    pub config: Account<'info, Config>,
    /// CHECK: PDA authority for token vaults.
    #[account(seeds = [VAULT_AUTHORITY_SEED], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OnlyOwner<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ GatewayError::OnlyOwner
    )]
    pub config: Account<'info, Config>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptOwnership<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    pub pending_owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct SettingManagerBool<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ GatewayError::OnlyOwner
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub token_mint: Account<'info, Mint>,
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + TokenConfig::LEN,
        seeds = [TOKEN_CONFIG_SEED, token_mint.key().as_ref()],
        bump
    )]
    pub token_config: Account<'info, TokenConfig>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetTokenFeeSettings<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ GatewayError::OnlyOwner
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub token_mint: Account<'info, Mint>,
    #[account(
        mut,
        seeds = [TOKEN_CONFIG_SEED, token_mint.key().as_ref()],
        bump = token_config.bump,
        constraint = token_config.mint == token_mint.key() @ GatewayError::TokenConfigMintMismatch
    )]
    pub token_config: Account<'info, TokenConfig>,
}

#[derive(Accounts)]
#[instruction(order_id: [u8; 32])]
pub struct CreateOrder<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    pub mint: Account<'info, Mint>,
    #[account(
        seeds = [TOKEN_CONFIG_SEED, mint.key().as_ref()],
        bump = token_config.bump,
        constraint = token_config.mint == mint.key() @ GatewayError::TokenConfigMintMismatch
    )]
    pub token_config: Account<'info, TokenConfig>,
    #[account(
        init_if_needed,
        payer = sender,
        space = 8 + UserNonce::LEN,
        seeds = [USER_NONCE_SEED, sender.key().as_ref()],
        bump
    )]
    pub user_nonce: Account<'info, UserNonce>,
    #[account(
        init,
        payer = sender,
        space = 8 + Order::LEN,
        seeds = [ORDER_SEED, order_id.as_ref()],
        bump
    )]
    pub order: Account<'info, Order>,
    /// CHECK: PDA authority for token vaults.
    #[account(seeds = [VAULT_AUTHORITY_SEED], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = sender
    )]
    pub sender_token_account: Account<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = sender,
        associated_token::mint = mint,
        associated_token::authority = vault_authority
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub sender: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    pub mint: Account<'info, Mint>,
    #[account(
        seeds = [TOKEN_CONFIG_SEED, mint.key().as_ref()],
        bump = token_config.bump,
        constraint = token_config.mint == mint.key() @ GatewayError::TokenConfigMintMismatch
    )]
    pub token_config: Account<'info, TokenConfig>,
    #[account(
        mut,
        seeds = [ORDER_SEED, order.order_id.as_ref()],
        bump = order.bump,
        constraint = order.token == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub order: Account<'info, Order>,
    /// CHECK: PDA authority for token vaults.
    #[account(seeds = [VAULT_AUTHORITY_SEED], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = vault_authority
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = treasury_token_account.owner == config.treasury @ GatewayError::TreasuryTokenOwnerMismatch,
        constraint = treasury_token_account.mint == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub treasury_token_account: Account<'info, TokenAccount>,
    /// CHECK: Used for event parity and token owner constraint.
    pub liquidity_provider: UncheckedAccount<'info>,
    #[account(
        mut,
        constraint = liquidity_provider_token_account.owner == liquidity_provider.key() @ GatewayError::LiquidityProviderTokenOwnerMismatch,
        constraint = liquidity_provider_token_account.mint == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub liquidity_provider_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = sender_fee_recipient_token_account.owner == order.sender_fee_recipient @ GatewayError::SenderFeeTokenOwnerMismatch,
        constraint = sender_fee_recipient_token_account.mint == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub sender_fee_recipient_token_account: Account<'info, TokenAccount>,
    pub aggregator: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    pub mint: Account<'info, Mint>,
    #[account(
        mut,
        seeds = [ORDER_SEED, order.order_id.as_ref()],
        bump = order.bump,
        constraint = order.token == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub order: Account<'info, Order>,
    /// CHECK: PDA authority for token vaults.
    #[account(seeds = [VAULT_AUTHORITY_SEED], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = vault_authority
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = treasury_token_account.owner == config.treasury @ GatewayError::TreasuryTokenOwnerMismatch,
        constraint = treasury_token_account.mint == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub treasury_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = refund_token_account.owner == order.refund_address @ GatewayError::RefundTokenOwnerMismatch,
        constraint = refund_token_account.mint == mint.key() @ GatewayError::OrderMintMismatch
    )]
    pub refund_token_account: Account<'info, TokenAccount>,
    pub aggregator: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Config {
    pub owner: Pubkey,
    pub pending_owner: Pubkey,
    pub treasury: Pubkey,
    pub aggregator: Pubkey,
    pub paused: bool,
    pub max_bps: u64,
    pub chain_id: u64,
    pub bump: u8,
}

impl Config {
    pub const LEN: usize = 32 + 32 + 32 + 32 + 1 + 8 + 8 + 1;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct TokenFeeSettings {
    pub sender_to_provider: u64,
    pub provider_to_aggregator: u64,
    pub sender_to_aggregator: u64,
    pub provider_to_aggregator_fx: u64,
}

#[account]
pub struct TokenConfig {
    pub mint: Pubkey,
    pub status: u8,
    pub fee_settings: TokenFeeSettings,
    pub bump: u8,
}

impl TokenConfig {
    pub const LEN: usize = 32 + 1 + 32 + 1;
}

#[account]
pub struct UserNonce {
    pub user: Pubkey,
    pub nonce: u64,
    pub bump: u8,
}

impl UserNonce {
    pub const LEN: usize = 32 + 8 + 1;
}

#[account]
pub struct Order {
    pub order_id: [u8; 32],
    pub sender: Pubkey,
    pub token: Pubkey,
    pub sender_fee_recipient: Pubkey,
    pub sender_fee: u64,
    pub protocol_fee: u64,
    pub is_fulfilled: bool,
    pub is_refunded: bool,
    pub refund_address: Pubkey,
    pub current_bps: u64,
    pub amount: u64,
    pub bump: u8,
}

impl Order {
    pub const LEN: usize = 32 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 32 + 8 + 8 + 1;
}

#[event]
pub struct SettingManagerBoolEvent {
    pub what: [u8; 32],
    pub value: Pubkey,
    pub status: u64,
}

#[event]
pub struct ProtocolAddressUpdated {
    pub what: [u8; 32],
    pub value: Pubkey,
}

#[event]
pub struct TokenFeeSettingsUpdated {
    pub token: Pubkey,
    pub sender_to_provider: u64,
    pub provider_to_aggregator: u64,
    pub sender_to_aggregator: u64,
    pub provider_to_aggregator_fx: u64,
}

#[event]
pub struct OrderCreated {
    pub sender: Pubkey,
    pub token: Pubkey,
    pub amount: u64,
    pub protocol_fee: u64,
    pub order_id: [u8; 32],
    pub rate: u64,
    pub message_hash: String,
}

#[event]
pub struct OrderSettled {
    pub split_order_id: [u8; 32],
    pub order_id: [u8; 32],
    pub liquidity_provider: Pubkey,
    pub settle_percent: u64,
    pub rebate_percent: u64,
}

#[event]
pub struct OrderRefunded {
    pub fee: u64,
    pub order_id: [u8; 32],
}

#[event]
pub struct SenderFeeTransferred {
    pub sender: Pubkey,
    pub amount: u64,
}

#[event]
pub struct LocalTransferFeeSplit {
    pub order_id: [u8; 32],
    pub sender_amount: u64,
    pub provider_amount: u64,
    pub aggregator_amount: u64,
}

#[event]
pub struct FxTransferFeeSplit {
    pub order_id: [u8; 32],
    pub sender_amount: u64,
    pub aggregator_amount: u64,
}

#[event]
pub struct OwnershipTransferStarted {
    pub current_owner: Pubkey,
    pub pending_owner: Pubkey,
}

#[event]
pub struct OwnershipTransferred {
    pub old_owner: Pubkey,
    pub new_owner: Pubkey,
}

#[event]
pub struct PausedChanged {
    pub is_paused: bool,
}

#[error_code]
pub enum GatewayError {
    #[msg("OnlyOwner")]
    OnlyOwner,
    #[msg("OnlyAggregator")]
    OnlyAggregator,
    #[msg("TokenNotSupported")]
    TokenNotSupported,
    #[msg("AmountIsZero")]
    AmountIsZero,
    #[msg("ThrowZeroAddress")]
    ThrowZeroAddress,
    #[msg("InvalidSenderFeeRecipient")]
    InvalidSenderFeeRecipient,
    #[msg("InvalidMessageHash")]
    InvalidMessageHash,
    #[msg("SenderFeeIsZero")]
    SenderFeeIsZero,
    #[msg("TokenFeeSettingsNotConfigured")]
    TokenFeeSettingsNotConfigured,
    #[msg("OrderFulfilled")]
    OrderFulfilled,
    #[msg("OrderRefunded")]
    OrderRefunded,
    #[msg("FeeExceedsProtocolFee")]
    FeeExceedsProtocolFee,
    #[msg("InvalidRebatePercent")]
    InvalidRebatePercent,
    #[msg("InvalidSettlePercent")]
    InvalidSettlePercent,
    #[msg("MathOverflow")]
    MathOverflow,
    #[msg("InvalidOrderId")]
    InvalidOrderId,
    #[msg("Paused")]
    Paused,
    #[msg("InvalidStatus")]
    InvalidStatus,
    #[msg("InvalidWhat")]
    InvalidWhat,
    #[msg("UnauthorizedPendingOwner")]
    UnauthorizedPendingOwner,
    #[msg("AddressAlreadySet")]
    AddressAlreadySet,
    #[msg("InvalidFeeBps")]
    InvalidFeeBps,
    #[msg("NonceOwnerMismatch")]
    NonceOwnerMismatch,
    #[msg("TokenConfigMintMismatch")]
    TokenConfigMintMismatch,
    #[msg("OrderMintMismatch")]
    OrderMintMismatch,
    #[msg("TreasuryTokenOwnerMismatch")]
    TreasuryTokenOwnerMismatch,
    #[msg("LiquidityProviderTokenOwnerMismatch")]
    LiquidityProviderTokenOwnerMismatch,
    #[msg("SenderFeeTokenOwnerMismatch")]
    SenderFeeTokenOwnerMismatch,
    #[msg("RefundTokenOwnerMismatch")]
    RefundTokenOwnerMismatch,
}

fn matches_word(what: &[u8; 32], expected: &[u8]) -> bool {
    if what[..expected.len()] != *expected {
        return false;
    }
    what[expected.len()..].iter().all(|b| *b == 0)
}

fn compute_order_id(sender: &Pubkey, nonce: u64, chain_id: u64) -> [u8; 32] {
    keccak::hashv(&[
        sender.as_ref(),
        &nonce.to_le_bytes(),
        &chain_id.to_le_bytes(),
    ])
    .0
}

fn mul_div_u64(amount: u64, numerator: u64, denominator: u64) -> Result<u64> {
    let scaled = (amount as u128)
        .checked_mul(numerator as u128)
        .ok_or(GatewayError::MathOverflow)?;
    let value = scaled
        .checked_div(denominator as u128)
        .ok_or(GatewayError::MathOverflow)?;
    u64::try_from(value).map_err(|_| error!(GatewayError::MathOverflow))
}

fn transfer_from_vault<'info>(
    amount: u64,
    vault_token_account: &Account<'info, TokenAccount>,
    destination_token_account: &Account<'info, TokenAccount>,
    vault_authority: &UncheckedAccount<'info>,
    token_program: &Program<'info, Token>,
    vault_authority_bump: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }

    let signer_seeds: &[&[u8]] = &[VAULT_AUTHORITY_SEED, &[vault_authority_bump]];
    let signer = &[signer_seeds];
    let transfer_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        Transfer {
            from: vault_token_account.to_account_info(),
            to: destination_token_account.to_account_info(),
            authority: vault_authority.to_account_info(),
        },
        signer,
    );
    token::transfer(transfer_ctx, amount)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_local_transfer_fee_splitting<'info>(
    order: &Order,
    settle_percent: u64,
    fee_settings: &TokenFeeSettings,
    max_bps: u64,
    sender_fee_recipient_token_account: &Account<'info, TokenAccount>,
    liquidity_provider_token_account: &Account<'info, TokenAccount>,
    treasury_token_account: &Account<'info, TokenAccount>,
    vault_token_account: &Account<'info, TokenAccount>,
    vault_authority: &UncheckedAccount<'info>,
    token_program: &Program<'info, Token>,
    vault_authority_bump: u8,
) -> Result<()> {
    let sender_fee = order.sender_fee;
    let provider_amount = mul_div_u64(sender_fee, fee_settings.sender_to_provider, max_bps)?;
    let current_provider_amount = mul_div_u64(provider_amount, settle_percent, max_bps)?;
    let aggregator_amount = mul_div_u64(
        current_provider_amount,
        fee_settings.provider_to_aggregator,
        max_bps,
    )?;
    let sender_amount = sender_fee
        .checked_sub(provider_amount)
        .ok_or(GatewayError::MathOverflow)?;

    if sender_amount != 0 && order.current_bps == 0 {
        transfer_from_vault(
            sender_amount,
            vault_token_account,
            sender_fee_recipient_token_account,
            vault_authority,
            token_program,
            vault_authority_bump,
        )?;
    }

    if aggregator_amount != 0 {
        transfer_from_vault(
            aggregator_amount,
            vault_token_account,
            treasury_token_account,
            vault_authority,
            token_program,
            vault_authority_bump,
        )?;
    }

    let provider_payout = current_provider_amount
        .checked_sub(aggregator_amount)
        .ok_or(GatewayError::MathOverflow)?;
    if provider_payout != 0 {
        transfer_from_vault(
            provider_payout,
            vault_token_account,
            liquidity_provider_token_account,
            vault_authority,
            token_program,
            vault_authority_bump,
        )?;
    }

    emit!(SenderFeeTransferred {
        sender: order.sender_fee_recipient,
        amount: if order.current_bps == 0 {
            sender_amount
        } else {
            0
        },
    });
    emit!(LocalTransferFeeSplit {
        order_id: order.order_id,
        sender_amount: if order.current_bps == 0 {
            sender_amount
        } else {
            0
        },
        provider_amount: provider_payout,
        aggregator_amount,
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_fx_transfer_fee_splitting<'info>(
    order: &Order,
    fee_settings: &TokenFeeSettings,
    max_bps: u64,
    sender_fee_recipient_token_account: &Account<'info, TokenAccount>,
    treasury_token_account: &Account<'info, TokenAccount>,
    vault_token_account: &Account<'info, TokenAccount>,
    vault_authority: &UncheckedAccount<'info>,
    token_program: &Program<'info, Token>,
    vault_authority_bump: u8,
) -> Result<()> {
    let sender_fee = order.sender_fee;
    let sender_amount = mul_div_u64(
        sender_fee,
        max_bps
            .checked_sub(fee_settings.sender_to_aggregator)
            .ok_or(GatewayError::MathOverflow)?,
        max_bps,
    )?;
    let aggregator_amount = sender_fee
        .checked_sub(sender_amount)
        .ok_or(GatewayError::MathOverflow)?;

    if sender_amount != 0 {
        transfer_from_vault(
            sender_amount,
            vault_token_account,
            sender_fee_recipient_token_account,
            vault_authority,
            token_program,
            vault_authority_bump,
        )?;
    }
    if aggregator_amount != 0 {
        transfer_from_vault(
            aggregator_amount,
            vault_token_account,
            treasury_token_account,
            vault_authority,
            token_program,
            vault_authority_bump,
        )?;
    }

    emit!(SenderFeeTransferred {
        sender: order.sender_fee_recipient,
        amount: sender_amount,
    });
    emit!(FxTransferFeeSplit {
        order_id: order.order_id,
        sender_amount,
        aggregator_amount,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_split(
        sender_fee: u64,
        settle_percent: u64,
        sender_to_provider: u64,
        provider_to_aggregator: u64,
        max_bps: u64,
        is_final_settlement: bool,
    ) -> (u64, u64, u64) {
        let provider_amount = mul_div_u64(sender_fee, sender_to_provider, max_bps).unwrap();
        let current_provider_amount =
            mul_div_u64(provider_amount, settle_percent, max_bps).unwrap();
        let aggregator_amount =
            mul_div_u64(current_provider_amount, provider_to_aggregator, max_bps).unwrap();
        let sender_amount = sender_fee - provider_amount;
        let sender_payout = if is_final_settlement {
            sender_amount
        } else {
            0
        };
        (
            sender_payout,
            current_provider_amount - aggregator_amount,
            aggregator_amount,
        )
    }

    #[test]
    fn computes_deterministic_order_id() {
        let sender = Pubkey::new_unique();
        let chain_id = 1397;
        let first = compute_order_id(&sender, 1, chain_id);
        let second = compute_order_id(&sender, 1, chain_id);
        let different_nonce = compute_order_id(&sender, 2, chain_id);
        assert_eq!(first, second);
        assert_ne!(first, different_nonce);
    }

    #[test]
    fn calculates_protocol_fee_for_fx() {
        let amount = 27_000_000_000_000u64;
        let provider_to_aggregator_fx = 500u64;
        let protocol_fee = mul_div_u64(amount, provider_to_aggregator_fx, 100_000).unwrap();
        assert_eq!(protocol_fee, 135_000_000_000);
    }

    #[test]
    fn local_fee_split_full_settlement_matches_evm_logic() {
        let (sender_amount, provider_amount, aggregator_amount) =
            local_split(1_000, 100_000, 50_000, 50_000, 100_000, true);
        assert_eq!(sender_amount, 500);
        assert_eq!(provider_amount, 250);
        assert_eq!(aggregator_amount, 250);
    }

    #[test]
    fn local_fee_split_partial_and_final_settlements_match_evm_logic() {
        let (sender_first, provider_first, aggregator_first) =
            local_split(2_000, 50_000, 50_000, 50_000, 100_000, false);
        assert_eq!(sender_first, 0);
        assert_eq!(provider_first, 250);
        assert_eq!(aggregator_first, 250);

        let (sender_second, provider_second, aggregator_second) =
            local_split(2_000, 50_000, 50_000, 50_000, 100_000, true);
        assert_eq!(sender_second, 1_000);
        assert_eq!(provider_second, 250);
        assert_eq!(aggregator_second, 250);
    }

    #[test]
    fn fx_sender_fee_split_matches_evm_logic() {
        let sender_fee = 1_000u64;
        let sender_to_aggregator = 0u64;
        let sender_amount =
            mul_div_u64(sender_fee, 100_000 - sender_to_aggregator, 100_000).unwrap();
        let aggregator_amount = sender_fee - sender_amount;
        assert_eq!(sender_amount, 1_000);
        assert_eq!(aggregator_amount, 0);
    }

    #[test]
    fn rebate_reduces_treasury_and_increases_provider() {
        let order_slice = 27_000_000_000_000u64;
        let mut protocol_fee = mul_div_u64(order_slice, 500, 100_000).unwrap();
        let base_provider = order_slice - protocol_fee;
        let rebate = mul_div_u64(protocol_fee, 50_000, 100_000).unwrap();
        protocol_fee -= rebate;
        let provider_final = base_provider + rebate;
        assert_eq!(protocol_fee, 67_500_000_000);
        assert_eq!(provider_final, 26_932_500_000_000);
    }
}
