use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("3rqpnuwCEHdtMVRaSSRQxZcUvD9X1Uh3jX6cmrK3qb33");

#[program]
pub mod gateway {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        max_bps: u64,
        protocol_fee_percent: u64,
    ) -> Result<()> {
        let settings = &mut ctx.accounts.settings;
        settings.max_bps = max_bps;
        settings.protocol_fee_percent = protocol_fee_percent;
        settings.treasury = ctx.accounts.treasury.key();
        settings.authority = ctx.accounts.authority.key();

        // Approved LPs list
        settings.approved_lps = vec![];

        Ok(())
    }

    // Instruction to manage approved LPs
    pub fn manage_liquidity_provider(
        ctx: Context<ManageLiquidityProvider>,
        lp: Pubkey,
        add: bool,
    ) -> Result<()> {
        let settings = &mut ctx.accounts.settings;

        if add {
            if !settings.approved_lps.contains(&lp) {
                settings.approved_lps.push(lp);
            }
        } else {
            settings.approved_lps.retain(|&x| x != lp);
        }

        Ok(())
    }

    pub fn create_order(
        ctx: Context<CreateOrder>,
        amount: u64,
        rate: u64,
        sender_fee: u64,
        message_hash: String,
    ) -> Result<()> {
        require!(amount > 0, GatewayError::AmountIsZero);
        require!(!message_hash.is_empty(), GatewayError::InvalidMessageHash);

        let order = &mut ctx.accounts.order;
        let settings = &ctx.accounts.settings;

        // Calculate protocol fee
        let protocol_fee = (amount)
            .checked_mul(settings.protocol_fee_percent)
            .unwrap()
            .checked_div(settings.max_bps)
            .unwrap();

        // Initialize order data
        order.sender = ctx.accounts.sender.key();
        order.mint = ctx.accounts.mint.key();
        order.sender_fee_recipient = ctx.accounts.sender_fee_recipient.key();
        order.sender_fee = sender_fee;
        order.protocol_fee = protocol_fee;
        order.is_fulfilled = false;
        order.is_refunded = false;
        order.refund_address = ctx.accounts.refund_address.key();
        order.current_bps = settings.max_bps;
        order.amount = amount;
        order.rate = rate;
        order.total_settled_amount = 0;
        order.last_update_slot = Clock::get()?.slot;

        // Transfer tokens from sender to vault
        let transfer_instruction = Transfer {
            from: ctx.accounts.sender_token_account.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.sender.to_account_info(),
        };

        let total_amount = amount.checked_add(sender_fee).unwrap();
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                transfer_instruction,
            ),
            total_amount,
        )?;

        emit!(OrderCreatedEvent {
            sender: ctx.accounts.sender.key(),
            mint: ctx.accounts.mint.key(),
            amount,
            protocol_fee,
            rate,
            message_hash,
            created_slot: Clock::get()?.slot,
        });

        Ok(())
    }

    pub fn settle(
        ctx: Context<Settle>,
        settle_percent: u64,
        split_order_id: [u8; 32],
    ) -> Result<()> {
        let order = &mut ctx.accounts.order;
        let settings = &ctx.accounts.settings;

        // Verify LP is approved
        require!(
            settings
                .approved_lps
                .contains(&ctx.accounts.liquidity_provider.key()),
            GatewayError::UnauthorizedLiquidityProvider
        );

        require!(!order.is_fulfilled, GatewayError::OrderFulfilled);
        require!(!order.is_refunded, GatewayError::OrderRefunded);

        // Verify no concurrent modifications
        require!(
            order.last_update_slot == Clock::get()?.slot,
            GatewayError::ConcurrentModification
        );

        // Update current BPS
        order.current_bps = order.current_bps.checked_sub(settle_percent).unwrap();

        // Calculate amounts
        let lp_amount = (order.amount)
            .checked_mul(settle_percent)
            .unwrap()
            .checked_div(settings.max_bps)
            .unwrap();

        // Update total settled amount and verify
        order.total_settled_amount = order
            .total_settled_amount
            .checked_add(lp_amount)
            .ok_or(GatewayError::ArithmeticError)?;
        require!(
            order.total_settled_amount <= order.amount,
            GatewayError::ExceedsOrderAmount
        );

        order.amount = order.amount.checked_sub(lp_amount).unwrap();

        let protocol_fee = (lp_amount)
            .checked_mul(settings.protocol_fee_percent)
            .unwrap()
            .checked_div(settings.max_bps)
            .unwrap();

        let lp_final_amount = lp_amount.checked_sub(protocol_fee).unwrap();

        // Update last operation slot
        order.last_update_slot = Clock::get()?.slot;

        // Transfer protocol fee
        let protocol_fee_ix = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.treasury_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                protocol_fee_ix,
                &[&[b"vault", order.key().as_ref(), &[ctx.bumps.vault_authority]]],
            ),
            protocol_fee,
        )?;

        // Transfer to liquidity provider
        let lp_transfer_ix = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.lp_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                lp_transfer_ix,
                &[&[b"vault", order.key().as_ref(), &[ctx.bumps.vault_authority]]],
            ),
            lp_final_amount,
        )?;

        if order.current_bps == 0 {
            order.is_fulfilled = true;

            if order.sender_fee > 0 {
                let sender_fee_ix = Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx
                        .accounts
                        .sender_fee_recipient_token_account
                        .to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                };

                token::transfer(
                    CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        sender_fee_ix,
                        &[&[b"vault", order.key().as_ref(), &[ctx.bumps.vault_authority]]],
                    ),
                    order.sender_fee,
                )?;
            }
        }

        emit!(OrderSettledEvent {
            split_order_id,
            order_id: order.key(),
            liquidity_provider: ctx.accounts.liquidity_provider.key(),
            settle_percent,
            settled_amount: lp_amount,
            remaining_amount: order.amount,
            slot: Clock::get()?.slot,
        });

        Ok(())
    }

    pub fn refund(ctx: Context<Refund>, fee: u64) -> Result<()> {
        let order = &mut ctx.accounts.order;

        require!(!order.is_fulfilled, GatewayError::OrderFulfilled);
        require!(!order.is_refunded, GatewayError::OrderRefunded);
        require!(
            order.protocol_fee >= fee,
            GatewayError::FeeExceedsProtocolFee
        );

        // Transfer fee if any
        if fee > 0 {
            let fee_ix = Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.treasury_token_account.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            };

            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    fee_ix,
                    &[&[b"vault", order.key().as_ref(), &[ctx.bumps.vault_authority]]],
                ),
                fee,
            )?;
        }

        // Update order state
        order.is_refunded = true;
        order.current_bps = 0;

        let refund_amount = order.amount.checked_sub(fee).unwrap();
        let total_refund = refund_amount.checked_add(order.sender_fee).unwrap();

        // Transfer refund amount
        let refund_ix = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.refund_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                refund_ix,
                &[&[b"vault", order.key().as_ref(), &[ctx.bumps.vault_authority]]],
            ),
            total_refund,
        )?;

        emit!(OrderRefundedEvent {
            fee,
            order_id: order.key(),
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + Settings::SPACE)]
    pub settings: Account<'info, Settings>,
    /// CHECK: This is safe as we just store the pubkey
    pub treasury: AccountInfo<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ManageLiquidityProvider<'info> {
    #[account(mut, has_one = authority)]
    pub settings: Account<'info, Settings>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CreateOrder<'info> {
    pub settings: Account<'info, Settings>,
    #[account(
        init,
        payer = sender,
        space = 8 + Order::SPACE,
    )]
    pub order: Account<'info, Order>,
    pub mint: Account<'info, token::Mint>,
    #[account(mut)]
    pub sender: Signer<'info>,
    #[account(
        mut,
        constraint = sender_token_account.mint == mint.key() @ GatewayError::InvalidMint,
        constraint = sender_token_account.owner == sender.key() @ GatewayError::InvalidOwner
    )]
    pub sender_token_account: Account<'info, TokenAccount>,
    /// CHECK: This is safe as we just store the pubkey
    pub sender_fee_recipient: AccountInfo<'info>,
    /// CHECK: This is safe as we just store the pubkey
    pub refund_address: AccountInfo<'info>,
    #[account(
        init,
        payer = sender,
        seeds = [b"vault", order.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = vault_authority,
    )]
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: PDA used as token account authority
    #[account(
        seeds = [b"vault", order.key().as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    pub settings: Account<'info, Settings>,
    #[account(mut)]
    pub order: Account<'info, Order>,
    #[account(
        mut,
        constraint = vault.mint == order.mint @ GatewayError::InvalidMint,
    )]
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: PDA used as token account authority
    #[account(
        seeds = [b"vault", order.key().as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    #[account(
        mut,
        constraint = treasury_token_account.mint == order.mint @ GatewayError::InvalidMint,
    )]
    pub treasury_token_account: Account<'info, TokenAccount>,
    pub liquidity_provider: Signer<'info>,
    #[account(
        mut,
        constraint = lp_token_account.mint == order.mint @ GatewayError::InvalidMint,
        constraint = lp_token_account.owner == liquidity_provider.key() @ GatewayError::InvalidOwner
    )]
    pub lp_token_account: Account<'info, TokenAccount>,
    #[account(
        mut,
        constraint = sender_fee_recipient_token_account.mint == order.mint @ GatewayError::InvalidMint,
    )]
    pub sender_fee_recipient_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    pub settings: Account<'info, Settings>,
    #[account(mut)]
    pub order: Account<'info, Order>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    /// CHECK: PDA used as token account authority
    #[account(
        seeds = [b"vault", order.key().as_ref()],
        bump
    )]
    pub vault_authority: AccountInfo<'info>,
    #[account(mut)]
    pub treasury_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub refund_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Settings {
    pub max_bps: u64,
    pub protocol_fee_percent: u64,
    pub treasury: Pubkey,
    pub authority: Pubkey,
    pub approved_lps: Vec<Pubkey>,
}

impl Settings {
    pub const SPACE: usize = 8 + 8 + 32 + 32 + 32 * 50; // Space for up to 50 approved LPs
}

#[account]
pub struct Order {
    pub sender: Pubkey,
    pub mint: Pubkey,
    pub sender_fee_recipient: Pubkey,
    pub sender_fee: u64,
    pub protocol_fee: u64,
    pub is_fulfilled: bool,
    pub is_refunded: bool,
    pub refund_address: Pubkey,
    pub current_bps: u64,
    pub amount: u64,
    pub rate: u64,
    pub total_settled_amount: u64,
    pub last_update_slot: u64,
}

impl Order {
    pub const SPACE: usize = 32 + 32 + 32 + 8 + 8 + 1 + 1 + 32 + 8 + 8 + 8 + 8 + 8;
}

#[error_code]
pub enum GatewayError {
    #[msg("Amount must be greater than zero")]
    AmountIsZero,
    #[msg("Message hash cannot be empty")]
    InvalidMessageHash,
    #[msg("Order is already fulfilled")]
    OrderFulfilled,
    #[msg("Order is already refunded")]
    OrderRefunded,
    #[msg("Fee exceeds protocol fee")]
    FeeExceedsProtocolFee,
    #[msg("Invalid token mint")]
    InvalidMint,
    #[msg("Invalid token account owner")]
    InvalidOwner,
    #[msg("Unauthorized liquidity provider")]
    UnauthorizedLiquidityProvider,
    #[msg("Concurrent modification detected")]
    ConcurrentModification,
    #[msg("Settlement amount exceeds order amount")]
    ExceedsOrderAmount,
    #[msg("Arithmetic error")]
    ArithmeticError,
}

#[event]
pub struct OrderCreatedEvent {
    pub sender: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub protocol_fee: u64,
    pub rate: u64,
    pub message_hash: String,
    pub created_slot: u64,
}

#[event]
pub struct OrderSettledEvent {
    pub split_order_id: [u8; 32],
    pub order_id: Pubkey,
    pub liquidity_provider: Pubkey,
    pub settle_percent: u64,
    pub settled_amount: u64,
    pub remaining_amount: u64,
    pub slot: u64,
}

#[event]
pub struct OrderRefundedEvent {
    pub fee: u64,
    pub order_id: Pubkey,
}
