use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::*;

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The initial owner/admin of the protocol.
    /// Security: `init` on a PDA-seeded account can only succeed once (Anchor discriminator
    /// check prevents re-initialization). Whoever calls this first becomes the owner.
    /// In practice, the deployer should call this atomically after program deployment.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Config account (singleton PDA). The `init` constraint guarantees this can only
    /// be created once — any subsequent call will fail with "already in use".
    #[account(
        init,
        payer = owner,
        space = 8 + Config::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub config: Account<'info, Config>,

    /// Treasury address to receive protocol fees.
    /// CHECK: validated by the owner at setup time.
    pub treasury: UncheckedAccount<'info>,

    /// Aggregator authority pubkey.
    /// CHECK: validated by the owner at setup time.
    pub aggregator: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Initializes the protocol config. Derives and stores vault_authority_bump.
pub fn handler(ctx: Context<Initialize>) -> Result<()> {
    let config = &mut ctx.accounts.config;

    config.owner = ctx.accounts.owner.key();
    config.aggregator = ctx.accounts.aggregator.key();
    config.treasury = ctx.accounts.treasury.key();
    config.paused = false;
    config.bump = ctx.bumps.config;

    // Derive vault_authority bump (pure PDA — no account needed)
    let (_, vault_authority_bump) = Pubkey::find_program_address(
        &[VAULT_AUTHORITY_SEED],
        ctx.program_id,
    );
    config.vault_authority_bump = vault_authority_bump;

    Ok(())
}
