use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::GatewayError;
use crate::state::*;

/// Discriminator for which address to update.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolAddressType {
    Treasury,
    Aggregator,
}

#[derive(Accounts)]
pub struct UpdateProtocolAddress<'info> {
    /// Protocol owner (admin).
    pub owner: Signer<'info>,

    /// Config — verifies owner.
    #[account(
        mut,
        has_one = owner,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
}

/// Updates treasury or aggregator address.
pub fn handler(
    ctx: Context<UpdateProtocolAddress>,
    address_type: ProtocolAddressType,
    new_address: Pubkey,
) -> Result<()> {
    require!(new_address != Pubkey::default(), GatewayError::ZeroAddress);

    let config = &mut ctx.accounts.config;

    match address_type {
        ProtocolAddressType::Treasury => {
            require!(config.treasury != new_address, GatewayError::AddressAlreadySet);
            config.treasury = new_address;
        }
        ProtocolAddressType::Aggregator => {
            require!(config.aggregator != new_address, GatewayError::AddressAlreadySet);
            config.aggregator = new_address;
        }
    }

    Ok(())
}
