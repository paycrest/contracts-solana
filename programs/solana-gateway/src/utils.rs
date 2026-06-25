use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, TransferChecked};

use crate::constants::*;

/// Transfer tokens INTO the vault (from a user/caller who is a signer).
/// Used in: create_order, settle_in
pub fn transfer_to_vault<'info>(
    from: &AccountInfo<'info>,
    vault: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    token_program: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_interface::transfer_checked(
        CpiContext::new(
            *token_program,
            TransferChecked {
                from: from.clone(),
                to: vault.clone(),
                authority: authority.clone(),
                mint: mint.clone(),
            },
        ),
        amount,
        decimals,
    )
}

/// Transfer tokens OUT of the vault (signed by vault_authority PDA).
/// Used in: settle_out, settle_in, refund
pub fn transfer_from_vault<'info>(
    vault: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    vault_authority: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    token_program: &Pubkey,
    vault_authority_bump: u8,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let signer_seeds: &[&[u8]] = &[VAULT_AUTHORITY_SEED, &[vault_authority_bump]];
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            *token_program,
            TransferChecked {
                from: vault.clone(),
                to: to.clone(),
                authority: vault_authority.clone(),
                mint: mint.clone(),
            },
            &[signer_seeds],
        ),
        amount,
        decimals,
    )
}
