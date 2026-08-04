//! `refund` — mirrors `Gateway.refund`. Aggregator-only; `fee` is capped by
//! `protocol_fee` as frozen at `create_order` time (D14 — this is the one
//! place that frozen value is ever read). Terminalizes the order (D8).

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address,
};
use pinocchio_token::instructions::transfer::Transfer;

use crate::{
    constants::{SEED_ORDER, SEED_VAULT_AUTHORITY, TOKEN_PROGRAM_ID},
    errors::GatewayError,
    events::OrderRefundedEvent,
    instructions::{addresses_eq, require_owned_by_program, require_signer},
    math::{checked_add, checked_sub},
    pda::{create_pda, verify_pda},
    state::{Config, OrderAccount},
    terminalize::terminalize_live_order,
};

fn err(e: GatewayError) -> ProgramError {
    ProgramError::from(e)
}

/// order_bump(1) vault_authority_bump(1) order_id(32) fee(8) = 42 bytes.
const IX_LEN: usize = 1 + 1 + 32 + 8;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), ProgramError> {
    let [
        aggregator_signer,
        config_ai,
        order_ai,
        vault_token_account,
        vault_authority_ai,
        refund_token_account,
        treasury_token_account,
        token_program_ai,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if data.len() != IX_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let order_bump = data[0];
    let vault_authority_bump = data[1];
    let mut order_id = [0u8; 32];
    order_id.copy_from_slice(&data[2..34]);
    let fee = u64::from_le_bytes(data[34..42].try_into().unwrap());

    require_signer(aggregator_signer).map_err(err)?;
    if token_program_ai.address().as_array() != TOKEN_PROGRAM_ID.as_array() {
        return Err(err(GatewayError::InvalidTokenProgram));
    }

    require_owned_by_program(config_ai, program_id).map_err(err)?;
    let config = {
        let d = config_ai.try_borrow().map_err(|_| err(GatewayError::InvalidAccountTag))?;
        Config::read_from(&d).map_err(err)?
    };
    if !addresses_eq(aggregator_signer.address(), &config.aggregator) {
        return Err(err(GatewayError::OnlyAggregator));
    }

    verify_pda(order_ai.address(), &[SEED_ORDER, &order_id], order_bump, program_id).map_err(err)?;
    let vault_authority = create_pda(&[SEED_VAULT_AUTHORITY], vault_authority_bump, program_id).map_err(err)?;
    verify_pda(vault_authority_ai.address(), &[SEED_VAULT_AUTHORITY], vault_authority_bump, program_id)
        .map_err(err)?;

    require_owned_by_program(order_ai, program_id).map_err(err)?;
    let order = {
        let d = order_ai.try_borrow().map_err(|_| err(GatewayError::InvalidAccountTag))?;
        match OrderAccount::load(&d).map_err(err)? {
            OrderAccount::Live(o) => o,
            OrderAccount::Tombstone(t) if t.is_fulfilled => return Err(err(GatewayError::OrderFulfilled)),
            OrderAccount::Tombstone(t) if t.is_refunded => return Err(err(GatewayError::OrderRefunded)),
            OrderAccount::Tombstone(_) => return Err(err(GatewayError::InvalidStatus)),
        }
    };

    if order.protocol_fee < fee {
        return Err(err(GatewayError::FeeExceedsProtocolFee));
    }

    let vault_info = crate::token::read_token_account(vault_token_account).map_err(err)?;
    if !addresses_eq(&vault_info.mint, &order.mint) || !addresses_eq(&vault_info.owner, &vault_authority) {
        return Err(err(GatewayError::InvalidTokenAccountOwner));
    }
    let refund_info = crate::token::read_token_account(refund_token_account).map_err(err)?;
    if !addresses_eq(&refund_info.mint, &order.mint) || !addresses_eq(&refund_info.owner, &order.refund_address) {
        return Err(err(GatewayError::InvalidTokenAccountOwner));
    }

    let vault_bump_arr = [vault_authority_bump];
    let vault_seeds = [Seed::from(SEED_VAULT_AUTHORITY), Seed::from(&vault_bump_arr)];

    if fee > 0 {
        let treasury_info = crate::token::read_token_account(treasury_token_account).map_err(err)?;
        if !addresses_eq(&treasury_info.mint, &order.mint) || !addresses_eq(&treasury_info.owner, &config.treasury) {
            return Err(err(GatewayError::InvalidTokenAccountOwner));
        }
        Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
            vault_token_account,
            treasury_token_account,
            vault_authority_ai,
            fee,
        )
        .invoke_signed(&[Signer::from(&vault_seeds)])?;
    }

    let refund_amount = checked_sub(order.amount, fee).map_err(err)?;
    let total_refund = checked_add(refund_amount, order.sender_fee).map_err(err)?;
    Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
        vault_token_account,
        refund_token_account,
        vault_authority_ai,
        total_refund,
    )
    .invoke_signed(&[Signer::from(&vault_seeds)])?;

    terminalize_live_order(order_ai, aggregator_signer, false, true).map_err(err)?;

    OrderRefundedEvent { fee, order_id }.emit();

    Ok(())
}
