//! `settle_out` — mirrors `Gateway.settleOut` (D8, D14). Aggregator-only,
//! partial settlement via `current_bps` decrement, treasury/rebate split
//! computed from *live* `TokenConfig` at settle time (not the `protocol_fee`
//! frozen at `create_order`, which is only ever used as the refund fee cap).

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address,
};
use pinocchio_token::instructions::transfer::Transfer;

use crate::{
    constants::{SEED_ORDER, SEED_VAULT_AUTHORITY, TOKEN_PROGRAM_ID},
    errors::GatewayError,
    events::{SenderFeeTransferredEvent, SettleOutEvent, TransferFeeSplitEvent},
    instructions::{addresses_eq, require_owned_by_program, require_signer},
    math::{checked_add, checked_sub, mul_div_floor},
    pda::verify_pda,
    state::{Config, OrderAccount, OrderLive, TokenConfig},
    terminalize::terminalize_live_order,
};

fn err(e: GatewayError) -> ProgramError {
    ProgramError::from(e)
}

/// order_bump(1) vault_authority_bump(1) split_order_id(32) order_id(32)
/// settle_percent(8) rebate_percent(8) = 82 bytes.
const IX_LEN: usize = 1 + 1 + 32 + 32 + 8 + 8;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), ProgramError> {
    let [
        aggregator_signer,
        config_ai,
        order_ai,
        token_config_ai,
        mint_ai,
        vault_token_account,
        vault_authority_ai,
        liquidity_provider_token_account,
        treasury_token_account,
        sender_fee_recipient_token_account,
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
    let mut split_order_id = [0u8; 32];
    split_order_id.copy_from_slice(&data[2..34]);
    let mut order_id = [0u8; 32];
    order_id.copy_from_slice(&data[34..66]);
    let settle_percent = u64::from_le_bytes(data[66..74].try_into().unwrap());
    let rebate_percent = u64::from_le_bytes(data[74..82].try_into().unwrap());

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
    if rebate_percent > config.max_bps {
        return Err(err(GatewayError::InvalidRebatePercent));
    }

    verify_pda(order_ai.address(), &[SEED_ORDER, &order_id], order_bump, program_id).map_err(err)?;
    verify_pda(
        vault_authority_ai.address(),
        &[SEED_VAULT_AUTHORITY],
        vault_authority_bump,
        program_id,
    )
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

    require_owned_by_program(token_config_ai, program_id).map_err(err)?;
    let token_config = {
        let d = token_config_ai
            .try_borrow()
            .map_err(|_| err(GatewayError::InvalidAccountTag))?;
        TokenConfig::read_from(&d).map_err(err)?
    };
    if !addresses_eq(&token_config.mint, &order.mint) || !addresses_eq(mint_ai.address(), &order.mint) {
        return Err(err(GatewayError::InvalidMint));
    }

    // -- currentOrderBPS captured before decrement, exactly like EVM's
    // local `currentOrderBPS` --
    let current_order_bps = order.current_bps;
    if settle_percent == 0 || settle_percent > current_order_bps {
        return Err(err(GatewayError::InvalidSettlePercent));
    }
    let new_bps = checked_sub(current_order_bps, settle_percent).map_err(err)?;
    let is_final = new_bps == 0;

    let mut lp_amount = mul_div_floor(order.amount, settle_percent, current_order_bps).map_err(err)?;
    let new_order_amount = checked_sub(order.amount, lp_amount).map_err(err)?;

    let mut treasury_fee = 0u64;
    if token_config.provider_to_treasury > 0 {
        treasury_fee = mul_div_floor(lp_amount, token_config.provider_to_treasury, config.max_bps).map_err(err)?;
        lp_amount = checked_sub(lp_amount, treasury_fee).map_err(err)?;
        if rebate_percent > 0 {
            let rebate_amount = mul_div_floor(treasury_fee, rebate_percent, config.max_bps).map_err(err)?;
            treasury_fee = checked_sub(treasury_fee, rebate_amount).map_err(err)?;
            lp_amount = checked_add(lp_amount, rebate_amount).map_err(err)?;
        }
    }

    let vault_bump_arr = [vault_authority_bump];
    let vault_seeds = [Seed::from(SEED_VAULT_AUTHORITY), Seed::from(&vault_bump_arr)];

    if treasury_fee > 0 {
        Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
            vault_token_account,
            treasury_token_account,
            vault_authority_ai,
            treasury_fee,
        )
        .invoke_signed(&[Signer::from(&vault_seeds)])?;
    }
    Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
        vault_token_account,
        liquidity_provider_token_account,
        vault_authority_ai,
        lp_amount,
    )
    .invoke_signed(&[Signer::from(&vault_seeds)])?;

    if is_final && order.sender_fee > 0 {
        let sender_fee_treasury_amount =
            mul_div_floor(order.sender_fee, token_config.sender_to_treasury, config.max_bps).map_err(err)?;
        let sender_amount = checked_sub(order.sender_fee, sender_fee_treasury_amount).map_err(err)?;

        if sender_amount > 0 {
            Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
                vault_token_account,
                sender_fee_recipient_token_account,
                vault_authority_ai,
                sender_amount,
            )
            .invoke_signed(&[Signer::from(&vault_seeds)])?;
        }
        if sender_fee_treasury_amount > 0 {
            Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
                vault_token_account,
                treasury_token_account,
                vault_authority_ai,
                sender_fee_treasury_amount,
            )
            .invoke_signed(&[Signer::from(&vault_seeds)])?;
        }

        SenderFeeTransferredEvent {
            order_id,
            sender: order.sender_fee_recipient,
            amount: sender_amount,
        }
        .emit();
        TransferFeeSplitEvent {
            order_id,
            sender_amount,
            aggregator_amount: sender_fee_treasury_amount,
        }
        .emit();
    }

    if is_final {
        terminalize_live_order(order_ai, aggregator_signer, true, false).map_err(err)?;
    } else {
        let updated = OrderLive {
            current_bps: new_bps,
            amount: new_order_amount,
            ..order
        };
        let mut out = order_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
        updated.write_to(&mut out).map_err(err)?;
    }

    SettleOutEvent {
        split_order_id,
        order_id,
        liquidity_provider: *liquidity_provider_token_account.address(),
        settle_percent,
        rebate_percent,
    }
    .emit();

    Ok(())
}
