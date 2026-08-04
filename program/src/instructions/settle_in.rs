//! `settle_in` — mirrors `Gateway.settleIn` / `_bookSettleInAndPayFees`
//! (D16). Permissionless: any LP may call it. The Order PDA is allocated
//! directly at tombstone size (16 bytes) — a pay-in order is terminal the
//! instant it exists, so there is no live-then-shrink step (D8/D16). Field
//! values EVM would persist to the `Order` struct (`sender`, `amount`,
//! `protocolFee`, ...) are carried only in the `SettleIn` event, since
//! nothing reads them from storage afterward.
//!
//! Order of operations mirrors EVM's `settleIn` exactly: validate, pull
//! funds in from the LP, book (create the tombstone — this is what arms
//! `OrderAlreadyExists` for any future replay of this `order_id`), *then*
//! pay out treasury/rebate/recipient, then split the sender fee.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address,
};
use pinocchio_system::create_account_with_minimum_balance_signed;
use pinocchio_token::instructions::transfer::Transfer;

use crate::{
    constants::{LAYOUT_VERSION, SEED_ORDER, SEED_VAULT_AUTHORITY, TOKEN_PROGRAM_ID},
    errors::GatewayError,
    events::SettleInEvent,
    instructions::{addresses_eq, is_zero_address, require_owned_by_program, require_signer},
    math::{checked_sub, mul_div_floor},
    pda::verify_pda,
    state::{Config, OrderTombstone, TokenConfig},
};

fn err(e: GatewayError) -> ProgramError {
    ProgramError::from(e)
}

/// order_bump(1) vault_authority_bump(1) order_id(32) amount(8)
/// sender_fee_recipient(32) sender_fee(8) recipient(32) rate(8)
/// rebate_percent(8) = 130 bytes.
const IX_LEN: usize = 1 + 1 + 32 + 8 + 32 + 8 + 32 + 8 + 8;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), ProgramError> {
    let [
        lp_signer,
        lp_source_token_account,
        order_ai,
        config_ai,
        token_config_ai,
        mint_ai,
        vault_token_account,
        vault_authority_ai,
        recipient_token_account,
        treasury_token_account,
        sender_fee_recipient_token_account,
        token_program_ai,
        _system_program,
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
    let amount = u64::from_le_bytes(data[34..42].try_into().unwrap());
    let mut sender_fee_recipient_bytes = [0u8; 32];
    sender_fee_recipient_bytes.copy_from_slice(&data[42..74]);
    let sender_fee_recipient = Address::new_from_array(sender_fee_recipient_bytes);
    let sender_fee = u64::from_le_bytes(data[74..82].try_into().unwrap());
    let mut recipient_bytes = [0u8; 32];
    recipient_bytes.copy_from_slice(&data[82..114]);
    let recipient = Address::new_from_array(recipient_bytes);
    let rate = u64::from_le_bytes(data[114..122].try_into().unwrap());
    let rebate_percent = u64::from_le_bytes(data[122..130].try_into().unwrap());

    require_signer(lp_signer).map_err(err)?;
    if token_program_ai.address().as_array() != TOKEN_PROGRAM_ID.as_array() {
        return Err(err(GatewayError::InvalidTokenProgram));
    }

    require_owned_by_program(config_ai, program_id).map_err(err)?;
    let config = {
        let d = config_ai.try_borrow().map_err(|_| err(GatewayError::InvalidAccountTag))?;
        Config::read_from(&d).map_err(err)?
    };
    if config.paused {
        return Err(err(GatewayError::ContractPaused));
    }
    if rebate_percent > config.max_bps {
        return Err(err(GatewayError::InvalidRebatePercent));
    }

    require_owned_by_program(token_config_ai, program_id).map_err(err)?;
    let token_config = {
        let d = token_config_ai
            .try_borrow()
            .map_err(|_| err(GatewayError::InvalidAccountTag))?;
        TokenConfig::read_from(&d).map_err(err)?
    };
    if !token_config.is_supported {
        return Err(err(GatewayError::TokenNotSupported));
    }
    if !addresses_eq(&token_config.mint, mint_ai.address()) {
        return Err(err(GatewayError::InvalidMint));
    }

    // -- `_handler(token, amount, /* refundAddress slot = */ recipient, senderFeeRecipient, senderFee)` --
    if amount == 0 {
        return Err(err(GatewayError::AmountIsZero));
    }
    if is_zero_address(&recipient) {
        return Err(err(GatewayError::ZeroRefundAddress));
    }
    if sender_fee != 0 && is_zero_address(&sender_fee_recipient) {
        return Err(err(GatewayError::InvalidSenderFeeRecipient));
    }

    if config.max_order_amount != 0 && amount > config.max_order_amount {
        return Err(err(GatewayError::AmountExceedsCap));
    }

    crate::token::assert_existing_token_account_for(recipient_token_account, mint_ai.address(), &recipient)
        .map_err(err)?;

    let vault_authority =
        crate::pda::create_pda(&[SEED_VAULT_AUTHORITY], vault_authority_bump, program_id).map_err(err)?;
    verify_pda(vault_authority_ai.address(), &[SEED_VAULT_AUTHORITY], vault_authority_bump, program_id)
        .map_err(err)?;
    let vault_info = crate::token::read_token_account(vault_token_account).map_err(err)?;
    if !addresses_eq(&vault_info.mint, mint_ai.address()) || !addresses_eq(&vault_info.owner, &vault_authority) {
        return Err(err(GatewayError::InvalidTokenAccountOwner));
    }

    let source_info = crate::token::read_token_account(lp_source_token_account).map_err(err)?;
    if !addresses_eq(&source_info.mint, mint_ai.address()) || !addresses_eq(&source_info.owner, lp_signer.address())
    {
        return Err(err(GatewayError::InvalidTokenAccountOwner));
    }

    verify_pda(order_ai.address(), &[SEED_ORDER, &order_id], order_bump, program_id).map_err(err)?;

    // -- Inbound: LP -> vault, amount + sender_fee --
    let total_in = amount.checked_add(sender_fee).ok_or(err(GatewayError::MathOverflow))?;
    Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
        lp_source_token_account,
        vault_token_account,
        lp_signer,
        total_in,
    )
    .invoke()?;

    // -- `_bookSettleInAndPayFees` fee math, live settings --
    let mut amount_to_settle = amount;
    let mut gross_treasury_fee = 0u64;
    if token_config.provider_to_treasury > 0 {
        gross_treasury_fee = mul_div_floor(amount, token_config.provider_to_treasury, config.max_bps).map_err(err)?;
        if gross_treasury_fee > 0 {
            amount_to_settle = checked_sub(amount, gross_treasury_fee).map_err(err)?;
        }
    }
    let mut treasury_fee = gross_treasury_fee;
    let mut rebate_amount = 0u64;
    if treasury_fee > 0 && rebate_percent > 0 {
        rebate_amount = mul_div_floor(treasury_fee, rebate_percent, config.max_bps).map_err(err)?;
        treasury_fee = checked_sub(treasury_fee, rebate_amount).map_err(err)?;
    }

    // -- Book: create the tombstone directly (arms OrderAlreadyExists for
    // this id, D5) before any outbound transfer, matching EVM's ordering. --
    let order_bump_arr = [order_bump];
    let order_seeds = [Seed::from(SEED_ORDER), Seed::from(&order_id), Seed::from(&order_bump_arr)];
    create_account_with_minimum_balance_signed(
        order_ai,
        OrderTombstone::LEN,
        program_id,
        lp_signer,
        None,
        &[Signer::from(&order_seeds)],
    )?;
    {
        let mut out = order_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
        OrderTombstone {
            version: LAYOUT_VERSION,
            bump: order_bump,
            is_fulfilled: true,
            is_refunded: false,
        }
        .write_to(&mut out)
        .map_err(err)?;
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
    if rebate_amount > 0 {
        Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
            vault_token_account,
            lp_source_token_account,
            vault_authority_ai,
            rebate_amount,
        )
        .invoke_signed(&[Signer::from(&vault_seeds)])?;
    }
    Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
        vault_token_account,
        recipient_token_account,
        vault_authority_ai,
        amount_to_settle,
    )
    .invoke_signed(&[Signer::from(&vault_seeds)])?;

    if sender_fee != 0 {
        let sender_fee_treasury_amount =
            mul_div_floor(sender_fee, token_config.sender_to_treasury, config.max_bps).map_err(err)?;
        let sender_amount = checked_sub(sender_fee, sender_fee_treasury_amount).map_err(err)?;

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

        crate::events::SenderFeeTransferredEvent {
            order_id,
            sender: sender_fee_recipient,
            amount: sender_amount,
        }
        .emit();
        crate::events::TransferFeeSplitEvent {
            order_id,
            sender_amount,
            aggregator_amount: sender_fee_treasury_amount,
        }
        .emit();
    }

    SettleInEvent {
        order_id,
        liquidity_provider: *lp_signer.address(),
        recipient,
        amount: amount_to_settle,
        mint: *mint_ai.address(),
        aggregator_fee: gross_treasury_fee,
        rate,
        rebate_percent,
    }
    .emit();

    Ok(())
}
