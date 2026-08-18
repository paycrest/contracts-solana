//! `create_order` — mirrors `Gateway.createOrder` (D3, D6, D9, D10, D15).
//!
//! Account order matches the D6 budget table: sponsor fee payer, depositor,
//! depositor source ATA, Order PDA, vault ATA, config, token config, mint,
//! refund ATA (read-only existence check), token program, system program.
//! This is the instruction the whole transaction-size analysis in the plan
//! is about — it carries the X25519-encrypted recipient blob as trailing
//! instruction data and needs a v0 transaction + ALT to fit (D6/O9); the
//! program itself doesn't know or care how the client assembled the
//! transaction, only that the blob arrives as bytes.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address,
};
use pinocchio_system::create_account_with_minimum_balance_signed;
use pinocchio_token::instructions::transfer::Transfer;

use crate::{
    constants::{MESSAGE_HASH_MAX_SIZE, SEED_ORDER, SEED_VAULT_AUTHORITY, TOKEN_PROGRAM_ID},
    errors::GatewayError,
    events::OrderCreated,
    hash::order_id_preimage_hash,
    instructions::{addresses_eq, is_zero_address, load_config, load_token_config, require_signer},
    math::mul_div_floor,
    pda::{create_pda, verify_pda},
    state::OrderLive,
};

fn err(e: GatewayError) -> ProgramError {
    ProgramError::from(e)
}

/// Fixed-width prefix of instruction data, before the variable-length
/// message hash: order_bump(1) vault_bump(1) nonce(8) amount(8) rate(8)
/// sender_fee(8) sender_fee_recipient(32) refund_address(32) = 98 bytes.
const FIXED_LEN: usize = 1 + 1 + 8 + 8 + 8 + 8 + 32 + 32;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), ProgramError> {
    let [
        fee_payer,
        depositor,
        depositor_token_account,
        order_ai,
        vault_token_account,
        config_ai,
        token_config_ai,
        mint_ai,
        refund_token_account,
        token_program_ai,
        _system_program,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if data.len() < FIXED_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let order_bump = data[0];
    let vault_bump = data[1];
    let nonce = u64::from_le_bytes(data[2..10].try_into().unwrap());
    let amount = u64::from_le_bytes(data[10..18].try_into().unwrap());
    let rate = u64::from_le_bytes(data[18..26].try_into().unwrap());
    let sender_fee = u64::from_le_bytes(data[26..34].try_into().unwrap());
    let mut sender_fee_recipient_bytes = [0u8; 32];
    sender_fee_recipient_bytes.copy_from_slice(&data[34..66]);
    let sender_fee_recipient = Address::new_from_array(sender_fee_recipient_bytes);
    let mut refund_address_bytes = [0u8; 32];
    refund_address_bytes.copy_from_slice(&data[66..98]);
    let refund_address = Address::new_from_array(refund_address_bytes);
    let message_hash = &data[FIXED_LEN..];

    require_signer(fee_payer).map_err(err)?;
    require_signer(depositor).map_err(err)?;

    if token_program_ai.address().as_array() != TOKEN_PROGRAM_ID.as_array() {
        return Err(err(GatewayError::InvalidTokenProgram));
    }

    // -- Config: paused + caps (D0/D15) --
    let config = load_config(config_ai, program_id).map_err(err)?;
    if config.paused {
        return Err(err(GatewayError::ContractPaused));
    }
    if config.max_order_amount != 0 && amount > config.max_order_amount {
        return Err(err(GatewayError::AmountExceedsCap));
    }

    // -- TokenConfig: supported + fee settings --
    let token_config = load_token_config(token_config_ai, mint_ai.address(), program_id).map_err(err)?;
    if !token_config.is_supported {
        return Err(err(GatewayError::TokenNotSupported));
    }
    if !addresses_eq(&token_config.mint, mint_ai.address()) {
        return Err(err(GatewayError::InvalidMint));
    }

    // -- `_handler` checks, EVM-exact order --
    if amount == 0 {
        return Err(err(GatewayError::AmountIsZero));
    }
    if is_zero_address(&refund_address) {
        return Err(err(GatewayError::ZeroRefundAddress));
    }
    if sender_fee != 0 && is_zero_address(&sender_fee_recipient) {
        return Err(err(GatewayError::InvalidSenderFeeRecipient));
    }
    if message_hash.is_empty() {
        return Err(err(GatewayError::InvalidMessageHash));
    }
    if message_hash.len() > MESSAGE_HASH_MAX_SIZE {
        return Err(err(GatewayError::InvalidMessageHash));
    }

    // -- D10: refund_address must already have a token account for mint --
    crate::token::assert_existing_token_account_for(refund_token_account, mint_ai.address(), &refund_address)
        .map_err(|_| err(GatewayError::MissingRefundTokenAccount))?;

    // -- Vault ATA: must be owned by the canonical vault authority PDA --
    let vault_authority = create_pda(&[SEED_VAULT_AUTHORITY], vault_bump, program_id).map_err(err)?;
    verify_pda(&vault_authority, &[SEED_VAULT_AUTHORITY], vault_bump, program_id).map_err(err)?;
    let vault_info = crate::token::read_token_account(vault_token_account)
        .map_err(|_| err(GatewayError::InvalidTokenAccountOwner))?;
    if !addresses_eq(&vault_info.mint, mint_ai.address()) {
        return Err(err(GatewayError::InvalidMint));
    }
    if !addresses_eq(&vault_info.owner, &vault_authority) {
        return Err(err(GatewayError::InvalidTokenAccountOwner));
    }
    if config.global_escrow_cap != 0 {
        let projected = vault_info
            .amount
            .checked_add(amount)
            .and_then(|v| v.checked_add(sender_fee))
            .ok_or(err(GatewayError::MathOverflow))?;
        if projected > config.global_escrow_cap {
            return Err(err(GatewayError::EscrowCapExceeded));
        }
    }

    // -- Depositor source ATA --
    let source_info = crate::token::read_token_account(depositor_token_account)
        .map_err(|_| err(GatewayError::InvalidTokenAccountOwner))?;
    if !addresses_eq(&source_info.mint, mint_ai.address()) {
        return Err(err(GatewayError::InvalidMint));
    }
    if !addresses_eq(&source_info.owner, depositor.address()) {
        return Err(err(GatewayError::InvalidTokenAccountOwner));
    }

    // -- D3: order_id = keccak(depositor, nonce, chain_id); Order PDA must match --
    let order_id = order_id_preimage_hash(depositor.address().as_array(), nonce, config.chain_id);
    verify_pda(order_ai.address(), &[SEED_ORDER, &order_id], order_bump, program_id).map_err(err)?;

    // -- protocolFee, computed from live settings at create time; only
    // ever consumed later as the refund fee cap (D14) --
    let protocol_fee = if token_config.provider_to_treasury > 0 {
        mul_div_floor(amount, token_config.provider_to_treasury, config.max_bps).map_err(err)?
    } else {
        0
    };

    // -- Escrow transfer: depositor -> vault, amount + sender_fee.
    // `.invoke()` always CPIs into `TokenProgram::ID` (the pinned legacy
    // Token program), regardless of `token_program_ai` — D9's hard pin is
    // structural here, not just the address check above. --
    let total_in = amount.checked_add(sender_fee).ok_or(err(GatewayError::MathOverflow))?;
    Transfer::<&AccountView, pinocchio_token::TokenProgram>::new(
        depositor_token_account,
        vault_token_account,
        depositor,
        total_in,
    )
    .invoke()?;

    // -- Create the Order PDA (this is also where a reused order_id fails:
    // CreateAccount refuses an already-in-use address, D5) --
    let order_bump_arr = [order_bump];
    let order_seeds = [Seed::from(SEED_ORDER), Seed::from(&order_id), Seed::from(&order_bump_arr)];
    let order_signer = Signer::from(&order_seeds);
    create_account_with_minimum_balance_signed(
        order_ai,
        OrderLive::LEN,
        program_id,
        fee_payer,
        None,
        &[order_signer],
    )?;

    let order = OrderLive {
        version: crate::constants::LAYOUT_VERSION,
        bump: order_bump,
        is_fulfilled: false,
        is_refunded: false,
        sender: *depositor.address(),
        mint: *mint_ai.address(),
        sender_fee_recipient,
        refund_address,
        amount,
        sender_fee,
        protocol_fee,
        current_bps: config.max_bps,
    };
    {
        let mut out = order_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
        order.write_to(&mut out).map_err(err)?;
    }

    // D2 quirk: first field is the refund address, matching what
    // Gateway.sol actually emits under the interface's `sender` name.
    OrderCreated {
        sender: refund_address,
        token: *mint_ai.address(),
        amount,
        protocol_fee,
        order_id,
        rate,
        message_hash,
    }
    .emit();

    Ok(())
}
