//! Admin/settings instructions — the Solana equivalent of
//! `GatewaySettingManager.sol` plus `Gateway.sol`'s `pause`/`unpause`.
//!
//! Ownership follows `Ownable2StepUpgradeable` exactly: `transfer_ownership`
//! only arms `pending_owner`; `accept_ownership` (signed by the pending
//! owner, not the current one) completes the handover.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address,
};
use pinocchio_system::create_account_with_minimum_balance_signed;

use crate::{
    constants::{SEED_CONFIG, SEED_TOKEN_CONFIG},
    errors::GatewayError,
    instructions::{addresses_eq, is_zero_address, require_owned_by_program, require_signer},
    pda::verify_pda,
    state::{Config, TokenConfig},
};

fn err(e: GatewayError) -> ProgramError {
    ProgramError::from(e)
}

fn load_config_checked(config_ai: &AccountView, program_id: &Address) -> Result<Config, ProgramError> {
    require_owned_by_program(config_ai, program_id).map_err(err)?;
    let data = config_ai.try_borrow().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    Config::read_from(&data).map_err(err)
}

fn require_owner(config: &Config, caller: &AccountView) -> Result<(), ProgramError> {
    require_signer(caller).map_err(err)?;
    if !addresses_eq(caller.address(), &config.owner) {
        return Err(err(GatewayError::OnlyOwner));
    }
    Ok(())
}

/// `initialize` — mirrors `Gateway.initialize()`: sets `MAX_BPS` and the
/// owner (Ownable2Step). Treasury and aggregator start zeroed, set
/// separately via `update_protocol_address` (matching the EVM deployment
/// sequence exactly, not collapsing it into one call).
pub fn initialize(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), ProgramError> {
    let [payer, config_ai, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require_signer(payer).map_err(err)?;
    if data.len() != 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let bump = data[0];
    let chain_id = u64::from_le_bytes(data[1..9].try_into().unwrap());

    verify_pda(config_ai.address(), &[SEED_CONFIG], bump, program_id).map_err(err)?;

    let bump_arr = [bump];
    let seeds = [Seed::from(SEED_CONFIG), Seed::from(&bump_arr)];
    let signer = Signer::from(&seeds);

    create_account_with_minimum_balance_signed(
        config_ai,
        Config::LEN,
        program_id,
        payer,
        None,
        &[signer],
    )?;

    let config = Config::new_initial(
        bump,
        *payer.address(),
        Address::new_from_array([0u8; 32]),
        Address::new_from_array([0u8; 32]),
        chain_id,
    );
    let mut out = config_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    config.write_to(&mut out).map_err(err)?;
    Ok(())
}

/// `updateProtocolAddress` — same "refuses a no-op write" guard as
/// `GatewaySettingManager.sol` (`require(current != value)`), which is not
/// a one-time lock, just a redundant-write guard.
pub fn update_protocol_address(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> Result<(), ProgramError> {
    let [owner_ai, config_ai] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let what = data[0];
    let mut new_addr_bytes = [0u8; 32];
    new_addr_bytes.copy_from_slice(&data[1..33]);
    let new_address = Address::new_from_array(new_addr_bytes);

    let mut config = load_config_checked(config_ai, program_id)?;
    require_owner(&config, owner_ai)?;

    if is_zero_address(&new_address) {
        return Err(err(GatewayError::ZeroAddress));
    }

    match what {
        0 => {
            if addresses_eq(&config.treasury, &new_address) {
                return Err(err(GatewayError::TreasuryAlreadySet));
            }
            config.treasury = new_address;
        }
        1 => {
            if addresses_eq(&config.aggregator, &new_address) {
                return Err(err(GatewayError::AggregatorAlreadySet));
            }
            config.aggregator = new_address;
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    let mut out = config_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    config.write_to(&mut out).map_err(err)?;
    Ok(())
}

pub fn transfer_ownership(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> Result<(), ProgramError> {
    let [owner_ai, config_ai] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut new_owner_bytes = [0u8; 32];
    new_owner_bytes.copy_from_slice(data);
    let new_owner = Address::new_from_array(new_owner_bytes);

    let mut config = load_config_checked(config_ai, program_id)?;
    require_owner(&config, owner_ai)?;

    config.pending_owner = new_owner;
    let mut out = config_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    config.write_to(&mut out).map_err(err)?;
    Ok(())
}

pub fn accept_ownership(
    program_id: &Address,
    accounts: &mut [AccountView],
    _data: &[u8],
) -> Result<(), ProgramError> {
    let [pending_owner_ai, config_ai] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require_signer(pending_owner_ai).map_err(err)?;

    let mut config = load_config_checked(config_ai, program_id)?;
    if is_zero_address(&config.pending_owner) || !addresses_eq(pending_owner_ai.address(), &config.pending_owner) {
        return Err(err(GatewayError::OnlyPendingOwner));
    }

    config.owner = config.pending_owner;
    config.pending_owner = Address::new_from_array([0u8; 32]);
    let mut out = config_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    config.write_to(&mut out).map_err(err)?;
    Ok(())
}

pub fn pause(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> Result<(), ProgramError> {
    set_paused(program_id, accounts, true)
}

pub fn unpause(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> Result<(), ProgramError> {
    set_paused(program_id, accounts, false)
}

fn set_paused(program_id: &Address, accounts: &mut [AccountView], paused: bool) -> Result<(), ProgramError> {
    let [owner_ai, config_ai] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut config = load_config_checked(config_ai, program_id)?;
    require_owner(&config, owner_ai)?;
    config.paused = paused;
    let mut out = config_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    config.write_to(&mut out).map_err(err)?;
    Ok(())
}

/// D15 — rollout caps, owner-tunable, no EVM equivalent.
pub fn set_caps(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> Result<(), ProgramError> {
    let [owner_ai, config_ai] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let max_order_amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let global_escrow_cap = u64::from_le_bytes(data[8..16].try_into().unwrap());

    let mut config = load_config_checked(config_ai, program_id)?;
    require_owner(&config, owner_ai)?;
    config.max_order_amount = max_order_amount;
    config.global_escrow_cap = global_escrow_cap;
    let mut out = config_ai.try_borrow_mut().map_err(|_| err(GatewayError::InvalidAccountTag))?;
    config.write_to(&mut out).map_err(err)?;
    Ok(())
}

/// `settingManagerBool('token', ...)` — registers or updates a token's
/// support flag. Creates the `TokenConfig` PDA on first use.
pub fn set_token_support(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> Result<(), ProgramError> {
    let [owner_ai, config_ai, mint_ai, token_config_ai, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let bump = data[0];
    let status = data[1];
    if status != 1 && status != 2 {
        return Err(err(GatewayError::InvalidStatus));
    }
    let is_supported = status == 1;

    let config = load_config_checked(config_ai, program_id)?;
    require_owner(&config, owner_ai)?;

    verify_pda(
        token_config_ai.address(),
        &[SEED_TOKEN_CONFIG, mint_ai.address().as_array()],
        bump,
        program_id,
    )
    .map_err(err)?;

    if token_config_ai.owned_by(program_id) && token_config_ai.data_len() == TokenConfig::LEN {
        // Already registered — just flip the flag, preserving fee settings.
        let mut existing = {
            let d = token_config_ai
                .try_borrow()
                .map_err(|_| err(GatewayError::InvalidAccountTag))?;
            TokenConfig::read_from(&d).map_err(err)?
        };
        existing.is_supported = is_supported;
        let mut out = token_config_ai
            .try_borrow_mut()
            .map_err(|_| err(GatewayError::InvalidAccountTag))?;
        existing.write_to(&mut out).map_err(err)?;
        return Ok(());
    }

    let bump_arr = [bump];
    let seeds = [
        Seed::from(SEED_TOKEN_CONFIG),
        Seed::from(mint_ai.address().as_array()),
        Seed::from(&bump_arr),
    ];
    let signer = Signer::from(&seeds);

    create_account_with_minimum_balance_signed(
        token_config_ai,
        TokenConfig::LEN,
        program_id,
        owner_ai,
        None,
        &[signer],
    )?;

    let mut tc = TokenConfig::new(bump, *mint_ai.address());
    tc.is_supported = is_supported;
    let mut out = token_config_ai
        .try_borrow_mut()
        .map_err(|_| err(GatewayError::InvalidAccountTag))?;
    tc.write_to(&mut out).map_err(err)?;
    Ok(())
}

/// `setTokenFeeSettings` — requires the token already be supported,
/// exactly like the EVM guard `require(_isTokenSupported[token] == 1, ...)`.
pub fn set_token_fee_settings(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> Result<(), ProgramError> {
    let [owner_ai, config_ai, token_config_ai] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let sender_to_treasury = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let provider_to_treasury = u64::from_le_bytes(data[8..16].try_into().unwrap());
    TokenConfig::validate_bps(sender_to_treasury, provider_to_treasury).map_err(err)?;

    let config = load_config_checked(config_ai, program_id)?;
    require_owner(&config, owner_ai)?;

    require_owned_by_program(token_config_ai, program_id).map_err(err)?;
    let mut tc = {
        let d = token_config_ai
            .try_borrow()
            .map_err(|_| err(GatewayError::InvalidAccountTag))?;
        TokenConfig::read_from(&d).map_err(err)?
    };
    if !tc.is_supported {
        return Err(err(GatewayError::TokenNotSupported));
    }
    tc.sender_to_treasury = sender_to_treasury;
    tc.provider_to_treasury = provider_to_treasury;

    let mut out = token_config_ai
        .try_borrow_mut()
        .map_err(|_| err(GatewayError::InvalidAccountTag))?;
    tc.write_to(&mut out).map_err(err)?;
    Ok(())
}
