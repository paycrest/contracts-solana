#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod bytes;
pub mod constants;
pub mod errors;
pub mod events;
pub mod hash;
pub mod instructions;
pub mod math;
pub mod pda;
pub mod state;
pub mod terminalize;
pub mod token;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use errors::GatewayError;

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "Paycrest Gateway",
    project_url: "https://paycrest.io",
    contacts: "email:engineering@paycrest.io",
    policy: "Report suspected vulnerabilities to engineering@paycrest.io. Please include the program id, a description of the issue, and reproduction steps. We ask that you give us a reasonable window to investigate and remediate before any public disclosure.",
    preferred_languages: "en",
    source_code: "https://github.com/paycrest/contracts-solana"
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use super::process_instruction;

    pinocchio::program_entrypoint!(process_instruction);
    pinocchio::default_allocator!();
    pinocchio::nostd_panic_handler!();
}

/// Opcodes. Append-only — same rule as `errors.rs`: renumbering changes
/// the meaning of every already-encoded instruction.
#[repr(u8)]
enum Opcode {
    Initialize = 0,
    SetTokenSupport = 1,
    SetTokenFeeSettings = 2,
    UpdateProtocolAddress = 3,
    TransferOwnership = 4,
    AcceptOwnership = 5,
    Pause = 6,
    Unpause = 7,
    SetCaps = 8,
    CreateOrder = 9,
    SettleOut = 10,
    SettleIn = 11,
    Refund = 12,
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::from(GatewayError::InvalidStatus))?;

    match *discriminator {
        d if d == Opcode::Initialize as u8 => instructions::admin::initialize(program_id, accounts, data),
        d if d == Opcode::SetTokenSupport as u8 => {
            instructions::admin::set_token_support(program_id, accounts, data)
        }
        d if d == Opcode::SetTokenFeeSettings as u8 => {
            instructions::admin::set_token_fee_settings(program_id, accounts, data)
        }
        d if d == Opcode::UpdateProtocolAddress as u8 => {
            instructions::admin::update_protocol_address(program_id, accounts, data)
        }
        d if d == Opcode::TransferOwnership as u8 => {
            instructions::admin::transfer_ownership(program_id, accounts, data)
        }
        d if d == Opcode::AcceptOwnership as u8 => {
            instructions::admin::accept_ownership(program_id, accounts, data)
        }
        d if d == Opcode::Pause as u8 => instructions::admin::pause(program_id, accounts, data),
        d if d == Opcode::Unpause as u8 => instructions::admin::unpause(program_id, accounts, data),
        d if d == Opcode::SetCaps as u8 => instructions::admin::set_caps(program_id, accounts, data),
        d if d == Opcode::CreateOrder as u8 => {
            instructions::create_order::process(program_id, accounts, data)
        }
        d if d == Opcode::SettleOut as u8 => instructions::settle_out::process(program_id, accounts, data),
        d if d == Opcode::SettleIn as u8 => instructions::settle_in::process(program_id, accounts, data),
        d if d == Opcode::Refund as u8 => instructions::refund::process(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
