//! D13 — Mollusk end-to-end smoke test. This is the layer that proves the
//! *compiled* `paycrest_gateway.so` actually works: correct entrypoint
//! wiring, correct CPI into the System Program to create the `Config` PDA,
//! correct byte-level state writes — none of which the native `cargo test`
//! unit tests in `program/src` can exercise, since those never execute the
//! real BPF binary.
//!
//! Ix data and account ordering here are hand-encoded exactly as an
//! external client (the aggregator, or the TS client in `ts/`) would build
//! them — not reused from the program crate's own types — so a bug in the
//! program's own encoder can't hide from this test.

#[cfg(test)]
mod tests {
    use mollusk_svm::{result::Check, Mollusk};
    use solana_account::Account;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_pubkey::Pubkey;

    const CONFIG_LEN: usize = 235;
    const TAG_CONFIG: [u8; 8] = [0x9b, 0x0c, 0xaa, 0xe0, 0x1e, 0xfa, 0xcc, 0x82];

    fn mollusk(program_id: &Pubkey) -> Mollusk {
        std::env::set_var("SBF_OUT_DIR", concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy"));
        Mollusk::new(program_id, "paycrest_gateway")
    }

    fn initialize_ix_data(bump: u8, chain_id: u64) -> Vec<u8> {
        let mut data = vec![0u8, bump]; // opcode 0 = Initialize
        data.extend_from_slice(&chain_id.to_le_bytes());
        data
    }

    #[test]
    fn initialize_creates_config_pda_with_correct_state() {
        let program_id = Pubkey::new_unique();
        let mollusk = mollusk(&program_id);

        let payer = Pubkey::new_unique();
        let (config_pda, bump) = Pubkey::find_program_address(&[b"config"], &program_id);
        let chain_id: u64 = 900_002; // devnet band, D3/O2

        let payer_account = Account::new(10_000_000_000, 0, &solana_sdk_ids::system_program::id());
        let config_account = Account::new(0, 0, &solana_sdk_ids::system_program::id());
        let system_program_account =
            mollusk_svm::program::keyed_account_for_system_program().1;

        let instruction = Instruction::new_with_bytes(
            program_id,
            &initialize_ix_data(bump, chain_id),
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
            ],
        );

        let rent_exempt_lamports = mollusk.sysvars.rent.minimum_balance(CONFIG_LEN);

        let result = mollusk.process_and_validate_instruction(
            &instruction,
            &[
                (payer, payer_account),
                (config_pda, config_account),
                (solana_sdk_ids::system_program::id(), system_program_account),
            ],
            &[
                Check::success(),
                Check::account(&config_pda)
                    .owner(&program_id)
                    .lamports(rent_exempt_lamports)
                    .space(CONFIG_LEN)
                    .build(),
            ],
        );

        // Verify the account tag and owner field independently of Mollusk's
        // Check builder, to pin the exact byte layout `state/config.rs`
        // promises — this is the check that would catch a discriminator
        // or offset regression that `Check::account` wouldn't notice.
        let final_config = result
            .resulting_accounts
            .iter()
            .find(|(pk, _)| *pk == config_pda)
            .map(|(_, acc)| acc.data.clone())
            .expect("config account must exist after initialize");

        assert_eq!(final_config.len(), CONFIG_LEN);
        assert_eq!(&final_config[0..8], &TAG_CONFIG, "account discriminator mismatch");
        assert_eq!(final_config[10], 0, "paused must start false");
        assert_eq!(&final_config[11..43], payer.as_ref(), "owner must be the initialize() signer");
        // chain_id at offset 139, 8 bytes LE (Config::OFF_CHAIN_ID).
        assert_eq!(&final_config[139..147], &chain_id.to_le_bytes());
        // max_bps at offset 147, must be 100_000 (Gateway.sol's MAX_BPS).
        assert_eq!(&final_config[147..155], &100_000u64.to_le_bytes());
    }

    #[test]
    fn initialize_rejects_wrong_config_pda() {
        let program_id = Pubkey::new_unique();
        let mollusk = mollusk(&program_id);

        let payer = Pubkey::new_unique();
        let (_correct_config_pda, bump) = Pubkey::find_program_address(&[b"config"], &program_id);
        // A random address is not the derived PDA for seeds ["config"] —
        // the program's own verify_pda check (not just the runtime's
        // signer-seed matching) must reject this before ever attempting
        // CreateAccount.
        let wrong_pda = Pubkey::new_unique();

        let payer_account = Account::new(10_000_000_000, 0, &solana_sdk_ids::system_program::id());
        let wrong_account = Account::new(0, 0, &solana_sdk_ids::system_program::id());
        let system_program_account = mollusk_svm::program::keyed_account_for_system_program().1;

        let instruction = Instruction::new_with_bytes(
            program_id,
            &initialize_ix_data(bump, 900_002),
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(wrong_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
            ],
        );

        mollusk.process_and_validate_instruction(
            &instruction,
            &[
                (payer, payer_account),
                (wrong_pda, wrong_account),
                (solana_sdk_ids::system_program::id(), system_program_account),
            ],
            &[Check::err(solana_program_error::ProgramError::Custom(21))],
        );
    }

    #[test]
    fn initialize_rejects_noncanonical_config_bump() {
        let program_id = Pubkey::new_unique();
        let mollusk = mollusk(&program_id);

        let payer = Pubkey::new_unique();
        let (config_pda, canonical_bump) = Pubkey::find_program_address(&[b"config"], &program_id);
        let wrong_bump = canonical_bump.wrapping_sub(1);

        let payer_account = Account::new(10_000_000_000, 0, &solana_sdk_ids::system_program::id());
        let config_account = Account::new(0, 0, &solana_sdk_ids::system_program::id());
        let system_program_account = mollusk_svm::program::keyed_account_for_system_program().1;

        let instruction = Instruction::new_with_bytes(
            program_id,
            &initialize_ix_data(wrong_bump, 900_002),
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
            ],
        );

        mollusk.process_and_validate_instruction(
            &instruction,
            &[
                (payer, payer_account),
                (config_pda, config_account),
                (solana_sdk_ids::system_program::id(), system_program_account),
            ],
            &[Check::err(solana_program_error::ProgramError::Custom(21))],
        );
    }
}
