use pinocchio::address::Address;

use crate::errors::GatewayError;

/// Derives a PDA from up to 4 base seeds plus a caller-supplied bump, using
/// `create_program_address` (one hash) rather than `find_program_address`
/// (up to 256 hashes). The bump always comes from the client or from
/// stored state — never searched for on-chain, which is what makes this
/// cheap. See D3/§2.1.
pub fn create_pda(seeds: &[&[u8]], bump: u8, program_id: &Address) -> Result<Address, GatewayError> {
    if seeds.len() > 4 {
        return Err(GatewayError::InvalidPda);
    }
    let bump_seed = [bump];
    let mut buf: [&[u8]; 5] = [&[], &[], &[], &[], &[]];
    for (i, s) in seeds.iter().enumerate() {
        buf[i] = s;
    }
    buf[seeds.len()] = &bump_seed;
    Address::create_program_address(&buf[..seeds.len() + 1], program_id)
        .map_err(|_| GatewayError::InvalidPda)
}

/// Verifies that `expected` is exactly the PDA derived from `seeds` + `bump`
/// under `program_id`. Every account passed into an instruction that is
/// supposed to be one of our PDAs must go through this — the alternative
/// (trusting the client-supplied address) is exactly the kind of check
/// Anchor's `#[account(seeds = ...)]` gives for free and Pinocchio does not
/// (D1/R5).
pub fn verify_pda(
    expected: &Address,
    seeds: &[&[u8]],
    bump: u8,
    program_id: &Address,
) -> Result<(), GatewayError> {
    let derived = create_pda(seeds, bump, program_id)?;
    if derived.as_array() != expected.as_array() {
        return Err(GatewayError::InvalidPda);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise `Address::create_program_address`, which only
    // type-checks on host because program/Cargo.toml enables
    // `solana-address`'s `curve25519` feature (see the comment there) —
    // without it, this file would fail `cargo check` outside `build-sbf`.
    #[test]
    fn verify_pda_accepts_the_correct_derivation_and_rejects_a_wrong_bump() {
        let program_id = Address::new_from_array([7u8; 32]);
        let (expected, bump) = Address::find_program_address(&[b"config"], &program_id);

        assert!(verify_pda(&expected, &[b"config"], bump, &program_id).is_ok());

        // Any other bump must not derive the same address (off-curve
        // search guarantees only one bump in [0,255] works, usually not
        // its neighbour).
        let wrong_bump = bump.wrapping_sub(1);
        if wrong_bump != bump {
            // create_program_address may itself Err (on-curve) for the
            // wrong bump, or Ok with a different address. Either way,
            // verify_pda must not accept it as equal to `expected`.
            if let Ok(addr) = create_pda(&[b"config"], wrong_bump, &program_id) {
                assert_ne!(addr.as_array(), expected.as_array());
            }
            assert!(verify_pda(&expected, &[b"config"], wrong_bump, &program_id).is_err());
        }
    }

    #[test]
    fn verify_pda_rejects_wrong_seeds() {
        let program_id = Address::new_from_array([7u8; 32]);
        let (expected, bump) = Address::find_program_address(&[b"config"], &program_id);
        assert!(verify_pda(&expected, &[b"not-config"], bump, &program_id).is_err());
    }
}
