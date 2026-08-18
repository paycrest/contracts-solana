use pinocchio::address::Address;

use crate::errors::GatewayError;

/// Derives the canonical PDA and bump via `find_program_address` (client-side
/// or once at init). On-chain validation must reject any non-canonical bump so
/// a single seed namespace maps to one address — the Solana analogue of
/// Solidity's single `mapping` slot.
pub fn find_canonical_pda(seeds: &[&[u8]], program_id: &Address) -> Result<(Address, u8), GatewayError> {
    if seeds.len() > 4 {
        return Err(GatewayError::InvalidPda);
    }
    let mut buf: [&[u8]; 4] = [&[], &[], &[], &[]];
    for (i, s) in seeds.iter().enumerate() {
        buf[i] = s;
    }
    Ok(Address::find_program_address(&buf[..seeds.len()], program_id))
}

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

/// Verifies that `expected` is the **canonical** PDA for `seeds` under
/// `program_id` and that `bump` is its canonical bump. Every account passed
/// into an instruction that is supposed to be one of our PDAs must go through
/// this — the alternative (trusting any off-curve bump) allows parallel fake
/// Config/Order state (D1/R5).
pub fn verify_pda(
    expected: &Address,
    seeds: &[&[u8]],
    bump: u8,
    program_id: &Address,
) -> Result<(), GatewayError> {
    let (canonical, canonical_bump) = find_canonical_pda(seeds, program_id)?;
    if bump != canonical_bump {
        return Err(GatewayError::InvalidPda);
    }
    if canonical.as_array() != expected.as_array() {
        return Err(GatewayError::InvalidPda);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_pda_accepts_the_correct_derivation_and_rejects_a_wrong_bump() {
        let program_id = Address::new_from_array([7u8; 32]);
        let (expected, bump) = Address::find_program_address(&[b"config"], &program_id);

        assert!(verify_pda(&expected, &[b"config"], bump, &program_id).is_ok());

        let wrong_bump = bump.wrapping_sub(1);
        if wrong_bump != bump {
            assert!(verify_pda(&expected, &[b"config"], wrong_bump, &program_id).is_err());
        }
    }

    #[test]
    fn verify_pda_rejects_wrong_seeds() {
        let program_id = Address::new_from_array([7u8; 32]);
        let (expected, bump) = Address::find_program_address(&[b"config"], &program_id);
        assert!(verify_pda(&expected, &[b"not-config"], bump, &program_id).is_err());
    }

    #[test]
    fn verify_pda_rejects_noncanonical_bump_even_when_address_matches_create() {
        let program_id = Address::new_from_array([7u8; 32]);
        let (_canonical, canonical_bump) = find_canonical_pda(&[b"config"], &program_id).unwrap();

        // Scan for any other bump that happens to derive a valid off-curve address.
        for candidate in 0..=255u8 {
            if candidate == canonical_bump {
                continue;
            }
            if let Ok(alt) = create_pda(&[b"config"], candidate, &program_id) {
                assert!(
                    verify_pda(&alt, &[b"config"], candidate, &program_id).is_err(),
                    "non-canonical bump {candidate} must not verify"
                );
            }
        }
    }
}
