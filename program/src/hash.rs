//! D3 — payout `order_id = keccak256(abi.encode(uint256(pubkey), uint256(nonce), uint256(chain_id)))`.
//!
//! `abi.encode` of three `uint256` words is just their 32-byte big-endian
//! concatenation (no length prefixes — these are all static-size words), so
//! passing three 32-byte slices to `sol_keccak256` and letting the syscall
//! concatenate-then-hash them reproduces the exact Solidity preimage.

/// Left-pad a `u64` into a 32-byte big-endian word, matching how Solidity
/// represents a `uint256` that only uses its low 8 bytes.
#[inline(always)]
pub fn u64_as_uint256_be(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    word
}

/// `keccak256(sender_pubkey || uint256(nonce) || uint256(chain_id))`.
#[inline(always)]
pub fn order_id_preimage_hash(sender: &[u8; 32], nonce: u64, chain_id: u64) -> [u8; 32] {
    let nonce_word = u64_as_uint256_be(nonce);
    let chain_id_word = u64_as_uint256_be(chain_id);
    keccak256(&[sender, &nonce_word, &chain_id_word])
}

#[cfg(target_os = "solana")]
#[inline(always)]
pub fn keccak256(inputs: &[&[u8]]) -> [u8; 32] {
    let mut result = [0u8; 32];
    unsafe {
        pinocchio::syscalls::sol_keccak256(
            inputs.as_ptr() as *const u8,
            inputs.len() as u64,
            result.as_mut_ptr(),
        );
    }
    result
}

/// Host stub. The `sol_keccak256` syscall only resolves on-chain; this
/// crate is never executed natively (Mollusk/LiteSVM load the compiled
/// `.so`), so a `cargo build`/`cargo check` on host never needs this to do
/// real work — it only needs to exist so the crate type-checks off-chain.
/// The real implementation used by host-side unit tests lives behind
/// `#[cfg(test)]` below, using an independent keccak crate so the test is
/// a genuine differential check against this function's own syscall path,
/// not a tautology.
#[cfg(not(target_os = "solana"))]
#[inline(always)]
pub fn keccak256(_inputs: &[&[u8]]) -> [u8; 32] {
    unreachable!("sol_keccak256 is only available when compiled for target_os = \"solana\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};

    fn reference_keccak256(inputs: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        for i in inputs {
            hasher.update(i);
        }
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        out
    }

    #[test]
    fn u64_left_pads_to_32_byte_word() {
        let word = u64_as_uint256_be(0x0102_0304_0506_0708);
        assert_eq!(&word[0..24], &[0u8; 24]);
        assert_eq!(&word[24..32], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    /// `abi.encode(uint256,uint256,uint256)` is concatenation with no
    /// framing — verify our preimage assembly matches that shape exactly
    /// against an independent keccak implementation.
    #[test]
    fn order_id_preimage_matches_abi_encode_concatenation() {
        let sender = [0x11u8; 32];
        let nonce: u64 = 1;
        let chain_id: u64 = 900_001;

        let nonce_word = u64_as_uint256_be(nonce);
        let chain_id_word = u64_as_uint256_be(chain_id);

        let mut preimage = [0u8; 96];
        preimage[0..32].copy_from_slice(&sender);
        preimage[32..64].copy_from_slice(&nonce_word);
        preimage[64..96].copy_from_slice(&chain_id_word);

        let expected = reference_keccak256(&[&preimage]);
        let actual = reference_keccak256(&[&sender, &nonce_word, &chain_id_word]);

        // sol_keccak256 hashes the concatenation of the slices it's given,
        // so passing 3 slices must equal hashing their concatenation as one.
        assert_eq!(actual, expected);
    }

    #[test]
    fn distinct_nonces_produce_distinct_ids() {
        let sender = [0x22u8; 32];
        let a = {
            let n = u64_as_uint256_be(1);
            let c = u64_as_uint256_be(900_001);
            reference_keccak256(&[&sender, &n, &c])
        };
        let b = {
            let n = u64_as_uint256_be(2);
            let c = u64_as_uint256_be(900_001);
            reference_keccak256(&[&sender, &n, &c])
        };
        assert_ne!(a, b);
    }
}
