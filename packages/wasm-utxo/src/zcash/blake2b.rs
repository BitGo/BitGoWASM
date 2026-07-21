//! BLAKE2b-256 with personalization, as used by Zcash ZIP-243 (sighash) and
//! ZIP-244 (txid / v6 sighash) hash trees.
//!
//! Every digest in the ZIP-244 tree is a BLAKE2b-256 hash keyed by a 16-byte
//! personalization string. This mirrors the `blake2b_256_personal` helper in the
//! BitGo miniscript fork (which is `pub(crate)` there and therefore not reachable
//! from this crate), including the fix for block-aligned inputs.

use blake2::digest::core_api::{Buffer, UpdateCore, VariableOutputCore};
use blake2::digest::Output;
use blake2::Blake2bVarCore;

/// Compute a BLAKE2b digest of `data` with a `personalization` string and an
/// explicit output length (1..=64 bytes).
///
/// The output length is part of the BLAKE2b parameter block, so it changes the
/// digest — this is not truncation. Used by F4Jumble (ZIP-316), which needs both
/// 64-byte and shorter outputs.
///
/// The `Buffer`/`digest_blocks` path retains the final block until finalization so
/// the correct finalization flag is used even when `data.len()` is an exact multiple
/// of the 128-byte BLAKE2b block size (the block-aligned bug fixed in the fork).
pub fn blake2b_var_personal(data: &[u8], personalization: &[u8], out_len: usize) -> Vec<u8> {
    debug_assert!(
        (1..=64).contains(&out_len),
        "BLAKE2b output length out of range"
    );
    let mut core = Blake2bVarCore::new_with_params(&[], personalization, 0, out_len);
    let mut buffer: Buffer<Blake2bVarCore> = Default::default();
    buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));

    let mut full_output: Output<Blake2bVarCore> = Default::default();
    VariableOutputCore::finalize_variable_core(&mut core, &mut buffer, &mut full_output);

    full_output[..out_len].to_vec()
}

/// Compute a BLAKE2b-256 digest of `data` with a 16-byte `personalization` string.
///
/// The personalization must be at most 16 bytes (ZIP personalization strings are
/// exactly 16 bytes, e.g. `b"ZTxIdIronwd_H_v6"`).
pub fn blake2b_256_personal(data: &[u8], personalization: &[u8]) -> [u8; 32] {
    let out = blake2b_var_personal(data, personalization, 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personalization_affects_output() {
        let data = b"the quick brown fox";
        let a = blake2b_256_personal(data, b"ZTxIdPrevoutHash");
        let b = blake2b_256_personal(data, b"ZTxIdSequencHash");
        assert_ne!(a, b);
        // Deterministic
        assert_eq!(a, blake2b_256_personal(data, b"ZTxIdPrevoutHash"));
    }

    #[test]
    fn block_aligned_input_is_stable() {
        // 256 bytes = exactly 2 BLAKE2b blocks — exercises the finalization-flag fix.
        let data = vec![0xabu8; 256];
        let h = blake2b_256_personal(&data, b"ZTxIdOutputsHash");
        // Just assert it produces a non-trivial, deterministic 32-byte output.
        assert_ne!(h, [0u8; 32]);
        assert_eq!(h, blake2b_256_personal(&data, b"ZTxIdOutputsHash"));
    }
}
