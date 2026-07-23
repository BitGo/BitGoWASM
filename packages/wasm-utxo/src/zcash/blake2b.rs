//! BLAKE2b with personalization, as used by Zcash ZIP-243 (sighash), ZIP-244
//! (txid / v6 sighash) hash trees, and ZIP-316 (F4Jumble).
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

    /// Known-answer test: standard (zero-personalization) BLAKE2b-512 must match the
    /// canonical RFC 7693 Appendix A vector for "abc". An empty personalization slice
    /// zero-fills the parameter block, i.e. standard unkeyed BLAKE2b — so this pins the
    /// core algorithm to the spec, independent of our own output.
    ///
    /// Source: RFC 7693 Appendix A, <https://www.rfc-editor.org/rfc/rfc7693#appendix-A>.
    #[test]
    fn rfc7693_blake2b512_abc_kat() {
        let out = blake2b_var_personal(b"abc", &[], 64);
        assert_eq!(
            hex::encode(out),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// Known-answer test for a **block-aligned** input — the case the block-aligned
    /// finalization fix exists for. The input is exactly 128 bytes (one full BLAKE2b
    /// block), which is where the old `f=0` implementation compressed a spurious
    /// all-zero final block and produced the wrong (but deterministic) digest.
    ///
    /// The expected value is the canonical BLAKE2 reference known-answer test for
    /// unkeyed BLAKE2b-512 over the byte sequence `00 01 02 … 7f`, so it is traceable
    /// to the spec rather than to our implementation.
    ///
    /// Source: BLAKE2 reference test vectors (`blake2-kat.json`, unkeyed BLAKE2b, the
    /// 128-byte input entry), <https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json>.
    /// Cross-checked with CPython `hashlib.blake2b(bytes(range(128)), digest_size=64)`.
    #[test]
    fn blake2_reference_block_aligned_kat() {
        let input: Vec<u8> = (0u8..128).collect();
        assert_eq!(input.len() % 128, 0, "input must be block-aligned");
        let out = blake2b_var_personal(&input, &[], 64);
        assert_eq!(
            hex::encode(out),
            "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e\
             8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115"
        );
    }

    /// Known-answer test for a block-aligned input on the **personalized, 32-byte**
    /// path this helper is actually used with (ZIP-243/244 digests). Input is 256
    /// bytes (two full blocks) with `data[i] = (i * 7) mod 256`.
    ///
    /// Expected value computed with an independent implementation — CPython
    /// `hashlib.blake2b` (OpenSSL), not the Rust `blake2` crate — so a regression in
    /// finalization would be caught against an external reference:
    /// `python3 -c "import hashlib; print(hashlib.blake2b(bytes((i*7)&0xff for i in range(256)), digest_size=32, person=b'ZTxIdOutputsHash').hexdigest())"`
    #[test]
    fn personalized_block_aligned_kat() {
        let data: Vec<u8> = (0..256).map(|i| ((i * 7) & 0xff) as u8).collect();
        assert_eq!(data.len() % 128, 0, "input must be block-aligned");
        let out = blake2b_256_personal(&data, b"ZTxIdOutputsHash");
        assert_eq!(
            hex::encode(out),
            "7ca4128983f3c5e23d89f011b9ccf13b176ae0ce24bc344a87da3b31d5635e5b"
        );
    }

    #[test]
    fn var_output_length_is_honored() {
        let data = b"variable length";
        for len in [1usize, 16, 32, 48, 64] {
            assert_eq!(
                blake2b_var_personal(data, b"UA_F4Jumble_H\0\0\0", len).len(),
                len
            );
        }
    }

    #[test]
    fn output_length_changes_digest() {
        // BLAKE2b folds the output length into its parameter block, so a shorter
        // output is NOT a prefix of a longer one.
        let data = b"length is part of the domain";
        let short = blake2b_var_personal(data, b"ZTxIdPrevoutHash", 16);
        let long = blake2b_var_personal(data, b"ZTxIdPrevoutHash", 32);
        assert_ne!(short[..], long[..16]);
    }

    #[test]
    fn blake2b_256_matches_var_at_32() {
        let data = b"consistency between helpers";
        assert_eq!(
            blake2b_256_personal(data, b"ZTxIdIronwd_H_v6").to_vec(),
            blake2b_var_personal(data, b"ZTxIdIronwd_H_v6", 32)
        );
    }
}
