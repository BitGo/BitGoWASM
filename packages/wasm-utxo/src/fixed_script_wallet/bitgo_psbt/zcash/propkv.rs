//! Zcash-specific proprietary key-value accessors: the legacy `BITGO` ZecConsensusBranchId
//! key and the `BITGO/ZEC/V6` namespace (v6 header params, Ironwood PCZT, unified addresses).
//!
//! Split verbatim out of the generic `propkv` module so it carries no Zcash keys.

use crate::fixed_script_wallet::bitgo_psbt::propkv::*;

/// Extract Zcash consensus branch ID from PSBT global proprietary map.
///
/// The consensus branch ID is stored as a 4-byte little-endian u32 value
/// under the BitGo proprietary key with subtype `ZecConsensusBranchId` (0x00).
///
/// # Returns
/// - `Some(u32)` if the consensus branch ID is present and valid
/// - `None` if the key is not present or the value is malformed
pub fn get_zec_consensus_branch_id(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<u32> {
    let kv = find_kv(
        ProprietaryKeySubtype::ZecConsensusBranchId,
        &psbt.proprietary,
    )
    .next()?;
    if kv.value.len() == 4 {
        let bytes: [u8; 4] = kv.value.as_slice().try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    } else {
        None
    }
}

/// Set Zcash consensus branch ID in PSBT global proprietary map.
///
/// The consensus branch ID is stored as a 4-byte little-endian u32 value
/// under the BitGo proprietary key with subtype `ZecConsensusBranchId` (0x00).
///
/// # Arguments
/// * `psbt` - The PSBT to modify
/// * `branch_id` - The Zcash consensus branch ID to store
///
/// # Example
/// ```ignore
/// use crate::zcash::NetworkUpgrade;
/// set_zec_consensus_branch_id(&mut psbt, NetworkUpgrade::Nu5.branch_id());
/// ```
///
/// See [`crate::zcash`] module for available network upgrades and their branch IDs.
pub fn set_zec_consensus_branch_id(psbt: &mut miniscript::bitcoin::psbt::Psbt, branch_id: u32) {
    let kv = BitGoKeyValue::new(
        ProprietaryKeySubtype::ZecConsensusBranchId,
        vec![], // empty key
        branch_id.to_le_bytes().to_vec(),
    );
    let (key, value) = kv.to_key_value();
    psbt.proprietary.insert(key, value);
}

/// Zcash v6 (Ironwood) proprietary namespace — its own private subtype space, so v6 keys don't
/// consume slots in the shared `BITGO` space (which is a hard-limited single byte shared by every
/// other BitGo proprietary key: MuSig2, PayGo, BIP322, WasmUtxo, etc).
pub const BITGO_ZEC_V6: &[u8] = b"BITGO/ZEC/V6";

/// Subtypes within the [`BITGO_ZEC_V6`] namespace.
///
/// This mirrors the v4 `ZecConsensusBranchId` (0x00 under the legacy `BITGO` prefix), but v4 is
/// untouched: the two 0x00 branch-id keys are unambiguous because their prefixes differ.
///
/// Note that a v6 PSBT still carries the legacy `BITGO`/`ZecConsensusBranchId` key as well, because
/// [`ZcashBitGoPsbt::new`] writes it for every Zcash PSBT. The v6 code paths read only the key in
/// this namespace; the legacy one is redundant but harmless, and keeping it means the shared
/// `new` constructor needs no v6 special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZecV6KeySubtype {
    ConsensusBranchId = 0x00,
    IronwoodPczt = 0x01,
    VersionGroupId = 0x02,
    ExpiryHeight = 0x03,
    /// Marker set once [`take_ironwood_pczt`] has actually dropped a PCZT (i.e. extraction
    /// happened, not just "no shielded output was ever added"). Persists even though the PCZT
    /// itself is gone, so a later read can tell the two "no PCZT" states apart.
    IronwoodExtracted = 0x04,
    /// The full ZIP-316 Unified Address string (UTF-8) the shielded output was addressed to, if
    /// the caller supplied one to [`crate::fixed_script_wallet::bitgo_psbt::zcash_psbt`]'s
    /// `add_ironwood_output`. The PCZT itself only carries the raw 43-byte Orchard receiver, which
    /// is lossy for a multi-receiver UA (transparent/Sapling receivers can't be recovered from it);
    /// storing the original string here lets output parsing return the exact UA the caller passed,
    /// receivers and all, after a serialize/deserialize round-trip.
    UnifiedAddress = 0x05,
    /// The full ZIP-316 Unified Address string (UTF-8) a plain transparent output (identified by
    /// its index in `unsigned_tx.output`) was addressed to, if the caller supplied one to
    /// [`crate::fixed_script_wallet::bitgo_psbt::zcash_psbt`]'s `add_transparent_output`. Mirrors
    /// `UnifiedAddress` above, but keyed by transparent output index rather than Orchard action
    /// index, and stored only for the output's transparent receiver (already fully recoverable
    /// from the scriptPubKey) — kept so output parsing can hand back the exact UA the caller
    /// passed, not one reconstructed as a bare transparent address.
    TransparentUnifiedAddress = 0x06,
    /// The real (non-dummy) Ironwood spend and output counts of the PCZT dropped by
    /// [`take_ironwood_pczt`], as two little-endian `u32`s. Written alongside `IronwoodExtracted`
    /// so ZIP-317 fee estimation still sees the bundle's actions once the PCZT itself is gone.
    IronwoodExtractedCounts = 0x07,
    /// The wallet's spend-validating key (`ak`, 32 bytes) for the stored Ironwood bundle.
    /// Written by `add_shielded_spends`; the keyless verifier reads it for the `Rk` check,
    /// which runs only when the key is present.
    IronwoodSpendValidatingKey = 0x08,
    /// A little-endian bitset over Ironwood action indices: bit `i` set means action `i`'s
    /// real output already carries its final `out_ciphertext`. Written all-clear by
    /// `add_shielded_spends`, updated by `add_out_ciphertexts`, read by
    /// `pending_out_ciphertexts`. Only spend bundles are tracked (shielding finalizes its
    /// ciphertexts at signing); a spend bundle without the bitset counts every real output as
    /// pending, so stripping the key cannot skip the ciphertexts-first rule.
    IronwoodOutCiphertextsSet = 0x09,
}

fn set_zec_v6(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    subtype: ZecV6KeySubtype,
    value: Vec<u8>,
) {
    let key = ProprietaryKey {
        prefix: BITGO_ZEC_V6.to_vec(),
        subtype: subtype as u8,
        key: vec![],
    };
    psbt.proprietary.insert(key, value);
}

fn get_zec_v6(psbt: &miniscript::bitcoin::psbt::Psbt, subtype: ZecV6KeySubtype) -> Option<Vec<u8>> {
    find_kv_iter(&psbt.proprietary, BITGO_ZEC_V6, Some(subtype as u8))
        .next()
        .map(|(_, v)| v.clone())
}

fn set_zec_v6_u32(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    subtype: ZecV6KeySubtype,
    value: u32,
) {
    set_zec_v6(psbt, subtype, value.to_le_bytes().to_vec());
}

fn get_zec_v6_u32(psbt: &miniscript::bitcoin::psbt::Psbt, subtype: ZecV6KeySubtype) -> Option<u32> {
    let bytes = get_zec_v6(psbt, subtype)?;
    Some(u32::from_le_bytes(bytes.as_slice().try_into().ok()?))
}

/// Store the Zcash v6 (Ironwood) consensus branch ID under the `BITGO_ZEC_V6` namespace.
pub fn set_zec_v6_consensus_branch_id(psbt: &mut miniscript::bitcoin::psbt::Psbt, branch_id: u32) {
    set_zec_v6_u32(psbt, ZecV6KeySubtype::ConsensusBranchId, branch_id);
}

/// Fetch the Zcash v6 (Ironwood) consensus branch ID from the `BITGO_ZEC_V6` namespace, if present.
pub fn get_zec_v6_consensus_branch_id(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<u32> {
    get_zec_v6_u32(psbt, ZecV6KeySubtype::ConsensusBranchId)
}

/// Store a serialized Ironwood (v6) PCZT bundle in the PSBT global proprietary map, under the
/// `BITGO_ZEC_V6` namespace's `IronwoodPczt` subtype. Overwrites any existing value.
pub fn set_ironwood_pczt(psbt: &mut miniscript::bitcoin::psbt::Psbt, bytes: Vec<u8>) {
    set_zec_v6(psbt, ZecV6KeySubtype::IronwoodPczt, bytes);
}

/// Fetch the serialized Ironwood (v6) PCZT bundle from the PSBT global proprietary map, if present.
pub fn get_ironwood_pczt(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<Vec<u8>> {
    get_zec_v6(psbt, ZecV6KeySubtype::IronwoodPczt)
}
/// Whether the PSBT carries an Ironwood (v6) PCZT bundle, without materializing it.
///
/// Use this instead of `get_ironwood_pczt(...).is_some()` when only presence matters: the getter
/// clones the whole (large) PCZT, which would otherwise happen on every check.
pub fn has_ironwood_pczt(psbt: &miniscript::bitcoin::psbt::Psbt) -> bool {
    find_kv_iter(
        &psbt.proprietary,
        BITGO_ZEC_V6,
        Some(ZecV6KeySubtype::IronwoodPczt as u8),
    )
    .next()
    .is_some()
}

/// Remove the serialized Ironwood (v6) PCZT bundle, returning whether one was present.
///
/// Used to make extraction terminal: once `combine_ironwood_proof` has produced the broadcast-ready
/// transaction, dropping the PCZT means any further Ironwood operation on that PSBT — including
/// after a `serialize`/`deserialize` round-trip — fails loudly instead of silently re-running
/// against state that has already been spent.
pub fn take_ironwood_pczt(psbt: &mut miniscript::bitcoin::psbt::Psbt) -> bool {
    let key = miniscript::bitcoin::psbt::raw::ProprietaryKey {
        prefix: BITGO_ZEC_V6.to_vec(),
        subtype: ZecV6KeySubtype::IronwoodPczt as u8,
        key: vec![],
    };
    let took = psbt.proprietary.remove(&key).is_some();
    if took {
        set_ironwood_extracted(psbt);
    }
    took
}

/// Mark the PSBT as having had its Ironwood PCZT extracted (see [`take_ironwood_pczt`]).
/// Persists across `serialize`/`deserialize`, unlike the PCZT itself, so a later "was a shielded
/// output added and then extracted, or never added at all?" check can tell the two apart even
/// though both look identical from PCZT-presence alone.
fn set_ironwood_extracted(psbt: &mut miniscript::bitcoin::psbt::Psbt) {
    set_zec_v6(psbt, ZecV6KeySubtype::IronwoodExtracted, vec![]);
}

/// Whether the PSBT's Ironwood PCZT has been extracted (dropped by [`take_ironwood_pczt`]).
pub fn is_ironwood_extracted(psbt: &miniscript::bitcoin::psbt::Psbt) -> bool {
    get_zec_v6(psbt, ZecV6KeySubtype::IronwoodExtracted).is_some()
}

/// Record the real Ironwood spend/output counts of a PCZT about to be dropped by
/// [`take_ironwood_pczt`] (see [`ZecV6KeySubtype::IronwoodExtractedCounts`]).
pub fn set_ironwood_extracted_counts(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    spends: u32,
    outputs: u32,
) {
    let mut value = spends.to_le_bytes().to_vec();
    value.extend_from_slice(&outputs.to_le_bytes());
    set_zec_v6(psbt, ZecV6KeySubtype::IronwoodExtractedCounts, value);
}

/// The `(spends, outputs)` recorded by [`set_ironwood_extracted_counts`], or `None` if absent or
/// malformed.
pub fn get_ironwood_extracted_counts(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<(u32, u32)> {
    let value = get_zec_v6(psbt, ZecV6KeySubtype::IronwoodExtractedCounts)?;
    let (spends, outputs) = value.as_slice().split_at_checked(4)?;
    Some((
        u32::from_le_bytes(spends.try_into().ok()?),
        u32::from_le_bytes(outputs.try_into().ok()?),
    ))
}

/// Store the Zcash v6 (Ironwood) header params — `version_group_id` and `expiry_height` — under the
/// `BITGO_ZEC_V6` namespace. `version_group_id`'s presence marks the PSBT as v6; `expiry_height` is
/// always written too (even when 0, a valid "no expiry" value, so it can be told apart from absent).
pub fn set_zec_v6_params(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    version_group_id: u32,
    expiry_height: u32,
) {
    set_zec_v6_u32(psbt, ZecV6KeySubtype::VersionGroupId, version_group_id);
    set_zec_v6_u32(psbt, ZecV6KeySubtype::ExpiryHeight, expiry_height);
}

/// Fetch the Zcash v6 (Ironwood) header params `(version_group_id, expiry_height)`, if present.
pub fn get_zec_v6_params(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<(u32, u32)> {
    let vgid = get_zec_v6_u32(psbt, ZecV6KeySubtype::VersionGroupId)?;
    let expiry = get_zec_v6_u32(psbt, ZecV6KeySubtype::ExpiryHeight)?;
    Some((vgid, expiry))
}

/// Store the full Unified Address string one Ironwood shielded output (identified by its
/// `action_index` in the orchard bundle) was addressed to, so it survives a serialize/deserialize
/// round-trip verbatim (receivers and all) instead of being rebuilt from just the raw Orchard
/// receiver. Keyed by `action_index` (as the `ProprietaryKey`'s `key` bytes) so a multi-recipient
/// bundle can store one UA per action. Overwrites any existing value for that index.
pub fn set_ironwood_unified_address(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    action_index: usize,
    ua: &str,
) {
    let key = ProprietaryKey {
        prefix: BITGO_ZEC_V6.to_vec(),
        subtype: ZecV6KeySubtype::UnifiedAddress as u8,
        key: (action_index as u32).to_le_bytes().to_vec(),
    };
    psbt.proprietary.insert(key, ua.as_bytes().to_vec());
}

/// Fetch the Unified Address string stored by [`set_ironwood_unified_address`] for `action_index`,
/// if present and valid UTF-8.
pub fn get_ironwood_unified_address(
    psbt: &miniscript::bitcoin::psbt::Psbt,
    action_index: usize,
) -> Option<String> {
    let key = ProprietaryKey {
        prefix: BITGO_ZEC_V6.to_vec(),
        subtype: ZecV6KeySubtype::UnifiedAddress as u8,
        key: (action_index as u32).to_le_bytes().to_vec(),
    };
    let bytes = psbt.proprietary.get(&key)?;
    String::from_utf8(bytes.clone()).ok()
}

/// Remove every Unified Address stored by [`set_ironwood_unified_address`], regardless of action
/// index.
///
/// Callers building a fresh batch of shielded outputs must call this before storing the new
/// batch's UAs (rather than only overwriting the indices the new batch happens to use):
/// `add_ironwood_output`/`add_ironwood_outputs` can run again on a PSBT whose PCZT was previously
/// extracted (see `take_ironwood_pczt`/`mark_ironwood_extracted`, which drop only the PCZT key, not
/// these), and a new batch's action count/indices need not match the old one's — so without a
/// blanket clear, a UA stored for a since-gone action index would survive and (if the new bundle
/// happens to reuse that index) be silently misattributed to a different recipient.
pub fn clear_ironwood_unified_addresses(psbt: &mut miniscript::bitcoin::psbt::Psbt) {
    psbt.proprietary.retain(|k, _| {
        !(k.prefix == BITGO_ZEC_V6 && k.subtype == ZecV6KeySubtype::UnifiedAddress as u8)
    });
}

/// Store the wallet's spend-validating key (`ak`, 32 bytes) for the stored Ironwood bundle.
/// Written when the bundle is installed; the keyless
/// verifier reads it for the `Rk` check.
pub fn set_ironwood_spend_validating_key(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    ak: &[u8; 32],
) {
    set_zec_v6(
        psbt,
        ZecV6KeySubtype::IronwoodSpendValidatingKey,
        ak.to_vec(),
    );
}

/// Fetch the wallet's spend-validating key stored by [`set_ironwood_spend_validating_key`],
/// if present and well-formed.
pub fn get_ironwood_spend_validating_key(
    psbt: &miniscript::bitcoin::psbt::Psbt,
) -> Option<[u8; 32]> {
    let bytes = get_zec_v6(psbt, ZecV6KeySubtype::IronwoodSpendValidatingKey)?;
    bytes.try_into().ok()
}

/// Store the full Unified Address string one plain transparent output (identified by its
/// `output_index` in `unsigned_tx.output`) was addressed to, so it survives a
/// serialize/deserialize round-trip verbatim rather than being lost down to just the
/// scriptPubKey. Keyed by `output_index`. Overwrites any existing value for that index.
pub fn set_transparent_output_unified_address(
    psbt: &mut miniscript::bitcoin::psbt::Psbt,
    output_index: usize,
    ua: &str,
) {
    let key = ProprietaryKey {
        prefix: BITGO_ZEC_V6.to_vec(),
        subtype: ZecV6KeySubtype::TransparentUnifiedAddress as u8,
        key: (output_index as u32).to_le_bytes().to_vec(),
    };
    psbt.proprietary.insert(key, ua.as_bytes().to_vec());
}

/// Store the `IronwoodOutCiphertextsSet` bitset ([`ZecV6KeySubtype::IronwoodOutCiphertextsSet`]):
/// one bit per action index, little-endian (bit `i` = byte `i / 8`, mask `1 << (i % 8)`), set
/// when that action's real output carries its final `out_ciphertext`.
pub fn set_ironwood_out_ciphertexts_set(psbt: &mut miniscript::bitcoin::psbt::Psbt, bits: Vec<u8>) {
    set_zec_v6(psbt, ZecV6KeySubtype::IronwoodOutCiphertextsSet, bits);
}

/// Fetch the `IronwoodOutCiphertextsSet` bitset, if present.
pub fn get_ironwood_out_ciphertexts_set(psbt: &miniscript::bitcoin::psbt::Psbt) -> Option<Vec<u8>> {
    get_zec_v6(psbt, ZecV6KeySubtype::IronwoodOutCiphertextsSet)
}

/// Fetch the Unified Address string stored by [`set_transparent_output_unified_address`] for
/// `output_index`, if present and valid UTF-8.
pub fn get_transparent_output_unified_address(
    psbt: &miniscript::bitcoin::psbt::Psbt,
    output_index: usize,
) -> Option<String> {
    let key = ProprietaryKey {
        prefix: BITGO_ZEC_V6.to_vec(),
        subtype: ZecV6KeySubtype::TransparentUnifiedAddress as u8,
        key: (output_index as u32).to_le_bytes().to_vec(),
    };
    let bytes = psbt.proprietary.get(&key)?;
    String::from_utf8(bytes.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zec_consensus_branch_id_roundtrip() {
        use crate::zcash::NetworkUpgrade;
        use miniscript::bitcoin::psbt::Psbt;
        use miniscript::bitcoin::Transaction;

        // Create a minimal PSBT
        let tx = Transaction {
            version: miniscript::bitcoin::transaction::Version::TWO,
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        // Initially no branch ID
        assert_eq!(get_zec_consensus_branch_id(&psbt), None);

        // Set NU5 branch ID using generated constant
        let nu5_branch_id = NetworkUpgrade::Nu5.branch_id();
        set_zec_consensus_branch_id(&mut psbt, nu5_branch_id);

        // Should be retrievable
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(nu5_branch_id));

        // Update to Sapling branch ID using generated constant
        let sapling_branch_id = NetworkUpgrade::Sapling.branch_id();
        set_zec_consensus_branch_id(&mut psbt, sapling_branch_id);

        // Should return the updated value
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(sapling_branch_id));
    }

    #[test]
    fn test_zec_consensus_branch_id_values() {
        use crate::zcash::NetworkUpgrade;

        // Verify known Zcash branch IDs match expected values from ZIP-200
        assert_eq!(NetworkUpgrade::Overwinter.branch_id(), 0x5ba81b19);
        assert_eq!(NetworkUpgrade::Sapling.branch_id(), 0x76b809bb);
        assert_eq!(NetworkUpgrade::Blossom.branch_id(), 0x2bb40e60);
        assert_eq!(NetworkUpgrade::Heartwood.branch_id(), 0xf5b9230b);
        assert_eq!(NetworkUpgrade::Canopy.branch_id(), 0xe9ff75a6);
        assert_eq!(NetworkUpgrade::Nu5.branch_id(), 0xc2d6d0b4);
        assert_eq!(NetworkUpgrade::Nu6.branch_id(), 0xc8e71055);
    }

    #[test]
    fn test_ironwood_pczt_and_v6_params_roundtrip() {
        use miniscript::bitcoin::psbt::Psbt;
        use miniscript::bitcoin::Transaction;

        let tx = Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(6),
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        assert_eq!(get_ironwood_pczt(&psbt), None);
        assert_eq!(get_zec_v6_params(&psbt), None);

        set_ironwood_pczt(&mut psbt, vec![1, 2, 3, 4]);
        set_zec_v6_params(&mut psbt, 0xD884B698, 42);

        assert_eq!(get_ironwood_pczt(&psbt), Some(vec![1, 2, 3, 4]));
        assert_eq!(get_zec_v6_params(&psbt), Some((0xD884B698, 42)));

        // Overwrite semantics.
        set_ironwood_pczt(&mut psbt, vec![9]);
        set_zec_v6_params(&mut psbt, 0xD884B698, 0);
        assert_eq!(get_ironwood_pczt(&psbt), Some(vec![9]));
        // expiry_height == 0 is a valid value, distinct from "absent".
        assert_eq!(get_zec_v6_params(&psbt), Some((0xD884B698, 0)));

        // These keys live under the private BITGO_ZEC_V6 namespace, not the shared BITGO space.
        for key in psbt.proprietary.keys() {
            assert_eq!(key.prefix, BITGO_ZEC_V6);
        }
    }

    #[test]
    fn test_zec_v6_consensus_branch_id_roundtrip() {
        use miniscript::bitcoin::psbt::Psbt;
        use miniscript::bitcoin::Transaction;

        let tx = Transaction {
            version: miniscript::bitcoin::transaction::Version::non_standard(6),
            lock_time: miniscript::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        assert_eq!(get_zec_v6_consensus_branch_id(&psbt), None);

        set_zec_v6_consensus_branch_id(&mut psbt, 0x736b_bdac);
        assert_eq!(get_zec_v6_consensus_branch_id(&psbt), Some(0x736b_bdac));

        // Coexists with the legacy (v4) key at the same subtype 0x00, disambiguated by prefix.
        set_zec_consensus_branch_id(&mut psbt, 0xc2d6_d0b4);
        assert_eq!(get_zec_consensus_branch_id(&psbt), Some(0xc2d6_d0b4));
        assert_eq!(get_zec_v6_consensus_branch_id(&psbt), Some(0x736b_bdac));
    }
}
