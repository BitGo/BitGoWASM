use miniscript::bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};

use crate::bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
use crate::bitcoin::blockdata::script::Builder;
use crate::bitcoin::{CompressedPublicKey, ScriptBuf};
use crate::fixed_script_wallet::wallet_keys::PubTriple;

/// Helper to convert CompressedPublicKey to x-only (32 bytes)
fn to_xonly_pubkey(key: CompressedPublicKey) -> [u8; 32] {
    let bytes = key.to_bytes();
    assert_eq!(bytes.len(), 33);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&bytes[1..]);
    xonly
}

/// Helper to build p2tr_ns script (n-of-n checksig chain)
pub fn build_p2tr_ns_script(keys: &[CompressedPublicKey]) -> ScriptBuf {
    let mut builder = Builder::default();
    for (i, key) in keys.iter().enumerate() {
        // convert to xonly key
        let key_bytes = to_xonly_pubkey(*key);
        builder = builder.push_slice(key_bytes);
        if i == keys.len() - 1 {
            builder = builder.push_opcode(OP_CHECKSIG);
        } else {
            builder = builder.push_opcode(OP_CHECKSIGVERIFY);
        }
    }
    builder.into_script()
}

/// A resolved tap leaf with depth and the actual keys
struct TapLeaf {
    depth: u8,
    keys: [CompressedPublicKey; 2],
}

/// Get the tap leaf configuration for a BitGo wallet.
///
/// For p2trMusig2: 2 leaves at depth 1
///   - user+backup
///   - backup+bitgo
///
/// For p2trLegacy: 3 leaves
///   - user+bitgo at depth 1
///   - user+backup at depth 2
///   - backup+bitgo at depth 2
fn get_tap_leaves(keys: &PubTriple, is_musig2: bool) -> Vec<TapLeaf> {
    let [user, backup, bitgo] = *keys;

    if is_musig2 {
        vec![
            TapLeaf {
                depth: 1,
                keys: [user, backup],
            },
            TapLeaf {
                depth: 1,
                keys: [backup, bitgo],
            },
        ]
    } else {
        vec![
            TapLeaf {
                depth: 1,
                keys: [user, bitgo],
            },
            TapLeaf {
                depth: 2,
                keys: [user, backup],
            },
            TapLeaf {
                depth: 2,
                keys: [backup, bitgo],
            },
        ]
    }
}

/// Build a TaprootBuilder with all leaves added (but not finalized)
fn build_taproot_builder(keys: &PubTriple, is_musig2: bool) -> TaprootBuilder {
    let mut builder = TaprootBuilder::new();

    for leaf in get_tap_leaves(keys, is_musig2) {
        let script = build_p2tr_ns_script(&leaf.keys);
        builder = builder.add_leaf(leaf.depth, script).expect("valid leaf");
    }

    builder
}

fn build_p2tr_spend_info(keys: &PubTriple, p2tr_musig2: bool) -> TaprootSpendInfo {
    use super::bitgo_musig::key_agg_bitgo_p2tr_legacy;
    use super::bitgo_musig::key_agg_p2tr_musig2;
    use crate::bitcoin::secp256k1::Secp256k1;
    use crate::bitcoin::XOnlyPublicKey;

    let secp = Secp256k1::new();
    let [user, _backup, bitgo] = *keys;

    let agg_key_bytes = if p2tr_musig2 {
        key_agg_p2tr_musig2(&[user, bitgo]).expect("valid aggregation")
    } else {
        key_agg_bitgo_p2tr_legacy(&[user, bitgo]).expect("valid aggregation")
    };
    let internal_key = XOnlyPublicKey::from_slice(&agg_key_bytes).expect("valid xonly key");

    build_taproot_builder(keys, p2tr_musig2)
        .finalize(&secp, internal_key)
        .expect("valid taptree")
}

/// Build a TapTree for PSBT output from wallet keys
pub fn build_tap_tree_for_output(
    pub_triple: &PubTriple,
    is_musig2: bool,
) -> miniscript::bitcoin::taproot::TapTree {
    miniscript::bitcoin::taproot::TapTree::try_from(build_taproot_builder(pub_triple, is_musig2))
        .expect("valid tap tree")
}

/// Create tap key origins for outputs with multiple leaf hashes per key.
/// Each key gets the leaf hashes for all leaves it participates in.
pub fn create_tap_bip32_derivation_for_output(
    wallet_keys: &crate::fixed_script_wallet::RootWalletKeys,
    chain: u32,
    index: u32,
    pub_triple: &PubTriple,
    is_musig2: bool,
) -> std::collections::BTreeMap<
    miniscript::bitcoin::XOnlyPublicKey,
    (
        Vec<miniscript::bitcoin::taproot::TapLeafHash>,
        (
            miniscript::bitcoin::bip32::Fingerprint,
            miniscript::bitcoin::bip32::DerivationPath,
        ),
    ),
> {
    use crate::fixed_script_wallet::derivation_path;
    use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1};
    use miniscript::bitcoin::taproot::{LeafVersion, TapLeafHash};
    use std::collections::BTreeMap;

    let secp = Secp256k1::new();

    // Build leaf scripts and compute their hashes
    let leaf_data: Vec<([CompressedPublicKey; 2], TapLeafHash)> =
        get_tap_leaves(pub_triple, is_musig2)
            .into_iter()
            .map(|leaf| {
                let script = build_p2tr_ns_script(&leaf.keys);
                let hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
                (leaf.keys, hash)
            })
            .collect();

    // For each key in the triple, collect leaf hashes of leaves it participates in
    let mut map = BTreeMap::new();
    for (i, key) in pub_triple.iter().enumerate() {
        let xpub = &wallet_keys.xpubs[i];
        let path = derivation_path(&wallet_keys.derivation_prefixes[i], chain, index);
        let derived = xpub.derive_pub(&secp, &path).expect("valid derivation");
        let pubkey = PublicKey::from_slice(&derived.to_pub().to_bytes()).expect("valid public key");
        let (x_only, _parity) = pubkey.x_only_public_key();

        // Collect leaf hashes for leaves this key participates in
        let key_leaf_hashes: Vec<TapLeafHash> = leaf_data
            .iter()
            .filter_map(|(leaf_keys, hash)| {
                if leaf_keys.contains(key) {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();

        map.insert(x_only, (key_leaf_hashes, (xpub.fingerprint(), path)));
    }

    map
}

#[derive(Debug)]
pub struct ScriptP2tr {
    pub spend_info: TaprootSpendInfo,
}

impl ScriptP2tr {
    pub fn new(keys: &PubTriple, p2tr_musig2: bool) -> ScriptP2tr {
        let spend_info = build_p2tr_spend_info(keys, p2tr_musig2);
        ScriptP2tr { spend_info }
    }

    pub fn output_script(&self) -> ScriptBuf {
        let output_key = self.spend_info.output_key().to_x_only_public_key();

        Builder::new()
            .push_int(1)
            .push_slice(output_key.serialize())
            .into_script()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::CompressedPublicKey;
    use crate::fixed_script_wallet::test_utils::fixtures::load_fixture_p2tr_output_scripts;

    fn test_p2tr_output_scripts_helper(script_type: &str, use_musig2: bool) {
        let fixtures = load_fixture_p2tr_output_scripts(script_type)
            .unwrap_or_else(|_| panic!("Failed to load {} output script fixtures", script_type));

        for (idx, fixture) in fixtures.iter().enumerate() {
            // Parse pubkeys from hex strings
            let pubkeys: Vec<CompressedPublicKey> = fixture
                .pubkeys
                .iter()
                .map(|hex| {
                    let bytes = hex::decode(hex).expect("Invalid hex pubkey");
                    CompressedPublicKey::from_slice(&bytes).expect("Invalid compressed pubkey")
                })
                .collect();

            assert_eq!(pubkeys.len(), 3, "Expected 3 pubkeys in fixture {}", idx);

            let pub_triple: [CompressedPublicKey; 3] =
                pubkeys.try_into().expect("Failed to convert to array");

            // Generate scripts using the from_p2tr method
            let spend_info = ScriptP2tr::new(&pub_triple, use_musig2);

            let internal_key = spend_info.spend_info.internal_key().serialize();
            assert_eq!(
                hex::encode(internal_key),
                fixture.internal_pubkey,
                "Internal key mismatch for {} fixture {}",
                idx,
                script_type
            );

            let output_script = spend_info.output_script();
            assert_eq!(
                output_script.to_hex_string(),
                fixture.output,
                "Output script mismatch for {} fixture {} (pubkeys: {:?})",
                script_type,
                idx,
                fixture.pubkeys
            );
        }
    }

    #[test]
    fn test_p2tr_output_scripts_from_fixture() {
        test_p2tr_output_scripts_helper("p2tr", false);
    }

    #[test]
    fn test_p2tr_musig2_output_scripts_from_fixture() {
        test_p2tr_output_scripts_helper("p2trMusig2", true);
    }
}
