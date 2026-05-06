use miniscript::bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};

use crate::bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
use crate::bitcoin::blockdata::script::Builder;
use crate::bitcoin::{CompressedPublicKey, ScriptBuf};
use crate::fixed_script_wallet::wallet_keys::PubTriple;
use crate::p2mr::{
    build_p2mr_script_pubkey, build_p2mr_tree, ScriptTreeNode, TAPSCRIPT_LEAF_VERSION,
};

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

/// Build the P2MR script tree for a BitGo wallet.
///
/// Tree structure (mirrors P2trLegacy, 3 leaves):
/// - Leaf 0 (depth 1): user + bitgo  (primary spend path)
/// - Leaf 1 (depth 2): user + backup (recovery)
/// - Leaf 2 (depth 2): backup + bitgo (recovery)
///
/// Each leaf uses the same 2-of-2 checksigverify script as P2TR.
fn build_p2mr_script_tree(keys: &PubTriple) -> ScriptTreeNode {
    let [user, backup, bitgo] = *keys;

    let leaf_user_bitgo = ScriptTreeNode::Leaf {
        script: build_p2tr_ns_script(&[user, bitgo]).into_bytes(),
        leaf_version: TAPSCRIPT_LEAF_VERSION,
    };
    let leaf_user_backup = ScriptTreeNode::Leaf {
        script: build_p2tr_ns_script(&[user, backup]).into_bytes(),
        leaf_version: TAPSCRIPT_LEAF_VERSION,
    };
    let leaf_backup_bitgo = ScriptTreeNode::Leaf {
        script: build_p2tr_ns_script(&[backup, bitgo]).into_bytes(),
        leaf_version: TAPSCRIPT_LEAF_VERSION,
    };

    // Branch(leaf0, Branch(leaf1, leaf2)) — same depth structure as P2trLegacy
    ScriptTreeNode::Branch(
        Box::new(leaf_user_bitgo),
        Box::new(ScriptTreeNode::Branch(
            Box::new(leaf_user_backup),
            Box::new(leaf_backup_bitgo),
        )),
    )
}

/// P2MR wallet script: 3-leaf Merkle tree using 2-of-2 checksigverify leaf scripts.
///
/// Unlike P2TR, P2MR has no internal key and no TapTweak.
/// The Merkle root is committed directly in the scriptPubKey (OP_2 <32-byte root>).
/// Control blocks are 1 + 32*depth bytes (no 32-byte internal key prefix).
#[derive(Debug)]
pub struct ScriptP2mr {
    /// The 32-byte Merkle root committed in the scriptPubKey.
    pub merkle_root: [u8; 32],
    /// Per-leaf spending info (leaf hash + control block), in tree DFS order.
    pub leaves: Vec<crate::p2mr::P2mrLeafInfo>,
}

impl ScriptP2mr {
    /// Build a P2MR wallet script from a public key triple.
    pub fn new(keys: &PubTriple) -> ScriptP2mr {
        let tree = build_p2mr_script_tree(keys);
        let info = build_p2mr_tree(&tree);
        ScriptP2mr {
            merkle_root: info.merkle_root,
            leaves: info.leaves,
        }
    }

    /// Return the 34-byte P2MR scriptPubKey: `OP_2 OP_PUSHBYTES_32 <merkle_root>`.
    pub fn output_script(&self) -> ScriptBuf {
        build_p2mr_script_pubkey(&self.merkle_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::CompressedPublicKey;
    use crate::fixed_script_wallet::test_utils::fixtures::load_fixture_p2tr_output_scripts;

    fn parse_compressed_pubkey(hex: &str) -> CompressedPublicKey {
        let bytes = hex::decode(hex).expect("Invalid hex pubkey");
        CompressedPublicKey::from_slice(&bytes).expect("Invalid compressed pubkey")
    }

    fn pub_triple_from_hex(user: &str, backup: &str, bitgo: &str) -> [CompressedPublicKey; 3] {
        [
            parse_compressed_pubkey(user),
            parse_compressed_pubkey(backup),
            parse_compressed_pubkey(bitgo),
        ]
    }

    /// P2MR output script fixture: known pubkey triple → expected merkle root + output script + control blocks.
    ///
    /// Tree structure: Branch(leaf_user_bitgo, Branch(leaf_user_backup, leaf_backup_bitgo))
    /// - leaf[0]: user+bitgo at depth 1 (primary spend path)
    /// - leaf[1]: user+backup at depth 2 (recovery)
    /// - leaf[2]: backup+bitgo at depth 2 (recovery)
    ///
    /// Control blocks: 1 byte (0xc1 = TAPSCRIPT_LEAF_VERSION | parity) + 32*depth bytes.
    struct P2mrFixture {
        pubkeys: [&'static str; 3],
        /// Expected 32-byte merkle root (hex).
        merkle_root: &'static str,
        /// Expected 34-byte output scriptPubKey (hex): `5220<merkle_root>`.
        output: &'static str,
        /// Expected control blocks for leaf[0], leaf[1], leaf[2] in DFS order.
        control_blocks: [&'static str; 3],
    }

    fn p2mr_fixtures() -> Vec<P2mrFixture> {
        vec![
            // Fixture 0: standard key order (user, backup, bitgo)
            // Same pubkeys as the first p2tr fixture for cross-comparison
            P2mrFixture {
                pubkeys: [
                    "02d20a62701c54f6eb3abb9f964b0e29ff90ffa3b4e3fcb73e7c67d4950fa6e3c7",
                    "028714039c6866c27eb6885ffbb4085964a603140e5a39b0fa29b1d9839212f9a2",
                    "03203ab799ce28e2cca044f594c69275050af4bb0854ad730a8f74622342300e64",
                ],
                merkle_root: "b69e64804422cb6cac96df1d742055b41aca27017dfcf79ef68482fad348b5c3",
                output: "5220b69e64804422cb6cac96df1d742055b41aca27017dfcf79ef68482fad348b5c3",
                control_blocks: [
                    // leaf[0] (user+bitgo, depth 1): control_byte || sibling_of_subtree(leaf[1],leaf[2])
                    "c1d88b89f6f10f490bb6e1e61585cb3e78f8b4993e574b4031cacc6859c5adbc45",
                    // leaf[1] (user+backup, depth 2): control_byte || sibling_leaf[2] || sibling_subtree(leaf[0])
                    "c1b33e39fb32e503897e9cdc949597dac7b156017bf55a4f9802b619db07d3070a62959ac7472a3cd0ea894b23888341247d3c890c711fff8ac9b02177609e3e27",
                    // leaf[2] (backup+bitgo, depth 2): control_byte || sibling_leaf[1] || sibling_subtree(leaf[0])
                    "c10e87e7b2bddc1e2f2cde702b5cbe51119df98538b35fa91c40a7c74fa9f5d39862959ac7472a3cd0ea894b23888341247d3c890c711fff8ac9b02177609e3e27",
                ],
            },
            // Fixture 1: different key order (user=bitgo key from fixture 0, backup same, bitgo=user key from fixture 0)
            P2mrFixture {
                pubkeys: [
                    "03203ab799ce28e2cca044f594c69275050af4bb0854ad730a8f74622342300e64",
                    "028714039c6866c27eb6885ffbb4085964a603140e5a39b0fa29b1d9839212f9a2",
                    "02d20a62701c54f6eb3abb9f964b0e29ff90ffa3b4e3fcb73e7c67d4950fa6e3c7",
                ],
                merkle_root: "e4ca158ee6f82dec51f1ecec71665f0735c170bf89c1fe9f9e568ad6257fabc0",
                output: "5220e4ca158ee6f82dec51f1ecec71665f0735c170bf89c1fe9f9e568ad6257fabc0",
                control_blocks: [
                    "c1154989ec963f9639848d336c522641b38bf5540ca0934318ac824e623ffd9e14",
                    "c19f8d752c1becee80ffd87719934911d9c8aef659fc3ab512ba67f920ffc47545c3a4b27e58190225770a6cf2fb7ee0d9c536951637b3b0cea693d8ba9528853d",
                    "c145fc694de6d51e7c6fcd37c35377b99e4e6e9a19adb600256a20dc0dd34561bcc3a4b27e58190225770a6cf2fb7ee0d9c536951637b3b0cea693d8ba9528853d",
                ],
            },
            // Fixture 2: secp256k1 generator points (well-known keys)
            P2mrFixture {
                pubkeys: [
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                ],
                merkle_root: "a5d2a17f0e34db3c9d55a4943e6828ce1c931e96d5f46bdf20a1d036fde07d34",
                output: "5220a5d2a17f0e34db3c9d55a4943e6828ce1c931e96d5f46bdf20a1d036fde07d34",
                control_blocks: [
                    "c1508c4c7eb9cae751fa8b8daf40586e3c11f4a8c925538ead255a4df5f28e7fd3",
                    "c1c9bcb65c1015db6b44e5c2977606cf7a5d8f13d226531c6d01133d0810bed17badc6b97cf6faab3e93e0bb6ca965fd1976982d39a86806d0e9603bfda05f46b4",
                    "c1df6587a7f3cf367a076047bc0e85893cabb6b1430f9e95ffc0003dad6593ba33adc6b97cf6faab3e93e0bb6ca965fd1976982d39a86806d0e9603bfda05f46b4",
                ],
            },
        ]
    }

    #[test]
    fn test_p2mr_output_scripts_fixture() {
        use crate::p2mr::verify_control_block;

        for (i, fixture) in p2mr_fixtures().iter().enumerate() {
            let triple =
                pub_triple_from_hex(fixture.pubkeys[0], fixture.pubkeys[1], fixture.pubkeys[2]);
            let script = ScriptP2mr::new(&triple);

            // Verify merkle root
            assert_eq!(
                hex::encode(script.merkle_root),
                fixture.merkle_root,
                "Merkle root mismatch for fixture {}",
                i
            );

            // Verify output script: OP_2 OP_PUSHBYTES_32 <merkle_root>
            assert_eq!(
                script.output_script().to_hex_string(),
                fixture.output,
                "Output script mismatch for fixture {}",
                i
            );
            // Sanity: output starts with 5220 (OP_2 OP_PUSHBYTES_32)
            assert!(
                fixture.output.starts_with("5220"),
                "Output script should start with 5220 (OP_2 OP_PUSHBYTES_32) for fixture {}",
                i
            );

            // Verify tree produces exactly 3 leaves
            assert_eq!(
                script.leaves.len(),
                3,
                "Expected 3 leaves for fixture {}",
                i
            );

            // Verify control blocks match expected values
            for (j, (leaf, expected_cb)) in script
                .leaves
                .iter()
                .zip(fixture.control_blocks.iter())
                .enumerate()
            {
                assert_eq!(
                    hex::encode(&leaf.control_block),
                    *expected_cb,
                    "Control block mismatch for fixture {} leaf {}",
                    i,
                    j
                );
                // Verify control block is cryptographically valid
                assert!(
                    verify_control_block(&leaf.leaf_hash, &leaf.control_block, &script.merkle_root),
                    "Control block verification failed for fixture {} leaf {}",
                    i,
                    j
                );
            }

            // Verify depth-1 control block is shorter than depth-2 ones:
            // depth 1: 1 + 32*1 = 33 bytes; depth 2: 1 + 32*2 = 65 bytes
            assert_eq!(
                script.leaves[0].control_block.len(),
                33,
                "leaf[0] (depth 1) control block should be 33 bytes"
            );
            assert_eq!(
                script.leaves[1].control_block.len(),
                65,
                "leaf[1] (depth 2) control block should be 65 bytes"
            );
            assert_eq!(
                script.leaves[2].control_block.len(),
                65,
                "leaf[2] (depth 2) control block should be 65 bytes"
            );
        }
    }

    #[test]
    fn test_p2mr_chain_values() {
        use crate::fixed_script_wallet::script_id::{Chain, Scope};
        use crate::fixed_script_wallet::wallet_scripts::OutputScriptType;
        use std::convert::TryFrom;

        // Chain 360: external P2MR
        let chain360 = Chain::try_from(360u32).unwrap();
        assert_eq!(chain360.script_type, OutputScriptType::P2mr);
        assert_eq!(chain360.scope, Scope::External);
        assert_eq!(chain360.value(), 360);

        // Chain 361: internal P2MR
        let chain361 = Chain::try_from(361u32).unwrap();
        assert_eq!(chain361.script_type, OutputScriptType::P2mr);
        assert_eq!(chain361.scope, Scope::Internal);
        assert_eq!(chain361.value(), 361);

        // Round-trip: value() matches what we set
        assert_eq!(
            Chain::new(OutputScriptType::P2mr, Scope::External).value(),
            360
        );
        assert_eq!(
            Chain::new(OutputScriptType::P2mr, Scope::Internal).value(),
            361
        );
    }

    #[test]
    fn test_p2mr_no_internal_key() {
        // P2MR output starts with 0x52 (OP_2), not 0x51 (OP_1 / taproot).
        // This verifies P2MR is distinguishable from P2TR at the scriptPubKey level.
        let triple = pub_triple_from_hex(
            "02d20a62701c54f6eb3abb9f964b0e29ff90ffa3b4e3fcb73e7c67d4950fa6e3c7",
            "028714039c6866c27eb6885ffbb4085964a603140e5a39b0fa29b1d9839212f9a2",
            "03203ab799ce28e2cca044f594c69275050af4bb0854ad730a8f74622342300e64",
        );
        let script = ScriptP2mr::new(&triple);
        let spk_bytes = script.output_script().to_bytes();
        assert_eq!(
            spk_bytes[0], 0x52,
            "P2MR scriptPubKey must start with OP_2 (0x52)"
        );
        assert_eq!(spk_bytes.len(), 34, "P2MR scriptPubKey must be 34 bytes");

        // Compare: P2TR for same keys would start with 0x51
        let p2tr = ScriptP2tr::new(&triple, false);
        assert_eq!(
            p2tr.output_script().to_bytes()[0],
            0x51,
            "P2TR scriptPubKey must start with OP_1 (0x51)"
        );

        // P2MR and P2TR produce different output scripts
        assert_ne!(
            script.output_script().to_hex_string(),
            p2tr.output_script().to_hex_string(),
            "P2MR and P2TR must produce different output scripts"
        );
    }

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
