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

fn build_p2tr_spend_info(keys: &PubTriple, p2tr_musig2: bool) -> TaprootSpendInfo {
    use super::bitgo_musig::key_agg_bitgo_p2tr_legacy;
    use super::bitgo_musig::key_agg_p2tr_musig2;
    use crate::bitcoin::secp256k1::Secp256k1;
    use crate::bitcoin::XOnlyPublicKey;

    let secp = Secp256k1::new();
    let user = keys[0];
    let backup = keys[1];
    let bitgo = keys[2];

    let agg_key_bytes = if p2tr_musig2 {
        key_agg_p2tr_musig2(&[user, bitgo]).expect("valid aggregation")
    } else {
        key_agg_bitgo_p2tr_legacy(&[user, bitgo]).expect("valid aggregation")
    };
    let internal_key = XOnlyPublicKey::from_slice(&agg_key_bytes).expect("valid xonly key");

    if p2tr_musig2 {
        // Build taptree with 2 script paths:
        // - user+backup (depth 1)
        // - backup+bitgo (depth 1)
        TaprootBuilder::new()
            .add_leaf(1, build_p2tr_ns_script(&[user, backup]))
            .expect("valid leaf")
            .add_leaf(1, build_p2tr_ns_script(&[backup, bitgo]))
            .expect("valid leaf")
            .finalize(&secp, internal_key)
            .expect("valid taptree")
    } else {
        // Build taptree with 3 script paths:
        // - user+bitgo (depth 1)
        // - user+backup (depth 2)
        // - backup+bitgo (depth 2)
        TaprootBuilder::new()
            .add_leaf(1, build_p2tr_ns_script(&[user, bitgo]))
            .expect("valid leaf")
            .add_leaf(2, build_p2tr_ns_script(&[user, backup]))
            .expect("valid leaf")
            .add_leaf(2, build_p2tr_ns_script(&[backup, bitgo]))
            .expect("valid leaf")
            .finalize(&secp, internal_key)
            .expect("valid taptree")
    }
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
