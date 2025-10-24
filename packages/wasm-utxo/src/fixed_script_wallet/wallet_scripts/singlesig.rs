/// This contains code relating to bitcoin cash replay protection inputs.
/// Unlike WalletScripts, these are single-signature where the key is with BitGo.
use crate::bitcoin::blockdata::opcodes::all::OP_CHECKSIG;
use crate::bitcoin::blockdata::script::Builder;
use crate::bitcoin::{CompressedPublicKey, ScriptBuf};

/// Build bare p2pk script (used for p2sh-p2pk replay protection)
pub fn build_p2pk_script(key: CompressedPublicKey) -> ScriptBuf {
    Builder::default()
        .push_slice(key.to_bytes())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

#[derive(Debug)]
pub struct ScriptP2shP2pk {
    pub redeem_script: ScriptBuf,
}

impl ScriptP2shP2pk {
    pub fn new(key: CompressedPublicKey) -> Self {
        ScriptP2shP2pk {
            redeem_script: build_p2pk_script(key),
        }
    }

    pub fn output_script(&self) -> ScriptBuf {
        self.redeem_script.to_p2sh()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::secp256k1::Secp256k1;
    use crate::fixed_script_wallet::test_utils::fixtures::{
        load_psbt_fixture, parse_wallet_keys, SignatureState,
    };

    #[test]
    fn test_p2sh_p2pk_script_generation_from_fixture() {
        let fixture = load_psbt_fixture("bitcoin", SignatureState::Fullsigned)
            .expect("Failed to load fixture");

        // Find the p2shP2pk input in the fixture
        let p2shp2pk_input = fixture
            .psbt_inputs
            .iter()
            .find_map(|input| match input {
                crate::fixed_script_wallet::test_utils::fixtures::PsbtInputFixture::P2shP2pk(i) => {
                    Some(i)
                }
                _ => None,
            })
            .expect("Failed to find p2shP2pk input in fixture");

        // Get the expected values from the fixture
        let expected_redeem_script = &p2shp2pk_input.redeem_script;
        let expected_pubkey = p2shp2pk_input
            .partial_sig
            .first()
            .map(|sig| &sig.pubkey)
            .expect("No partial signature found");

        // Parse the wallet keys
        let xprvs = parse_wallet_keys(&fixture).expect("Failed to parse wallet keys");
        let secp = Secp256k1::new();

        // Find which key matches the expected pubkey
        let mut matching_key = None;
        for xprv in &xprvs {
            let xpub = crate::bitcoin::bip32::Xpub::from_priv(&secp, xprv);
            // Convert secp256k1::PublicKey to bitcoin::PublicKey
            let bitcoin_pubkey = crate::bitcoin::PublicKey::new(xpub.public_key);
            let compressed_pubkey = CompressedPublicKey::try_from(bitcoin_pubkey)
                .expect("Failed to convert to compressed pubkey");
            let pubkey_hex = hex::encode(compressed_pubkey.to_bytes());

            if pubkey_hex == *expected_pubkey {
                matching_key = Some(compressed_pubkey);
                break;
            }
        }

        let pubkey = matching_key.expect("Could not find matching pubkey in wallet keys");

        // Build the p2sh-p2pk script
        let script = ScriptP2shP2pk::new(pubkey);

        // Verify the redeem script matches
        assert_eq!(
            script.redeem_script.to_hex_string(),
            *expected_redeem_script,
            "Redeem script mismatch"
        );

        // Verify the output script (p2sh wrapped) matches the fixture
        // Get the output script from the non-witness UTXO
        use crate::bitcoin::consensus::Decodable;
        use crate::bitcoin::Transaction;

        let input_index = fixture
            .psbt_inputs
            .iter()
            .position(|input| {
                matches!(
                    input,
                    crate::fixed_script_wallet::test_utils::fixtures::PsbtInputFixture::P2shP2pk(_)
                )
            })
            .expect("Failed to find p2shP2pk input index");
        let vout = fixture.inputs[input_index].index as usize;

        let tx_bytes = hex::decode(&p2shp2pk_input.non_witness_utxo).expect("Failed to decode hex");
        let prev_tx: Transaction = Decodable::consensus_decode(&mut tx_bytes.as_slice())
            .expect("Failed to decode non-witness utxo");
        let expected_output_script = prev_tx.output[vout].script_pubkey.to_hex_string();

        assert_eq!(
            script.output_script().to_hex_string(),
            expected_output_script,
            "Output script (p2sh) mismatch"
        );
    }

    #[test]
    fn test_build_p2pk_script() {
        // Test with a known public key
        let pubkey_hex = "0336ef228ffe9b8efffba052c32d334660dd1f8366cf8fe44ae5aa672b6b629095";
        let pubkey_bytes = hex::decode(pubkey_hex).expect("Failed to decode pubkey hex");
        let pubkey =
            CompressedPublicKey::from_slice(&pubkey_bytes).expect("Failed to parse pubkey");

        let script = build_p2pk_script(pubkey);

        // Expected: 21 (push 33 bytes) + pubkey + ac (OP_CHECKSIG)
        let expected = format!("21{}ac", pubkey_hex);
        assert_eq!(
            script.to_hex_string(),
            expected,
            "P2PK script format mismatch"
        );
    }
}
