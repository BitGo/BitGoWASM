//! Inscription reveal transaction creation and signing
//!
//! Handles creating P2TR outputs with inscription scripts and signing
//! reveal transactions using taproot script path spending.

use super::envelope::build_inscription_script;
use crate::error::WasmUtxoError;
use miniscript::bitcoin::consensus::Encodable;
use miniscript::bitcoin::hashes::sha256;
use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::key::UntweakedKeypair;
use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use miniscript::bitcoin::sighash::{Prevouts, SighashCache};
use miniscript::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use miniscript::bitcoin::{ScriptBuf, Transaction, TxOut, Witness};

/// NUMS point (Nothing Up My Sleeve) - a secp256k1 x coordinate with unknown discrete logarithm.
/// Equal to SHA256(uncompressedDER(SECP256K1_GENERATOR_POINT)).
/// Used as internal key when key-path spending is disabled.
/// This matches utxo-lib's implementation for compatibility.
fn nums_point() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    // Generator point G is the public key for secret key = 1
    let one = SecretKey::from_slice(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .expect("valid secret key");
    let generator = PublicKey::from_secret_key(&secp, &one);
    // Uncompressed format: 04 || x || y (65 bytes)
    let uncompressed = generator.serialize_uncompressed();
    // SHA256 hash of uncompressed generator point
    let hash = sha256::Hash::hash(&uncompressed);
    XOnlyPublicKey::from_slice(hash.as_ref()).expect("valid x-only pubkey")
}

/// Taproot leaf script data needed for spending
#[derive(Debug, Clone)]
pub struct TapLeafScript {
    pub leaf_version: u8,
    pub script: Vec<u8>,
    pub control_block: Vec<u8>,
}

/// Prepared data for an inscription reveal transaction
#[derive(Debug, Clone)]
pub struct InscriptionRevealData {
    /// The P2TR output script for the commit transaction (network-agnostic)
    pub output_script: Vec<u8>,
    pub reveal_transaction_vsize: usize,
    pub tap_leaf_script: TapLeafScript,
}

/// Create inscription reveal data including the commit output script and tap leaf script
///
/// # Arguments
/// * `script_pubkey` - The x-only public key for the OP_CHECKSIG in the inscription script
/// * `content_type` - MIME type of the inscription
/// * `data` - The inscription data
///
/// # Returns
/// `InscriptionRevealData` containing the commit output script, estimated vsize, and tap leaf script
pub fn create_inscription_reveal_data(
    script_pubkey: &XOnlyPublicKey,
    content_type: &str,
    data: &[u8],
) -> Result<InscriptionRevealData, WasmUtxoError> {
    let secp = Secp256k1::new();

    // Build the inscription script (pubkey is used for OP_CHECKSIG inside the script)
    let script = build_inscription_script(script_pubkey, content_type, data);

    // Create taproot tree with the inscription script as the only leaf
    let builder = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|e| WasmUtxoError::new(&format!("Failed to build taproot tree: {:?}", e)))?;

    // Use NUMS point as internal key (disables key-path spending)
    // This matches utxo-lib's behavior for compatibility
    let internal_key = nums_point();
    let spend_info = builder
        .finalize(&secp, internal_key)
        .map_err(|e| WasmUtxoError::new(&format!("Failed to finalize taproot: {:?}", e)))?;

    // Get the output script (network-agnostic)
    let output_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    // Get the control block for the script
    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| WasmUtxoError::new("Failed to get control block"))?;

    // Estimate reveal transaction vsize
    let reveal_vsize = estimate_reveal_vsize(&script, &control_block);

    Ok(InscriptionRevealData {
        output_script: output_script.to_bytes(),
        reveal_transaction_vsize: reveal_vsize,
        tap_leaf_script: TapLeafScript {
            leaf_version: LeafVersion::TapScript.to_consensus() as u8,
            script: script.to_bytes(),
            control_block: control_block.serialize(),
        },
    })
}

/// Sign a reveal transaction
///
/// # Arguments
/// * `private_key` - The private key (32 bytes)
/// * `tap_leaf_script` - The tap leaf script from `create_inscription_reveal_data`
/// * `commit_tx` - The commit transaction
/// * `commit_output_script` - The commit output script (P2TR)
/// * `recipient_output_script` - Where to send the inscription (output script)
/// * `output_value_sats` - Value in satoshis for the inscription output
///
/// # Returns
/// The signed reveal transaction as bytes (ready to broadcast)
pub fn sign_reveal_transaction(
    private_key: &SecretKey,
    tap_leaf_script: &TapLeafScript,
    commit_tx: &Transaction,
    commit_output_script: &[u8],
    recipient_output_script: &[u8],
    output_value_sats: u64,
) -> Result<Vec<u8>, WasmUtxoError> {
    let secp = Secp256k1::new();

    // Convert output scripts
    let commit_script = ScriptBuf::from_bytes(commit_output_script.to_vec());
    let recipient_script = ScriptBuf::from_bytes(recipient_output_script.to_vec());

    // Find the commit output (must be exactly one)
    let matching_outputs: Vec<_> = commit_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, out)| out.script_pubkey == commit_script)
        .collect();

    let (vout, commit_output) = match matching_outputs.len() {
        0 => return Err(WasmUtxoError::new("Commit output not found in transaction")),
        1 => matching_outputs[0],
        n => {
            return Err(WasmUtxoError::new(&format!(
                "Expected exactly one commit output, found {}",
                n
            )))
        }
    };

    // Parse tap leaf script
    let script = ScriptBuf::from_bytes(tap_leaf_script.script.clone());
    let control_block = ControlBlock::decode(&tap_leaf_script.control_block)
        .map_err(|e| WasmUtxoError::new(&format!("Invalid control block: {:?}", e)))?;

    // Create the reveal transaction
    let reveal_input = miniscript::bitcoin::TxIn {
        previous_output: miniscript::bitcoin::OutPoint {
            txid: commit_tx.compute_txid(),
            vout: vout as u32,
        },
        script_sig: ScriptBuf::new(),
        sequence: miniscript::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let reveal_output = TxOut {
        value: miniscript::bitcoin::Amount::from_sat(output_value_sats),
        script_pubkey: recipient_script,
    };

    let mut reveal_tx = Transaction {
        version: miniscript::bitcoin::transaction::Version::TWO,
        lock_time: miniscript::bitcoin::absolute::LockTime::ZERO,
        input: vec![reveal_input],
        output: vec![reveal_output],
    };

    // Sign the transaction using taproot script path
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let prevouts = vec![commit_output.clone()];

    let mut sighash_cache = SighashCache::new(&reveal_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            miniscript::bitcoin::TapSighashType::Default,
        )
        .map_err(|e| WasmUtxoError::new(&format!("Failed to compute sighash: {}", e)))?;

    // Sign
    let keypair = UntweakedKeypair::from_secret_key(&secp, private_key);
    let message = miniscript::bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    // Build witness: <signature> <script> <control_block>
    let tap_sig = miniscript::bitcoin::taproot::Signature {
        signature,
        sighash_type: miniscript::bitcoin::TapSighashType::Default,
    };

    let mut witness = Witness::new();
    witness.push(tap_sig.to_vec());
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    reveal_tx.input[0].witness = witness;

    // Serialize the signed transaction
    let mut tx_bytes = Vec::new();
    reveal_tx
        .consensus_encode(&mut tx_bytes)
        .map_err(|e| WasmUtxoError::new(&format!("Failed to serialize transaction: {}", e)))?;

    Ok(tx_bytes)
}

/// Estimate the virtual size of a reveal transaction
fn estimate_reveal_vsize(script: &ScriptBuf, control_block: &ControlBlock) -> usize {
    // Transaction overhead
    let tx_overhead = 10; // version(4) + locktime(4) + varint inputs(1) + varint outputs(1)
    let segwit_overhead = 2; // marker + flag

    // Input: outpoint(36) + scriptSig len(1) + sequence(4)
    let input_base = 41;

    // Output: value(8) + scriptPubKey len + scriptPubKey (~34 for P2TR)
    let output_base = 43;

    // Witness: signature(64+1) + script + control_block + witness stack count
    let witness_size = 1 + 65 + script.len() + control_block.serialize().len();
    let witness_weight = witness_size; // witness is already in weight units (1:1)

    // Calculate weight
    let base_weight = (tx_overhead + input_base + output_base) * 4;
    let total_weight = base_weight + segwit_overhead + witness_weight;

    // Virtual size = ceil(weight / 4)
    (total_weight + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::hashes::hex::FromHex;

    fn test_keypair() -> (SecretKey, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid key");
        let (xonly, _) = secret_key.x_only_public_key(&secp);
        (secret_key, xonly)
    }

    #[test]
    fn test_create_inscription_reveal_data() {
        let (_, pubkey) = test_keypair();
        let result = create_inscription_reveal_data(&pubkey, "text/plain", b"Hello!");

        assert!(result.is_ok());
        let data = result.unwrap();
        // P2TR output scripts start with 0x51 0x20 (OP_1 PUSH32)
        assert_eq!(data.output_script.len(), 34);
        assert_eq!(data.output_script[0], 0x51); // OP_1
        assert_eq!(data.output_script[1], 0x20); // PUSH32
        assert!(data.reveal_transaction_vsize > 100);
        assert!(!data.tap_leaf_script.script.is_empty());
        assert!(!data.tap_leaf_script.control_block.is_empty());
    }

    /// Test with the same x-only pubkey as utxo-ord test
    /// Expected output script: 5120dc8b12eec336e7215fd1213acf66fb0d5dd962813c0616988a12c08493831109
    /// Expected address: tb1pmj939mkrxmnjzh73yyav7ehmp4wajc5p8srpdxy2ztqgfyurzyys4sg9zx
    #[test]
    fn test_utxo_ord_fixture_short_data() {
        // Same x-only pubkey as utxo-ord test
        let xonly_hex = "af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3";
        let xonly_bytes = Vec::<u8>::from_hex(xonly_hex).unwrap();
        let pubkey = XOnlyPublicKey::from_slice(&xonly_bytes).unwrap();

        let inscription_data = b"Never Gonna Give You Up";
        let result = create_inscription_reveal_data(&pubkey, "text/plain", inscription_data);

        assert!(result.is_ok());
        let data = result.unwrap();

        // Log the actual output for debugging
        let output_hex = hex::encode(&data.output_script);
        println!("X-only pubkey: {}", xonly_hex);
        println!(
            "Inscription data: {:?}",
            String::from_utf8_lossy(inscription_data)
        );
        println!("Output script (actual):   {}", output_hex);
        println!("Output script (expected): 5120dc8b12eec336e7215fd1213acf66fb0d5dd962813c0616988a12c08493831109");

        // Log the tap leaf script for debugging
        println!(
            "Tap leaf script hex: {}",
            hex::encode(&data.tap_leaf_script.script)
        );
        println!(
            "Control block hex: {}",
            hex::encode(&data.tap_leaf_script.control_block)
        );

        // Basic structure checks
        assert_eq!(data.output_script.len(), 34);
        assert_eq!(data.output_script[0], 0x51); // OP_1
        assert_eq!(data.output_script[1], 0x20); // PUSH32

        // Assert byte-exact match with utxo-ord
        let expected_hex = "5120dc8b12eec336e7215fd1213acf66fb0d5dd962813c0616988a12c08493831109";
        assert_eq!(
            output_hex, expected_hex,
            "Output script should match utxo-ord fixture"
        );
    }

    /// Test with large data (>520 bytes) - same as utxo-ord test
    /// Expected output script: 5120ec90ba87f3e7c5462eb2173afdc50e00cea6fc69166677171d70f45dfb3a31b8
    /// Expected address: tb1pajgt4plnulz5vt4jzua0m3gwqr82dlrfzen8w9cawr69m7e6xxuq7dzypl
    #[test]
    fn test_utxo_ord_fixture_large_data() {
        let xonly_hex = "af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3";
        let xonly_bytes = Vec::<u8>::from_hex(xonly_hex).unwrap();
        let pubkey = XOnlyPublicKey::from_slice(&xonly_bytes).unwrap();

        // "Never Gonna Let You Down" repeated 100 times
        let base = b"Never Gonna Let You Down";
        let inscription_data: Vec<u8> = base
            .iter()
            .cycle()
            .take(base.len() * 100)
            .copied()
            .collect();

        let result = create_inscription_reveal_data(&pubkey, "text/plain", &inscription_data);

        assert!(result.is_ok());
        let data = result.unwrap();

        let output_hex = hex::encode(&data.output_script);
        println!("Output script (actual):   {}", output_hex);
        println!("Output script (expected): 5120ec90ba87f3e7c5462eb2173afdc50e00cea6fc69166677171d70f45dfb3a31b8");

        assert_eq!(data.output_script.len(), 34);
        assert_eq!(data.output_script[0], 0x51);
        assert_eq!(data.output_script[1], 0x20);

        // Assert byte-exact match with utxo-ord
        let expected_hex = "5120ec90ba87f3e7c5462eb2173afdc50e00cea6fc69166677171d70f45dfb3a31b8";
        assert_eq!(
            output_hex, expected_hex,
            "Output script should match utxo-ord fixture"
        );
    }

    /// Debug test to understand taproot key tweaking
    #[test]
    fn test_taproot_tweak_details() {
        let xonly_hex = "af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3";
        let xonly_bytes = Vec::<u8>::from_hex(xonly_hex).unwrap();
        let internal_key = XOnlyPublicKey::from_slice(&xonly_bytes).unwrap();

        println!("Internal key: {}", internal_key);

        let secp = Secp256k1::new();
        let script =
            build_inscription_script(&internal_key, "text/plain", b"Never Gonna Give You Up");

        println!("Inscription script hex: {}", hex::encode(script.as_bytes()));
        println!("Inscription script len: {}", script.len());

        // Build taproot tree
        let builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();

        let spend_info = builder.finalize(&secp, internal_key).unwrap();

        println!("Output key (tweaked): {}", spend_info.output_key());
        println!(
            "Merkle root: {:?}",
            spend_info.merkle_root().map(|r| r.to_string())
        );

        let output_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
        println!("Output script: {}", hex::encode(output_script.as_bytes()));
    }
}
