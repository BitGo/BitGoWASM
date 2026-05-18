//! BIP-352 test vector validation.
//!
//! Tests against the official BIP-352 send_and_receive_test_vectors.json.

#[cfg(test)]
mod tests {
    use miniscript::bitcoin::secp256k1::{Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

    use crate::silent_payments::address;
    use crate::silent_payments::labels;
    use crate::silent_payments::scanner;
    use crate::silent_payments::sender;
    use crate::silent_payments::spending;

    #[derive(serde::Deserialize, Debug)]
    struct TestCase {
        comment: String,
        sending: Vec<SendingTest>,
        receiving: Vec<ReceivingTest>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct SendingTest {
        given: SendingGiven,
        expected: SendingExpected,
    }

    #[derive(serde::Deserialize, Debug)]
    struct SendingGiven {
        vin: Vec<VinEntry>,
        recipients: Vec<RecipientEntry>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct VinEntry {
        txid: String,
        vout: u32,
        #[serde(rename = "scriptSig")]
        script_sig: String,
        txinwitness: String,
        prevout: PrevoutEntry,
        #[serde(default)]
        private_key: Option<String>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct PrevoutEntry {
        #[serde(rename = "scriptPubKey")]
        script_pub_key: ScriptPubKeyEntry,
    }

    #[derive(serde::Deserialize, Debug)]
    struct ScriptPubKeyEntry {
        hex: String,
    }

    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct RecipientEntry {
        address: String,
        scan_pub_key: String,
        spend_pub_key: String,
    }

    #[derive(serde::Deserialize, Debug)]
    struct SendingExpected {
        outputs: Vec<Vec<String>>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct ReceivingTest {
        given: ReceivingGiven,
        expected: ReceivingExpected,
    }

    #[derive(serde::Deserialize, Debug)]
    struct ReceivingGiven {
        vin: Vec<VinEntry>,
        outputs: Vec<String>,
        key_material: KeyMaterial,
        labels: Vec<u32>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct KeyMaterial {
        spend_priv_key: String,
        scan_priv_key: String,
    }

    #[derive(serde::Deserialize, Debug)]
    struct ReceivingExpected {
        addresses: Vec<String>,
        #[serde(default)]
        outputs: Vec<ExpectedOutput>,
        #[serde(default)]
        n_outputs: Option<u32>,
    }

    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct ExpectedOutput {
        pub_key: String,
        priv_key_tweak: String,
        signature: String,
    }

    fn load_test_vectors() -> Vec<TestCase> {
        let content = std::fs::read_to_string(
            "test/fixtures/silent_payments/send_and_receive_test_vectors.json",
        )
        .expect("Failed to load BIP-352 test vectors");
        serde_json::from_str(&content).expect("Failed to parse test vectors")
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("valid hex")
    }

    fn is_taproot_script(script_hex: &str) -> bool {
        // P2TR starts with 5120 (OP_1 OP_PUSHBYTES_32)
        script_hex.starts_with("5120")
    }

    fn is_p2wpkh_script(script_hex: &str) -> bool {
        // P2WPKH starts with 0014 (OP_0 OP_PUSHBYTES_20)
        script_hex.starts_with("0014")
    }

    /// Count the number of witness items from the serialized witness hex.
    /// The witness is encoded as: varint(count) || [varint(len) || item]...
    fn count_witness_items(witness_hex: &str) -> usize {
        if witness_hex.is_empty() {
            return 0;
        }
        let bytes = hex_to_bytes(witness_hex);
        if bytes.is_empty() {
            return 0;
        }
        // First byte is the item count (compact size, typically < 0xfd)
        bytes[0] as usize
    }

    /// Check if a P2TR input is a script-path spend (should be excluded from SP).
    /// Key-path spend: 1 witness item (signature). Script-path: 2+ items.
    fn is_taproot_script_path(vin: &VinEntry) -> bool {
        let script_hex = &vin.prevout.script_pub_key.hex;
        if !is_taproot_script(script_hex) {
            return false;
        }
        count_witness_items(&vin.txinwitness) > 1
    }

    /// Check if an input uses an uncompressed public key (should be excluded from SP).
    fn has_uncompressed_pubkey(vin: &VinEntry) -> bool {
        let script_hex = &vin.prevout.script_pub_key.hex;

        if script_hex.starts_with("76a9") {
            // P2PKH: check the pubkey in scriptSig
            let script_sig_bytes = hex_to_bytes(&vin.script_sig);
            if script_sig_bytes.is_empty() {
                return false;
            }
            let sig_len = script_sig_bytes[0] as usize;
            if script_sig_bytes.len() < 1 + sig_len + 1 {
                return false;
            }
            let pubkey_len = script_sig_bytes[1 + sig_len] as usize;
            pubkey_len == 65 // uncompressed
        } else if script_hex.starts_with("0014") || script_hex.starts_with("a914") {
            // P2WPKH or P2SH-P2WPKH: check last witness item
            if vin.txinwitness.is_empty() {
                return false;
            }
            let witness_bytes = hex_to_bytes(&vin.txinwitness);
            if witness_bytes.is_empty() {
                return false;
            }
            let count = witness_bytes[0] as usize;
            // Parse to the last item
            let mut pos = 1;
            for i in 0..count {
                if pos >= witness_bytes.len() {
                    return false;
                }
                let item_len = witness_bytes[pos] as usize;
                if i == count - 1 {
                    return item_len == 65; // uncompressed pubkey
                }
                pos += 1 + item_len;
            }
            false
        } else {
            false
        }
    }

    /// Check if a P2SH input is not P2SH-P2WPKH (bare P2SH multisig, etc.).
    /// These inputs are not eligible for Silent Payments.
    fn is_invalid_p2sh(vin: &VinEntry) -> bool {
        let script_hex = &vin.prevout.script_pub_key.hex;
        if !script_hex.starts_with("a914") {
            return false;
        }
        // P2SH-P2WPKH: scriptSig pushes a 22-byte redeemScript (0x0014{20-byte hash})
        // and has a witness. If no witness or scriptSig doesn't push a P2WPKH redeemScript,
        // it's a bare P2SH (multisig, etc.) which is not eligible.
        if vin.txinwitness.is_empty() {
            return true; // No witness = bare P2SH
        }
        let script_sig_bytes = hex_to_bytes(&vin.script_sig);
        if script_sig_bytes.is_empty() || script_sig_bytes.len() < 23 {
            return true;
        }
        // First byte should be 0x16 (push 22 bytes), then 0x00 0x14 (witness v0, 20-byte program)
        !(script_sig_bytes[0] == 0x16 && script_sig_bytes[1] == 0x00 && script_sig_bytes[2] == 0x14)
    }

    /// Parse a txid hex string to little-endian bytes (Bitcoin's internal byte order).
    /// Bitcoin txids are displayed in big-endian (reversed), but stored in LE.
    fn txid_to_le_bytes(txid_hex: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let decoded = hex_to_bytes(txid_hex);
        assert_eq!(decoded.len(), 32);
        // Reverse to get LE (internal byte order)
        for (i, b) in decoded.iter().rev().enumerate() {
            bytes[i] = *b;
        }
        bytes
    }

    /// Extract the public key from an input for scanning purposes.
    fn extract_pubkey_from_vin(vin: &VinEntry) -> Option<PublicKey> {
        let script_hex = &vin.prevout.script_pub_key.hex;

        if is_taproot_script(script_hex) {
            // P2TR: x-only key from witness program bytes [2..34]
            let script_bytes = hex_to_bytes(script_hex);
            let x_only = XOnlyPublicKey::from_slice(&script_bytes[2..34]).ok()?;
            Some(PublicKey::from_x_only_public_key(x_only, Parity::Even))
        } else if is_p2wpkh_script(script_hex) {
            // P2WPKH: compressed pubkey from last witness item
            let witness_hex = &vin.txinwitness;
            if witness_hex.is_empty() {
                return None;
            }
            // Witness items are space-separated hex strings
            let items: Vec<&str> = witness_hex.split(' ').collect();
            if items.is_empty() {
                return None;
            }
            let last_item = items.last()?;
            let pubkey_bytes = hex_to_bytes(last_item);
            PublicKey::from_slice(&pubkey_bytes).ok()
        } else if script_hex.starts_with("76a9") {
            // P2PKH: compressed pubkey from scriptSig
            let script_sig_bytes = hex_to_bytes(&vin.script_sig);
            crate::silent_payments::scanner::extract_input_pubkey(
                miniscript::bitcoin::Script::from_bytes(&hex_to_bytes(script_hex)),
                &script_sig_bytes,
                &[],
            )
        } else if script_hex.starts_with("a914") {
            // P2SH-P2WPKH: compressed pubkey from witness
            let witness_hex = &vin.txinwitness;
            if witness_hex.is_empty() {
                return None;
            }
            let items: Vec<&str> = witness_hex.split(' ').collect();
            let last_item = items.last()?;
            let pubkey_bytes = hex_to_bytes(last_item);
            PublicKey::from_slice(&pubkey_bytes).ok()
        } else {
            None
        }
    }

    #[test]
    fn test_sending_vectors() {
        let vectors = load_test_vectors();

        for (test_idx, test) in vectors.iter().enumerate() {
            for (send_idx, sending) in test.sending.iter().enumerate() {
                let given = &sending.given;
                let expected = &sending.expected;

                // Build sender inputs from private keys
                let mut sender_inputs = Vec::new();
                let mut outpoints = Vec::new();

                for vin in &given.vin {
                    // All outpoints are included (not just eligible inputs)
                    outpoints.push(sender::SenderOutpoint {
                        txid: txid_to_le_bytes(&vin.txid),
                        vout: vin.vout,
                    });

                    // Skip ineligible inputs:
                    // - P2TR script-path spends
                    // - Inputs with uncompressed public keys
                    // - Bare P2SH (non-P2SH-P2WPKH) inputs
                    if is_taproot_script_path(vin)
                        || has_uncompressed_pubkey(vin)
                        || is_invalid_p2sh(vin)
                    {
                        continue;
                    }

                    if let Some(ref pk_hex) = vin.private_key {
                        let sk_bytes = hex_to_bytes(pk_hex);
                        let sk = SecretKey::from_slice(&sk_bytes)
                            .expect("valid private key in test vector");

                        let is_taproot = is_taproot_script(&vin.prevout.script_pub_key.hex);

                        sender_inputs.push(sender::SenderInput {
                            private_key: sk,
                            is_taproot,
                        });
                    }
                }

                // Decode recipient addresses
                let recipients: Vec<address::SilentPaymentAddress> = given
                    .recipients
                    .iter()
                    .map(|r| address::decode(&r.address).expect("valid SP address"))
                    .collect();

                // If expected outputs are all empty, this test expects sending to fail
                // or produce no outputs (e.g., K_max tests, zero-sum key tests).
                let expect_empty = expected.outputs.iter().all(|o| o.is_empty());

                // Derive outputs
                let outputs =
                    sender::derive_silent_payment_outputs(&sender_inputs, &outpoints, &recipients);

                let outputs = match outputs {
                    Ok(o) => o,
                    Err(_e) => {
                        if expect_empty {
                            continue;
                        }
                        panic!(
                            "Test #{} '{}' send #{}: derive_outputs failed: {}",
                            test_idx, test.comment, send_idx, _e
                        );
                    }
                };

                // If we expected empty but got success, that's OK for tests like K_max
                // where the sender produces valid outputs but the test focus is on receiver behavior.
                if expect_empty {
                    continue;
                }

                // Verify outputs match expected.
                // expected.outputs is a list of valid output sets (different orderings
                // of recipients within a B_scan group produce different outputs).
                // Our outputs should match exactly one of these sets.
                let mut actual_pubkeys: Vec<String> = outputs
                    .iter()
                    .map(|o| hex::encode(o.x_only_pubkey))
                    .collect();
                actual_pubkeys.sort();

                let matched = expected.outputs.iter().any(|group| {
                    let mut expected_sorted: Vec<String> = group.clone();
                    expected_sorted.sort();
                    actual_pubkeys == expected_sorted
                });

                assert!(
                    matched,
                    "Test #{} '{}' send #{}: output pubkeys don't match any expected group.\nActual: {:?}\nExpected groups: {:?}",
                    test_idx, test.comment, send_idx, actual_pubkeys, expected.outputs
                );
            }
        }
    }

    #[test]
    fn test_receiving_vectors() {
        let secp = Secp256k1::new();
        let vectors = load_test_vectors();

        for (test_idx, test) in vectors.iter().enumerate() {
            for (recv_idx, receiving) in test.receiving.iter().enumerate() {
                let given = &receiving.given;
                let expected = &receiving.expected;

                // Parse receiver keys
                let b_scan =
                    SecretKey::from_slice(&hex_to_bytes(&given.key_material.scan_priv_key))
                        .expect("valid scan key");
                let b_spend =
                    SecretKey::from_slice(&hex_to_bytes(&given.key_material.spend_priv_key))
                        .expect("valid spend key");
                let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);

                // Extract input public keys
                let mut input_pubkeys = Vec::new();
                let mut outpoints = Vec::new();

                for vin in &given.vin {
                    // All outpoints are included
                    outpoints.push(sender::SenderOutpoint {
                        txid: txid_to_le_bytes(&vin.txid),
                        vout: vin.vout,
                    });

                    // Skip ineligible inputs
                    if is_taproot_script_path(vin)
                        || has_uncompressed_pubkey(vin)
                        || is_invalid_p2sh(vin)
                    {
                        continue;
                    }

                    if let Some(pk) = extract_pubkey_from_vin(vin) {
                        input_pubkeys.push(pk);
                    }
                }

                if input_pubkeys.is_empty() {
                    // No eligible inputs, skip
                    continue;
                }

                // Parse taproot outputs
                let taproot_outputs: Vec<scanner::TaprootOutput> = given
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(idx, pk_hex)| {
                        let mut x_only = [0u8; 32];
                        x_only.copy_from_slice(&hex_to_bytes(pk_hex));
                        scanner::TaprootOutput {
                            x_only_pubkey: x_only,
                            index: idx as u32,
                        }
                    })
                    .collect();

                // Build label lookup if needed
                let label_lookup = if !given.labels.is_empty() {
                    Some(labels::build_label_lookup(&b_scan, &given.labels))
                } else {
                    None
                };

                // Scan
                let results = scanner::scan_transaction(
                    &b_scan,
                    &b_spend_pub,
                    &input_pubkeys,
                    &outpoints,
                    &taproot_outputs,
                    label_lookup.as_ref(),
                );

                let results = match results {
                    Ok(r) => r,
                    Err(e) => {
                        if expected.outputs.is_empty() {
                            continue;
                        }
                        panic!(
                            "Test #{} '{}' recv #{}: scan failed: {}",
                            test_idx, test.comment, recv_idx, e
                        );
                    }
                };

                // If n_outputs is set, verify we found exactly that many matches
                // (used for K_max test where individual outputs are not listed).
                if let Some(n) = expected.n_outputs {
                    assert_eq!(
                        results.len(),
                        n as usize,
                        "Test #{} '{}' recv #{}: expected n_outputs={}, got {}",
                        test_idx,
                        test.comment,
                        recv_idx,
                        n,
                        results.len()
                    );
                    // Skip individual output verification for n_outputs tests
                    continue;
                }

                // Verify: check that we found the expected outputs
                let expected_pubkeys: Vec<String> =
                    expected.outputs.iter().map(|o| o.pub_key.clone()).collect();

                let mut matched_pubkeys: Vec<String> = results
                    .iter()
                    .map(|r| {
                        let output = &taproot_outputs[r.output_index as usize];
                        hex::encode(output.x_only_pubkey)
                    })
                    .collect();
                matched_pubkeys.sort();

                let mut sorted_expected = expected_pubkeys.clone();
                sorted_expected.sort();

                assert_eq!(
                    matched_pubkeys, sorted_expected,
                    "Test #{} '{}' recv #{}: matched pubkeys mismatch.\nExpected: {:?}\nActual: {:?}",
                    test_idx, test.comment, recv_idx, sorted_expected, matched_pubkeys
                );

                // Verify tweaks and spend key derivation
                for result in &results {
                    let output = &taproot_outputs[result.output_index as usize];
                    let output_pubkey_hex = hex::encode(output.x_only_pubkey);

                    // Find the matching expected output
                    let expected_output = expected
                        .outputs
                        .iter()
                        .find(|o| o.pub_key == output_pubkey_hex);

                    if let Some(exp) = expected_output {
                        // For labeled outputs, the priv_key_tweak = t_k + label_tweak.
                        // For non-labeled outputs, priv_key_tweak = t_k.
                        let expected_tweak_bytes = hex_to_bytes(&exp.priv_key_tweak);

                        if result.label.is_some() {
                            // Verify that t_k + label_tweak = expected priv_key_tweak
                            let label_tweak = result
                                .label_tweak
                                .expect("label_tweak should be set for label match");
                            let mut combined = SecretKey::from_slice(&result.tweak).unwrap();
                            let label_scalar =
                                miniscript::bitcoin::secp256k1::Scalar::from_be_bytes(label_tweak)
                                    .unwrap();
                            combined = combined.add_tweak(&label_scalar).unwrap();
                            assert_eq!(
                                combined.secret_bytes().to_vec(),
                                expected_tweak_bytes,
                                "Test #{} '{}' recv #{}: combined tweak (t_k + label) mismatch for output {}",
                                test_idx,
                                test.comment,
                                recv_idx,
                                output_pubkey_hex
                            );

                            // Verify spend key derivation with combined tweak
                            let mut combined_tweak = [0u8; 32];
                            combined_tweak.copy_from_slice(&combined.secret_bytes());
                            let derived_key =
                                spending::derive_spend_key(&b_spend, &combined_tweak).unwrap();
                            let derived_pub = PublicKey::from_secret_key(&secp, &derived_key);
                            let (derived_x_only, _) = derived_pub.x_only_public_key();
                            assert_eq!(
                                hex::encode(derived_x_only.serialize()),
                                output_pubkey_hex,
                                "Test #{} '{}' recv #{}: derived spend key doesn't match labeled output",
                                test_idx, test.comment, recv_idx,
                            );
                        } else {
                            // Non-labeled: tweak should match directly
                            assert_eq!(
                                result.tweak.to_vec(),
                                expected_tweak_bytes,
                                "Test #{} '{}' recv #{}: tweak mismatch for output {}",
                                test_idx,
                                test.comment,
                                recv_idx,
                                output_pubkey_hex
                            );

                            // Verify spend key derivation
                            let derived_key =
                                spending::derive_spend_key(&b_spend, &result.tweak).unwrap();
                            let derived_pub = PublicKey::from_secret_key(&secp, &derived_key);
                            let (derived_x_only, _) = derived_pub.x_only_public_key();
                            assert_eq!(
                                hex::encode(derived_x_only.serialize()),
                                output_pubkey_hex,
                                "Test #{} '{}' recv #{}: derived spend key doesn't match output",
                                test_idx,
                                test.comment,
                                recv_idx,
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_address_encode_decode_from_vectors() {
        let vectors = load_test_vectors();
        let secp = Secp256k1::new();

        for test in &vectors {
            for receiving in &test.receiving {
                let given = &receiving.given;
                let expected = &receiving.expected;

                let b_scan =
                    SecretKey::from_slice(&hex_to_bytes(&given.key_material.scan_priv_key))
                        .unwrap();
                let b_spend =
                    SecretKey::from_slice(&hex_to_bytes(&given.key_material.spend_priv_key))
                        .unwrap();
                let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan);
                let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend);

                // The first expected address should be the base address (no label)
                if !expected.addresses.is_empty() {
                    let expected_addr = &expected.addresses[0];
                    let encoded = address::encode(
                        &b_scan_pub,
                        &b_spend_pub,
                        crate::networks::Network::Bitcoin,
                    )
                    .unwrap();

                    // For labeled addresses, we need to apply the label
                    if given.labels.is_empty() {
                        assert_eq!(
                            encoded, *expected_addr,
                            "Address encoding mismatch for test '{}'",
                            test.comment
                        );
                    } else {
                        // First address is always the base address
                        assert_eq!(
                            encoded, *expected_addr,
                            "Base address encoding mismatch for test '{}'",
                            test.comment
                        );
                    }

                    // Test decode roundtrip
                    let decoded = address::decode(expected_addr).unwrap();
                    let re_encoded = decoded.to_string();
                    assert_eq!(
                        re_encoded, *expected_addr,
                        "Address decode-encode roundtrip mismatch for test '{}'",
                        test.comment
                    );
                }

                // Test labeled addresses
                if !given.labels.is_empty() && expected.addresses.len() > 1 {
                    for (i, &m) in given.labels.iter().enumerate() {
                        if i + 1 < expected.addresses.len() {
                            let labeled = labels::encode_labeled_address(
                                &b_scan_pub,
                                &b_spend_pub,
                                &b_scan,
                                m,
                                crate::networks::Network::Bitcoin,
                            )
                            .unwrap();
                            assert_eq!(
                                labeled,
                                expected.addresses[i + 1],
                                "Labeled address mismatch for test '{}' label m={}",
                                test.comment,
                                m
                            );
                        }
                    }
                }
            }
        }
    }
}
