use crate::bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG;
use crate::bitcoin::blockdata::script::Builder;
use crate::bitcoin::{CompressedPublicKey, ScriptBuf};
use crate::fixed_script_wallet::wallet_keys::PubTriple;

/// Build bare multisig script. Needs to wrapped to be useful as an output script.
pub fn build_multisig_script_2_of_3(keys: &PubTriple) -> ScriptBuf {
    let quorum = 2;
    let total_count = 3;
    let mut builder = Builder::default().push_int(quorum as i64);
    for key in keys {
        builder = builder.push_slice(key.to_bytes())
    }
    builder
        .push_int(total_count as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

pub fn parse_multisig_script_2_of_3(script: &ScriptBuf) -> Result<PubTriple, String> {
    use crate::bitcoin::blockdata::opcodes::all::{OP_PUSHNUM_2, OP_PUSHNUM_3};
    use crate::bitcoin::blockdata::script::Instruction;

    let instructions: Vec<_> = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse script instructions: {}", e))?;

    // Expected format: OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
    if instructions.len() != 6 {
        return Err(format!(
            "Invalid multisig script length: expected 6 instructions, got {}",
            instructions.len()
        ));
    }

    // Check OP_2 (quorum)
    if instructions[0] != Instruction::Op(OP_PUSHNUM_2) {
        return Err("First instruction should be OP_2".to_string());
    }

    // Check OP_3 (total keys)
    if instructions[4] != Instruction::Op(OP_PUSHNUM_3) {
        return Err("Fifth instruction should be OP_3".to_string());
    }

    // Check OP_CHECKMULTISIG
    if instructions[5] != Instruction::Op(OP_CHECKMULTISIG) {
        return Err("Last instruction should be OP_CHECKMULTISIG".to_string());
    }

    // Extract the three public keys
    let mut keys = Vec::new();
    for (idx, instruction) in instructions.iter().enumerate().skip(1).take(3) {
        match instruction {
            Instruction::PushBytes(bytes) => {
                let key = CompressedPublicKey::from_slice(bytes.as_bytes()).map_err(|e| {
                    format!(
                        "Failed to parse compressed public key at position {}: {}",
                        idx, e
                    )
                })?;
                keys.push(key);
            }
            _ => {
                return Err(format!(
                    "Instruction at position {} should be a push bytes instruction",
                    idx
                ));
            }
        }
    }

    keys.try_into()
        .map_err(|_| "Failed to convert vec to array of 3 keys".to_string())
}

#[derive(Debug)]
pub struct ScriptP2sh {
    pub redeem_script: ScriptBuf,
}

#[derive(Debug)]
pub struct ScriptP2shP2wsh {
    pub redeem_script: ScriptBuf,
    pub witness_script: ScriptBuf,
}

#[derive(Debug)]
pub struct ScriptP2wsh {
    pub witness_script: ScriptBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::blockdata::opcodes::all::{
        OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_2, OP_PUSHNUM_3, OP_PUSHNUM_4,
    };
    use crate::bitcoin::blockdata::script::Builder;
    use crate::fixed_script_wallet::wallet_keys::tests::get_test_wallet_keys;
    use crate::fixed_script_wallet::wallet_keys::to_pub_triple;

    #[test]
    fn test_parse_multisig_script_2_of_3_valid() {
        // Get test keys
        let wallet_keys = get_test_wallet_keys("test_parse");
        let derived_keys = wallet_keys.derive_for_chain_and_index(0, 0).unwrap();
        let pub_triple = to_pub_triple(&derived_keys);

        // Build a valid 2-of-3 multisig script
        let script = build_multisig_script_2_of_3(&pub_triple);

        // Parse it back
        let parsed_keys = parse_multisig_script_2_of_3(&script).expect("Should parse valid script");

        // Verify the keys match
        assert_eq!(parsed_keys, pub_triple);
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_roundtrip() {
        // Test multiple different key sets
        for seed in ["seed1", "seed2", "seed3"] {
            let wallet_keys = get_test_wallet_keys(seed);
            let derived_keys = wallet_keys.derive_for_chain_and_index(0, 42).unwrap();
            let original_keys = to_pub_triple(&derived_keys);

            // Build script from keys
            let script = build_multisig_script_2_of_3(&original_keys);

            // Parse script back to keys
            let parsed_keys =
                parse_multisig_script_2_of_3(&script).expect("Should parse valid script");

            // Verify roundtrip
            assert_eq!(
                parsed_keys, original_keys,
                "Roundtrip failed for seed: {}",
                seed
            );
        }
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_invalid_length() {
        // Test script with wrong number of instructions
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_slice([0x02; 33]) // Only one key instead of three
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let result = parse_multisig_script_2_of_3(&script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid multisig script length"));
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_wrong_quorum() {
        // Create a valid key for testing
        let wallet_keys = get_test_wallet_keys("test_wrong_quorum");
        let derived_keys = wallet_keys.derive_for_chain_and_index(0, 0).unwrap();
        let pub_triple = to_pub_triple(&derived_keys);

        // Build script with wrong quorum (OP_1 instead of OP_2)
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(pub_triple[0].to_bytes())
            .push_slice(pub_triple[1].to_bytes())
            .push_slice(pub_triple[2].to_bytes())
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let result = parse_multisig_script_2_of_3(&script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("First instruction should be OP_2"));
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_wrong_total() {
        // Create a valid key for testing
        let wallet_keys = get_test_wallet_keys("test_wrong_total");
        let derived_keys = wallet_keys.derive_for_chain_and_index(0, 0).unwrap();
        let pub_triple = to_pub_triple(&derived_keys);

        // Build script with wrong total (OP_4 instead of OP_3)
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_slice(pub_triple[0].to_bytes())
            .push_slice(pub_triple[1].to_bytes())
            .push_slice(pub_triple[2].to_bytes())
            .push_opcode(OP_PUSHNUM_4)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let result = parse_multisig_script_2_of_3(&script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Fifth instruction should be OP_3"));
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_missing_checkmultisig() {
        // Create a valid key for testing
        let wallet_keys = get_test_wallet_keys("test_missing_checkmultisig");
        let derived_keys = wallet_keys.derive_for_chain_and_index(0, 0).unwrap();
        let pub_triple = to_pub_triple(&derived_keys);

        // Build script without OP_CHECKMULTISIG
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_slice(pub_triple[0].to_bytes())
            .push_slice(pub_triple[1].to_bytes())
            .push_slice(pub_triple[2].to_bytes())
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_PUSHNUM_1) // Wrong opcode instead of OP_CHECKMULTISIG
            .into_script();

        let result = parse_multisig_script_2_of_3(&script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Last instruction should be OP_CHECKMULTISIG"));
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_invalid_pubkey() {
        // Build script with invalid public key data
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_slice([0x00; 10]) // Invalid public key (too short)
            .push_slice([0x02; 33]) // Valid compressed pubkey format
            .push_slice([0x03; 33]) // Valid compressed pubkey format
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let result = parse_multisig_script_2_of_3(&script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Failed to parse compressed public key at position 1"));
    }

    #[test]
    fn test_parse_multisig_script_2_of_3_non_pushbytes_instruction() {
        // Build script with non-pushbytes instruction where pubkey should be
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_PUSHNUM_1) // Wrong: should be pubkey bytes
            .push_slice([0x02; 33])
            .push_slice([0x03; 33])
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();

        let result = parse_multisig_script_2_of_3(&script);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Instruction at position 1 should be a push bytes instruction"));
    }
}
