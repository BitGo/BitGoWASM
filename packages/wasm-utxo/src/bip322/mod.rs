//! BIP-0322 Generic Signed Message Format
//!
//! This module implements BIP-0322 for BitGo fixed-script wallets.
//! It allows proving control of wallet addresses by signing arbitrary messages.
//!
//! The protocol creates two virtual transactions:
//! - `to_spend`: A virtual transaction that cannot be broadcast
//! - `to_sign`: The actual proof that spends `to_spend`

pub mod bitgo_psbt;

use miniscript::bitcoin::hashes::{sha256, Hash, HashEngine};
use miniscript::bitcoin::script::Builder;
use miniscript::bitcoin::{
    absolute::LockTime, opcodes, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};

/// Default BIP-0322 tag for message hashing
pub const DEFAULT_TAG: &str = "BIP0322-signed-message";

/// Compute a BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)
///
/// This is used to create a domain-separated hash of the message.
pub fn bip340_tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    // Compute SHA256(tag)
    let tag_hash = sha256::Hash::hash(tag.as_bytes());

    // Compute SHA256(SHA256(tag) || SHA256(tag) || message)
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(message);

    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute the BIP-0322 message hash
///
/// Uses the default tag "BIP0322-signed-message" or a custom tag if provided.
pub fn message_hash(message: &[u8], tag: Option<&str>) -> [u8; 32] {
    let tag = tag.unwrap_or(DEFAULT_TAG);
    bip340_tagged_hash(tag, message)
}

/// Create the BIP-0322 `to_spend` virtual transaction
///
/// This transaction has:
/// - nVersion = 0
/// - nLockTime = 0
/// - Single input with prevout 000...000:0xFFFFFFFF (coinbase-style)
/// - scriptSig = OP_0 PUSH32[message_hash]
/// - Single output with value 0 and the message_challenge scriptPubKey
pub fn create_to_spend_tx(message_hash: [u8; 32], script_pubkey: ScriptBuf) -> Transaction {
    // Create the scriptSig: OP_0 PUSH32[message_hash]
    let script_sig = Builder::new()
        .push_opcode(opcodes::OP_0)
        .push_slice(message_hash)
        .into_script();

    // Create the virtual coinbase-style input
    let input = TxIn {
        previous_output: OutPoint {
            txid: Txid::all_zeros(),
            vout: 0xFFFFFFFF,
        },
        script_sig,
        sequence: Sequence::ZERO,
        witness: Witness::new(),
    };

    // Create the output with the message_challenge (scriptPubKey to prove control of)
    let output = TxOut {
        value: Amount::ZERO,
        script_pubkey,
    };

    Transaction {
        version: transaction::Version(0),
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    }
}

/// Create the BIP-0322 `to_sign` unsigned transaction
///
/// This transaction has:
/// - nVersion = 0
/// - nLockTime = 0
/// - Single input spending to_spend output at index 0
/// - nSequence = 0
/// - Single output with value 0 and OP_RETURN scriptPubKey
pub fn create_to_sign_tx(to_spend_txid: Txid) -> Transaction {
    // Create the input spending to_spend:0
    let input = TxIn {
        previous_output: OutPoint {
            txid: to_spend_txid,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: Witness::new(),
    };

    // Create the OP_RETURN output
    let output = TxOut {
        value: Amount::ZERO,
        script_pubkey: Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script(),
    };

    Transaction {
        version: transaction::Version(0),
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    }
}

/// A message to be signed with its corresponding script location
#[derive(Debug, Clone)]
pub struct Bip322Message {
    /// The message to sign (UTF-8 string)
    pub message: String,
    /// The wallet chain code
    pub chain: u32,
    /// The wallet derivation index
    pub index: u32,
}

/// Parameters for creating a BIP-0322 PSBT
pub struct CreateBip322PsbtParams<'a> {
    /// Messages to sign, each with its script location
    pub messages: &'a [Bip322Message],
    /// Optional custom tag for message hashing (default: "BIP0322-signed-message")
    pub tag: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_hash_empty() {
        // Test vector from BIP-0322
        // Message = "" (empty string)
        // Expected: c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1
        let hash = message_hash(b"", None);
        let expected =
            hex::decode("c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1")
                .unwrap();
        assert_eq!(hash.to_vec(), expected);
    }

    #[test]
    fn test_message_hash_hello_world() {
        // Test vector from BIP-0322
        // Message = "Hello World"
        // Expected: f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a
        let hash = message_hash(b"Hello World", None);
        let expected =
            hex::decode("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a")
                .unwrap();
        assert_eq!(hash.to_vec(), expected);
    }

    #[test]
    fn test_message_hash_custom_tag() {
        // Custom tags should produce different hashes
        let hash_default = message_hash(b"test", None);
        let hash_custom1 = message_hash(b"test", Some("CustomTag"));
        let hash_custom2 = message_hash(b"test", Some("DifferentTag"));

        // All hashes should be different from each other
        assert_ne!(hash_default, hash_custom1);
        assert_ne!(hash_default, hash_custom2);
        assert_ne!(hash_custom1, hash_custom2);

        // Same tag should produce same hash (deterministic)
        let hash_custom1_again = message_hash(b"test", Some("CustomTag"));
        assert_eq!(hash_custom1, hash_custom1_again);
    }

    #[test]
    fn test_to_spend_txid_empty_message() {
        // Test vector from BIP-0322
        // Message = "" (empty string)
        // to_spend txid: c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7
        let hash = message_hash(b"", None);

        // P2WPKH scriptPubKey for bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l
        // This is OP_0 PUSH20[pubkeyhash]
        let script_pubkey =
            ScriptBuf::from_hex("00142b05d564e6a7a33c087f16e0f730d1440123799d").unwrap();

        let to_spend = create_to_spend_tx(hash, script_pubkey);
        let txid = to_spend.compute_txid();

        let expected_txid = "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7";
        assert_eq!(txid.to_string(), expected_txid);
    }

    #[test]
    fn test_to_spend_txid_hello_world() {
        // Test vector from BIP-0322
        // Message = "Hello World"
        // to_spend txid: b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b
        let hash = message_hash(b"Hello World", None);

        // P2WPKH scriptPubKey for bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l
        let script_pubkey =
            ScriptBuf::from_hex("00142b05d564e6a7a33c087f16e0f730d1440123799d").unwrap();

        let to_spend = create_to_spend_tx(hash, script_pubkey);
        let txid = to_spend.compute_txid();

        let expected_txid = "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b";
        assert_eq!(txid.to_string(), expected_txid);
    }

    #[test]
    fn test_to_sign_txid_empty_message() {
        // Test vector from BIP-0322
        // Message = "" (empty string)
        // to_sign txid (unsigned): 1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6
        let hash = message_hash(b"", None);
        let script_pubkey =
            ScriptBuf::from_hex("00142b05d564e6a7a33c087f16e0f730d1440123799d").unwrap();
        let to_spend = create_to_spend_tx(hash, script_pubkey);
        let to_sign = create_to_sign_tx(to_spend.compute_txid());
        let txid = to_sign.compute_txid();

        let expected_txid = "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6";
        assert_eq!(txid.to_string(), expected_txid);
    }

    #[test]
    fn test_to_sign_txid_hello_world() {
        // Test vector from BIP-0322
        // Message = "Hello World"
        // to_sign txid (unsigned): 88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf
        let hash = message_hash(b"Hello World", None);
        let script_pubkey =
            ScriptBuf::from_hex("00142b05d564e6a7a33c087f16e0f730d1440123799d").unwrap();
        let to_spend = create_to_spend_tx(hash, script_pubkey);
        let to_sign = create_to_sign_tx(to_spend.compute_txid());
        let txid = to_sign.compute_txid();

        let expected_txid = "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf";
        assert_eq!(txid.to_string(), expected_txid);
    }
}
