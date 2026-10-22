//! Tests for the v4/Sapling `ZcashBitGoPsbt` surface.

use super::*;
use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};

#[test]
fn test_decode_zcash_transaction() {
    // Version with overwintered bit
    let version = 0x80000004u32;
    let mut tx_bytes = Vec::new();

    // Version
    version.consensus_encode(&mut tx_bytes).unwrap();

    // Version group ID
    ZCASH_SAPLING_VERSION_GROUP_ID
        .consensus_encode(&mut tx_bytes)
        .unwrap();

    // Empty inputs
    0u8.consensus_encode(&mut tx_bytes).unwrap();

    // Empty outputs
    0u8.consensus_encode(&mut tx_bytes).unwrap();

    // Lock time
    0u32.consensus_encode(&mut tx_bytes).unwrap();

    // Expiry height
    0u32.consensus_encode(&mut tx_bytes).unwrap();

    let parts = crate::zcash::transaction::decode_zcash_transaction_parts(&tx_bytes).unwrap();

    assert_eq!(parts.version_group_id, Some(ZCASH_SAPLING_VERSION_GROUP_ID));
    assert_eq!(parts.expiry_height, Some(0));
    assert_eq!(parts.transaction.input.len(), 0);
    assert_eq!(parts.transaction.output.len(), 0);
    // Should be empty for this simple test tx
    assert!(parts.sapling_fields.is_empty());
}

#[test]
fn test_round_trip_empty_zcash_psbt() {
    use crate::fixed_script_wallet::test_utils::get_test_wallet_keys;
    use crate::fixed_script_wallet::RootWalletKeys;
    use crate::networks::Network;

    let wallet_keys = RootWalletKeys::new(get_test_wallet_keys("empty-zcash-round-trip"));
    let psbt = ZcashBitGoPsbt::new(
        Network::Zcash,
        &wallet_keys,
        0xc2d6d0b4,
        Some(4),
        Some(0),
        Some(ZCASH_SAPLING_VERSION_GROUP_ID),
        Some(0),
    );
    let bytes = psbt.serialize().unwrap();

    ZcashBitGoPsbt::deserialize(&bytes, Network::Zcash).unwrap();
}

#[test]
fn test_round_trip_zcash_psbt() {
    use crate::fixed_script_wallet::test_utils::fixtures::{
        load_psbt_fixture_with_format_and_namespace, FixtureNamespace, SignatureState, TxFormat,
    };
    use crate::networks::Network;

    // Load the Zcash fixture from utxolib-compat
    let fixture = load_psbt_fixture_with_format_and_namespace(
        "zcash",
        SignatureState::Unsigned,
        TxFormat::Psbt,
        FixtureNamespace::UtxolibCompat,
    )
    .expect("Failed to load Zcash fixture");

    // Deserialize from fixture
    let original_bytes = BASE64_STANDARD.decode(&fixture.psbt_base64).unwrap();
    let zcash_psbt = ZcashBitGoPsbt::deserialize(&original_bytes, Network::Zcash).unwrap();

    // Verify Zcash-specific fields were extracted
    assert!(zcash_psbt.version_group_id.is_some());
    assert!(zcash_psbt.expiry_height.is_some());

    // Verify transaction was parsed
    assert_eq!(zcash_psbt.psbt.unsigned_tx.input.len(), 2);
    assert_eq!(zcash_psbt.psbt.unsigned_tx.output.len(), 4);

    // Serialize back
    let serialized = zcash_psbt.serialize().unwrap();

    // Note: We don't assert byte-for-byte equality because PSBT serialization may reorder
    // global map entries. Instead, we verify that deserializing the serialized PSBT
    // produces the same data.

    // Deserialize again
    let round_trip = ZcashBitGoPsbt::deserialize(&serialized, Network::Zcash).unwrap();

    // Verify the data matches
    assert_eq!(
        zcash_psbt.version_group_id, round_trip.version_group_id,
        "Version group ID should match"
    );
    assert_eq!(
        zcash_psbt.expiry_height, round_trip.expiry_height,
        "Expiry height should match"
    );
    assert_eq!(
        zcash_psbt.psbt.unsigned_tx.input.len(),
        round_trip.psbt.unsigned_tx.input.len(),
        "Input count should match"
    );
    assert_eq!(
        zcash_psbt.psbt.unsigned_tx.output.len(),
        round_trip.psbt.unsigned_tx.output.len(),
        "Output count should match"
    );
    assert_eq!(
        zcash_psbt.psbt.inputs.len(),
        round_trip.psbt.inputs.len(),
        "PSBT input count should match"
    );
    assert_eq!(
        zcash_psbt.psbt.outputs.len(),
        round_trip.psbt.outputs.len(),
        "PSBT output count should match"
    );
}
