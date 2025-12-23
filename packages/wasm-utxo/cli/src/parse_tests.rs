//! Integration tests for parse_node functionality
//!
//! These tests verify that the parse_node functions from wasm-utxo work correctly
//! with the CLI fixtures.

#[cfg(test)]
mod tests {
    use crate::format::fixtures::assert_tree_matches_fixture;
    use crate::test_utils::{load_psbt_bytes, load_tx_bytes, SignatureState, TxFormat};
    use wasm_utxo::parse_node::{parse_psbt_bytes_internal, parse_psbt_bytes_raw, parse_tx_bytes_internal};
    use wasm_utxo::Network;

    #[test]
    fn test_parse_psbt_bitcoin_fullsigned() -> Result<(), Box<dyn std::error::Error>> {
        let psbt_bytes = load_psbt_bytes(
            Network::Bitcoin,
            SignatureState::Fullsigned,
            TxFormat::Psbt,
        )?;

        let node = parse_psbt_bytes_internal(&psbt_bytes)?;

        assert_tree_matches_fixture(&node, "psbt_bitcoin_fullsigned")?;
        Ok(())
    }

    #[test]
    fn test_parse_tx_bitcoin_fullsigned() -> Result<(), Box<dyn std::error::Error>> {
        let tx_bytes = load_tx_bytes(
            Network::Bitcoin,
            SignatureState::Fullsigned,
            TxFormat::PsbtLite,
        )?;

        let node = parse_tx_bytes_internal(&tx_bytes)?;

        assert_tree_matches_fixture(&node, "tx_bitcoin_fullsigned")?;
        Ok(())
    }

    #[test]
    fn test_parse_psbt_raw_bitcoin_fullsigned() -> Result<(), Box<dyn std::error::Error>> {
        let psbt_bytes =
            load_psbt_bytes(Network::Bitcoin, SignatureState::Fullsigned, TxFormat::Psbt)?;

        let node = parse_psbt_bytes_raw(&psbt_bytes)?;

        assert_tree_matches_fixture(&node, "psbt_raw_bitcoin_fullsigned")?;
        Ok(())
    }
}

