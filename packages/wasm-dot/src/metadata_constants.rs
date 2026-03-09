//! Extract pallet constants from runtime metadata.
//!
//! Provides functions to read SCALE-encoded constants from chain metadata
//! without requiring any polkadot-js dependencies. Used by the WASM path
//! to compute values like proxy deposit costs.

use crate::error::WasmDotError;
use crate::transaction::decode_metadata;

/// Extract the proxy deposit cost from runtime metadata.
///
/// Returns `ProxyDepositBase + ProxyDepositFactor` from the Proxy pallet
/// constants, which represents the cost of adding/removing a proxy.
/// This matches the legacy account-lib `getAddProxyCost()` / `getRemoveProxyCost()`.
///
/// Both constants are u128 values (SCALE-encoded as 16 bytes LE).
///
/// # Arguments
/// * `metadata_hex` - Runtime metadata as a hex string (0x-prefixed or bare),
///   matching the `state_getMetadata` RPC wire format.
///
/// # Returns
/// The sum as a decimal string (suitable for BigInt conversion in JS).
pub fn get_proxy_deposit_cost(metadata_hex: &str) -> Result<u128, WasmDotError> {
    let metadata = decode_metadata(metadata_hex)?;

    let proxy_pallet = metadata.pallet_by_name("Proxy").ok_or_else(|| {
        WasmDotError::InvalidInput("Proxy pallet not found in metadata".to_string())
    })?;

    let base = proxy_pallet
        .constant_by_name("ProxyDepositBase")
        .ok_or_else(|| {
            WasmDotError::InvalidInput(
                "ProxyDepositBase constant not found in Proxy pallet".to_string(),
            )
        })?;

    let factor = proxy_pallet
        .constant_by_name("ProxyDepositFactor")
        .ok_or_else(|| {
            WasmDotError::InvalidInput(
                "ProxyDepositFactor constant not found in Proxy pallet".to_string(),
            )
        })?;

    let base_value = decode_u128_le(base.value(), "ProxyDepositBase")?;
    let factor_value = decode_u128_le(factor.value(), "ProxyDepositFactor")?;

    Ok(base_value + factor_value)
}

/// Decode a SCALE-encoded u128 from little-endian bytes.
fn decode_u128_le(bytes: &[u8], name: &str) -> Result<u128, WasmDotError> {
    if bytes.len() < 16 {
        return Err(WasmDotError::ScaleDecodeError(format!(
            "{} constant has {} bytes, expected 16 for u128",
            name,
            bytes.len()
        )));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    Ok(u128::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test with real Westend metadata fixture.
    ///
    /// Extracts ProxyDepositBase + ProxyDepositFactor from the Proxy pallet.
    /// The exact values depend on the metadata version in the fixture.
    #[test]
    fn test_get_proxy_deposit_cost_westend() {
        let metadata_bytes = include_bytes!("../test-fixtures/westend_metadata.scale");
        let metadata_hex = format!("0x{}", hex::encode(metadata_bytes));

        let cost = get_proxy_deposit_cost(&metadata_hex).unwrap();
        // Verify the function returns a non-zero value and doesn't error
        assert!(cost > 0, "proxy deposit cost should be positive");
        // The Westend metadata in this fixture yields 1_002_050_000_000 planck
        // (ProxyDepositBase + ProxyDepositFactor for this runtime version)
        assert_eq!(cost, 1_002_050_000_000u128);
    }

    /// Test individual constant extraction to verify correctness.
    #[test]
    fn test_proxy_deposit_individual_constants() {
        let metadata_bytes = include_bytes!("../test-fixtures/westend_metadata.scale");
        let metadata_hex = format!("0x{}", hex::encode(metadata_bytes));
        let metadata = decode_metadata(&metadata_hex).unwrap();

        let proxy_pallet = metadata.pallet_by_name("Proxy").unwrap();

        let base = proxy_pallet.constant_by_name("ProxyDepositBase").unwrap();
        let factor = proxy_pallet.constant_by_name("ProxyDepositFactor").unwrap();

        let base_value = decode_u128_le(base.value(), "ProxyDepositBase").unwrap();
        let factor_value = decode_u128_le(factor.value(), "ProxyDepositFactor").unwrap();

        // Both should be positive
        assert!(base_value > 0);
        assert!(factor_value > 0);
        // Base should be larger than factor (deposit base > per-proxy factor)
        assert!(base_value > factor_value);
        // Sum should match get_proxy_deposit_cost
        assert_eq!(base_value + factor_value, 1_002_050_000_000u128);
    }

    #[test]
    fn test_get_proxy_deposit_cost_invalid_metadata() {
        let result = get_proxy_deposit_cost("0xdeadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_u128_le_valid() {
        // 42 as u128 LE
        let bytes = 42u128.to_le_bytes();
        assert_eq!(decode_u128_le(&bytes, "test").unwrap(), 42);
    }

    #[test]
    fn test_decode_u128_le_too_short() {
        let result = decode_u128_le(&[1, 2, 3], "test");
        assert!(result.is_err());
    }
}
