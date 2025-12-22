//! BitGo transaction utilities for handling network-specific transaction variants
//!
//! This module provides utilities for working with transactions across different
//! bitcoin-like networks, including those with non-standard sighash types and
//! transaction formats.

use crate::networks::Network;

/// Bitcoin Cash and related forks use SIGHASH_FORKID flag
const SIGHASH_FORKID: u32 = 0x40;

/// Standard sighash type values
const SIGHASH_ALL: u32 = 0x01;
const SIGHASH_NONE: u32 = 0x02;
const SIGHASH_SINGLE: u32 = 0x03;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// Returns the SIGHASH_FORKID value for networks that use it.
///
/// Different networks use different fork IDs in their sighash computation:
/// - Bitcoin Cash, Ecash, Bitcoin SV: fork_id = 0
/// - Bitcoin Gold: fork_id = 79
/// - All other networks: None (don't use SIGHASH_FORKID)
///
/// # Arguments
///
/// * `network` - The network to get the fork ID for
///
/// # Returns
///
/// `Some(fork_id)` for FORKID networks, `None` otherwise
pub fn get_sighash_fork_id(network: Network) -> Option<u32> {
    match network.mainnet() {
        Network::BitcoinCash | Network::Ecash | Network::BitcoinSV => Some(0),
        Network::BitcoinGold => Some(79),
        _ => None,
    }
}

/// Validates a sighash type for a given network
///
/// Different networks have different valid sighash types:
/// - Bitcoin and most networks: 0, 1, 2, 3, and combinations with ANYONECANPAY (0x80)
/// - Bitcoin Cash/BSV/Ecash: Same as above, but also with SIGHASH_FORKID (0x40)
///
/// # Arguments
///
/// * `sighash_type` - The sighash type value to validate
/// * `network` - The network context for validation
///
/// # Returns
///
/// `Ok(())` if the sighash type is valid for the network, otherwise `Err` with a description
pub fn validate_sighash_type(sighash_type: u32, network: Network) -> Result<(), String> {
    // Handle the special case of 0 (no sighash type specified)
    if sighash_type == 0 {
        return Ok(());
    }

    // Determine if this network uses SIGHASH_FORKID
    // Bitcoin Cash, Bitcoin Gold, Bitcoin SV, and Ecash all use SIGHASH_FORKID
    let uses_forkid = matches!(
        network.mainnet(),
        Network::BitcoinCash | Network::BitcoinGold | Network::BitcoinSV | Network::Ecash
    );

    // Extract the base sighash type (without flags)
    let has_forkid = (sighash_type & SIGHASH_FORKID) != 0;
    let has_anyonecanpay = (sighash_type & SIGHASH_ANYONECANPAY) != 0;
    let base_type = sighash_type & 0x1F; // Mask off flags to get base type

    // Validate FORKID usage
    if has_forkid && !uses_forkid {
        return Err(format!(
            "SIGHASH_FORKID (0x40) is not valid for network {:?}. Sighash type: 0x{:02x}",
            network, sighash_type
        ));
    }

    // For Bitcoin Cash and forks, FORKID is required
    if uses_forkid && !has_forkid {
        return Err(format!(
            "SIGHASH_FORKID (0x40) is required for network {:?}. Sighash type: 0x{:02x}",
            network, sighash_type
        ));
    }

    // Validate the base sighash type
    match base_type {
        SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE => Ok(()),
        _ => Err(format!(
            "Invalid base sighash type: 0x{:02x}. Expected SIGHASH_ALL (0x01), SIGHASH_NONE (0x02), or SIGHASH_SINGLE (0x03). Full sighash type: 0x{:02x}{}{}",
            base_type,
            sighash_type,
            if has_anyonecanpay { " (with ANYONECANPAY)" } else { "" },
            if has_forkid { " (with FORKID)" } else { "" }
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_sighash_fork_id() {
        // Networks with fork_id = 0
        assert_eq!(get_sighash_fork_id(Network::BitcoinCash), Some(0));
        assert_eq!(get_sighash_fork_id(Network::BitcoinCashTestnet), Some(0));
        assert_eq!(get_sighash_fork_id(Network::Ecash), Some(0));
        assert_eq!(get_sighash_fork_id(Network::EcashTestnet), Some(0));
        assert_eq!(get_sighash_fork_id(Network::BitcoinSV), Some(0));
        assert_eq!(get_sighash_fork_id(Network::BitcoinSVTestnet), Some(0));

        // Bitcoin Gold has fork_id = 79
        assert_eq!(get_sighash_fork_id(Network::BitcoinGold), Some(79));
        assert_eq!(get_sighash_fork_id(Network::BitcoinGoldTestnet), Some(79));

        // Standard networks don't use FORKID
        assert_eq!(get_sighash_fork_id(Network::Bitcoin), None);
        assert_eq!(get_sighash_fork_id(Network::BitcoinTestnet3), None);
        assert_eq!(get_sighash_fork_id(Network::Litecoin), None);
        assert_eq!(get_sighash_fork_id(Network::Dogecoin), None);
        assert_eq!(get_sighash_fork_id(Network::Dash), None);
        assert_eq!(get_sighash_fork_id(Network::Zcash), None);
    }

    #[test]
    fn test_bitcoin_sighash_types() {
        // Bitcoin accepts standard types without FORKID
        assert!(validate_sighash_type(0, Network::Bitcoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_ALL, Network::Bitcoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_NONE, Network::Bitcoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_SINGLE, Network::Bitcoin).is_ok());
        assert!(
            validate_sighash_type(SIGHASH_ALL | SIGHASH_ANYONECANPAY, Network::Bitcoin).is_ok()
        );

        // Bitcoin does not accept FORKID
        assert!(validate_sighash_type(SIGHASH_ALL | SIGHASH_FORKID, Network::Bitcoin).is_err());
        assert!(validate_sighash_type(0x41, Network::Bitcoin).is_err());
    }

    #[test]
    fn test_bitcoin_cash_sighash_types() {
        // Bitcoin Cash requires FORKID
        assert!(validate_sighash_type(0, Network::BitcoinCash).is_ok()); // Special case: 0 is allowed
        assert!(validate_sighash_type(0x41, Network::BitcoinCash).is_ok()); // ALL | FORKID
        assert!(validate_sighash_type(0x42, Network::BitcoinCash).is_ok()); // NONE | FORKID
        assert!(validate_sighash_type(0x43, Network::BitcoinCash).is_ok()); // SINGLE | FORKID
        assert!(validate_sighash_type(0xC1, Network::BitcoinCash).is_ok()); // ALL | FORKID | ANYONECANPAY

        // Bitcoin Cash does not accept types without FORKID (except 0)
        assert!(validate_sighash_type(SIGHASH_ALL, Network::BitcoinCash).is_err());
        assert!(validate_sighash_type(SIGHASH_NONE, Network::BitcoinCash).is_err());
        assert!(validate_sighash_type(SIGHASH_SINGLE, Network::BitcoinCash).is_err());
    }

    #[test]
    fn test_ecash_sighash_types() {
        // Ecash also uses FORKID (Bitcoin Cash fork)
        assert!(validate_sighash_type(0, Network::Ecash).is_ok());
        assert!(validate_sighash_type(0x41, Network::Ecash).is_ok()); // ALL | FORKID
        assert!(validate_sighash_type(SIGHASH_ALL, Network::Ecash).is_err()); // Missing FORKID
    }

    #[test]
    fn test_bitcoin_gold_sighash_types() {
        // Bitcoin Gold uses FORKID (Bitcoin Cash fork)
        assert!(validate_sighash_type(0, Network::BitcoinGold).is_ok());
        assert!(validate_sighash_type(0x41, Network::BitcoinGold).is_ok()); // ALL | FORKID
        assert!(validate_sighash_type(SIGHASH_ALL, Network::BitcoinGold).is_err());
        // Missing FORKID
    }

    #[test]
    fn test_bitcoin_sv_sighash_types() {
        // Bitcoin SV also uses FORKID (Bitcoin Cash fork)
        assert!(validate_sighash_type(0, Network::BitcoinSV).is_ok());
        assert!(validate_sighash_type(0x41, Network::BitcoinSV).is_ok()); // ALL | FORKID
        assert!(validate_sighash_type(SIGHASH_ALL, Network::BitcoinSV).is_err());
        // Missing FORKID
    }

    #[test]
    fn test_invalid_base_types() {
        // Invalid base type
        assert!(validate_sighash_type(0x04, Network::Bitcoin).is_err());
        assert!(validate_sighash_type(0x44, Network::BitcoinCash).is_err()); // Invalid base with FORKID
    }

    #[test]
    fn test_litecoin_sighash_types() {
        // Litecoin uses standard Bitcoin sighash types
        assert!(validate_sighash_type(0, Network::Litecoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_ALL, Network::Litecoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_ALL | SIGHASH_FORKID, Network::Litecoin).is_err());
    }

    #[test]
    fn test_dogecoin_sighash_types() {
        // Dogecoin uses standard Bitcoin sighash types
        assert!(validate_sighash_type(0, Network::Dogecoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_ALL, Network::Dogecoin).is_ok());
        assert!(validate_sighash_type(SIGHASH_ALL | SIGHASH_FORKID, Network::Dogecoin).is_err());
    }

    #[test]
    fn test_sighash_anyonecanpay_combinations() {
        // Test ANYONECANPAY flag combinations for Bitcoin
        assert!(
            validate_sighash_type(SIGHASH_ALL | SIGHASH_ANYONECANPAY, Network::Bitcoin).is_ok()
        );
        assert!(
            validate_sighash_type(SIGHASH_NONE | SIGHASH_ANYONECANPAY, Network::Bitcoin).is_ok()
        );
        assert!(
            validate_sighash_type(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, Network::Bitcoin).is_ok()
        );

        // Test ANYONECANPAY flag combinations for Bitcoin Cash (must include FORKID)
        assert!(validate_sighash_type(
            SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            Network::BitcoinCash
        )
        .is_ok());
        assert!(validate_sighash_type(
            SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            Network::BitcoinCash
        )
        .is_ok());
        assert!(validate_sighash_type(
            SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            Network::BitcoinCash
        )
        .is_ok());

        // Without FORKID should fail for Bitcoin Cash
        assert!(
            validate_sighash_type(SIGHASH_ALL | SIGHASH_ANYONECANPAY, Network::BitcoinCash)
                .is_err()
        );
    }
}
