//! Zcash-specific address resolution: ZIP-316 unified addresses layered on top of the general
//! network/coin address codecs in [`crate::address::networks`].

use crate::address::networks::to_output_script_with_coin;
use crate::address::AddressError;

type Result<T> = std::result::Result<T, AddressError>;

/// Like [`to_output_script_with_coin`], but when `address` is a ZIP-316 unified address for
/// `coin`'s network, resolves it through the UA path instead of erroring outright (a UA string
/// is never itself a valid transparent address).
///
/// `resolve_shielded` picks which of the UA's receivers is authoritative:
/// - `true`: only the Orchard/Ironwood receiver is resolved, returned as its raw 43 bytes
///   (diversifier + `pk_d`) — there is no scriptPubKey for a shielded output, so this can't
///   return a `ScriptBuf` uniformly and returns raw bytes instead. A UA with no Orchard/Ironwood
///   receiver (e.g. Sapling-only) errors rather than silently falling back to transparent.
/// - `false`: only the transparent receiver is resolved, as its scriptPubKey bytes. A UA with no
///   transparent receiver errors rather than silently falling back to Orchard/Ironwood.
///
/// A UA that can't yield the receiver the caller asked for is a caller bug, not an alternate
/// valid address, so this always errors rather than trying the other receiver kind.
///
/// If `address` merely *looks* like a UA for this network (right Bech32m HRP) but is malformed,
/// this also errors rather than falling back to the transparent path.
pub fn to_output_script_or_shielded_receiver_with_coin(
    address: &str,
    coin: &str,
    resolve_shielded: bool,
) -> Result<Vec<u8>> {
    if crate::zcash::unified_address::looks_like_unified_for_network(address, coin) {
        let ua = crate::zcash::unified_address::UnifiedAddress::parse(address, coin)
            .map_err(|e| AddressError::InvalidAddress(e.to_string()))?;
        return if resolve_shielded {
            match ua
                .orchard_receiver()
                .map_err(|e| AddressError::InvalidAddress(e.to_string()))?
            {
                Some(receiver) => Ok(receiver),
                None => Err(AddressError::InvalidAddress(format!(
                    "unified address has no Orchard/Ironwood receiver: {address}"
                ))),
            }
        } else {
            match ua
                .transparent_script()
                .map_err(|e| AddressError::InvalidAddress(e.to_string()))?
            {
                Some(script) => Ok(script),
                None => Err(AddressError::InvalidAddress(format!(
                    "unified address has no transparent receiver: {address}"
                ))),
            }
        };
    }
    to_output_script_with_coin(address, coin).map(|script| script.to_bytes().to_vec())
}

/// Whether `address` is a ZIP-316 unified address for `coin`'s network carrying an
/// Orchard/Ironwood receiver.
///
/// A plain membership check, not a decoder: returns `false` (rather than erroring) for a
/// malformed unified address, one on the wrong network, an ordinary (non-UA) address, or a UA
/// with no Orchard/Ironwood receiver (e.g. Sapling-only). Use
/// [`to_output_script_or_shielded_receiver_with_coin`] when the actual receiver bytes are
/// needed, or when a malformed UA should surface as an error instead of `false`.
pub fn has_orchard_receiver(address: &str, coin: &str) -> bool {
    if !crate::zcash::unified_address::looks_like_unified_for_network(address, coin) {
        return false;
    }
    crate::zcash::unified_address::UnifiedAddress::parse(address, coin)
        .ok()
        .and_then(|ua| ua.orchard_receiver().ok())
        .flatten()
        .is_some()
}

/// Whether `address` has a usable transparent receiver for `coin`'s network: either `address`
/// is a ZIP-316 unified address carrying a transparent receiver, or `address` is itself an
/// ordinary transparent address that decodes for `coin`.
///
/// A plain membership check, not a decoder: returns `false` (rather than erroring) for a
/// malformed unified address, one on the wrong network, a UA with no transparent receiver
/// (e.g. Orchard-only), or an address that is neither a unified address nor a valid transparent
/// address for `coin`. Use [`to_output_script_or_shielded_receiver_with_coin`] /
/// [`to_output_script_with_coin`] when the actual scriptPubKey is needed, or when a malformed
/// address should surface as an error instead of `false`.
pub fn has_transparent_receiver(address: &str, coin: &str) -> bool {
    if crate::zcash::unified_address::looks_like_unified_for_network(address, coin) {
        return crate::zcash::unified_address::UnifiedAddress::parse(address, coin)
            .ok()
            .and_then(|ua| ua.transparent_script().ok())
            .flatten()
            .is_some();
    }
    to_output_script_with_coin(address, coin).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::hashes::Hash;
    use crate::bitcoin::{PubkeyHash, ScriptBuf};

    mod shielded_output {
        use super::*;

        fn ua_fixtures() -> serde_json::Value {
            let s = crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
                "zcash/unified_address.json",
            )
            .expect("load unified_address.json");
            serde_json::from_str(&s).expect("parse unified_address.json")
        }

        fn fx(v: &serde_json::Value, group: &str, key: &str) -> String {
            v[group][key]
                .as_str()
                .unwrap_or_else(|| panic!("missing fixture field {}.{}", group, key))
                .to_string()
        }

        #[test]
        fn resolve_shielded_true_returns_the_orchard_receiver_for_a_unified_address() {
            let f = ua_fixtures();
            let ua = fx(&f, "zip316Mainnet", "unified");
            let expected = hex::decode(fx(&f, "zip316Mainnet", "orchardReceiverHex")).unwrap();

            let receiver =
                to_output_script_or_shielded_receiver_with_coin(&ua, "zec", true).unwrap();
            assert_eq!(receiver, expected);
            assert_eq!(receiver.len(), 43);
        }

        #[test]
        fn resolve_shielded_false_returns_the_transparent_receiver_for_a_unified_address() {
            // A unified address is now always attempted as one, regardless of `resolve_shielded`
            // -- the flag only picks which of its receivers is authoritative. `false` resolves
            // the UA's transparent receiver rather than erroring outright.
            let f = ua_fixtures();
            let ua = fx(&f, "zip316Mainnet", "unified");
            let expected_hash =
                hex::decode(fx(&f, "zip316Mainnet", "transparentPubkeyHashHex")).unwrap();
            let expected = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(
                expected_hash.try_into().unwrap(),
            ))
            .to_bytes();

            let script =
                to_output_script_or_shielded_receiver_with_coin(&ua, "zec", false).unwrap();
            assert_eq!(script, expected);
        }

        #[test]
        fn resolve_shielded_false_errors_on_a_unified_address_with_no_transparent_receiver() {
            // An orchard-only UA has no transparent receiver, so `resolve_shielded: false` must
            // error rather than silently returning the Orchard receiver instead.
            let f = ua_fixtures();
            let receiver: [u8; 43] = hex::decode(fx(&f, "zip316Mainnet", "orchardReceiverHex"))
                .unwrap()
                .try_into()
                .unwrap();
            let orchard_only =
                crate::zcash::unified_address::encode_orchard_receiver(&receiver, "zec").unwrap();

            let err = to_output_script_or_shielded_receiver_with_coin(&orchard_only, "zec", false)
                .unwrap_err();
            assert!(
                err.to_string().contains("no transparent receiver"),
                "expected a transparent-receiver-missing error; got: {err}"
            );
        }

        #[test]
        fn falls_through_to_the_transparent_path_for_an_ordinary_address_regardless_of_resolve_shielded(
        ) {
            let f = ua_fixtures();
            let addr = fx(&f, "testnetWallet", "transparentAddress");
            let expected_hash = hex::decode(fx(&f, "testnetWallet", "transparentPubkeyHashHex"))
                .unwrap()
                .try_into()
                .unwrap();
            let expected =
                ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(expected_hash)).to_bytes();

            for resolve_shielded in [true, false] {
                let script = to_output_script_or_shielded_receiver_with_coin(
                    &addr,
                    "tzec",
                    resolve_shielded,
                )
                .unwrap();
                assert_eq!(script, expected);
            }
        }

        #[test]
        fn errors_on_a_wrong_network_unified_address_rather_than_succeeding() {
            // The mainnet UA's HRP ("u") doesn't match testnet's ("utest"), so
            // `looks_like_unified_for_network` itself returns false — this never reaches
            // `UnifiedAddress::parse`'s own (separately tested, in unified_address.rs)
            // `WrongHrp` check; it falls through to the transparent path instead, which fails for
            // an unrelated reason (a UA string never decodes as a transparent address). Assert on
            // that specific failure rather than a bare `is_err()`, so this pins down which path
            // actually rejected it — a bare `is_err()` would still pass even if the network check
            // were silently removed entirely.
            let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
            let err =
                to_output_script_or_shielded_receiver_with_coin(&ua, "tzec", true).unwrap_err();
            assert!(
                err.to_string().contains("Could not decode address"),
                "expected the transparent-decode fallback to fail; got: {err}"
            );
        }
    }

    mod receiver_presence {
        use super::*;

        fn ua_fixtures() -> serde_json::Value {
            let s = crate::fixed_script_wallet::test_utils::fixtures::load_fixture(
                "zcash/unified_address.json",
            )
            .expect("load unified_address.json");
            serde_json::from_str(&s).expect("parse unified_address.json")
        }

        fn fx(v: &serde_json::Value, group: &str, key: &str) -> String {
            v[group][key]
                .as_str()
                .unwrap_or_else(|| panic!("missing fixture field {}.{}", group, key))
                .to_string()
        }

        #[test]
        fn has_orchard_receiver_is_true_for_a_ua_with_an_orchard_receiver() {
            let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
            assert!(has_orchard_receiver(&ua, "zec"));
        }

        #[test]
        fn has_orchard_receiver_is_false_for_an_ordinary_transparent_address() {
            let f = ua_fixtures();
            let addr = fx(&f, "testnetWallet", "transparentAddress");
            assert!(!has_orchard_receiver(&addr, "tzec"));
        }

        #[test]
        fn has_orchard_receiver_is_false_for_a_wrong_network_unified_address() {
            let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
            assert!(!has_orchard_receiver(&ua, "tzec"));
        }

        #[test]
        fn has_orchard_receiver_is_false_for_garbage_input() {
            assert!(!has_orchard_receiver("not an address", "zec"));
            assert!(!has_orchard_receiver("", "zec"));
        }

        #[test]
        fn has_transparent_receiver_is_true_for_a_ua_with_a_transparent_receiver() {
            let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
            assert!(has_transparent_receiver(&ua, "zec"));
        }

        #[test]
        fn has_transparent_receiver_is_false_for_an_orchard_only_ua() {
            let f = ua_fixtures();
            let receiver: [u8; 43] = hex::decode(fx(&f, "zip316Mainnet", "orchardReceiverHex"))
                .unwrap()
                .try_into()
                .unwrap();
            let orchard_only =
                crate::zcash::unified_address::encode_orchard_receiver(&receiver, "zec").unwrap();
            assert!(!has_transparent_receiver(&orchard_only, "zec"));
        }

        #[test]
        fn has_transparent_receiver_is_true_for_an_ordinary_transparent_address() {
            let f = ua_fixtures();
            let addr = fx(&f, "testnetWallet", "transparentAddress");
            assert!(has_transparent_receiver(&addr, "tzec"));
        }

        #[test]
        fn has_transparent_receiver_is_false_for_a_malformed_address() {
            assert!(!has_transparent_receiver("not an address", "tzec"));
            assert!(!has_transparent_receiver("", "tzec"));
        }

        #[test]
        fn has_transparent_receiver_is_false_for_a_wrong_network_unified_address() {
            // Mainnet UA's HRP doesn't match testnet's, so this never reaches the UA parser at
            // all -- it falls through to the transparent path, which also fails (a UA string
            // never decodes as a transparent address).
            let ua = fx(&ua_fixtures(), "zip316Mainnet", "unified");
            assert!(!has_transparent_receiver(&ua, "tzec"));
        }

        #[test]
        fn has_transparent_receiver_is_true_for_a_non_zcash_coin_address() {
            assert!(has_transparent_receiver(
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "btc"
            ));
        }
    }
}
