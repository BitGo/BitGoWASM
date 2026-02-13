//! Zcash network parameters
//!
//! Static constants for Zcash network upgrades, consensus branch IDs,
//! and activation heights for mainnet and testnet.
//!
//! References:
//! - <https://github.com/ZcashFoundation/zebra/blob/main/zebra-chain/src/parameters/network_upgrade.rs>
//! - <https://github.com/ZcashFoundation/zebra/blob/main/zebra-chain/src/parameters/constants.rs>
//!
//! Tests verify parity with `zebra-chain` crate.

pub mod transaction;

/// Zcash network upgrade identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUpgrade {
    Overwinter,
    Sapling,
    Blossom,
    Heartwood,
    Canopy,
    Nu5,
    Nu6,
    Nu6_1,
}

/// Parameters for a single network upgrade
#[derive(Debug, Clone, Copy)]
pub struct UpgradeParams {
    pub branch_id: u32,
    pub mainnet_activation_height: u32,
    pub testnet_activation_height: u32,
}

impl NetworkUpgrade {
    /// All network upgrades in chronological order
    pub const ALL: &'static [NetworkUpgrade] = &[
        NetworkUpgrade::Overwinter,
        NetworkUpgrade::Sapling,
        NetworkUpgrade::Blossom,
        NetworkUpgrade::Heartwood,
        NetworkUpgrade::Canopy,
        NetworkUpgrade::Nu5,
        NetworkUpgrade::Nu6,
        NetworkUpgrade::Nu6_1,
    ];

    /// Get the parameters for this network upgrade
    pub const fn params(self) -> UpgradeParams {
        match self {
            NetworkUpgrade::Overwinter => UpgradeParams {
                branch_id: 0x5ba81b19,
                mainnet_activation_height: 347500,
                testnet_activation_height: 207500,
            },
            NetworkUpgrade::Sapling => UpgradeParams {
                branch_id: 0x76b809bb,
                mainnet_activation_height: 419200,
                testnet_activation_height: 280000,
            },
            NetworkUpgrade::Blossom => UpgradeParams {
                branch_id: 0x2bb40e60,
                mainnet_activation_height: 653600,
                testnet_activation_height: 584000,
            },
            NetworkUpgrade::Heartwood => UpgradeParams {
                branch_id: 0xf5b9230b,
                mainnet_activation_height: 903000,
                testnet_activation_height: 903800,
            },
            NetworkUpgrade::Canopy => UpgradeParams {
                branch_id: 0xe9ff75a6,
                mainnet_activation_height: 1046400,
                testnet_activation_height: 1028500,
            },
            NetworkUpgrade::Nu5 => UpgradeParams {
                branch_id: 0xc2d6d0b4,
                mainnet_activation_height: 1687104,
                testnet_activation_height: 1842420,
            },
            // https://zips.z.cash/zip-0253
            NetworkUpgrade::Nu6 => UpgradeParams {
                branch_id: 0xc8e71055,
                mainnet_activation_height: 2726400,
                testnet_activation_height: 2976000,
            },
            // https://zips.z.cash/zip-0254
            NetworkUpgrade::Nu6_1 => UpgradeParams {
                branch_id: 0x4dec4df0,
                mainnet_activation_height: 3146400,
                testnet_activation_height: 3536500,
            },
        }
    }

    /// Get the consensus branch ID for this network upgrade
    pub const fn branch_id(self) -> u32 {
        self.params().branch_id
    }

    /// Get the mainnet activation height
    pub const fn mainnet_activation_height(self) -> u32 {
        self.params().mainnet_activation_height
    }

    /// Get the testnet activation height
    pub const fn testnet_activation_height(self) -> u32 {
        self.params().testnet_activation_height
    }

    /// Get the activation height for the specified network
    pub const fn activation_height(self, is_mainnet: bool) -> u32 {
        if is_mainnet {
            self.mainnet_activation_height()
        } else {
            self.testnet_activation_height()
        }
    }
}

/// Get the network upgrade active at a given block height
///
/// Returns `None` if the height is before Overwinter activation.
pub fn network_upgrade_at_height(height: u32, is_mainnet: bool) -> Option<NetworkUpgrade> {
    // Iterate in reverse chronological order
    NetworkUpgrade::ALL
        .iter()
        .rev()
        .find(|&&upgrade| height >= upgrade.activation_height(is_mainnet))
        .copied()
}

/// Get the consensus branch ID for a given block height
///
/// Returns `None` if the height is before Overwinter activation.
pub fn branch_id_for_height(height: u32, is_mainnet: bool) -> Option<u32> {
    network_upgrade_at_height(height, is_mainnet).map(|u| u.branch_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upgrade_ordering() {
        // Verify chronological ordering
        for i in 1..NetworkUpgrade::ALL.len() {
            let prev = NetworkUpgrade::ALL[i - 1];
            let curr = NetworkUpgrade::ALL[i];
            assert!(
                prev.mainnet_activation_height() < curr.mainnet_activation_height(),
                "{:?} should activate before {:?} on mainnet",
                prev,
                curr
            );
        }
    }

    /// Tests that verify our constants match zebra-chain crate.
    /// These tests are exhaustive - they verify ALL upgrades in zebra-chain
    /// and will fail if we're missing any.
    #[cfg(not(target_arch = "wasm32"))]
    mod parity_with_zebra_chain {
        use super::*;
        use zebra_chain::parameters::{
            Network as ZebraNetwork, NetworkUpgrade as ZebraNetworkUpgrade,
        };

        /// Map our NetworkUpgrade to zebra-chain's NetworkUpgrade.
        /// This match is exhaustive - if zebra adds a new upgrade, this will fail to compile.
        fn to_zebra_upgrade(upgrade: NetworkUpgrade) -> ZebraNetworkUpgrade {
            match upgrade {
                NetworkUpgrade::Overwinter => ZebraNetworkUpgrade::Overwinter,
                NetworkUpgrade::Sapling => ZebraNetworkUpgrade::Sapling,
                NetworkUpgrade::Blossom => ZebraNetworkUpgrade::Blossom,
                NetworkUpgrade::Heartwood => ZebraNetworkUpgrade::Heartwood,
                NetworkUpgrade::Canopy => ZebraNetworkUpgrade::Canopy,
                NetworkUpgrade::Nu5 => ZebraNetworkUpgrade::Nu5,
                NetworkUpgrade::Nu6 => ZebraNetworkUpgrade::Nu6,
                NetworkUpgrade::Nu6_1 => ZebraNetworkUpgrade::Nu6_1,
            }
        }

        /// Map zebra-chain's NetworkUpgrade to ours.
        /// This match is exhaustive - if zebra adds a new upgrade, this will fail to compile.
        /// We skip Genesis and BeforeOverwinter as they have no branch IDs.
        fn from_zebra_upgrade(upgrade: ZebraNetworkUpgrade) -> Option<NetworkUpgrade> {
            match upgrade {
                ZebraNetworkUpgrade::Genesis | ZebraNetworkUpgrade::BeforeOverwinter => None,
                ZebraNetworkUpgrade::Overwinter => Some(NetworkUpgrade::Overwinter),
                ZebraNetworkUpgrade::Sapling => Some(NetworkUpgrade::Sapling),
                ZebraNetworkUpgrade::Blossom => Some(NetworkUpgrade::Blossom),
                ZebraNetworkUpgrade::Heartwood => Some(NetworkUpgrade::Heartwood),
                ZebraNetworkUpgrade::Canopy => Some(NetworkUpgrade::Canopy),
                ZebraNetworkUpgrade::Nu5 => Some(NetworkUpgrade::Nu5),
                ZebraNetworkUpgrade::Nu6 => Some(NetworkUpgrade::Nu6),
                ZebraNetworkUpgrade::Nu6_1 => Some(NetworkUpgrade::Nu6_1),
                #[cfg(any(test, feature = "zebra-test"))]
                ZebraNetworkUpgrade::Nu7 => None,
                #[cfg(zcash_unstable = "zfuture")]
                ZebraNetworkUpgrade::ZFuture => None,
            }
        }

        #[test]
        fn test_exhaustive_coverage() {
            // Verify we have a mapping for every zebra upgrade with a branch ID
            for zebra_upgrade in ZebraNetworkUpgrade::iter() {
                // Skip upgrades without branch IDs
                if zebra_upgrade.branch_id().is_none() {
                    continue;
                }

                // Skip test-only upgrades
                #[cfg(any(test, feature = "zebra-test"))]
                if matches!(zebra_upgrade, ZebraNetworkUpgrade::Nu7) {
                    continue;
                }
                #[cfg(zcash_unstable = "zfuture")]
                if matches!(zebra_upgrade, ZebraNetworkUpgrade::ZFuture) {
                    continue;
                }

                let our_upgrade = from_zebra_upgrade(zebra_upgrade).unwrap_or_else(|| {
                    panic!(
                        "Missing mapping for zebra upgrade {:?}. Add it to NetworkUpgrade enum!",
                        zebra_upgrade
                    )
                });

                // Verify round-trip
                assert_eq!(
                    to_zebra_upgrade(our_upgrade),
                    zebra_upgrade,
                    "Round-trip failed for {:?}",
                    zebra_upgrade
                );
            }

            // Verify every upgrade in our ALL list maps to zebra
            for &our_upgrade in NetworkUpgrade::ALL {
                let zebra_upgrade = to_zebra_upgrade(our_upgrade);
                assert!(
                    zebra_upgrade.branch_id().is_some(),
                    "{:?} should have a branch ID",
                    our_upgrade
                );
            }
        }

        #[test]
        fn test_branch_ids_match_zebra() {
            for &upgrade in NetworkUpgrade::ALL {
                let zebra_upgrade = to_zebra_upgrade(upgrade);
                let expected = zebra_upgrade
                    .branch_id()
                    .map(u32::from)
                    .expect("upgrade should have branch_id");

                assert_eq!(
                    upgrade.branch_id(),
                    expected,
                    "{:?} branch_id mismatch: ours=0x{:08x}, zebra=0x{:08x}",
                    upgrade,
                    upgrade.branch_id(),
                    expected
                );
            }
        }

        #[test]
        fn test_mainnet_heights_match_zebra() {
            let network = ZebraNetwork::Mainnet;
            for &upgrade in NetworkUpgrade::ALL {
                let zebra_upgrade = to_zebra_upgrade(upgrade);
                let expected = zebra_upgrade
                    .activation_height(&network)
                    .map(|h| h.0)
                    .expect("upgrade should have mainnet activation height");

                assert_eq!(
                    upgrade.mainnet_activation_height(),
                    expected,
                    "{:?} mainnet activation height mismatch: ours={}, zebra={}",
                    upgrade,
                    upgrade.mainnet_activation_height(),
                    expected
                );
            }
        }

        #[test]
        fn test_testnet_heights_match_zebra() {
            let network = ZebraNetwork::new_default_testnet();
            for &upgrade in NetworkUpgrade::ALL {
                let zebra_upgrade = to_zebra_upgrade(upgrade);
                let expected = zebra_upgrade
                    .activation_height(&network)
                    .map(|h| h.0)
                    .expect("upgrade should have testnet activation height");

                assert_eq!(
                    upgrade.testnet_activation_height(),
                    expected,
                    "{:?} testnet activation height mismatch: ours={}, zebra={}",
                    upgrade,
                    upgrade.testnet_activation_height(),
                    expected
                );
            }
        }
    }
}
