//! ZIP-317 dimensions for Zcash conventional fee estimation.
//!
//! The ZIP-317 counterpart of [`super::dimensions::WasmDimensions`]: it tracks the quantities
//! ZIP-317 prices — the transparent inputs' and outputs' serialized sizes and the Ironwood
//! spends/outputs — instead of bitcoin weight. It is opt-in and independent of `WasmDimensions`:
//! callers choose which estimator to use.

use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::bitgo_psbt::BitGoPsbt as InnerBitGoPsbt;
use crate::fixed_script_wallet::wallet_scripts::OutputScriptType;
use crate::fixed_script_wallet::Chain;
use crate::zcash::zip317::{self, Zip317ActionCounts, Zip317Error};
use wasm_bindgen::prelude::*;

use super::BitGoPsbt;

/// ZIP-317 dimensions: composable with [`Self::plus`] / [`Self::times`], priced with
/// [`Self::get_conventional_fee`].
///
/// Ironwood spends and outputs are tracked separately because the Constructor builds
/// unpadded bundles: the action count is `max(spends, outputs)`, not their sum.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WasmZip317Dimensions {
    tx_in_total_size: u32,
    tx_out_total_size: u32,
    ironwood_spends: u32,
    ironwood_outputs: u32,
}

impl WasmZip317Dimensions {
    fn counts(&self) -> Zip317ActionCounts {
        Zip317ActionCounts {
            tx_in_total_size: self.tx_in_total_size as u64,
            tx_out_total_size: self.tx_out_total_size as u64,
            n_actions_ironwood: self.get_ironwood_actions() as u64,
            ..Default::default()
        }
    }

    fn from_input_script_sig_len(script_sig_len: usize) -> WasmZip317Dimensions {
        WasmZip317Dimensions {
            tx_in_total_size: saturating_u32(zip317::transparent_input_size(script_sig_len)),
            ..Default::default()
        }
    }
}

#[wasm_bindgen]
impl WasmZip317Dimensions {
    /// Create empty dimensions.
    pub fn empty() -> WasmZip317Dimensions {
        WasmZip317Dimensions::default()
    }

    /// Create dimensions from a Zcash BitGoPsbt (any version).
    ///
    /// Transparent inputs are sized with the scriptSig their scripts will finalize to (the real
    /// one once finalized), transparent outputs exactly, and the Ironwood side from the real
    /// (non-dummy) spends and outputs of the stored PCZT — or, once the PCZT has been extracted
    /// by `combine_ironwood_proof`, from the counts recorded at extraction.
    pub fn from_psbt(psbt: &BitGoPsbt) -> Result<WasmZip317Dimensions, WasmUtxoError> {
        let InnerBitGoPsbt::Zcash(z, _) = &psbt.psbt else {
            return Err(Zip317Error::NotZcashPsbt.into());
        };
        let (tx_in_total_size, tx_out_total_size) = z.zip317_transparent_sizes();
        let (spends, outputs) = z
            .ironwood_real_spend_and_output_counts()
            .map_err(Zip317Error::IronwoodPczt)?;
        Ok(WasmZip317Dimensions {
            tx_in_total_size: saturating_u32(tx_in_total_size),
            tx_out_total_size: saturating_u32(tx_out_total_size),
            ironwood_spends: saturating_u32(spends as u64),
            ironwood_outputs: saturating_u32(outputs as u64),
        })
    }

    /// Create dimensions for a single transparent wallet input from its chain code.
    ///
    /// Zcash wallets only have P2SH chains (0, 1); any other chain is rejected.
    pub fn from_input(chain: u32) -> Result<WasmZip317Dimensions, WasmUtxoError> {
        let chain_enum =
            Chain::try_from(chain).map_err(|_| Zip317Error::UnsupportedChain(chain))?;
        match chain_enum.script_type {
            OutputScriptType::P2sh => Ok(Self::from_input_script_sig_len(
                zip317::p2sh_multisig_script_sig_len(zip317::P2SH_2OF3_REDEEM_SCRIPT_LEN),
            )),
            _ => Err(Zip317Error::UnsupportedChain(chain).into()),
        }
    }

    /// Create dimensions for a single transparent input from its script type.
    ///
    /// # Arguments
    /// * `script_type` - One of: "p2sh" (2-of-3 wallet input), "p2shP2pk" (replay protection)
    pub fn from_input_script_type(
        script_type: &str,
    ) -> Result<WasmZip317Dimensions, WasmUtxoError> {
        let script_sig_len = match script_type {
            "p2sh" => zip317::p2sh_multisig_script_sig_len(zip317::P2SH_2OF3_REDEEM_SCRIPT_LEN),
            "p2shP2pk" => zip317::p2sh_p2pk_script_sig_len(zip317::P2SH_P2PK_REDEEM_SCRIPT_LEN),
            _ => {
                return Err(Zip317Error::UnsupportedInputScriptType(script_type.to_string()).into())
            }
        };
        Ok(Self::from_input_script_sig_len(script_sig_len))
    }

    /// Create dimensions for a single transparent output from its scriptPubKey length.
    pub fn from_output_script_length(length: u32) -> WasmZip317Dimensions {
        WasmZip317Dimensions {
            tx_out_total_size: saturating_u32(zip317::transparent_output_size(length as usize)),
            ..Default::default()
        }
    }

    /// Create dimensions for `count` Ironwood spends (shielded notes being spent).
    pub fn from_ironwood_spends(count: u32) -> WasmZip317Dimensions {
        WasmZip317Dimensions {
            ironwood_spends: count,
            ..Default::default()
        }
    }

    /// Create dimensions for `count` Ironwood (shielded) outputs.
    pub fn from_ironwood_outputs(count: u32) -> WasmZip317Dimensions {
        WasmZip317Dimensions {
            ironwood_outputs: count,
            ..Default::default()
        }
    }

    /// Combine with another instance.
    pub fn plus(&self, other: &WasmZip317Dimensions) -> WasmZip317Dimensions {
        WasmZip317Dimensions {
            tx_in_total_size: self.tx_in_total_size.saturating_add(other.tx_in_total_size),
            tx_out_total_size: self
                .tx_out_total_size
                .saturating_add(other.tx_out_total_size),
            ironwood_spends: self.ironwood_spends.saturating_add(other.ironwood_spends),
            ironwood_outputs: self.ironwood_outputs.saturating_add(other.ironwood_outputs),
        }
    }

    /// Multiply by a scalar.
    pub fn times(&self, n: u32) -> WasmZip317Dimensions {
        WasmZip317Dimensions {
            tx_in_total_size: self.tx_in_total_size.saturating_mul(n),
            tx_out_total_size: self.tx_out_total_size.saturating_mul(n),
            ironwood_spends: self.ironwood_spends.saturating_mul(n),
            ironwood_outputs: self.ironwood_outputs.saturating_mul(n),
        }
    }

    /// The sum of the transparent inputs' estimated final serialized sizes, in bytes.
    pub fn get_tx_in_total_size(&self) -> u32 {
        self.tx_in_total_size
    }

    /// The sum of the transparent outputs' serialized sizes, in bytes.
    pub fn get_tx_out_total_size(&self) -> u32 {
        self.tx_out_total_size
    }

    /// The number of Ironwood spends.
    pub fn get_ironwood_spends(&self) -> u32 {
        self.ironwood_spends
    }

    /// The number of Ironwood outputs.
    pub fn get_ironwood_outputs(&self) -> u32 {
        self.ironwood_outputs
    }

    /// The number of Ironwood actions: `max(spends, outputs)` (unpadded bundle).
    pub fn get_ironwood_actions(&self) -> u32 {
        self.ironwood_spends.max(self.ironwood_outputs)
    }

    /// The ZIP-317 `logical_actions`.
    pub fn get_logical_actions(&self) -> u32 {
        saturating_u32(zip317::logical_actions(&self.counts()))
    }

    /// The ZIP-317 conventional fee in zatoshi (as a `bigint`):
    /// `5_000 × max(2, logical_actions)`.
    pub fn get_conventional_fee(&self) -> u64 {
        zip317::conventional_fee(&self.counts())
    }
}

/// Clamp to `u32`: sizes and counts this large are not real transactions, and saturating keeps
/// the fee estimate an overestimate instead of silently wrapping.
fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_input_matches_the_p2sh_script_type() {
        assert_eq!(
            WasmZip317Dimensions::from_input(0).unwrap(),
            WasmZip317Dimensions::from_input_script_type("p2sh").unwrap()
        );
        assert_eq!(
            WasmZip317Dimensions::from_input(0)
                .unwrap()
                .get_tx_in_total_size(),
            299
        );
    }

    #[test]
    fn rejects_inputs_zcash_wallets_cannot_have() {
        assert!(matches!(
            WasmZip317Dimensions::from_input(20),
            Err(WasmUtxoError::Zip317(Zip317Error::UnsupportedChain(20)))
        ));
        assert!(matches!(
            WasmZip317Dimensions::from_input(7),
            Err(WasmUtxoError::Zip317(Zip317Error::UnsupportedChain(7)))
        ));
        assert!(matches!(
            WasmZip317Dimensions::from_input_script_type("p2wsh"),
            Err(WasmUtxoError::Zip317(
                Zip317Error::UnsupportedInputScriptType(_)
            ))
        ));
    }

    #[test]
    fn ironwood_actions_are_the_max_of_spends_and_outputs() {
        let d = WasmZip317Dimensions::from_ironwood_spends(2)
            .plus(&WasmZip317Dimensions::from_ironwood_outputs(3));
        assert_eq!(d.get_ironwood_actions(), 3);
        assert_eq!(d.get_logical_actions(), 3);
        assert_eq!(d.get_conventional_fee(), 15_000);
    }

    #[test]
    fn shielding_one_input_to_one_output_hits_the_grace_floor() {
        // 299-byte P2SH input (ceil(299/150) = 2) + one Ironwood output: 2 + 1 = 3 actions.
        let d = WasmZip317Dimensions::from_input(0)
            .unwrap()
            .plus(&WasmZip317Dimensions::from_ironwood_outputs(1));
        assert_eq!(d.get_logical_actions(), 3);
        assert_eq!(d.get_conventional_fee(), 15_000);
        // Nothing at all still pays for two actions.
        assert_eq!(WasmZip317Dimensions::empty().get_conventional_fee(), 10_000);
    }

    #[test]
    fn times_scales_every_term() {
        let d = WasmZip317Dimensions::from_input(0)
            .unwrap()
            .plus(&WasmZip317Dimensions::from_output_script_length(23))
            .plus(&WasmZip317Dimensions::from_ironwood_outputs(1))
            .times(3);
        assert_eq!(d.get_tx_in_total_size(), 3 * 299);
        assert_eq!(d.get_tx_out_total_size(), 3 * 32);
        assert_eq!(d.get_ironwood_outputs(), 3);
    }

    #[test]
    fn plus_and_times_saturate_instead_of_wrapping() {
        let d = WasmZip317Dimensions::from_input(0).unwrap().times(u32::MAX);
        assert_eq!(d.get_tx_in_total_size(), u32::MAX);
        assert_eq!(d.plus(&d).get_tx_in_total_size(), u32::MAX);
        assert!(d.get_conventional_fee() > WasmZip317Dimensions::empty().get_conventional_fee());
    }
}
