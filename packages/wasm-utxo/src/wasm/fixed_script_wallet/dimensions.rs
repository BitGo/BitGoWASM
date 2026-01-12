//! Dimensions for estimating transaction virtual size.
//!
//! This module provides weight-based estimation for transaction fees,
//! tracking min/max bounds to account for ECDSA signature variance.

use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::{
    parse_shared_chain_and_index, InputScriptType,
};
use crate::fixed_script_wallet::wallet_scripts::{Chain, OutputScriptType};
use miniscript::bitcoin::VarInt;
use wasm_bindgen::prelude::*;

use super::BitGoPsbt;

// ============================================================================
// Weight calculation constants
// ============================================================================

// ECDSA signature sizes (DER encoding variance)
const ECDSA_SIG_MIN: usize = 71;
const ECDSA_SIG_MAX: usize = 73;

// Schnorr signature (fixed size, no sighash byte in witness)
const SCHNORR_SIG: usize = 64;

// Script constants
const OP_SIZE: usize = 1;
const OP_0_SIZE: usize = OP_SIZE;
const OP_PUSH_SIZE: usize = OP_SIZE;
const OP_CHECKSIG_SIZE: usize = OP_SIZE;
const OP_CHECKSIGVERIFY_SIZE: usize = OP_SIZE;

// Public key sizes
const SCHNORR_PUBKEY_SIZE: usize = 32;
const P2MS_PUB_SCRIPT_SIZE: usize = 105; // 2-of-3 multisig script with compressed pubkeys
const P2WSH_PUB_SCRIPT_SIZE: usize = 34;
const P2PK_PUB_SCRIPT_SIZE: usize = 35;

// Transaction overhead
const TX_OVERHEAD_SIZE: usize = 10; // version(4) + locktime(4) + varint for ins(1) + varint for outs(1)
const TX_SEGWIT_OVERHEAD_SIZE: usize = 11; // adds marker(1) + flag(1), but witness varint saves 1

// ============================================================================
// Weight calculation helpers
// ============================================================================

/// Compute the size of a length-prefixed slice (varint + data)
fn var_slice_size(length: usize) -> usize {
    VarInt::from(length).size() + length
}

/// Compute the size of a witness vector
fn vector_size(element_lengths: &[usize]) -> usize {
    VarInt::from(element_lengths.len()).size()
        + element_lengths
            .iter()
            .map(|&len| var_slice_size(len))
            .sum::<usize>()
}

/// Compute input weight from script and witness component lengths
fn compute_input_weight(script_components: &[usize], witness_components: &[usize]) -> usize {
    let script_length: usize = script_components.iter().sum();
    // Base size: prevout(32) + index(4) + sequence(4) + scriptSig
    let base_size = 40 + var_slice_size(script_length);
    // Witness size (only counted once in weight)
    let witness_size = if witness_components.is_empty() {
        0
    } else {
        vector_size(witness_components)
    };
    // Weight = 3 * base + (base + witness)
    3 * base_size + base_size + witness_size
}

// ============================================================================
// Input weight definitions
// ============================================================================

struct InputWeights {
    min: usize,
    max: usize,
    is_segwit: bool,
}

/// Get p2sh 2-of-3 multisig input components
fn get_p2sh_components(sig_size: usize) -> Vec<usize> {
    vec![
        OP_0_SIZE,
        OP_PUSH_SIZE + sig_size,                 // sig 1
        OP_PUSH_SIZE + sig_size,                 // sig 2
        OP_PUSH_SIZE + 1 + P2MS_PUB_SCRIPT_SIZE, // OP_PUSHDATA1 + redeemScript
    ]
}

/// Get p2sh-p2wsh 2-of-3 multisig input components
fn get_p2sh_p2wsh_components(sig_size: usize) -> (Vec<usize>, Vec<usize>) {
    (
        vec![OP_SIZE + P2WSH_PUB_SCRIPT_SIZE],
        vec![
            0, // OP_0 placeholder in witness
            sig_size,
            sig_size,
            P2MS_PUB_SCRIPT_SIZE,
        ],
    )
}

/// Get p2wsh 2-of-3 multisig input components
fn get_p2wsh_components(sig_size: usize) -> (Vec<usize>, Vec<usize>) {
    (
        vec![],
        vec![
            0, // OP_0 placeholder
            sig_size,
            sig_size,
            P2MS_PUB_SCRIPT_SIZE,
        ],
    )
}

/// Get p2tr script path spend components (2-of-2 Schnorr in tapleaf)
fn get_p2tr_script_path_components(level: usize) -> (Vec<usize>, Vec<usize>) {
    let leaf_script = OP_PUSH_SIZE
        + SCHNORR_PUBKEY_SIZE
        + OP_CHECKSIG_SIZE
        + OP_PUSH_SIZE
        + SCHNORR_PUBKEY_SIZE
        + OP_CHECKSIGVERIFY_SIZE;
    let control_block = 1 + 32 + 32 * level; // header(1) + internalKey(32) + path(32 * level)
    (
        vec![],
        vec![SCHNORR_SIG, SCHNORR_SIG, leaf_script, control_block],
    )
}

/// Get p2tr keypath spend components (single aggregated Schnorr signature)
fn get_p2tr_keypath_components() -> (Vec<usize>, Vec<usize>) {
    (vec![], vec![SCHNORR_SIG])
}

/// Get p2sh-p2pk input components (single signature, used for replay protection)
fn get_p2sh_p2pk_components(sig_size: usize) -> Vec<usize> {
    vec![
        OP_PUSH_SIZE + sig_size,             // signature
        OP_PUSH_SIZE + P2PK_PUB_SCRIPT_SIZE, // redeemScript (pubkey + OP_CHECKSIG)
    ]
}

/// Get input weight range for a given script type
fn get_input_weights_for_type(script_type: InputScriptType) -> InputWeights {
    match script_type {
        InputScriptType::P2sh => {
            let min = compute_input_weight(&get_p2sh_components(ECDSA_SIG_MIN), &[]);
            let max = compute_input_weight(&get_p2sh_components(ECDSA_SIG_MAX), &[]);
            InputWeights {
                min,
                max,
                is_segwit: false,
            }
        }
        InputScriptType::P2shP2wsh => {
            let (script_min, witness_min) = get_p2sh_p2wsh_components(ECDSA_SIG_MIN);
            let (script_max, witness_max) = get_p2sh_p2wsh_components(ECDSA_SIG_MAX);
            let min = compute_input_weight(&script_min, &witness_min);
            let max = compute_input_weight(&script_max, &witness_max);
            InputWeights {
                min,
                max,
                is_segwit: true,
            }
        }
        InputScriptType::P2wsh => {
            let (script_min, witness_min) = get_p2wsh_components(ECDSA_SIG_MIN);
            let (script_max, witness_max) = get_p2wsh_components(ECDSA_SIG_MAX);
            let min = compute_input_weight(&script_min, &witness_min);
            let max = compute_input_weight(&script_max, &witness_max);
            InputWeights {
                min,
                max,
                is_segwit: true,
            }
        }
        InputScriptType::P2trLegacy => {
            // Legacy p2tr uses script path level 1 by default (user+bitgo)
            let (script, witness) = get_p2tr_script_path_components(1);
            let w = compute_input_weight(&script, &witness);
            InputWeights {
                min: w,
                max: w,
                is_segwit: true,
            }
        }
        InputScriptType::P2trMusig2KeyPath => {
            let (script, witness) = get_p2tr_keypath_components();
            let w = compute_input_weight(&script, &witness);
            InputWeights {
                min: w,
                max: w,
                is_segwit: true,
            }
        }
        InputScriptType::P2trMusig2ScriptPath => {
            let (script, witness) = get_p2tr_script_path_components(1);
            let w = compute_input_weight(&script, &witness);
            InputWeights {
                min: w,
                max: w,
                is_segwit: true,
            }
        }
        InputScriptType::P2shP2pk => {
            let min = compute_input_weight(&get_p2sh_p2pk_components(ECDSA_SIG_MIN), &[]);
            let max = compute_input_weight(&get_p2sh_p2pk_components(ECDSA_SIG_MAX), &[]);
            InputWeights {
                min,
                max,
                is_segwit: false,
            }
        }
    }
}

/// Get input weights for a chain code with optional signer/cosigner
fn get_input_weights_for_chain(
    chain: u32,
    _signer: Option<&str>,
    cosigner: Option<&str>,
) -> Result<InputWeights, String> {
    let chain_enum = Chain::try_from(chain).map_err(|e| e.to_string())?;

    match chain_enum.script_type {
        OutputScriptType::P2sh => Ok(get_input_weights_for_type(InputScriptType::P2sh)),
        OutputScriptType::P2shP2wsh => Ok(get_input_weights_for_type(InputScriptType::P2shP2wsh)),
        OutputScriptType::P2wsh => Ok(get_input_weights_for_type(InputScriptType::P2wsh)),
        OutputScriptType::P2trLegacy => {
            // Legacy p2tr - always script path
            // user+bitgo = level 1, user+backup = level 2
            let is_recovery = cosigner == Some("backup");
            let level = if is_recovery { 2 } else { 1 };
            let (script, witness) = get_p2tr_script_path_components(level);
            let w = compute_input_weight(&script, &witness);
            Ok(InputWeights {
                min: w,
                max: w,
                is_segwit: true,
            })
        }
        OutputScriptType::P2trMusig2 => {
            // p2trMusig2 - keypath for user+bitgo, scriptpath for user+backup
            let is_recovery = cosigner == Some("backup");
            if is_recovery {
                let (script, witness) = get_p2tr_script_path_components(1);
                let w = compute_input_weight(&script, &witness);
                Ok(InputWeights {
                    min: w,
                    max: w,
                    is_segwit: true,
                })
            } else {
                let (script, witness) = get_p2tr_keypath_components();
                let w = compute_input_weight(&script, &witness);
                Ok(InputWeights {
                    min: w,
                    max: w,
                    is_segwit: true,
                })
            }
        }
    }
}

/// Parse script type string to InputScriptType enum
fn parse_script_type(script_type: &str) -> Result<InputScriptType, String> {
    match script_type {
        "p2sh" => Ok(InputScriptType::P2sh),
        "p2shP2wsh" => Ok(InputScriptType::P2shP2wsh),
        "p2wsh" => Ok(InputScriptType::P2wsh),
        "p2trLegacy" => Ok(InputScriptType::P2trLegacy),
        "p2trMusig2KeyPath" => Ok(InputScriptType::P2trMusig2KeyPath),
        "p2trMusig2ScriptPath" => Ok(InputScriptType::P2trMusig2ScriptPath),
        "p2shP2pk" => Ok(InputScriptType::P2shP2pk),
        _ => Err(format!("Unknown script type: {}", script_type)),
    }
}

// ============================================================================
// Output weight calculation
// ============================================================================

/// Compute output weight from script length
/// Output weight = 4 * (8 bytes value + scriptLength + varint)
fn compute_output_weight(script_length: usize) -> usize {
    4 * (8 + var_slice_size(script_length))
}

// ============================================================================
// WasmDimensions struct
// ============================================================================

/// Dimensions for estimating transaction virtual size.
///
/// Tracks weight internally with min/max bounds to handle ECDSA signature variance.
/// Schnorr signatures have no variance (always 64 bytes).
#[wasm_bindgen]
pub struct WasmDimensions {
    input_weight_min: usize,
    input_weight_max: usize,
    output_weight: usize,
    has_segwit: bool,
}

#[wasm_bindgen]
impl WasmDimensions {
    /// Create empty dimensions (zero weight)
    pub fn empty() -> WasmDimensions {
        WasmDimensions {
            input_weight_min: 0,
            input_weight_max: 0,
            output_weight: 0,
            has_segwit: false,
        }
    }

    /// Create dimensions from a BitGoPsbt
    ///
    /// Parses PSBT inputs and outputs to compute weight bounds without
    /// requiring wallet keys. Input types are detected from BIP32 derivation
    /// paths stored in the PSBT.
    pub fn from_psbt(psbt: &BitGoPsbt) -> Result<WasmDimensions, WasmUtxoError> {
        let inner_psbt = psbt.psbt.psbt();
        let unsigned_tx = &inner_psbt.unsigned_tx;

        let mut input_weight_min: usize = 0;
        let mut input_weight_max: usize = 0;
        let mut has_segwit = false;

        // Process inputs
        for (i, psbt_input) in inner_psbt.inputs.iter().enumerate() {
            // Try to get chain from derivation paths
            let weights = match parse_shared_chain_and_index(psbt_input) {
                Ok((chain, _index)) => {
                    // Determine script type from chain and PSBT input metadata
                    let chain_enum = Chain::try_from(chain).map_err(|e| {
                        WasmUtxoError::new(&format!(
                            "Invalid chain {} at input {}: {}",
                            chain, i, e
                        ))
                    })?;

                    // For p2trMusig2, check if it's keypath or scriptpath
                    let script_type = match chain_enum.script_type {
                        OutputScriptType::P2sh => InputScriptType::P2sh,
                        OutputScriptType::P2shP2wsh => InputScriptType::P2shP2wsh,
                        OutputScriptType::P2wsh => InputScriptType::P2wsh,
                        OutputScriptType::P2trLegacy => InputScriptType::P2trLegacy,
                        OutputScriptType::P2trMusig2 => {
                            // Check if tap_scripts are populated to distinguish keypath/scriptpath
                            if !psbt_input.tap_script_sigs.is_empty()
                                || !psbt_input.tap_scripts.is_empty()
                            {
                                InputScriptType::P2trMusig2ScriptPath
                            } else {
                                InputScriptType::P2trMusig2KeyPath
                            }
                        }
                    };

                    get_input_weights_for_type(script_type)
                }
                Err(_) => {
                    // No derivation path - check if it's a replay protection input
                    // Replay protection inputs have unknownKeyVals with specific markers
                    // For now, assume p2shP2pk for inputs without derivation paths
                    get_input_weights_for_type(InputScriptType::P2shP2pk)
                }
            };

            input_weight_min += weights.min;
            input_weight_max += weights.max;
            has_segwit = has_segwit || weights.is_segwit;
        }

        // Process outputs
        let mut output_weight: usize = 0;
        for output in &unsigned_tx.output {
            output_weight += compute_output_weight(output.script_pubkey.len());
        }

        Ok(WasmDimensions {
            input_weight_min,
            input_weight_max,
            output_weight,
            has_segwit,
        })
    }

    /// Create dimensions for a single input from chain code
    ///
    /// # Arguments
    /// * `chain` - Chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
    /// * `signer` - Optional signer key ("user", "backup", "bitgo")
    /// * `cosigner` - Optional cosigner key ("user", "backup", "bitgo")
    pub fn from_input(
        chain: u32,
        signer: Option<String>,
        cosigner: Option<String>,
    ) -> Result<WasmDimensions, WasmUtxoError> {
        let weights = get_input_weights_for_chain(chain, signer.as_deref(), cosigner.as_deref())
            .map_err(|e| WasmUtxoError::new(&e))?;

        Ok(WasmDimensions {
            input_weight_min: weights.min,
            input_weight_max: weights.max,
            output_weight: 0,
            has_segwit: weights.is_segwit,
        })
    }

    /// Create dimensions for a single input from script type string
    ///
    /// # Arguments
    /// * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2trLegacy",
    ///                   "p2trMusig2KeyPath", "p2trMusig2ScriptPath", "p2shP2pk"
    pub fn from_input_script_type(script_type: &str) -> Result<WasmDimensions, WasmUtxoError> {
        let parsed = parse_script_type(script_type).map_err(|e| WasmUtxoError::new(&e))?;
        let weights = get_input_weights_for_type(parsed);

        Ok(WasmDimensions {
            input_weight_min: weights.min,
            input_weight_max: weights.max,
            output_weight: 0,
            has_segwit: weights.is_segwit,
        })
    }

    /// Create dimensions for a single output from script bytes
    pub fn from_output_script(script: &[u8]) -> WasmDimensions {
        let weight = compute_output_weight(script.len());
        WasmDimensions {
            input_weight_min: 0,
            input_weight_max: 0,
            output_weight: weight,
            has_segwit: false,
        }
    }

    /// Combine with another Dimensions instance
    pub fn plus(&self, other: &WasmDimensions) -> WasmDimensions {
        WasmDimensions {
            input_weight_min: self.input_weight_min + other.input_weight_min,
            input_weight_max: self.input_weight_max + other.input_weight_max,
            output_weight: self.output_weight + other.output_weight,
            has_segwit: self.has_segwit || other.has_segwit,
        }
    }

    /// Multiply dimensions by a scalar
    pub fn times(&self, n: u32) -> WasmDimensions {
        WasmDimensions {
            input_weight_min: self.input_weight_min * n as usize,
            input_weight_max: self.input_weight_max * n as usize,
            output_weight: self.output_weight * n as usize,
            has_segwit: self.has_segwit,
        }
    }

    /// Whether any inputs are segwit (affects overhead calculation)
    pub fn has_segwit(&self) -> bool {
        self.has_segwit
    }

    /// Check if this Dimensions has any content (inputs or outputs)
    fn has_content(&self) -> bool {
        self.input_weight_max > 0 || self.output_weight > 0
    }

    /// Get the overhead weight (transaction structure)
    fn get_overhead_weight(&self) -> usize {
        if !self.has_content() {
            return 0;
        }
        let overhead_size = if self.has_segwit {
            TX_SEGWIT_OVERHEAD_SIZE
        } else {
            TX_OVERHEAD_SIZE
        };
        4 * overhead_size
    }

    /// Get total weight (min or max)
    ///
    /// # Arguments
    /// * `size` - "min" or "max", defaults to "max"
    pub fn get_weight(&self, size: Option<String>) -> u32 {
        let use_min = size.as_deref() == Some("min");
        let input_weight = if use_min {
            self.input_weight_min
        } else {
            self.input_weight_max
        };
        (self.get_overhead_weight() + input_weight + self.output_weight) as u32
    }

    /// Get virtual size (min or max)
    ///
    /// # Arguments
    /// * `size` - "min" or "max", defaults to "max"
    pub fn get_vsize(&self, size: Option<String>) -> u32 {
        let weight = self.get_weight(size);
        weight.div_ceil(4)
    }

    /// Get input weight only (min or max)
    ///
    /// # Arguments
    /// * `size` - "min" or "max", defaults to "max"
    pub fn get_input_weight(&self, size: Option<String>) -> u32 {
        let use_min = size.as_deref() == Some("min");
        if use_min {
            self.input_weight_min as u32
        } else {
            self.input_weight_max as u32
        }
    }

    /// Get input virtual size (min or max)
    ///
    /// # Arguments
    /// * `size` - "min" or "max", defaults to "max"
    pub fn get_input_vsize(&self, size: Option<String>) -> u32 {
        self.get_input_weight(size).div_ceil(4)
    }

    /// Get output weight
    pub fn get_output_weight(&self) -> u32 {
        self.output_weight as u32
    }

    /// Get output virtual size
    pub fn get_output_vsize(&self) -> u32 {
        (self.output_weight as u32).div_ceil(4)
    }
}
