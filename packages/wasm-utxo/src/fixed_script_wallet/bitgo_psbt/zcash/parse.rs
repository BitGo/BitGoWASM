//! Zcash-specific parsed-transaction types and the parse entry points that surface the
//! shielded (Ironwood) side alongside the transparent one.
//!
//! The coin-neutral parse on [`BitGoPsbt`] knows nothing about the shielded side: on a
//! PSBT that carries Ironwood data it fails loudly with
//! [`ParseTransactionError::UseZcashParse`] instead of silently dropping it. This module
//! composes that generic machinery with the shielded fold, producing the richer
//! [`ZcashParsedTransaction`] (per-action output indices, shielded spends, the bundle's
//! value balance). The key-free verifier checks the bundle before any plaintext value is
//! returned.

use super::ZcashBitGoPsbt;
use crate::fixed_script_wallet::bitgo_psbt::{
    BitGoPsbt, ParseTransactionError, ParsedInput, ParsedOutput,
};
use crate::fixed_script_wallet::{ReplayProtection, RootWalletKeys};
use crate::zcash::ironwood_build::OrchardAddressBytes;

/// One shielded (Ironwood) spend, as surfaced by the parse.
///
/// Plaintext values from the PCZT, verified by the key-free verifier before they
/// reach the caller: the rebuilt note commits to a leaf under the bundle's anchor and
/// matches the recorded `cmx`. What a keyless party cannot check (note ownership,
/// nullifier validity) can only make the transaction invalid, never misdirected.
#[derive(Clone, Debug)]
pub struct ZcashShieldedSpend {
    /// The spend's action index in the orchard bundle.
    pub action_index: usize,
    /// Note value in zatoshi.
    pub value: u64,
    /// Raw 43-byte Orchard recipient of the spent note.
    pub recipient: OrchardAddressBytes,
    /// The nullifier this spend reveals (committed in the action data).
    pub nullifier: [u8; 32],
    /// The note commitment recomputed from the verified plaintext.
    pub cmx: [u8; 32],
    /// The witness's leaf position in the commitment tree.
    pub position: u32,
    /// The single-receiver Unified Address of the spent note's Orchard receiver.
    pub address: String,
    /// Whether the signer replaced the Constructor's placeholder `rk` with a randomized one.
    pub rk_replaced: bool,
    /// Whether a spend-auth signature is installed.
    pub signed: bool,
}

/// A transparent Zcash input. Same shape as [`ParsedInput`]; the JS layer adds the
/// additive `isShielded: false`.
#[derive(Clone, Debug)]
pub struct ZcashParsedInput {
    pub base: ParsedInput,
}

/// A Zcash output: the transparent parse shape plus the shielded marker and, for shielded
/// outputs, the PCZT action index and change marker.
#[derive(Clone, Debug)]
pub struct ZcashParsedOutput {
    pub base: ParsedOutput,
    pub is_shielded: bool,
    /// The output's action index in the orchard bundle; `None` for transparent outputs.
    pub action_index: Option<usize>,
    /// For a shielded output: whether it pays back to a spent note's own address (see
    /// [`crate::zcash::ironwood_verify::VerifiedOutput::is_change`]); such outputs are
    /// excluded from `spend_amount`. Always `false` for transparent outputs, whose wallet
    /// ownership is the base parse's `script_id`.
    pub is_change: bool,
}

/// The inputs of a Zcash transaction: transparent, or the shielded spends of a deshield /
/// shielded-to-shielded bundle.
#[derive(Clone, Debug)]
pub enum ZcashParsedInputs {
    Transparent(Vec<ZcashParsedInput>),
    Shielded(Vec<ZcashShieldedSpend>),
}

/// The parsed view of a Zcash transaction, including the shielded side.
#[derive(Clone, Debug)]
pub struct ZcashParsedTransaction {
    pub inputs: ZcashParsedInputs,
    pub outputs: Vec<ZcashParsedOutput>,
    pub spend_amount: u64,
    pub miner_fee: u64,
    pub virtual_size: u32,
    /// The orchard bundle's value balance (Σv_spend − Σv_out — negative when the shielded
    /// pool gains value); `0` when the PSBT carries no Ironwood bundle.
    pub value_balance: i64,
    /// Whether this is a v6 (Ironwood) PSBT. The JS layer only exposes the Ironwood fields
    /// (`inputKind`, `shieldedSpends`, `valueBalance`) for v6.
    pub is_ironwood_v6: bool,
}

/// Errors from the Zcash-specific parse.
#[derive(Debug, strum::IntoStaticStr)]
pub enum ZcashParseTransactionError {
    /// The transparent side failed to parse; the shielded side is untouched.
    Transparent(ParseTransactionError),
    /// The PSBT mixes transparent inputs with shielded spends.
    MixedInputKinds,
    /// The shielded side could not be read (no usable PCZT, an unencodable address, or a
    /// value overflow).
    Shielded(String),
    /// The shielded side failed key-free verification; the error code is the
    /// failing verifier check (`IronwoodVerifyError.<check>`).
    Verify(crate::zcash::ironwood_build::IronwoodVerifyError),
}

impl std::fmt::Display for ZcashParseTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZcashParseTransactionError::Transparent(error) => write!(f, "{error}"),
            ZcashParseTransactionError::MixedInputKinds => write!(
                f,
                "a PSBT cannot mix transparent inputs with shielded spends"
            ),
            ZcashParseTransactionError::Shielded(error) => write!(f, "Shielded side: {error}"),
            ZcashParseTransactionError::Verify(error) => {
                write!(f, "Shielded side failed verification: {error}")
            }
        }
    }
}

impl std::error::Error for ZcashParseTransactionError {}

impl From<ParseTransactionError> for ZcashParseTransactionError {
    fn from(error: ParseTransactionError) -> Self {
        ZcashParseTransactionError::Transparent(error)
    }
}

impl From<crate::zcash::ironwood_build::IronwoodVerifyError> for ZcashParseTransactionError {
    fn from(error: crate::zcash::ironwood_build::IronwoodVerifyError) -> Self {
        ZcashParseTransactionError::Verify(error)
    }
}

impl crate::error::WasmErrorCode for ZcashParseTransactionError {
    fn code(&self) -> String {
        match self {
            // Transparent failures keep the coin-neutral parse's codes
            // (`ParseTransactionError.*`), exactly as before the Zcash parse existed.
            ZcashParseTransactionError::Transparent(error) => {
                crate::error::WasmErrorCode::code(error)
            }
            // A verification failure carries the failing check as its code
            // (`IronwoodVerifyError.NoteCommitment`, …) — callers key diagnostics on it.
            ZcashParseTransactionError::Verify(error) => crate::error::WasmErrorCode::code(error),
            _ => format!("ZcashParseTransactionError.{}", <&'static str>::from(self)),
        }
    }
}

/// Whether `bitgo_psbt` carries Ironwood (shielded) data the generic parse cannot see: a
/// stored PCZT, or one already extracted (its shielded side existed and was consumed).
pub(crate) fn carries_shielded_data(bitgo_psbt: &BitGoPsbt) -> bool {
    match bitgo_psbt {
        BitGoPsbt::Zcash(z, _) => {
            super::propkv::has_ironwood_pczt(&z.psbt)
                || super::propkv::is_ironwood_extracted(&z.psbt)
        }
        _ => false,
    }
}

/// The Zcash PSBT behind `bitgo_psbt`; the Zcash parse is only routed Zcash PSBTs.
fn zcash_psbt(bitgo_psbt: &BitGoPsbt) -> Result<&ZcashBitGoPsbt, ZcashParseTransactionError> {
    match bitgo_psbt {
        BitGoPsbt::Zcash(z, _) => Ok(z),
        _ => Err(ZcashParseTransactionError::Shielded(
            "the Zcash parse requires a Zcash PSBT".to_string(),
        )),
    }
}

/// Parse the Zcash outputs (transparent + shielded) with wallet keys.
///
/// Reads only the outputs: unlike [`parse_transaction_with_wallet_keys`], it never touches
/// the transparent inputs or the bundle-level value accounting.
pub(crate) fn parse_outputs_with_wallet_keys(
    bitgo_psbt: &BitGoPsbt,
    wallet_keys: &RootWalletKeys,
    paygo_pubkeys: &[miniscript::bitcoin::secp256k1::PublicKey],
) -> Result<Vec<ZcashParsedOutput>, ZcashParseTransactionError> {
    let z = zcash_psbt(bitgo_psbt)?;
    let (shielded_outputs, _spends, _value_balance) = shielded_side(z)?;
    let mut outputs = transparent_outputs(bitgo_psbt.parse_outputs(wallet_keys, paygo_pubkeys)?);
    outputs.extend(shielded_outputs);
    Ok(outputs)
}

/// Parse the Zcash transaction with wallet keys, surfacing the shielded side.
pub(crate) fn parse_transaction_with_wallet_keys(
    bitgo_psbt: &BitGoPsbt,
    wallet_keys: &RootWalletKeys,
    replay_protection: &ReplayProtection,
    paygo_pubkeys: &[miniscript::bitcoin::secp256k1::PublicKey],
) -> Result<ZcashParsedTransaction, ZcashParseTransactionError> {
    let z = zcash_psbt(bitgo_psbt)?;
    let (shielded_outputs, shielded_spends, value_balance) = shielded_side(z)?;

    // Transparent side, shared with the coin-neutral parse.
    let transparent_inputs = bitgo_psbt.parse_inputs(wallet_keys, replay_protection)?;
    if !transparent_inputs.is_empty() && !shielded_spends.is_empty() {
        return Err(ZcashParseTransactionError::MixedInputKinds);
    }
    let parsed_transparent_outputs = bitgo_psbt.parse_outputs(wallet_keys, paygo_pubkeys)?;

    // Totals: shielded spends fund the transaction in place of transparent inputs
    // (deshield / shielded-to-shielded); without them `miner_fee` underflows.
    let mut shielded_spend_total = 0u64;
    for spend in &shielded_spends {
        shielded_spend_total = shielded_spend_total
            .checked_add(spend.value)
            .ok_or_else(|| {
                ZcashParseTransactionError::Shielded(format!(
                    "action {}: shielded spend value overflow",
                    spend.action_index
                ))
            })?;
    }
    let total_input_value = BitGoPsbt::sum_input_values(&transparent_inputs)?
        .checked_add(shielded_spend_total)
        .ok_or(ZcashParseTransactionError::Shielded(
            "total input value overflow".to_string(),
        ))?;

    let unsigned_tx = &bitgo_psbt.psbt().unsigned_tx;
    let (mut total_output_value, mut spend_amount) =
        BitGoPsbt::sum_output_values(&unsigned_tx.output, &parsed_transparent_outputs)?;

    // Fold in the shielded outputs, if any: they're invisible to the transparent-only
    // parsing above, so without this they'd silently vanish into `miner_fee` and
    // undercount the send.
    let mut outputs = transparent_outputs(parsed_transparent_outputs);
    for output in shielded_outputs {
        let output_index = outputs.len();
        total_output_value = total_output_value.checked_add(output.base.value).ok_or(
            ParseTransactionError::OutputValueOverflow {
                index: output_index,
            },
        )?;
        if !output.is_change {
            spend_amount = spend_amount.checked_add(output.base.value).ok_or(
                ParseTransactionError::SpendAmountOverflow {
                    index: output_index,
                },
            )?;
        }
        outputs.push(output);
    }

    // Calculate miner fee
    let miner_fee = total_input_value
        .checked_sub(total_output_value)
        .ok_or(ParseTransactionError::FeeCalculation)?;

    // Calculate virtual size from unsigned transaction weight
    let virtual_size = unsigned_tx.weight().to_vbytes_ceil() as u32;

    let inputs = if shielded_spends.is_empty() {
        ZcashParsedInputs::Transparent(
            transparent_inputs
                .into_iter()
                .map(|base| ZcashParsedInput { base })
                .collect(),
        )
    } else {
        ZcashParsedInputs::Shielded(shielded_spends)
    };

    Ok(ZcashParsedTransaction {
        inputs,
        outputs,
        spend_amount,
        miner_fee,
        virtual_size,
        value_balance,
        is_ironwood_v6: z.is_ironwood_v6(),
    })
}

/// Wrap the coin-neutral parsed outputs as transparent Zcash outputs.
fn transparent_outputs(outputs: Vec<ParsedOutput>) -> Vec<ZcashParsedOutput> {
    outputs
        .into_iter()
        .map(|base| ZcashParsedOutput {
            base,
            is_shielded: false,
            action_index: None,
            is_change: false,
        })
        .collect()
}

/// Synthesize a [`ZcashParsedOutput`] for every real shielded output the key-free verifier
/// reported.
fn shielded_parsed_outputs(
    z: &ZcashBitGoPsbt,
    shielded_outputs: &[crate::zcash::ironwood_verify::VerifiedOutput],
) -> Result<Vec<ZcashParsedOutput>, ZcashParseTransactionError> {
    shielded_outputs
        .iter()
        .map(|output| {
            // Prefer the caller's original Unified Address (if `add_ironwood_output` was
            // given one for this action): it may carry a transparent/Sapling receiver
            // alongside the Orchard one, which a single-receiver reconstruction from
            // `recipient` alone cannot recover.
            let address =
                match super::propkv::get_ironwood_unified_address(&z.psbt, output.action_index) {
                    Some(ua) => ua,
                    None => crate::zcash::unified_address::encode_orchard_receiver(
                        &output.recipient,
                        z.network().to_coin_name(),
                    )
                    .map_err(|e| ZcashParseTransactionError::Shielded(e.to_string()))?,
                };
            Ok(ZcashParsedOutput {
                base: ParsedOutput {
                    address: Some(address),
                    // No scriptPubKey exists for a shielded output; the raw receiver is
                    // still available here (not a scriptPubKey, but the same "raw
                    // output-destination bytes" role this field plays for transparent
                    // outputs).
                    script: output.recipient.to_vec(),
                    value: output.value,
                    script_id: None,
                    paygo: false,
                    derivation_path: None,
                },
                is_shielded: true,
                action_index: Some(output.action_index),
                is_change: output.is_change,
            })
        })
        .collect()
}

/// The shielded side of the PSBT: `(shielded outputs, shielded spends, value balance)`.
///
/// Empty when no Ironwood bundle was ever added; a loud error when it was already extracted
/// (so an extraction can never silently look like a PSBT that never carried a shielded
/// side).
fn shielded_side(
    z: &ZcashBitGoPsbt,
) -> Result<(Vec<ZcashParsedOutput>, Vec<ZcashShieldedSpend>, i64), ZcashParseTransactionError> {
    if z.require_no_shielded_output_ever_added()
        .map_err(ZcashParseTransactionError::Shielded)?
    {
        return Ok((Vec::new(), Vec::new(), 0));
    }
    // The keyless verifier runs before any plaintext value leaves here: a
    // tampered bundle fails with the failing check's error code. The plaintext itself is
    // left in the PCZT untouched — the prover needs it, and the parse surfaces it.
    let pczt = z
        .ironwood_pczt()
        .map_err(ZcashParseTransactionError::Shielded)?;
    let report = z.keyless_verify(&pczt)?;
    let outputs = shielded_parsed_outputs(z, &report.outputs)?;
    let spends = report
        .spends
        .iter()
        .map(|spend| {
            ZcashShieldedSpend::from_verified(spend, z.network().to_coin_name())
                .map_err(|e| ZcashParseTransactionError::Shielded(e.to_string()))
        })
        .collect::<Result<Vec<_>, ZcashParseTransactionError>>()?;
    Ok((outputs, spends, report.value_balance))
}

impl ZcashShieldedSpend {
    /// A verified spend in the parse shape, with the single-receiver Unified Address of its
    /// Orchard receiver on `coin_name`'s network.
    ///
    /// The stored Unified Addresses belong to the bundle's *outputs* (keyed by their action
    /// index), so a spend's address is always rebuilt from its own receiver.
    pub(crate) fn from_verified(
        spend: &crate::zcash::ironwood_verify::VerifiedSpend,
        coin_name: &str,
    ) -> Result<Self, crate::zcash::unified_address::UnifiedAddressError> {
        let address =
            crate::zcash::unified_address::encode_orchard_receiver(&spend.recipient, coin_name)?;
        Ok(ZcashShieldedSpend {
            action_index: spend.action_index,
            value: spend.value,
            recipient: spend.recipient,
            nullifier: spend.nullifier,
            cmx: spend.cmx,
            position: spend.position,
            address,
            rk_replaced: spend.randomizer_installed,
            signed: spend.signed,
        })
    }
}
