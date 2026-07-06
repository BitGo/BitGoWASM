//! Single-key transparent PSBT signing helpers.
//!
//! These operate on plain `miniscript::bitcoin::psbt::Psbt` and have no `wasm_bindgen` surface —
//! they're shared by `wasm::psbt::WrapPsbt`'s wasm-bindgen methods and directly by
//! `wasm-utxo-cli`'s `psbt` build commands (which never go through the wasm layer). No new
//! sighash code: these compose the existing `Psbt::sign`/`sign_forkid`/`sign_zcash` and
//! `PsbtExt` primitives that already back `fixed_script_wallet`.

use crate::zcash::transaction::ZcashTransactionParts;
use miniscript::bitcoin::bip32::Fingerprint;
use miniscript::bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use miniscript::bitcoin::{
    psbt, Amount, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, XOnlyPublicKey,
};
use miniscript::descriptor::{SinglePub, SinglePubKey};
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ToPublicKey};
use std::str::FromStr;

#[derive(Debug)]
pub(crate) struct SingleKeySigner {
    privkey: PrivateKey,
    pubkey: PublicKey,
    _pubkey_xonly: XOnlyPublicKey,
    pub(crate) fingerprint: Fingerprint,
    fingerprint_xonly: Fingerprint,
}

impl SingleKeySigner {
    fn fingerprint(key: SinglePubKey) -> Fingerprint {
        DescriptorPublicKey::Single(SinglePub { origin: None, key }).master_fingerprint()
    }

    pub(crate) fn from_privkey<C: Signing>(
        privkey: PrivateKey,
        secp: &Secp256k1<C>,
    ) -> SingleKeySigner {
        let pubkey = privkey.public_key(secp);
        let pubkey_xonly = pubkey.to_x_only_pubkey();
        SingleKeySigner {
            privkey,
            pubkey,
            _pubkey_xonly: pubkey_xonly,
            fingerprint: SingleKeySigner::fingerprint(SinglePubKey::FullKey(pubkey)),
            fingerprint_xonly: SingleKeySigner::fingerprint(SinglePubKey::XOnly(pubkey_xonly)),
        }
    }
}

impl psbt::GetKey for SingleKeySigner {
    type Error = String;

    fn get_key<C: Signing>(
        &self,
        key_request: psbt::KeyRequest,
        _secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            // NOTE: this KeyRequest does not occur for taproot signatures
            // even if the descriptor keys are definite, we will receive a bip32 request
            // instead based on `DescriptorPublicKey::Single(SinglePub { origin: None, key, })`
            psbt::KeyRequest::Pubkey(req_pubkey) => {
                if req_pubkey == self.pubkey {
                    Ok(Some(self.privkey))
                } else {
                    Ok(None)
                }
            }

            psbt::KeyRequest::Bip32((fingerprint, _path)) => {
                if fingerprint.eq(&self.fingerprint) || fingerprint.eq(&self.fingerprint_xonly) {
                    Ok(Some(self.privkey))
                } else {
                    Ok(None)
                }
            }

            _ => Ok(None),
        }
    }
}

/// Compute the output script for a descriptor string, which may embed private keys (e.g.
/// `pkh(<privkey>)`, `wpkh(<privkey>)`) — used to derive an address directly from a signing
/// descriptor without a separate private-key argument.
///
/// Uses `Descriptor::parse_descriptor`, which turns any embedded secret keys into their
/// corresponding public keys (discarding the resulting key map — this is a read-only address
/// derivation, not a signing operation). Resolves at derivation index 0; index is a no-op for
/// non-wildcard descriptors, which is the expected case for a descriptor naming concrete keys.
pub fn script_pubkey_from_descriptor(descriptor: &str) -> Result<ScriptBuf, String> {
    let secp = Secp256k1::new();
    let (desc, _keymap) =
        Descriptor::parse_descriptor(&secp, descriptor).map_err(|e| e.to_string())?;
    let definite = desc.at_derivation_index(0).map_err(|e| e.to_string())?;
    Ok(definite.script_pubkey())
}

/// Add a witness_utxo input spending the given definite descriptor's output, populating
/// `bip32_derivation`/`tap_key_origins` from the descriptor so the input is signable via
/// [`sign_with_privkey`] / [`sign_zcash_with_privkey`].
///
/// `descriptor` is a definite descriptor string with concrete keys, e.g. `pkh(<pubkey>)` or
/// `wpkh(<pubkey>)`; not limited to P2PKH.
///
/// `non_witness_utxo`, when given, is validated against `witness_utxo` and the descriptor via
/// the checked `PsbtExt::update_input_with_descriptor` (BIP174-safe). When omitted, falls back
/// to `PsbtInputExt::update_with_descriptor_unchecked` — safe only for value-committing sighash
/// networks where `non_witness_utxo` is cryptographically pointless (see
/// [`Network::requires_prev_tx_for_legacy_input`](crate::Network::requires_prev_tx_for_legacy_input)).
/// Callers must gate on that predicate themselves before omitting `non_witness_utxo`.
#[allow(clippy::too_many_arguments)]
pub fn add_input_with_descriptor(
    psbt: &mut miniscript::bitcoin::Psbt,
    index: usize,
    txid: Txid,
    vout: u32,
    value: u64,
    script_pubkey: ScriptBuf,
    descriptor: &str,
    sequence: u32,
    non_witness_utxo: Option<Transaction>,
) -> Result<(), String> {
    let desc =
        Descriptor::<DefiniteDescriptorKey>::from_str(descriptor).map_err(|e| e.to_string())?;

    let tx_in = TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(sequence),
        witness: miniscript::bitcoin::Witness::default(),
    };
    let has_non_witness_utxo = non_witness_utxo.is_some();
    let psbt_input = psbt::Input {
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }),
        non_witness_utxo,
        ..Default::default()
    };
    crate::psbt_ops::insert_input(psbt, index, tx_in, psbt_input)?;

    if has_non_witness_utxo {
        psbt.update_input_with_descriptor(index, &desc)
            .map_err(|e| e.to_string())
    } else {
        psbt.inputs[index]
            .update_with_descriptor_unchecked(&desc)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Sign all inputs of a PSBT with a single private key.
///
/// `fork_id` selects the sighash algorithm: `Some(id)` uses `Psbt::sign_forkid` (BCH-family /
/// BTG), `None` uses plain `Psbt::sign`. See [`Network::sighash_fork_id`](crate::Network::sighash_fork_id).
pub fn sign_with_privkey<C: Signing + Verification>(
    psbt: &mut miniscript::bitcoin::Psbt,
    privkey: PrivateKey,
    secp: &Secp256k1<C>,
    fork_id: Option<u32>,
) -> Result<psbt::SigningKeysMap, psbt::SigningErrors> {
    let signer = SingleKeySigner::from_privkey(privkey, secp);
    match fork_id {
        Some(id) => psbt.sign_forkid(&signer, secp, id),
        None => psbt.sign(&signer, secp),
    }
    .map_err(|(_, errors)| errors)
}

/// Finalize a fully-signed PSBT (using `finalize_mut_with_fork_id`, matching the `fork_id` used
/// to sign) and encode the extracted transaction.
pub fn finalize_and_encode_transaction(
    mut psbt: miniscript::bitcoin::Psbt,
    fork_id: Option<u32>,
) -> Result<Vec<u8>, String> {
    use miniscript::bitcoin::consensus::Encodable;

    psbt.finalize_mut_with_fork_id(&Secp256k1::verification_only(), fork_id)
        .map_err(|errors| {
            format!(
                "Failed to finalize PSBT: {}",
                errors
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let tx = psbt
        .extract_tx()
        .map_err(|e| format!("Failed to extract transaction: {}", e))?;
    let mut bytes = Vec::new();
    tx.consensus_encode(&mut bytes)
        .map_err(|e| format!("Failed to encode transaction: {}", e))?;
    Ok(bytes)
}

/// Sign all Zcash transparent inputs of a PSBT using the ZIP-243 sighash algorithm
/// (`Psbt::sign_zcash` in the rust-bitcoin fork).
pub fn sign_zcash_with_privkey<C: Signing + Verification>(
    psbt: &mut miniscript::bitcoin::Psbt,
    privkey: PrivateKey,
    secp: &Secp256k1<C>,
    consensus_branch_id: u32,
    version_group_id: u32,
    expiry_height: u32,
) -> Result<psbt::SigningKeysMap, psbt::SigningErrors> {
    let signer = SingleKeySigner::from_privkey(privkey, secp);
    psbt.sign_zcash(
        &signer,
        secp,
        consensus_branch_id,
        version_group_id,
        expiry_height,
    )
    .map_err(|(_, errors)| errors)
}

/// Finalize a fully-signed PSBT using ZIP-243 sighash verification (`finalize_mut_with_zcash`)
/// and encode it as Zcash overwintered transaction bytes.
pub fn finalize_and_encode_zcash_transaction(
    mut psbt: miniscript::bitcoin::Psbt,
    consensus_branch_id: u32,
    version_group_id: u32,
    expiry_height: u32,
) -> Result<Vec<u8>, String> {
    psbt.finalize_mut_with_zcash(
        &Secp256k1::verification_only(),
        consensus_branch_id,
        version_group_id,
        expiry_height,
    )
    .map_err(|errors| {
        format!(
            "Failed to finalize PSBT: {}",
            errors
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let parts = ZcashTransactionParts::extract_from_psbt(psbt, version_group_id, expiry_height)?;
    crate::zcash::transaction::encode_zcash_transaction_parts(&parts)
}
