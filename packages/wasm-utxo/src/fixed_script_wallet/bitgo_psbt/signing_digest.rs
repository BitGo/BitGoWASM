//! The exact message each input's signer must sign, and the state of existing signatures.
//!
//! [`BitGoPsbt::signing_digest`] derives, from the PSBT alone, the digest a key signs for one
//! input: legacy ECDSA, BIP143 or fork-id ECDSA, Zcash ZIP-243 (v4) or the Zcash v6 ZIP-244
//! transparent digest, or the BIP-341 script-path digest. Callers that review a transaction before
//! signing use it to bind what they display to what is signed, without re-implementing any of
//! these schemes.
//!
//! [`BitGoPsbt::partial_signatures`] reports every ECDSA and Schnorr signature already stored for
//! an input and whether it verifies against that same digest.
//!
//! [`taproot_script_path`] checks that a Taproot input's single leaf is committed to by the
//! funding output and returns the keys the leaf requires.
//!
//! Nothing here trusts a signature, derivation hint or script annotation: the digest is computed
//! from the unsigned transaction, the funding outputs, and (for script-path spends) the leaf the
//! control block proves.

use miniscript::bitcoin::hashes::Hash;
use miniscript::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
use miniscript::bitcoin::psbt::{Input, Psbt};
use miniscript::bitcoin::script::Instruction;
use miniscript::bitcoin::secp256k1::{Message, Secp256k1};
use miniscript::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use miniscript::bitcoin::taproot::{ControlBlock, LeafVersion};
use miniscript::bitcoin::{PublicKey, ScriptBuf, TapLeafHash, XOnlyPublicKey};

use super::p2tr_musig2_input::collect_prevouts;
use super::{psbt_wallet_input, BitGoPsbt};

/// The signature scheme a [`SigningDigest`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestScheme {
    /// Legacy or BIP143 ECDSA.
    Ecdsa,
    /// BIP143-style ECDSA with the network's `SIGHASH_FORKID` replay protection.
    EcdsaForkId,
    /// Zcash version 4 (Sapling) transparent input, ZIP-243.
    Zip243,
    /// Zcash version 6 (Ironwood) transparent input, ZIP-244.
    Zip244,
    /// BIP-341 script-path spend of one leaf.
    TaprootScriptPath,
}

/// What an input's signer signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningDigest {
    pub digest: [u8; 32],
    /// The sighash flag byte the digest was computed for: the ECDSA flag, or the Taproot
    /// `SighashType` (0 is `Default`).
    pub sighash_type: u32,
    pub scheme: DigestScheme,
}

#[derive(Debug, strum::IntoStaticStr)]
pub enum SigningDigestError {
    InputIndexOutOfRange {
        index: usize,
    },
    /// The Zcash PSBT carries no `ZecConsensusBranchId`.
    MissingZcashBranchId,
    /// A Taproot input that is not a spend of exactly one leaf (key path, MuSig2 key path, no
    /// leaf, or several leaves).
    UnsupportedTaprootSpend(&'static str),
    /// The funding output is not a Taproot output, or the control block does not commit to it.
    TaprootCommitmentMismatch,
    /// The leaf is not an n-of-n chain of x-only `CHECKSIGVERIFY`/`CHECKSIG`.
    UnsupportedLeafScript,
    /// The input lacks the data a digest needs (funding output, script).
    Sighash(String),
}

impl std::fmt::Display for SigningDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputIndexOutOfRange { index } => {
                write!(f, "signing-digest: input {index} out of range")
            }
            Self::MissingZcashBranchId => {
                write!(f, "signing-digest: Zcash PSBT has no ZecConsensusBranchId")
            }
            Self::UnsupportedTaprootSpend(why) => {
                write!(f, "signing-digest: unsupported taproot spend: {why}")
            }
            Self::TaprootCommitmentMismatch => write!(
                f,
                "signing-digest: the control block does not commit the leaf to the funding output"
            ),
            Self::UnsupportedLeafScript => write!(
                f,
                "signing-digest: leaf is not an n-of-n x-only CHECKSIGVERIFY/CHECKSIG chain"
            ),
            Self::Sighash(e) => write!(f, "signing-digest: cannot compute the digest: {e}"),
        }
    }
}

impl std::error::Error for SigningDigestError {}
crate::impl_wasm_error_code!(SigningDigestError);

/// The key of a stored signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKey {
    Ecdsa(PublicKey),
    Schnorr(XOnlyPublicKey),
}

/// One signature already stored on an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialSignature {
    pub key: SignerKey,
    /// The sighash flag the signature carries.
    pub sighash_type: u32,
    /// The signature verifies against [`BitGoPsbt::signing_digest`] for its input, under `key`.
    /// A signature with a different flag than the digest's, or for another leaf, is not valid.
    pub valid: bool,
}

/// A verified single-leaf Taproot script-path spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootScriptPath {
    pub leaf_script: ScriptBuf,
    pub leaf_version: LeafVersion,
    pub leaf_hash: TapLeafHash,
    pub control_block: ControlBlock,
    /// The keys the leaf requires, in script order. The leaf is an n-of-n chain.
    pub keys: Vec<XOnlyPublicKey>,
}

fn parse_leaf_keys(script: &ScriptBuf) -> Result<Vec<XOnlyPublicKey>, SigningDigestError> {
    let invalid = || SigningDigestError::UnsupportedLeafScript;
    let mut keys = Vec::new();
    let mut instructions = script.instructions();
    loop {
        let Some(Ok(Instruction::PushBytes(bytes))) = instructions.next() else {
            return Err(invalid());
        };
        keys.push(XOnlyPublicKey::from_slice(bytes.as_bytes()).map_err(|_| invalid())?);
        let Some(Ok(Instruction::Op(op))) = instructions.next() else {
            return Err(invalid());
        };
        // Every key but the last is followed by `CHECKSIGVERIFY`; the last by `CHECKSIG`.
        if instructions.clone().next().is_some() {
            if op != OP_CHECKSIGVERIFY {
                return Err(invalid());
            }
        } else if op == OP_CHECKSIG {
            return Ok(keys);
        } else {
            return Err(invalid());
        }
    }
}

/// The single leaf a Taproot input spends, proven to be in the tree the funding output commits
/// to, and the keys it requires.
///
/// The funding output comes from `witness_utxo` or `non_witness_utxo`. Annotations such as
/// `tap_internal_key`, `tap_merkle_root` and `tap_key_origins` are not consulted.
pub fn taproot_script_path(
    psbt: &Psbt,
    input_index: usize,
) -> Result<TaprootScriptPath, SigningDigestError> {
    let input = psbt
        .inputs
        .get(input_index)
        .ok_or(SigningDigestError::InputIndexOutOfRange { index: input_index })?;
    taproot_script_path_of(psbt, input, input_index)
}

fn taproot_script_path_of(
    psbt: &Psbt,
    input: &Input,
    input_index: usize,
) -> Result<TaprootScriptPath, SigningDigestError> {
    let mut leaves = input.tap_scripts.iter();
    let (control_block, (leaf_script, leaf_version)) = match (leaves.next(), leaves.next()) {
        (Some(leaf), None) => leaf,
        (None, _) => {
            return Err(SigningDigestError::UnsupportedTaprootSpend(
                "no script-path leaf",
            ))
        }
        _ => {
            return Err(SigningDigestError::UnsupportedTaprootSpend(
                "several script-path leaves",
            ))
        }
    };
    let prevout = psbt.unsigned_tx.input[input_index].previous_output;
    let (funding_script, _) = psbt_wallet_input::get_output_script_and_value(input, prevout)
        .map_err(|e| SigningDigestError::Sighash(e.to_string()))?;
    if !funding_script.is_p2tr() {
        return Err(SigningDigestError::TaprootCommitmentMismatch);
    }
    let output_key = XOnlyPublicKey::from_slice(&funding_script.as_bytes()[2..34])
        .map_err(|_| SigningDigestError::TaprootCommitmentMismatch)?;
    if !control_block.verify_taproot_commitment(
        &Secp256k1::verification_only(),
        output_key,
        leaf_script,
    ) {
        return Err(SigningDigestError::TaprootCommitmentMismatch);
    }
    Ok(TaprootScriptPath {
        keys: parse_leaf_keys(leaf_script)?,
        leaf_hash: TapLeafHash::from_script(leaf_script, *leaf_version),
        leaf_script: leaf_script.clone(),
        leaf_version: *leaf_version,
        control_block: control_block.clone(),
    })
}

fn taproot_digest(psbt: &Psbt, input_index: usize) -> Result<SigningDigest, SigningDigestError> {
    let path = taproot_script_path(psbt, input_index)?;
    let sighash_type = psbt.inputs[input_index]
        .sighash_type
        .map(|declared| declared.taproot_hash_ty())
        .transpose()
        .map_err(|e| SigningDigestError::Sighash(e.to_string()))?
        .unwrap_or(TapSighashType::Default);
    let prevouts =
        collect_prevouts(psbt).map_err(|e| SigningDigestError::Sighash(e.to_string()))?;
    let digest = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            path.leaf_hash,
            sighash_type,
        )
        .map_err(|e| SigningDigestError::Sighash(e.to_string()))?;
    Ok(SigningDigest {
        digest: digest.to_byte_array(),
        sighash_type: sighash_type as u32,
        scheme: DigestScheme::TaprootScriptPath,
    })
}

impl BitGoPsbt {
    /// The digest the signer of `input_index` signs, derived from the unsigned transaction and
    /// the funding outputs only.
    ///
    /// Taproot inputs must spend exactly one leaf, which must be committed to by the funding
    /// output (see [`taproot_script_path`]); a sighash type declared on the input must be
    /// valid for the scheme. Zcash version 6 (Ironwood) PSBTs get the transparent ZIP-244
    /// digest, which commits to the Ironwood bundle the PSBT carries (or to none).
    pub fn signing_digest(&self, input_index: usize) -> Result<SigningDigest, SigningDigestError> {
        let psbt = self.psbt();
        let input = psbt
            .inputs
            .get(input_index)
            .ok_or(SigningDigestError::InputIndexOutOfRange { index: input_index })?;
        if !input.tap_scripts.is_empty() {
            return taproot_digest(psbt, input_index);
        }
        let sighash = |e: &dyn std::fmt::Display| SigningDigestError::Sighash(e.to_string());
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        match self {
            BitGoPsbt::Zcash(zcash, _) => {
                if zcash.is_ironwood_v6() {
                    let digest = zcash
                        .v6_transparent_sighash(input_index)
                        .map_err(SigningDigestError::Sighash)?;
                    return Ok(SigningDigest {
                        digest,
                        sighash_type: 0x01,
                        scheme: DigestScheme::Zip244,
                    });
                }
                let (branch_id, version_group_id, expiry_height) = zcash
                    .zip243_sighash_params()
                    .ok_or(SigningDigestError::MissingZcashBranchId)?;
                let (message, sighash_type) = psbt
                    .sighash_zcash(
                        input_index,
                        &mut cache,
                        branch_id,
                        version_group_id,
                        expiry_height,
                    )
                    .map_err(|e| sighash(&e))?;
                Ok(SigningDigest {
                    digest: *message.as_ref(),
                    sighash_type,
                    scheme: DigestScheme::Zip243,
                })
            }
            BitGoPsbt::BitcoinLike(_, network) | BitGoPsbt::Dash(_, network) => {
                match network.sighash_fork_id() {
                    Some(fork_id) => {
                        let (message, sighash_type) = psbt
                            .sighash_forkid(input_index, &mut cache, fork_id)
                            .map_err(|e| sighash(&e))?;
                        Ok(SigningDigest {
                            digest: *message.as_ref(),
                            sighash_type,
                            scheme: DigestScheme::EcdsaForkId,
                        })
                    }
                    None => {
                        let (message, sighash_type) = psbt
                            .sighash_ecdsa(input_index, &mut cache)
                            .map_err(|e| sighash(&e))?;
                        Ok(SigningDigest {
                            digest: *message.as_ref(),
                            sighash_type: sighash_type.to_u32(),
                            scheme: DigestScheme::Ecdsa,
                        })
                    }
                }
            }
        }
    }

    /// Every ECDSA (`partial_sigs`) and Schnorr script-path (`tap_script_sigs`) signature stored
    /// on the input, each checked against [`Self::signing_digest`].
    ///
    /// MuSig2 partial signatures and key-path signatures are not reported. An input without
    /// stored signatures yields an empty list without computing a digest.
    pub fn partial_signatures(
        &self,
        input_index: usize,
    ) -> Result<Vec<PartialSignature>, SigningDigestError> {
        let psbt = self.psbt();
        let input = psbt
            .inputs
            .get(input_index)
            .ok_or(SigningDigestError::InputIndexOutOfRange { index: input_index })?;
        if input.partial_sigs.is_empty() && input.tap_script_sigs.is_empty() {
            return Ok(Vec::new());
        }
        let secp = Secp256k1::verification_only();
        let digest = self.signing_digest(input_index)?;
        let message = Message::from_digest(digest.digest);
        let mut out = Vec::new();
        for (key, signature) in &input.partial_sigs {
            out.push(PartialSignature {
                key: SignerKey::Ecdsa(*key),
                sighash_type: signature.sighash_type,
                valid: digest.scheme != DigestScheme::TaprootScriptPath
                    && signature.sighash_type == digest.sighash_type
                    && secp
                        .verify_ecdsa(&message, &signature.signature, &key.inner)
                        .is_ok(),
            });
        }
        if !input.tap_script_sigs.is_empty() {
            let leaf_hash = taproot_script_path(psbt, input_index)?.leaf_hash;
            for ((key, signed_leaf), signature) in &input.tap_script_sigs {
                out.push(PartialSignature {
                    key: SignerKey::Schnorr(*key),
                    sighash_type: signature.sighash_type as u32,
                    valid: digest.scheme == DigestScheme::TaprootScriptPath
                        && *signed_leaf == leaf_hash
                        && signature.sighash_type as u32 == digest.sighash_type
                        && secp
                            .verify_schnorr(&signature.signature, &message, key)
                            .is_ok(),
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed_script_wallet::test_utils::fixtures::{
        load_psbt_fixture_with_format_and_namespace, FixtureNamespace, SignatureState,
    };

    // The half-signed PSBTs `@bitgo/utxo-lib` produced: an oracle independent of this crate for
    // every signature stored in them. Every stored signature must verify against the digest this
    // module derives, on every network, script type and format.
    crate::test_psbt_fixtures!(test_utxolib_half_signatures_verify, network, format, {
        let fixture = load_psbt_fixture_with_format_and_namespace(
            network.to_utxolib_name(),
            SignatureState::Halfsigned,
            format,
            FixtureNamespace::UtxolibCompat,
        )
        .unwrap();
        let psbt = fixture.to_bitgo_psbt(network).unwrap();
        let mut stored = 0;
        for index in 0..psbt.psbt().inputs.len() {
            for signature in psbt.partial_signatures(index).unwrap() {
                assert!(signature.valid, "input {index} of {network:?}");
                stored += 1;
            }
        }
        assert!(stored > 0, "{network:?} fixture holds no signature");
    });

    // The unsigned fixtures: a digest exists for every ECDSA and script-path input, and a
    // signature made over it by the user key (derived through the existing signer) is accepted.
    crate::test_psbt_fixtures!(test_signing_digest_matches_signer, network, format, {
        let fixture = load_psbt_fixture_with_format_and_namespace(
            network.to_utxolib_name(),
            SignatureState::Unsigned,
            format,
            FixtureNamespace::UtxolibCompat,
        )
        .unwrap();
        let mut psbt = fixture.to_bitgo_psbt(network).unwrap();
        let digests: Vec<_> = (0..psbt.psbt().inputs.len())
            .map(|index| psbt.signing_digest(index))
            .collect();
        let xprv = *fixture.get_wallet_xprvs().unwrap().user_key();
        psbt.sign_all_with_xpriv(&xprv).unwrap();
        let mut verified = 0;
        for (index, digest) in digests.iter().enumerate() {
            let signatures = psbt.partial_signatures(index).unwrap();
            if signatures.is_empty() {
                continue;
            }
            let digest = digest.as_ref().unwrap();
            assert!(signatures.iter().all(|signature| signature.valid));
            assert!(signatures
                .iter()
                .all(|signature| signature.sighash_type == digest.sighash_type));
            verified += 1;
        }
        assert!(verified > 0, "{network:?}: the user key signed nothing");
    });

    fn bitcoin_halfsigned() -> BitGoPsbt {
        use crate::fixed_script_wallet::test_utils::fixtures::TxFormat;
        load_psbt_fixture_with_format_and_namespace(
            crate::Network::Bitcoin.to_utxolib_name(),
            SignatureState::Halfsigned,
            TxFormat::Psbt,
            FixtureNamespace::UtxolibCompat,
        )
        .unwrap()
        .to_bitgo_psbt(crate::Network::Bitcoin)
        .unwrap()
    }

    fn first_taproot_input(psbt: &BitGoPsbt) -> usize {
        psbt.psbt()
            .inputs
            .iter()
            .position(|input| !input.tap_scripts.is_empty() && !input.tap_script_sigs.is_empty())
            .expect("fixture has a signed script-path input")
    }

    #[test]
    fn script_path_signatures_are_schnorr_and_the_leaf_is_proven() {
        let psbt = bitcoin_halfsigned();
        let index = first_taproot_input(&psbt);
        let signatures = psbt.partial_signatures(index).unwrap();
        assert!(signatures
            .iter()
            .all(|s| matches!(s.key, SignerKey::Schnorr(_)) && s.valid));
        let path = taproot_script_path(psbt.psbt(), index).unwrap();
        assert_eq!(path.keys.len(), 2);
        assert_eq!(
            psbt.signing_digest(index).unwrap().scheme,
            DigestScheme::TaprootScriptPath
        );
    }

    #[test]
    fn a_leaf_the_funding_output_does_not_commit_to_is_refused() {
        let mut psbt = bitcoin_halfsigned();
        let index = first_taproot_input(&psbt);
        let input = &mut psbt.psbt_mut().inputs[index];
        for (script, _) in input.tap_scripts.values_mut() {
            let mut bytes = script.to_bytes();
            bytes[5] ^= 1;
            *script = ScriptBuf::from_bytes(bytes);
        }
        assert!(matches!(
            psbt.signing_digest(index),
            Err(SigningDigestError::TaprootCommitmentMismatch)
        ));
    }

    #[test]
    fn a_changed_output_invalidates_every_stored_signature() {
        let mut psbt = bitcoin_halfsigned();
        psbt.psbt_mut().unsigned_tx.output[0].value = miniscript::bitcoin::Amount::from_sat(1);
        let mut checked = 0;
        for index in 0..psbt.psbt().inputs.len() {
            for signature in psbt.partial_signatures(index).unwrap() {
                assert!(!signature.valid);
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    #[test]
    fn leaf_scripts_must_be_n_of_n_xonly_chains() {
        let key = |byte: u8| {
            let secp = Secp256k1::new();
            secp256k1::Keypair::from_seckey_slice(&secp, &[byte; 32])
                .unwrap()
                .x_only_public_key()
                .0
        };
        let script = |ops: &[(u8, bool)]| {
            let mut builder = miniscript::bitcoin::script::Builder::new();
            for (byte, verify) in ops {
                builder = builder
                    .push_x_only_key(&key(*byte))
                    .push_opcode(if *verify {
                        OP_CHECKSIGVERIFY
                    } else {
                        OP_CHECKSIG
                    });
            }
            builder.into_script()
        };
        assert_eq!(
            parse_leaf_keys(&script(&[(1, true), (2, false)])).unwrap(),
            vec![key(1), key(2)]
        );
        assert_eq!(
            parse_leaf_keys(&script(&[(1, false)])).unwrap(),
            vec![key(1)]
        );
        // CHECKSIG in the middle, CHECKSIGVERIFY at the end, an empty script.
        for bad in [
            script(&[(1, false), (2, false)]),
            script(&[(1, true), (2, true)]),
            ScriptBuf::new(),
        ] {
            assert!(matches!(
                parse_leaf_keys(&bad),
                Err(SigningDigestError::UnsupportedLeafScript)
            ));
        }
    }
}
