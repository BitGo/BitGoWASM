use crate::fixed_script_wallet::wallet_scripts::{parse_multisig_script_2_of_3, parse_p2pk_script};
use miniscript::bitcoin::{CompressedPublicKey, Psbt, PublicKey, ScriptBuf, TxIn};

/// Coin-specific parameters for computing sighash on compact (no OP_0) inputs.
pub(crate) enum SighashContext {
    Bitcoin {
        fork_id: Option<u32>,
    },
    Zcash {
        consensus_branch_id: u32,
        version_group_id: u32,
        expiry_height: u32,
    },
}

/// The structured content of a fixed-script wallet input (P2SH/P2WSH/P2SH-P2WSH or P2SH-P2PK).
pub(crate) enum FixedScriptInput {
    /// 2-of-3 multisig input.
    Multisig {
        inner_script: ScriptBuf,
        /// Sig slots in order. Empty bytes = OP_0 placeholder; non-empty = raw DER sig bytes.
        slots: Vec<Vec<u8>>,
    },
    /// P2SH-P2PK replay protection input.
    ReplayProtection {
        pubkey: CompressedPublicKey,
        /// Raw sig bytes, or `None` if the slot is an OP_0 placeholder.
        sig_bytes: Option<Vec<u8>>,
    },
    /// Input with neither scriptSig nor witness — not yet signed.
    Unsigned,
}

impl FixedScriptInput {
    /// Parse a fixed-script wallet input from a transaction input.
    /// Does not enforce any minimum slot count — callers decide what's valid.
    pub(crate) fn from_txin(tx_in: &TxIn) -> Result<Self, String> {
        let has_witness = !tx_in.witness.is_empty();
        let has_script_sig = !tx_in.script_sig.is_empty();

        let (inner_script, slots) = if has_witness {
            let items: Vec<&[u8]> = tx_in.witness.iter().collect();
            if items.len() < 2 {
                return Err(format!(
                    "Expected at least 2 witness items, got {}",
                    items.len()
                ));
            }
            let inner_script = ScriptBuf::from(items.last().unwrap().to_vec());
            let slots = items[1..items.len() - 1]
                .iter()
                .map(|s| s.to_vec())
                .collect();
            (inner_script, slots)
        } else if has_script_sig {
            let instructions: Vec<_> = tx_in
                .script_sig
                .instructions()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to parse scriptSig: {}", e))?;
            if instructions.len() < 2 {
                return Err(format!(
                    "Expected at least 2 scriptSig items, got {}",
                    instructions.len()
                ));
            }
            let redeem_bytes = match instructions.last().unwrap() {
                miniscript::bitcoin::script::Instruction::PushBytes(b) => b.as_bytes().to_vec(),
                _ => return Err("Last scriptSig item is not a push".to_string()),
            };
            let inner_script = ScriptBuf::from(redeem_bytes);
            // For multisig, scriptSig is OP_0 <sig...> <redeemScript>:
            //   index 0 is OP_0 (skip it), slots start at index 1.
            // For P2SH-P2PK, scriptSig is <sig> <redeemScript>:
            //   index 0 IS the sig, so slots must start at index 0.
            let slot_start = if parse_p2pk_script(&inner_script).is_some() {
                0
            } else {
                1
            };
            let slots = instructions[slot_start..instructions.len() - 1]
                .iter()
                .map(|inst| match inst {
                    miniscript::bitcoin::script::Instruction::PushBytes(b) => b.as_bytes().to_vec(),
                    miniscript::bitcoin::script::Instruction::Op(_) => vec![],
                })
                .collect();
            (inner_script, slots)
        } else {
            return Ok(Self::Unsigned);
        };

        if parse_multisig_script_2_of_3(&inner_script).is_ok() {
            Ok(Self::Multisig {
                inner_script,
                slots,
            })
        } else if let Some(pubkey) = parse_p2pk_script(&inner_script) {
            let sig_bytes = slots.into_iter().next().filter(|s| !s.is_empty());
            Ok(Self::ReplayProtection { pubkey, sig_bytes })
        } else {
            Err(
                "scriptSig/witness does not correspond to a known script type \
                 (multisig 2-of-3 or P2SH-P2PK)"
                    .to_string(),
            )
        }
    }

    /// Insert signatures into `psbt.inputs[index].partial_sigs`.
    /// Handles positional (OP_0 placeholders) and compact (no OP_0) cases.
    /// For compact inputs the sighash is computed using `ctx`.
    pub(crate) fn apply_signatures(
        &self,
        psbt: &mut Psbt,
        index: usize,
        ctx: &SighashContext,
    ) -> Result<(), String> {
        use miniscript::bitcoin::ecdsa::Signature as EcdsaSig;

        match self {
            Self::Multisig {
                inner_script,
                slots,
            } => {
                let pubkeys = parse_multisig_script_2_of_3(inner_script)
                    .map_err(|e| format!("Input {}: {}", index, e))?;

                if slots.iter().any(|s| s.is_empty()) {
                    // Positional: slot j → pubkey j
                    for (j, slot) in slots.iter().enumerate() {
                        if slot.is_empty() {
                            continue;
                        }
                        let sig = EcdsaSig::from_slice(slot)
                            .map_err(|e| format!("Input {}: slot {}: {}", index, j, e))?;
                        let pk = CompressedPublicKey::from_slice(&pubkeys[j].to_bytes())
                            .map_err(|e| format!("Input {}: {}", index, e))?;
                        psbt.inputs[index]
                            .partial_sigs
                            .insert(PublicKey::from(pk), sig);
                    }
                } else {
                    // Compact: ECDSA verify against coin-specific sighash
                    let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
                    let candidate_pks: Vec<miniscript::bitcoin::secp256k1::PublicKey> = psbt.inputs
                        [index]
                        .bip32_derivation
                        .keys()
                        .cloned()
                        .collect();
                    let message = Self::compute_compact_sighash(psbt, index, ctx)?;
                    for slot in slots.iter().filter(|s| !s.is_empty()) {
                        let sig = EcdsaSig::from_slice(slot)
                            .map_err(|e| format!("Input {}: {}", index, e))?;
                        let matched_pk = candidate_pks
                            .iter()
                            .find(|pk| secp.verify_ecdsa(&message, &sig.signature, pk).is_ok())
                            .ok_or_else(|| {
                                format!("Input {}: sig doesn't match any wallet pubkey", index)
                            })?;
                        psbt.inputs[index]
                            .partial_sigs
                            .insert(PublicKey::new(*matched_pk), sig);
                    }
                }
            }
            Self::ReplayProtection { pubkey, sig_bytes } => {
                if let Some(bytes) = sig_bytes {
                    let sig = EcdsaSig::from_slice(bytes)
                        .map_err(|e| format!("Input {}: {}", index, e))?;
                    psbt.inputs[index]
                        .partial_sigs
                        .insert(PublicKey::from(*pubkey), sig);
                }
            }
            Self::Unsigned => {}
        }
        Ok(())
    }

    fn compute_compact_sighash(
        psbt: &Psbt,
        index: usize,
        ctx: &SighashContext,
    ) -> Result<miniscript::bitcoin::secp256k1::Message, String> {
        use miniscript::bitcoin::sighash::SighashCache;

        let mut cache = SighashCache::new(&psbt.unsigned_tx);

        match ctx {
            SighashContext::Bitcoin { fork_id } => {
                if let Some(fid) = fork_id {
                    psbt.sighash_forkid(index, &mut cache, *fid)
                        .map(|(msg, _)| msg)
                        .map_err(|e| format!("Input {}: FORKID sighash: {}", index, e))
                } else {
                    psbt.sighash_ecdsa(index, &mut cache)
                        .map(|(msg, _)| msg)
                        .map_err(|e| format!("Input {}: sighash: {}", index, e))
                }
            }
            SighashContext::Zcash {
                consensus_branch_id,
                version_group_id,
                expiry_height,
            } => {
                use miniscript::bitcoin::sighash::SighashCacheZcashExt;
                let prevout = psbt.unsigned_tx.input[index].previous_output;
                let value =
                    crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input::get_output_script_and_value(
                        &psbt.inputs[index], prevout,
                    )
                    .map(|(_, v)| v)
                    .unwrap_or(miniscript::bitcoin::Amount::ZERO);
                let script = psbt.inputs[index]
                    .witness_script
                    .as_ref()
                    .or(psbt.inputs[index].redeem_script.as_ref())
                    .ok_or_else(|| format!("Input {}: no redeem/witness script", index))?;
                cache
                    .p2sh_signature_hash_zcash(
                        index,
                        script,
                        value,
                        0x01u32,
                        *consensus_branch_id,
                        *version_group_id,
                        *expiry_height,
                    )
                    .map(|h| {
                        miniscript::bitcoin::secp256k1::Message::from_digest(h.to_byte_array())
                    })
                    .map_err(|e| format!("Input {}: Zcash sighash: {}", index, e))
            }
        }
    }

    /// Parse all inputs from a transaction.
    pub(crate) fn parse_all(tx: &miniscript::bitcoin::Transaction) -> Result<Vec<Self>, String> {
        tx.input
            .iter()
            .enumerate()
            .map(|(i, tx_in)| Self::from_txin(tx_in).map_err(|e| format!("Input {}: {}", i, e)))
            .collect()
    }
}
