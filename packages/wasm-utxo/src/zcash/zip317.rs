//! ZIP-317 conventional fee estimation.
//!
//! Formula per [ZIP-317 §Fee calculation]: the transparent terms are **size**-based (bytes over
//! the standard P2PKH input/output sizes), the Sapling term is `max(spends, outputs)`, JoinSplit
//! pairs count double, and each shielded-bundle action counts once.
//!
//! The Ironwood term is settled by zebra's NU6.3 implementation
//! (`zebra-chain::transaction::unmined::zip317`): *Ironwood actions have the same structure and
//! cost as Orchard actions, so they are counted the same way* — they enter `logical_actions` as
//! their own additive term. A v6 transaction carries either an Orchard or an Ironwood bundle,
//! so in practice exactly one of the two terms is non-zero.
//!
//! [ZIP-317 §Fee calculation]: https://zips.z.cash/zip-0317#fee-calculation

/// The marginal fee per logical action, in zatoshi (ZIP-317 §Fee calculation).
pub const MARGINAL_FEE: u64 = 5_000;
/// The minimum number of actions a transaction pays for (ZIP-317 §Fee calculation).
pub const GRACE_ACTIONS: u64 = 2;
/// The standard size of a P2PKH input for the transparent logical-action divisor (ZIP-317).
pub const P2PKH_STANDARD_INPUT_SIZE: u64 = 150;
/// The standard size of a P2PKH output for the transparent logical-action divisor (ZIP-317).
pub const P2PKH_STANDARD_OUTPUT_SIZE: u64 = 34;

/// The ZIP-317 count inputs. The transparent sides are **serialized sizes**, not item counts —
/// a naive input/output count misprices them (ZIP-317 §Fee calculation).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Zip317ActionCounts {
    /// The sum of the estimated final serialized sizes of the transaction's transparent inputs.
    pub tx_in_total_size: u64,
    /// The sum of the serialized sizes of the transaction's transparent outputs.
    pub tx_out_total_size: u64,
    /// The number of Sprout JoinSplit descriptions.
    pub n_join_split: u64,
    /// The number of Sapling spends (per anchor).
    pub n_spends_sapling: u64,
    /// The number of Sapling outputs.
    pub n_outputs_sapling: u64,
    /// The number of Orchard actions.
    pub n_actions_orchard: u64,
    /// The number of Ironwood actions (v6 only; same footing as Orchard actions).
    pub n_actions_ironwood: u64,
}

impl Zip317ActionCounts {
    /// Counts for a transaction with only an Ironwood bundle of `n_actions` actions.
    pub fn ironwood_only(n_actions: u64) -> Self {
        Self {
            n_actions_ironwood: n_actions,
            ..Self::default()
        }
    }
}

/// The ZIP-317 `logical_actions` for these counts: `max(ceil(tx_in_total_size / 150),
/// ceil(tx_out_total_size / 34)) + 2 × nJoinSplit + max(nSpendsSapling, nOutputsSapling)
/// + nActionsOrchard + nActionsIronwood`.
pub fn logical_actions(c: &Zip317ActionCounts) -> u64 {
    let tx_in_logical_actions = c.tx_in_total_size.div_ceil(P2PKH_STANDARD_INPUT_SIZE);
    let tx_out_logical_actions = c.tx_out_total_size.div_ceil(P2PKH_STANDARD_OUTPUT_SIZE);

    tx_in_logical_actions.max(tx_out_logical_actions)
        + 2 * c.n_join_split
        + c.n_spends_sapling.max(c.n_outputs_sapling)
        + c.n_actions_orchard
        + c.n_actions_ironwood
}

/// The ZIP-317 conventional fee in zatoshi: `MARGINAL_FEE × max(GRACE_ACTIONS, logical_actions)`.
pub fn conventional_fee(c: &Zip317ActionCounts) -> u64 {
    MARGINAL_FEE * GRACE_ACTIONS.max(logical_actions(c))
}

// ============================================================================
// Transparent serialized sizes
// ============================================================================

/// Each signature push in a finalized scriptSig: the maximum DER-encoded ECDSA signature (72)
/// plus its sighash byte, matching the `dimensions` estimator's max convention.
const MAX_SIG_WITH_SIGHASH: usize = 73;
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// The redeem script of a BitGo 2-of-3 multisig wallet input over compressed keys:
/// `OP_2 <33> <33> <33> OP_3 OP_CHECKMULTISIG`.
pub const P2SH_2OF3_REDEEM_SCRIPT_LEN: usize = 105;
/// The redeem script of a P2SH-P2PK replay-protection input: `<33> OP_CHECKSIG`.
pub const P2SH_P2PK_REDEEM_SCRIPT_LEN: usize = 35;

/// The length of a minimal data push of `len` bytes: opcode(s) + data.
fn push_len(len: usize) -> usize {
    let opcode = match len {
        0..=75 => 1,
        76..=255 => 2,
        256..=65535 => 3,
        _ => 5,
    };
    opcode + len
}

/// A finalized P2SH 2-of-3 multisig scriptSig: `OP_0 <sig> <sig> <redeemScript>`.
pub fn p2sh_multisig_script_sig_len(redeem_script_len: usize) -> usize {
    1 + 2 * push_len(MAX_SIG_WITH_SIGHASH) + push_len(redeem_script_len)
}

/// A finalized P2SH-P2PK scriptSig: `<sig> <redeemScript>`.
pub fn p2sh_p2pk_script_sig_len(redeem_script_len: usize) -> usize {
    push_len(MAX_SIG_WITH_SIGHASH) + push_len(redeem_script_len)
}

/// A finalized P2PKH scriptSig: `<sig> <pubkey>`.
pub fn p2pkh_script_sig_len() -> usize {
    push_len(MAX_SIG_WITH_SIGHASH) + push_len(COMPRESSED_PUBKEY_LEN)
}

/// The serialized size of a transparent input: outpoint (txid 32 + vout 4) +
/// CompactSize(scriptSig) + scriptSig + sequence (4).
pub fn transparent_input_size(script_sig_len: usize) -> u64 {
    (36 + super::v6::compact_size_len(script_sig_len) + script_sig_len + 4) as u64
}

/// The serialized size of a transparent output: value (8) + CompactSize(scriptPubKey) +
/// scriptPubKey.
pub fn transparent_output_size(script_pubkey_len: usize) -> u64 {
    (8 + super::v6::compact_size_len(script_pubkey_len) + script_pubkey_len) as u64
}

// ============================================================================
// Errors
// ============================================================================

/// Failure modes of building ZIP-317 dimensions.
#[derive(Debug, strum::IntoStaticStr)]
pub enum Zip317Error {
    /// The PSBT is not a Zcash PSBT.
    NotZcashPsbt,
    /// The input script type is not one a Zcash wallet input can have (no segwit or taproot).
    UnsupportedInputScriptType(String),
    /// The chain code is invalid, or its script type is not available on Zcash.
    UnsupportedChain(u32),
    /// The stored Ironwood PCZT could not be read (or was already extracted).
    IronwoodPczt(String),
}

impl core::fmt::Display for Zip317Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotZcashPsbt => write!(f, "zip317: not a Zcash PSBT"),
            Self::UnsupportedInputScriptType(t) => {
                write!(f, "zip317: input script type {t} is not supported on Zcash")
            }
            Self::UnsupportedChain(c) => {
                write!(f, "zip317: chain {c} is invalid or not supported on Zcash")
            }
            Self::IronwoodPczt(e) => write!(f, "zip317: cannot read the Ironwood PCZT: {e}"),
        }
    }
}

impl std::error::Error for Zip317Error {}

crate::impl_wasm_error_code!(Zip317Error);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_actions_floor_prices_an_empty_transaction_at_two_actions() {
        // No inputs, no outputs, no shielded sides: still billed for GRACE_ACTIONS.
        let counts = Zip317ActionCounts::default();
        assert_eq!(logical_actions(&counts), 0);
        assert_eq!(conventional_fee(&counts), MARGINAL_FEE * 2);
    }

    #[test]
    fn transparent_terms_are_size_based_not_count_based() {
        // The divisor is on total bytes: exactly 150 input bytes (or 34 output bytes) is one
        // logical action, and 151 is two.
        let one_action = Zip317ActionCounts {
            tx_in_total_size: 150,
            ..Zip317ActionCounts::default()
        };
        assert_eq!(logical_actions(&one_action), 1);

        let one_action_outputs = Zip317ActionCounts {
            tx_out_total_size: 34,
            ..Zip317ActionCounts::default()
        };
        assert_eq!(logical_actions(&one_action_outputs), 1);

        let two_actions = Zip317ActionCounts {
            tx_in_total_size: 151,
            ..Zip317ActionCounts::default()
        };
        assert_eq!(logical_actions(&two_actions), 2);
    }

    #[test]
    fn transparent_sides_take_the_max_of_the_two_divisions() {
        // 3 input-actions vs 1 output-action ⇒ 3.
        let counts = Zip317ActionCounts {
            tx_in_total_size: 3 * P2PKH_STANDARD_INPUT_SIZE,
            tx_out_total_size: P2PKH_STANDARD_OUTPUT_SIZE,
            ..Zip317ActionCounts::default()
        };
        assert_eq!(logical_actions(&counts), 3);
    }

    #[test]
    fn ironwood_actions_are_an_additive_term_on_the_same_footings_as_orchard() {
        // Two Ironwood actions over an otherwise empty transparent side: logical_actions = 2,
        // billed at 2 × MARGINAL_FEE (above the grace floor).
        let counts = Zip317ActionCounts::ironwood_only(2);
        assert_eq!(logical_actions(&counts), 2);
        assert_eq!(conventional_fee(&counts), 2 * MARGINAL_FEE);

        // Orchard actions count identically — a v6 tx carries one bundle or the other.
        let orchard = Zip317ActionCounts {
            n_actions_orchard: 2,
            ..Zip317ActionCounts::default()
        };
        assert_eq!(logical_actions(&orchard), logical_actions(&counts));
    }

    #[test]
    fn single_shielded_output_hits_the_grace_floor() {
        // A 1-action shielding transaction: logical_actions = 1, but ZIP-317 bills two.
        let counts = Zip317ActionCounts::ironwood_only(1);
        assert_eq!(logical_actions(&counts), 1);
        assert_eq!(conventional_fee(&counts), 2 * MARGINAL_FEE);
    }

    #[test]
    fn redeem_script_lengths_match_the_wallet_scripts() {
        // OP_2 + 3 × push(33) + OP_3 + OP_CHECKMULTISIG; push(33) + OP_CHECKSIG.
        assert_eq!(P2SH_2OF3_REDEEM_SCRIPT_LEN, 1 + 3 * (1 + 33) + 1 + 1);
        assert_eq!(P2SH_P2PK_REDEEM_SCRIPT_LEN, 1 + 33 + 1);
        // OP_0 + 2 × push(73) + OP_PUSHDATA1 push(105) = 1 + 148 + 107 = 256, which takes the
        // 3-byte CompactSize: 36 + 3 + 256 + 4 = 299.
        assert_eq!(
            p2sh_multisig_script_sig_len(P2SH_2OF3_REDEEM_SCRIPT_LEN),
            256
        );
        assert_eq!(
            transparent_input_size(p2sh_multisig_script_sig_len(P2SH_2OF3_REDEEM_SCRIPT_LEN)),
            299
        );
        // A P2SH output script (23 bytes): 8 + 1 + 23 = 32.
        assert_eq!(transparent_output_size(23), 32);
    }

    #[test]
    fn mixed_multi_action_bundle() {
        // 2 Ironwood actions + 1 transparent input of 170 bytes (ceil(170/150) = 2):
        // logical_actions = 2 + 2 = 4 ⇒ 20_000 zatoshi.
        let counts = Zip317ActionCounts {
            tx_in_total_size: 170,
            n_actions_ironwood: 2,
            ..Zip317ActionCounts::default()
        };
        assert_eq!(logical_actions(&counts), 4);
        assert_eq!(conventional_fee(&counts), 4 * MARGINAL_FEE);
    }
}
