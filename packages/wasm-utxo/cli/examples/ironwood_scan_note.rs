//! Decrypt the Ironwood/Orchard output notes of a transaction with a full viewing key.
//!
//! Stands in for a wallet's note-scanning step: given the transaction that paid the wallet and
//! its `orchard_fvk.hex`, reconstruct each on-chain action and recover the received note
//! plaintext — the `recipient`/`value`/`rho`/`rseed`/`cmx` fields a spend `--notes-file` needs.
//! Both the External and Internal (change) scopes are tried. Actions that decrypt under
//! neither (spends with a dummy output, or notes to someone else) are reported as
//! `spend-or-unrelated`.
//!
//! Two input modes:
//! - `<raw-v6-tx-hex>`: this crate's wire codec (v6 with an empty Orchard slot and a populated
//!   Ironwood bundle). A non-v6 transaction is reported as `{"noIronwoodBundle": true}`.
//! - `<node-tx.json>`: the node's `getrawtransaction` verbose tx object. Transactions can carry
//!   both an Orchard bundle (migration) and an Ironwood bundle, which the wire codec rejects,
//!   so this mode reads the node's parsed fields and scans each pool under its own note
//!   version.
//!
//! Usage: `ironwood_scan_note <raw-v6-tx-hex|node-tx.json> <fvk-file>`.

use anyhow::{bail, Context};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use orchard::value::ValueCommitment;
use orchard::Action as OrchardAction;
use wasm_utxo::zcash::transaction::ZCASH_V6_VERSION_HEADER;
use wasm_utxo::zcash::v6::decode_v6_transaction;

/// The wire fields of one action, from either input mode.
struct ActionParts {
    cv: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    enc_ciphertext: [u8; 580],
    out_ciphertext: [u8; 80],
}

/// Which note plaintext version an action's output is encrypted under.
#[derive(Clone, Copy)]
enum Pool {
    Ironwood,
    Orchard,
}

/// The wallet's incoming viewing keys, one per scope.
struct Ivks(Vec<(&'static str, PreparedIncomingViewingKey)>);

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        bail!("usage: ironwood_scan_note <raw-v6-tx-hex|node-tx.json> <fvk-file>");
    }
    let fvk_hex = std::fs::read_to_string(&args[2])
        .with_context(|| format!("reading fvk file {}", args[2]))?;
    let fvk_bytes: [u8; 96] = hex::decode(fvk_hex.trim())
        .context("invalid fvk hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("fvk must be 96 bytes"))?;
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).context("invalid fvk")?;
    let ivks = Ivks(
        [("external", Scope::External), ("internal", Scope::Internal)]
            .into_iter()
            .map(|(name, scope)| (name, PreparedIncomingViewingKey::new(&fvk.to_ivk(scope))))
            .collect(),
    );

    // A readable file selects the node-JSON mode; anything else is raw tx hex.
    match std::fs::read_to_string(&args[1]) {
        Ok(contents) => run_node_tx_mode(&contents, &ivks),
        Err(_) => {
            let arg = args[1].trim();
            let raw = hex::decode(arg.strip_prefix("0x").unwrap_or(arg))
                .with_context(|| format!("{arg} is neither a readable file nor tx hex"))?;
            run_raw_tx_mode(&raw, &ivks)
        }
    }
}

/// Scan a node-decoded transaction JSON, checking both the Ironwood and Orchard bundles.
fn run_node_tx_mode(contents: &str, ivks: &Ivks) -> anyhow::Result<()> {
    let raw_json: serde_json::Value =
        serde_json::from_str(contents).context("node tx file is not valid JSON")?;
    // Accept both the bare tx object and the RPC wrapper ({jsonrpc, id, result}).
    let tx_json = raw_json.get("result").unwrap_or(&raw_json);
    let mut pools = Vec::new();
    for (name, pool) in [("ironwood", Pool::Ironwood), ("orchard", Pool::Orchard)] {
        let Some(actions) = tx_json
            .pointer(&format!("/{name}/actions"))
            .and_then(|a| a.as_array())
        else {
            continue;
        };
        let notes = actions
            .iter()
            .enumerate()
            .map(|(i, a)| scan_action(i, &parse_json_action(a)?, pool, ivks))
            .collect::<anyhow::Result<Vec<_>>>()?;
        pools.push(serde_json::json!({ "pool": name, "actions": actions.len(), "notes": notes }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "txid": tx_json.get("txid"),
            "pools": pools,
        }))?
    );
    Ok(())
}

fn run_raw_tx_mode(raw: &[u8], ivks: &Ivks) -> anyhow::Result<()> {
    // Tolerate non-v6 transactions (a block scanner feeds every raw tx through here); a v6
    // transaction that fails to decode is an error.
    let header = raw.get(..4).context("tx is shorter than its header")?;
    if u32::from_le_bytes(header.try_into().unwrap()) != ZCASH_V6_VERSION_HEADER {
        println!("{}", serde_json::json!({"noIronwoodBundle": true}));
        return Ok(());
    }
    let tx = decode_v6_transaction(raw)
        .map_err(|e| anyhow::anyhow!("decoding v6 transaction: {e:?}"))?;
    let Some(bundle) = tx.ironwood_bundle.as_ref() else {
        println!("{}", serde_json::json!({"noIronwoodBundle": true}));
        return Ok(());
    };

    let actions: Vec<serde_json::Value> = bundle
        .actions
        .iter()
        .enumerate()
        .map(|(i, a)| {
            serde_json::json!({
                "actionIndex": i,
                "cmx": hex::encode(a.cmx),
                "nullifier": hex::encode(a.nullifier),
            })
        })
        .collect();
    let notes = bundle
        .actions
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let parts = ActionParts {
                cv: a.cv,
                nullifier: a.nullifier,
                rk: a.rk,
                cmx: a.cmx,
                ephemeral_key: a.ephemeral_key,
                enc_ciphertext: a.enc_ciphertext,
                out_ciphertext: a.out_ciphertext,
            };
            scan_action(i, &parts, Pool::Ironwood, ivks)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // `txid()` is in internal byte order; print the canonical display order.
    let mut txid = tx.txid();
    txid.reverse();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "txid": hex::encode(txid),
            "valueBalance": bundle.value_balance,
            "actions": actions,
            "notes": notes,
        }))?
    );
    Ok(())
}

/// Read an action from the node's parsed field names.
fn parse_json_action(a: &serde_json::Value) -> anyhow::Result<ActionParts> {
    fn bytes<const N: usize>(a: &serde_json::Value, field: &str) -> anyhow::Result<[u8; N]> {
        let value = a[field]
            .as_str()
            .with_context(|| format!("action is missing {field}"))?;
        hex::decode(value.trim().trim_start_matches("0x"))
            .with_context(|| format!("invalid {field} hex"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{field} must be {N} bytes"))
    }
    Ok(ActionParts {
        cv: bytes(a, "cv")?,
        nullifier: bytes(a, "nullifier")?,
        rk: bytes(a, "rk")?,
        cmx: bytes(a, "cmx")?,
        ephemeral_key: bytes(a, "ephemeralKey")?,
        enc_ciphertext: bytes(a, "encCiphertext")?,
        out_ciphertext: bytes(a, "outCiphertext")?,
    })
}

/// Rebuild an orchard action from its wire fields and try recipient-side decryption under
/// each scope.
fn scan_action(
    index: usize,
    parts: &ActionParts,
    pool: Pool,
    ivks: &Ivks,
) -> anyhow::Result<serde_json::Value> {
    let cv_net = Option::from(ValueCommitment::from_bytes(&parts.cv)).context("invalid cv")?;
    let rk = VerificationKey::<SpendAuth>::try_from(parts.rk).context("invalid rk")?;
    let cmx =
        Option::from(ExtractedNoteCommitment::from_bytes(&parts.cmx)).context("invalid cmx")?;
    let nf = Option::from(Nullifier::from_bytes(&parts.nullifier)).context("invalid nullifier")?;
    let encrypted_note = TransmittedNoteCiphertext {
        epk_bytes: parts.ephemeral_key,
        enc_ciphertext: parts.enc_ciphertext,
        out_ciphertext: parts.out_ciphertext,
    };
    let action = OrchardAction::from_parts(nf, rk, cmx, encrypted_note, cv_net, ())
        .context("invalid action")?;

    for (scope, ivk) in &ivks.0 {
        let decrypted = match pool {
            Pool::Ironwood => zcash_note_encryption::try_note_decryption(
                &IronwoodDomain::for_action(&action),
                ivk,
                &action,
            ),
            Pool::Orchard => zcash_note_encryption::try_note_decryption(
                &OrchardDomain::for_action(&action),
                ivk,
                &action,
            ),
        };
        if let Some((note, recipient, memo)) = decrypted {
            return Ok(serde_json::json!({
                "actionIndex": index,
                "kind": "output",
                "scope": scope,
                "note": {
                    "recipient": hex::encode(recipient.to_raw_address_bytes()),
                    "value": note.value().inner(),
                    "rho": hex::encode(note.rho().to_bytes()),
                    "rseed": hex::encode(note.rseed().as_bytes()),
                    "cmx": hex::encode(parts.cmx),
                    "memo": hex::encode(memo.as_ref()),
                },
            }));
        }
    }
    Ok(serde_json::json!({"actionIndex": index, "kind": "spend-or-unrelated"}))
}
