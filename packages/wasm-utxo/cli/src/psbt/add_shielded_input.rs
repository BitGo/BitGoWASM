//! Constructor role for the **spend** flow: add the shielded spends (and optionally shielded
//! outputs) to a v6 PSBT as a single keyless orchard PCZT.
//!
//! The notes come from a JSON file in the shape the build service produces (the TypeScript
//! spend fixtures' `request` object is one) — the note plaintexts, their witnesses, and either
//! their nullifiers or enough plaintext to derive them locally from the `--fvk-file` (the
//! stand-in for the viewing-key holder's `generate-nullifiers` round):
//!
//! ```json
//! {
//!   "anchor": "<hex32>",
//!   "spends": [{
//!     "recipient": "<hex43>", "value": 100000000,
//!     "rho": "<hex32>", "rseed": "<hex32>", "cmx": "<hex32>",
//!     "witness": { "position": 0, "authPath": ["<hex32>", "..."] },
//!     "nullifier": "<hex32>"
//!   }],
//!   "outputs": [{ "recipient": "<hex43>", "amount": 90000000 }]
//! }
//! ```
//!
//! `authPath` is either the 32 sibling hashes (leaf-to-root) or their flattened 1024-byte hex
//! encoding. `value` and `amount` may be JSON numbers or decimal strings. `nullifier` is
//! optional when `--fvk-file` is given; each output may also carry a `memo` (512-byte hex,
//! ZIP-302 no-memo by default) and a `unifiedAddress`. Prints the updated PSBT as hex to
//! stdout, with the action map on stderr (the actions are shuffled, so the `--action-index`
//! arguments of the later steps must come from it).

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use serde::Deserialize;
use std::path::PathBuf;
use wasm_utxo::fixed_script_wallet::bitgo_psbt::zcash::IronwoodOutputRequest;
use wasm_utxo::zcash::ironwood_build::{IronwoodWitness, WitnessAuthPath};
use wasm_utxo::zcash::ironwood_construct::IronwoodKeylessSpendSpec;
use wasm_utxo::Network;

use crate::input::read_input_bytes;
use crate::psbt::common::{
    auth_path_from_flat_hex, auth_path_from_hashes, parse_fvk_file, parse_hex, print_zcash_psbt,
    read_zcash_psbt, zip302_no_memo,
};

#[derive(Deserialize)]
struct NotesFile {
    anchor: Option<String>,
    spends: Vec<NoteSpend>,
    #[serde(default)]
    outputs: Vec<NoteOutput>,
}

#[derive(Deserialize)]
struct NoteSpend {
    recipient: String,
    value: JsonU64,
    rho: String,
    rseed: String,
    cmx: String,
    witness: NoteWitness,
    nullifier: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteWitness {
    position: u32,
    auth_path: AuthPath,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthPath {
    Hashes(Vec<String>),
    Flattened(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteOutput {
    recipient: String,
    amount: JsonU64,
    memo: Option<String>,
    unified_address: Option<String>,
}

/// A `u64` as a JSON number or a decimal string (the fixtures write values as strings to stay
/// bigint-safe).
#[derive(Deserialize)]
#[serde(untagged)]
enum JsonU64 {
    Number(u64),
    Text(String),
}

impl JsonU64 {
    fn parse(&self, what: &str) -> Result<u64> {
        match self {
            JsonU64::Number(number) => Ok(*number),
            JsonU64::Text(text) => text
                .trim()
                .parse()
                .with_context(|| format!("{what} is not an unsigned integer")),
        }
    }
}

pub fn handle_add_shielded_input_command(
    path: PathBuf,
    network: Network,
    notes_file: PathBuf,
    fvk_file: Option<PathBuf>,
    anchor: Option<String>,
) -> Result<()> {
    let mut psbt = read_zcash_psbt(&path, network)?;

    let notes = read_input_bytes(&notes_file, "notes file")?;
    let notes: NotesFile =
        serde_json::from_slice(&notes).context("notes file is not a valid notes JSON")?;

    let anchor: [u8; 32] = match (&anchor, &notes.anchor) {
        (Some(anchor), _) => parse_hex(anchor, "--anchor")?,
        (None, Some(anchor)) => parse_hex(anchor, "notes anchor")?,
        (None, None) => {
            bail!("an anchor is required: pass --anchor or put \"anchor\" in the notes file")
        }
    };
    if notes.spends.is_empty() {
        bail!(
            "the notes file carries no spends; output-only builds are the shielding flow \
             (add-shielded-output)"
        );
    }
    let fvk = fvk_file.map(|path| parse_fvk_file(&path)).transpose()?;

    let spends = notes
        .spends
        .iter()
        .enumerate()
        .map(|(i, spend)| parse_spend(spend, &format!("spend {i}"), fvk.as_ref()))
        .collect::<Result<Vec<_>>>()?;
    let outputs = notes
        .outputs
        .iter()
        .enumerate()
        .map(|(i, output)| parse_output(output, &format!("output {i}")))
        .collect::<Result<Vec<_>>>()?;

    let map = psbt
        .add_shielded_spends(&spends, &outputs, &anchor, OsRng)
        .map_err(|e| anyhow!("failed to add the shielded spends: {e}"))?;

    // The actions are shuffled, so the later steps' --action-index arguments must come from
    // this map. It goes to stderr, keeping stdout to the PSBT hex alone.
    eprintln!(
        "{}",
        serde_json::json!({
            "spendActionIndices": map.spend_action_indices(),
            "outputActionIndices": map.output_action_indices(),
        })
    );
    print_zcash_psbt(&psbt)
}

/// One spent note. The nullifier is taken from the entry or derived locally from the note
/// plaintext under the stand-in FVK.
fn parse_spend(
    spend: &NoteSpend,
    what: &str,
    fvk: Option<&orchard::keys::FullViewingKey>,
) -> Result<IronwoodKeylessSpendSpec> {
    let recipient = parse_hex(&spend.recipient, &format!("{what} recipient"))?;
    let value = spend.value.parse(&format!("{what} value"))?;
    let rho = parse_hex(&spend.rho, &format!("{what} rho"))?;
    let rseed = parse_hex(&spend.rseed, &format!("{what} rseed"))?;
    let cmx = parse_hex(&spend.cmx, &format!("{what} cmx"))?;
    let auth_path: WitnessAuthPath = match &spend.witness.auth_path {
        AuthPath::Hashes(hashes) => auth_path_from_hashes(hashes, &format!("{what} authPath"))?,
        AuthPath::Flattened(flattened) => {
            auth_path_from_flat_hex(flattened, &format!("{what} authPath"))?
        }
    };
    let nullifier = match (&spend.nullifier, fvk) {
        (Some(nullifier), _) => parse_hex(nullifier, &format!("{what} nullifier"))?,
        (None, Some(fvk)) => derive_nullifier(fvk, &recipient, value, &rho, &rseed)
            .with_context(|| format!("{what}: deriving the nullifier locally failed"))?,
        (None, None) => bail!("{what} has no \"nullifier\"; pass --fvk-file to derive it"),
    };

    Ok(IronwoodKeylessSpendSpec {
        recipient,
        value,
        rho,
        rseed,
        cmx,
        witness: IronwoodWitness {
            position: spend.witness.position,
            auth_path,
        },
        nullifier,
    })
}

/// One requested shielded output. There is no `ovk`: the viewing-key holder owns encryption in
/// the spend flow.
fn parse_output(output: &NoteOutput, what: &str) -> Result<IronwoodOutputRequest> {
    Ok(IronwoodOutputRequest {
        recipient: parse_hex(&output.recipient, &format!("{what} recipient"))?,
        amount: output.amount.parse(&format!("{what} amount"))?,
        ovk: None,
        memo: match &output.memo {
            Some(memo) => parse_hex(memo, &format!("{what} memo"))?,
            None => zip302_no_memo(),
        },
        unified_address: output.unified_address.clone(),
    })
}

/// The nullifier of the note the plaintext describes, under the stand-in FVK — the local
/// equivalent of the viewing-key holder's `generate-nullifiers` round.
fn derive_nullifier(
    fvk: &orchard::keys::FullViewingKey,
    recipient: &[u8; 43],
    value: u64,
    rho: &[u8; 32],
    rseed: &[u8; 32],
) -> Result<[u8; 32]> {
    use orchard::bundle::BundleVersion;
    use orchard::note::{Note, RandomSeed, Rho};
    use orchard::value::NoteValue;
    use orchard::Address;

    let address = Option::<Address>::from(Address::from_raw_address_bytes(recipient))
        .context("the spend recipient is not a valid Orchard address")?;
    let rho = Option::<Rho>::from(Rho::from_bytes(rho))
        .context("the spend rho is not a canonical field element")?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(*rseed, &rho))
        .context("the spend rseed is not canonical")?;
    let note = Option::<Note>::from(Note::from_parts(
        address,
        NoteValue::from_raw(value),
        rho,
        rseed,
        BundleVersion::ironwood_v3().note_version(),
    ))
    .context("the spend plaintext does not form a valid note")?;
    Ok(note.nullifier(fvk).to_bytes())
}
