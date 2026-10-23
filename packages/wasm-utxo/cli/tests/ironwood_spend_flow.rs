//! End-to-end runs of the Ironwood spend-flow subcommands against the TypeScript spend
//! fixtures' requests: build → out-ciphertexts → randomizers → signatures → proof request.
//! Local proving is left to the library's own `orchard-proving` tests.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use orchard::keys::{FullViewingKey, SpendingKey};
use serde_json::Value;

/// The wallet key the fixtures were generated with.
const SPENDING_KEY: [u8; 32] = [7u8; 32];
/// The NU6.3 testnet consensus branch id.
const BRANCH_ID: &str = "0x37a5165b";

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test/fixtures/zcash")
        .join(format!("ironwood_spend_{name}.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A fresh scratch directory holding the stand-in key files.
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wasm-utxo-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(SPENDING_KEY)).unwrap();
    std::fs::write(dir.join("sk.hex"), hex::encode(SPENDING_KEY)).unwrap();
    std::fs::write(
        dir.join("fvk.hex"),
        hex::encode(FullViewingKey::from(&sk).to_bytes()),
    )
    .unwrap();
    dir
}

fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wasm-utxo-cli"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Run a subcommand that must succeed; returns its (stdout, stderr), trimmed.
fn ok(args: &[&str], stdin: &str) -> (String, String) {
    let output = run(args, stdin);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{args:?} failed:\n{stderr}\n{stdout}"
    );
    (stdout.trim().to_string(), stderr.trim().to_string())
}

fn indices(value: &Value) -> Vec<usize> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap() as usize)
        .collect()
}

/// The empty v6 skeleton, optionally paying a transparent output.
fn skeleton(transparent_output: Option<&Value>) -> String {
    let (psbt, _) = ok(
        &[
            "psbt",
            "create-zcash-v6",
            "--network",
            "tzec",
            "--consensus-branch-id",
            BRANCH_ID,
        ],
        "",
    );
    let Some(output) = transparent_output else {
        return psbt;
    };
    ok(
        &[
            "psbt",
            "add-output",
            "-",
            "--script",
            output["script"].as_str().unwrap(),
            "--value",
            output["value"].as_str().unwrap(),
        ],
        &psbt,
    )
    .0
}

/// `add-shielded-input` from a notes file; returns the PSBT and the action map.
fn add_shielded_input(dir: &Path, psbt: &str, notes: &Value) -> (String, Value) {
    let notes_path = dir.join("notes.json");
    std::fs::write(&notes_path, notes.to_string()).unwrap();
    let (psbt, map) = ok(
        &[
            "psbt",
            "add-shielded-input",
            "-",
            "--network",
            "tzec",
            "--notes-file",
            notes_path.to_str().unwrap(),
            "--fvk-file",
            dir.join("fvk.hex").to_str().unwrap(),
        ],
        psbt,
    );
    (psbt, serde_json::from_str(&map).unwrap())
}

/// A shielded→shielded transfer through every round up to the proof request, with the
/// nullifiers derived locally from the FVK.
#[test]
fn transfer_runs_through_the_proof_request() {
    let dir = scratch_dir("transfer");
    let fvk = dir.join("fvk.hex");
    let fvk = fvk.to_str().unwrap();
    let sk = dir.join("sk.hex");
    let sk = sk.to_str().unwrap();

    let mut notes = fixture("transfer")["request"].clone();
    for spend in notes["spends"].as_array_mut().unwrap() {
        spend.as_object_mut().unwrap().remove("nullifier");
    }
    let (psbt, map) = add_shielded_input(&dir, &skeleton(None), &notes);
    let spends = indices(&map["spendActionIndices"]);
    assert_eq!(spends.len(), 2);

    let (psbt, served) = ok(
        &[
            "psbt",
            "out-ciphertexts",
            "-",
            "--network",
            "tzec",
            "--fvk-file",
            fvk,
        ],
        &psbt,
    );
    let served: Value = serde_json::from_str(&served).unwrap();
    let mut expected = indices(&map["outputActionIndices"]);
    expected.sort_unstable();
    assert_eq!(indices(&served["actionIndices"]), expected);

    let mut psbt = psbt;
    let mut alphas = Vec::new();
    for &action_index in &spends {
        let index = action_index.to_string();
        let (next, randomizer) = ok(
            &[
                "psbt",
                "set-spend-randomizer",
                "-",
                "--network",
                "tzec",
                "--action-index",
                &index,
                "--fvk-file",
                fvk,
            ],
            &psbt,
        );
        let randomizer: Value = serde_json::from_str(&randomizer).unwrap();
        alphas.push((index, randomizer["alpha"].as_str().unwrap().to_string()));
        psbt = next;
    }

    // Proving before signing fails with a typed error, before any proving work.
    let alpha_args: Vec<String> = alphas
        .iter()
        .map(|(index, alpha)| format!("{index}:{alpha}"))
        .collect();
    let mut prove_args = vec!["psbt", "prove", "-", "--network", "tzec", "--request"];
    for alpha in &alpha_args {
        prove_args.extend(["--alpha", alpha]);
    }
    let unsigned = run(&prove_args, &psbt);
    assert!(!unsigned.status.success());

    for (index, alpha) in &alphas {
        psbt = ok(
            &[
                "psbt",
                "add-spend-signature",
                "-",
                "--network",
                "tzec",
                "--action-index",
                index,
                "--alpha",
                alpha,
                "--sk-file",
                sk,
            ],
            &psbt,
        )
        .0;
    }

    let (request, _) = ok(&prove_args, &psbt);
    assert!(!hex::decode(request).unwrap().is_empty());

    // A proof request without the alphas is rejected: the PSBT never stores them.
    let missing = run(
        &["psbt", "prove", "-", "--network", "tzec", "--request"],
        &psbt,
    );
    assert!(!missing.status.success());

    let (parsed, _) = ok(
        &["psbt", "parse", "-", "--network", "tzec", "--no-color"],
        &psbt,
    );
    assert!(parsed.contains("ready_for_proof"));
    assert!(parsed.contains("installed"));
}

/// A deshield has no shielded outputs: the ciphertext round passes the PSBT through unchanged.
#[test]
fn deshield_out_ciphertexts_passes_through() {
    let dir = scratch_dir("deshield");
    let fixture = fixture("deshield");
    let skeleton = skeleton(Some(&fixture["request"]["transparentOutput"]));
    let (psbt, map) = add_shielded_input(&dir, &skeleton, &fixture["request"]);
    assert!(indices(&map["outputActionIndices"]).is_empty());

    let (unchanged, served) = ok(
        &[
            "psbt",
            "out-ciphertexts",
            "-",
            "--network",
            "tzec",
            "--fvk-file",
            dir.join("fvk.hex").to_str().unwrap(),
        ],
        &psbt,
    );
    assert_eq!(unchanged, psbt);
    let served: Value = serde_json::from_str(&served).unwrap();
    assert!(indices(&served["actionIndices"]).is_empty());
}

/// The signer flags are mutually exclusive, and `--alpha` only goes with `--sk-file`.
#[test]
fn add_spend_signature_rejects_mixed_signer_flags() {
    let base = [
        "psbt",
        "add-spend-signature",
        "-",
        "--network",
        "tzec",
        "--action-index",
        "0",
    ];
    let signature = "00".repeat(64);
    let alpha = "01".repeat(32);
    for extra in [
        vec!["--signature", signature.as_str(), "--alpha", alpha.as_str()],
        vec!["--sk-file", "sk.hex"],
        vec![],
    ] {
        let args: Vec<&str> = base.iter().copied().chain(extra).collect();
        let output = run(&args, "");
        assert!(!output.status.success(), "{args:?} should be rejected");
    }
}
