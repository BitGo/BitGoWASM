use std::process::Command;

fn main() {
    // Extract version from package.json using proper JSON parsing
    let package_json =
        std::fs::read_to_string("package.json").expect("Failed to read package.json");

    let package: serde_json::Value =
        serde_json::from_str(&package_json).expect("Failed to parse package.json as JSON");

    let version = package
        .get("version")
        .and_then(|v| v.as_str())
        .expect("Failed to find 'version' field in package.json");

    println!("cargo:rustc-env=WASM_UTXO_VERSION={}", version);

    // Capture git commit hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=WASM_UTXO_GIT_HASH={}", git_hash);

    // Rerun if package.json changes
    println!("cargo:rerun-if-changed=package.json");
}
