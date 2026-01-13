//! Rust-level WASM benchmarks to drill down into BIP32 performance
//!
//! These benchmarks break down fromBase58 and fromSeed into component operations
//! to identify where time is spent.
//!
//! Run with: `wasm-pack test --node --release`

use wasm_bindgen_test::*;

const XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const XPUB: &str = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
const SEED: [u8; 32] = [1u8; 32];
const OPS: usize = 100;

use std::cell::RefCell;

thread_local! {
    static RESULTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

fn log(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

fn bench<F: FnMut()>(name: &str, ops: usize, mut f: F) {
    // Warm-up
    for _ in 0..10 {
        f();
    }

    let start = now_ms();
    for _ in 0..ops {
        f();
    }
    let elapsed = now_ms() - start;
    let ops_per_sec = (ops as f64) / (elapsed / 1000.0);

    let result = format!(
        "  {}: {:.2}ms for {} ops ({:.0} ops/sec)",
        name, elapsed, ops, ops_per_sec
    );
    log(&result);
    RESULTS.with(|r| r.borrow_mut().push(result));
}

fn dump_results(header: &str) {
    let mut output = String::from(header);
    output.push('\n');
    RESULTS.with(|r| {
        for line in r.borrow().iter() {
            output.push_str(line);
            output.push('\n');
        }
    });
    // Use panic to show results in test output
    panic!("\n{}", output);
}

fn clear_results() {
    RESULTS.with(|r| r.borrow_mut().clear());
}

/// Benchmark: Break down fromBase58(xprv) into components
#[wasm_bindgen_test]
fn bench_from_base58_xprv_breakdown() {
    use bip32::XPrv;
    use std::str::FromStr;

    clear_results();
    log("\n=== fromBase58(xprv) Breakdown ===");

    // 1. Base58 decode only
    bench("bs58 decode (with checksum)", OPS, || {
        let _ = bs58::decode(XPRV).with_check(None).into_vec().unwrap();
    });

    // 2. Parse the decoded bytes into XPrv
    bench("XPrv::from_str (full parsing)", OPS, || {
        let _ = XPrv::from_str(XPRV).unwrap();
    });

    // 3. Full fromBase58 (what we expose)
    bench("Full fromBase58(xprv)", OPS, || {
        let _ = XPrv::from_str(XPRV).unwrap();
    });

    // 4. Just creating a SigningKey from bytes (the expensive part)
    bench("SigningKey::from_slice (32 bytes)", OPS, || {
        use k256::ecdsa::SigningKey;
        let secret = [0x11u8; 32];
        let _ = SigningKey::from_slice(&secret).unwrap();
    });

    // 5. Computing public key from private key
    bench("SigningKey -> VerifyingKey", OPS, || {
        use k256::ecdsa::SigningKey;
        let secret = [0x11u8; 32];
        let sk = SigningKey::from_slice(&secret).unwrap();
        let _ = sk.verifying_key();
    });
}

/// Benchmark: Break down fromBase58(xpub) into components
#[wasm_bindgen_test]
fn bench_from_base58_xpub_breakdown() {
    use bip32::XPub;
    use std::str::FromStr;

    log("\n=== fromBase58(xpub) Breakdown ===");

    // 1. Base58 decode only
    bench("bs58 decode (with checksum)", OPS, || {
        let _ = bs58::decode(XPUB).with_check(None).into_vec().unwrap();
    });

    // 2. Full fromBase58
    bench("Full fromBase58(xpub)", OPS, || {
        let _ = XPub::from_str(XPUB).unwrap();
    });

    // 3. VerifyingKey from SEC1 bytes (point decompression)
    bench("VerifyingKey::from_sec1_bytes (33 bytes)", OPS, || {
        use k256::ecdsa::VerifyingKey;
        // Compressed public key (starts with 02 or 03)
        let compressed = [
            0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93,
            0xa0, 0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e,
            0x8f, 0xf4, 0x9c, 0x85, 0xc2,
        ];
        let _ = VerifyingKey::from_sec1_bytes(&compressed).unwrap();
    });
}

/// Benchmark: Break down fromSeed into components
#[wasm_bindgen_test]
fn bench_from_seed_breakdown() {
    use bip32::XPrv;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    log("\n=== fromSeed Breakdown ===");

    // 1. HMAC-SHA512 only
    bench("HMAC-SHA512 (seed -> 64 bytes)", OPS, || {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
        mac.update(&SEED);
        let _ = mac.finalize().into_bytes();
    });

    // 2. Full fromSeed
    bench("Full fromSeed", OPS, || {
        let _ = XPrv::new(SEED).unwrap();
    });

    // 3. SigningKey creation (called inside XPrv::new)
    bench("SigningKey::from_slice", OPS, || {
        use k256::ecdsa::SigningKey;
        let _ = SigningKey::from_slice(&SEED).unwrap();
    });
}

/// Benchmark: Derivation operations
#[wasm_bindgen_test]
fn bench_derivation_breakdown() {
    use bip32::{XPrv, XPub};
    use std::str::FromStr;

    log("\n=== Derivation Breakdown ===");

    let xprv = XPrv::from_str(XPRV).unwrap();
    let xpub = XPub::from_str(XPUB).unwrap();

    // 1. Single child derivation (private)
    bench("xprv.derive_child(0)", OPS, || {
        use bip32::ChildNumber;
        let cn = ChildNumber::new(0, false).unwrap();
        let _ = xprv.derive_child(cn).unwrap();
    });

    // 2. Single child derivation (public)
    bench("xpub.derive_child(0)", OPS, || {
        use bip32::ChildNumber;
        let cn = ChildNumber::new(0, false).unwrap();
        let _ = xpub.derive_child(cn).unwrap();
    });

    // 3. xprv -> xpub (neutered)
    bench("xprv.public_key() [neutered]", OPS, || {
        let _ = xprv.public_key();
    });

    // 4. HMAC-SHA512 (used in derivation)
    bench("HMAC-SHA512 (derivation step)", OPS, || {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let chain_code = [0u8; 32];
        let mut mac = HmacSha512::new_from_slice(&chain_code).unwrap();
        mac.update(&[0u8; 37]); // pubkey + index
        let _ = mac.finalize().into_bytes();
    });

    // 5. Scalar multiplication (the expensive EC operation)
    bench("EC point multiplication (G * scalar)", OPS, || {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::ProjectivePoint;
        use k256::Scalar;
        let scalar = Scalar::ONE;
        let point = ProjectivePoint::GENERATOR * scalar;
        let _ = point.to_affine().to_encoded_point(true);
    });

    // 6. EC point addition
    bench("EC point addition", OPS, || {
        use k256::ProjectivePoint;
        let g = ProjectivePoint::GENERATOR;
        let _ = g + g;
    });
}

/// Summary benchmark comparing full operations - outputs all results via panic
#[wasm_bindgen_test]
fn bench_full_operations_summary() {
    use bip32::{XPrv, XPub};
    use std::str::FromStr;

    clear_results();

    // === fromBase58(xprv) Breakdown ===
    RESULTS.with(|r| {
        r.borrow_mut()
            .push("\n=== fromBase58(xprv) Breakdown ===".into())
    });

    bench("bs58 decode (with checksum)", OPS, || {
        let _ = bs58::decode(XPRV).with_check(None).into_vec().unwrap();
    });

    bench("XPrv::from_str (full parsing)", OPS, || {
        let _ = XPrv::from_str(XPRV).unwrap();
    });

    bench("SigningKey::from_slice (32 bytes)", OPS, || {
        use k256::ecdsa::SigningKey;
        let secret = [0x11u8; 32];
        let _ = SigningKey::from_slice(&secret).unwrap();
    });

    bench("SigningKey -> VerifyingKey", OPS, || {
        use k256::ecdsa::SigningKey;
        let secret = [0x11u8; 32];
        let sk = SigningKey::from_slice(&secret).unwrap();
        let _ = sk.verifying_key();
    });

    // === fromBase58(xpub) Breakdown ===
    RESULTS.with(|r| {
        r.borrow_mut()
            .push("\n=== fromBase58(xpub) Breakdown ===".into())
    });

    bench("bs58 decode (with checksum)", OPS, || {
        let _ = bs58::decode(XPUB).with_check(None).into_vec().unwrap();
    });

    bench("XPub::from_str (full parsing)", OPS, || {
        let _ = XPub::from_str(XPUB).unwrap();
    });

    bench("VerifyingKey::from_sec1_bytes (33 bytes)", OPS, || {
        use k256::ecdsa::VerifyingKey;
        let compressed = [
            0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93,
            0xa0, 0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e,
            0x8f, 0xf4, 0x9c, 0x85, 0xc2,
        ];
        let _ = VerifyingKey::from_sec1_bytes(&compressed).unwrap();
    });

    // === fromSeed Breakdown ===
    RESULTS.with(|r| r.borrow_mut().push("\n=== fromSeed Breakdown ===".into()));

    bench("HMAC-SHA512 (seed -> 64 bytes)", OPS, || {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
        mac.update(&SEED);
        let _ = mac.finalize().into_bytes();
    });

    bench("Full fromSeed (XPrv::new)", OPS, || {
        let _ = XPrv::new(SEED).unwrap();
    });

    // === Derivation Breakdown ===
    RESULTS.with(|r| r.borrow_mut().push("\n=== Derivation Breakdown ===".into()));

    let xprv = XPrv::from_str(XPRV).unwrap();
    let xpub = XPub::from_str(XPUB).unwrap();

    bench("xprv.derive_child(0)", OPS, || {
        use bip32::ChildNumber;
        let cn = ChildNumber::new(0, false).unwrap();
        let _ = xprv.derive_child(cn).unwrap();
    });

    bench("xpub.derive_child(0)", OPS, || {
        use bip32::ChildNumber;
        let cn = ChildNumber::new(0, false).unwrap();
        let _ = xpub.derive_child(cn).unwrap();
    });

    bench("xprv.public_key() [neutered]", OPS, || {
        let _ = xprv.public_key();
    });

    bench("EC point multiplication (G * scalar)", OPS, || {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::ProjectivePoint;
        use k256::Scalar;
        let scalar = Scalar::ONE;
        let point = ProjectivePoint::GENERATOR * scalar;
        let _ = point.to_affine().to_encoded_point(true);
    });

    bench("EC point addition", OPS, || {
        use k256::ProjectivePoint;
        let g = ProjectivePoint::GENERATOR;
        let _ = g + g;
    });

    // === Full Operations Summary ===
    RESULTS.with(|r| {
        r.borrow_mut()
            .push("\n=== Full Operations Summary ===".into())
    });

    bench("fromBase58(xprv)", OPS, || {
        let _ = XPrv::from_str(XPRV).unwrap();
    });

    bench("fromBase58(xpub)", OPS, || {
        let _ = XPub::from_str(XPUB).unwrap();
    });

    bench("fromSeed", OPS, || {
        let _ = XPrv::new(SEED).unwrap();
    });

    bench("derivePath m/44'/0'/0'/0/0 (xprv)", OPS, || {
        use bip32::DerivationPath;
        let path: DerivationPath = "m/44'/0'/0'/0/0".parse().unwrap();
        let mut current = xprv.clone();
        for cn in path {
            current = current.derive_child(cn).unwrap();
        }
    });

    bench("derivePath 0/0/0/0/0 (xpub)", OPS, || {
        use bip32::DerivationPath;
        let path: DerivationPath = "m/0/0/0/0/0".parse().unwrap();
        let mut current = xpub.clone();
        for cn in path {
            current = current.derive_child(cn).unwrap();
        }
    });

    dump_results("BENCHMARK RESULTS");
}
