//! MuSig2 Functional API for utxolib compatibility testing
//!
//! This module contains the Functional API methods that require manual SecNonce
//! handling. These methods are kept for utxolib compatibility tests and are only
//! compiled in test mode.
//!
//! For production use, prefer the State-Machine API in the parent module which
//! provides better protection against nonce reuse.

use super::{
    p2tr_musig2_input::{
        collect_prevouts, derive_xpriv_for_input_tap, derive_xpub_for_input_tap, Musig2Context,
        Musig2Error, Musig2Input, Musig2PubNonce,
    },
    BitGoPsbt,
};
use crate::bitcoin::{
    bip32::Xpriv,
    hashes::Hash,
    key::{TapTweak, UntweakedPublicKey},
    secp256k1::{self, Parity, PublicKey},
    sighash::TapSighash,
    taproot::TapNodeHash,
};
use crate::fixed_script_wallet::RootWalletKeys;
use musig2::{secp::Point, PubNonce};

/// Helper function to create a MuSig2 context for an input (minimal validation)
///
/// This is a lightweight helper for test utilities that:
/// 1. Checks the PSBT is BitcoinLike (not Zcash)
/// 2. Creates a Musig2Context
///
/// # Note
/// This function performs minimal validation. It's designed for test utilities
/// where the PSBT structure is already known to be valid.
fn musig2_context_unchecked<'a>(
    bitgo_psbt: &'a mut BitGoPsbt,
    input_index: usize,
) -> Result<Musig2Context<'a>, String> {
    if matches!(bitgo_psbt, BitGoPsbt::Zcash(_, _)) {
        return Err("MuSig2 not supported for Zcash".to_string());
    }

    let psbt = bitgo_psbt.psbt_mut();
    Musig2Context::new(psbt, input_index).map_err(|e| e.to_string())
}

/// Generate and set a user nonce for a MuSig2 input (Functional API)
///
/// This method uses the Functional API from the musig2 crate, which requires
/// manual SecNonce handling. It's kept for utxolib compatibility tests.
///
/// This method:
/// 1. Derives the signer's key for this input from tap_key_origins
/// 2. Computes the taproot sighash
/// 3. Generates a nonce using the provided session_id
/// 4. Sets the public nonce in the PSBT proprietary fields
/// 5. Returns both nonces (secret for signing, public for exchange with counterparty)
///
/// # Arguments
/// * `ctx` - The Musig2Context for the input
/// * `xpriv` - The signer's extended private key
/// * `session_id` - 32-byte session ID (random in production, deterministic in tests)
///
/// # Returns
/// A tuple of (SecNonce, PubNonce) - keep the SecNonce secret for signing later
pub fn generate_and_set_user_nonce(
    ctx: &mut Musig2Context,
    xpriv: &Xpriv,
    session_id: [u8; 32],
) -> Result<(musig2::SecNonce, musig2::PubNonce), Musig2Error> {
    use crate::bitcoin::bip32::Xpub;
    use crate::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};

    // Derive the signer's key for this input
    let tap_key_origins = &ctx.psbt.inputs[ctx.input_index].tap_key_origins;
    let derived_xpriv = derive_xpriv_for_input_tap(xpriv, tap_key_origins)
        .map_err(|e| Musig2Error::SignatureAggregation(format!("Failed to derive xpriv: {}", e)))?;
    let secp = secp256k1::Secp256k1::new();
    let derived_xpub = Xpub::from_priv(&secp, &derived_xpriv);
    let signer_pub_key = derived_xpub.to_pub();

    // Compute sighash
    let prevouts = collect_prevouts(ctx.psbt)?;
    let mut sighash_cache = SighashCache::new(&ctx.psbt.unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            ctx.input_index,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to compute sighash: {}", e))
        })?;

    // Get tap output key for nonce generation
    let tap_output_key = ctx.musig2_input.participants.tap_output_key;
    let mut tap_output_key_bytes = vec![0x02];
    tap_output_key_bytes.extend_from_slice(&tap_output_key.serialize());
    let agg_pk = musig2::secp::Point::try_from(tap_output_key_bytes.as_slice()).map_err(|e| {
        Musig2Error::SignatureAggregation(format!("Failed to convert tap output key: {}", e))
    })?;

    // Convert secret key to scalar
    let secret_scalar = musig2::secp::Scalar::try_from(
        &derived_xpriv.private_key.secret_bytes()[..],
    )
    .map_err(|e| Musig2Error::SignatureAggregation(format!("Failed to parse secret key: {}", e)))?;

    // Generate nonce
    let (sec_nonce, pub_nonce) =
        generate_user_nonce(secret_scalar, session_id, agg_pk, &sighash, &[]);

    // Set the public nonce in the PSBT
    ctx.set_nonce(signer_pub_key, tap_output_key, pub_nonce.clone())?;

    // Return both nonces - caller keeps secret nonce for signing, sends public nonce to counterparty
    Ok((sec_nonce, pub_nonce))
}

/// Sign a MuSig2 input and set the partial signature in the PSBT (Functional API)
///
/// This method uses the Functional API from the musig2 crate, which requires
/// manual SecNonce handling. It's kept for utxolib compatibility tests.
///
/// This method:
/// 1. Derives the signer's key for this input from tap_key_origins
/// 2. Computes the taproot sighash
/// 3. Aggregates public nonces from all participants
/// 4. Creates a MuSig2 key aggregation context with taproot tweak
/// 5. Creates a partial signature using the provided secret nonce
/// 6. Sets the partial signature in the PSBT proprietary fields
///
/// # Arguments
/// * `ctx` - The Musig2Context for the input
/// * `xpriv` - The signer's extended private key
/// * `sec_nonce` - The secret nonce generated earlier for this signing session
///
/// # Returns
/// Ok(()) if the signature was successfully created and set
pub fn sign_and_set_partial_signature(
    ctx: &mut Musig2Context,
    xpriv: &Xpriv,
    sec_nonce: musig2::SecNonce,
) -> Result<(), Musig2Error> {
    use crate::bitcoin::bip32::Xpub;
    use crate::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use crate::bitcoin::taproot::TapNodeHash;
    use musig2::AggNonce;

    // Derive the signer's key for this input
    let tap_key_origins = &ctx.psbt.inputs[ctx.input_index].tap_key_origins;
    let derived_xpriv = derive_xpriv_for_input_tap(xpriv, tap_key_origins)
        .map_err(|e| Musig2Error::SignatureAggregation(format!("Failed to derive xpriv: {}", e)))?;
    let secp = secp256k1::Secp256k1::new();
    let derived_xpub = Xpub::from_priv(&secp, &derived_xpriv);
    let signer_pub_key = derived_xpub.to_pub();

    // Compute sighash
    let prevouts = collect_prevouts(ctx.psbt)?;
    let tap_merkle_root = ctx.psbt.inputs[ctx.input_index]
        .tap_merkle_root
        .unwrap_or_else(|| TapNodeHash::from_byte_array([0u8; 32]));
    let mut sighash_cache = SighashCache::new(&ctx.psbt.unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            ctx.input_index,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to compute sighash: {}", e))
        })?;
    let message = sighash.to_byte_array();

    // Aggregate nonces
    let pub_nonces = ctx.musig2_input.get_pub_nonces();
    let agg_nonce = AggNonce::sum(&pub_nonces);

    // Create key aggregation context
    let participant_keys = ctx.musig2_input.get_participant_pubkeys()?;
    let key_agg_ctx = musig2::KeyAggContext::new(participant_keys).map_err(|e| {
        Musig2Error::SignatureAggregation(format!("Failed to create key agg context: {}", e))
    })?;

    // Apply taproot tweak
    let tap_tree_root_bytes = tap_merkle_root.to_byte_array();
    let key_agg_ctx = key_agg_ctx
        .with_taproot_tweak(&tap_tree_root_bytes)
        .map_err(|e| {
            Musig2Error::SignatureAggregation(format!("Failed to apply taproot tweak: {}", e))
        })?;

    // Convert secret key to scalar
    let secret_scalar = musig2::secp::Scalar::try_from(
        &derived_xpriv.private_key.secret_bytes()[..],
    )
    .map_err(|e| Musig2Error::SignatureAggregation(format!("Failed to parse secret key: {}", e)))?;

    // Create partial signature
    let partial_sig =
        create_partial_signature(&key_agg_ctx, secret_scalar, sec_nonce, &agg_nonce, message)?;

    // Set the partial signature in the PSBT
    let tap_output_key = ctx.musig2_input.participants.tap_output_key;
    ctx.set_partial_signature(signer_pub_key, tap_output_key, partial_sig)
}

/// Generate and set a deterministic nonce for testing
///
/// This is a test-only method that generates a deterministic nonce to match
/// the behavior of test fixtures.
///
/// # Arguments
/// * `ctx` - The Musig2Context for the input
/// * `xpriv` - The signer's extended private key
/// * `counterparty_nonce` - The other party's public nonce
///
/// # Returns
/// The generated deterministic public nonce
///
/// # Note
/// This method should ONLY be used in tests.
pub fn generate_and_set_deterministic_nonce(
    ctx: &mut Musig2Context,
    xpriv: &Xpriv,
    counterparty_nonce: &musig2::PubNonce,
) -> Result<musig2::PubNonce, String> {
    use crate::bitcoin::bip32::Xpub;
    use crate::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use crate::bitcoin::taproot::TapNodeHash;

    // Derive the key for this input
    let tap_key_origins = &ctx.psbt.inputs[ctx.input_index].tap_key_origins;
    let derived_xpriv = derive_xpriv_for_input_tap(xpriv, tap_key_origins)
        .map_err(|e| format!("Failed to derive xpriv: {}", e))?;
    let secp = secp256k1::Secp256k1::new();
    let derived_xpub = Xpub::from_priv(&secp, &derived_xpriv);
    let pub_key = derived_xpub.to_pub();

    // Get tap_internal_key and tap_merkle_root
    let internal_pub_key = ctx.psbt.inputs[ctx.input_index]
        .tap_internal_key
        .ok_or_else(|| "tap_internal_key is required".to_string())?;
    let tap_merkle_root = ctx.psbt.inputs[ctx.input_index]
        .tap_merkle_root
        .unwrap_or_else(|| TapNodeHash::from_byte_array([0u8; 32]));

    // Compute sighash
    let prevouts = collect_prevouts(ctx.psbt).map_err(|e| e.to_string())?;
    let mut sighash_cache = SighashCache::new(&ctx.psbt.unsigned_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            ctx.input_index,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| format!("Failed to compute sighash: {}", e))?;

    // Generate deterministic nonce
    let pub_nonce = create_musig2_deterministic_nonce(
        &derived_xpriv.private_key,
        counterparty_nonce,
        &internal_pub_key,
        &tap_merkle_root,
        &sighash,
    )
    .map_err(|e| e.to_string())?;

    // Set the nonce in the PSBT
    let tap_output_key = ctx.musig2_input.participants.tap_output_key;
    ctx.set_nonce(pub_key, tap_output_key, pub_nonce.clone())
        .map_err(|e| e.to_string())?;

    Ok(pub_nonce)
}

/// Generate a user nonce for MuSig2 signing (Functional API)
///
/// This method uses the Functional API from the musig2 crate, which requires
/// manual SecNonce handling. It's kept for utxolib compatibility tests.
///
/// This static method generates both a secret nonce (SecNonce) and public nonce (PubNonce)
/// using the provided session_id. In production, session_id should be securely random.
/// For deterministic tests, use a fixed session_id.
///
/// # Arguments
/// * `secret_key` - The user's secret key as a scalar
/// * `session_id` - 32-byte session ID (random in production, deterministic in tests)
/// * `agg_pk` - The aggregated public key (tweaked taproot output key)
/// * `sighash` - The taproot sighash being signed
/// * `extra_input` - Optional extra randomness (use empty slice [] if not needed)
///
/// # Returns
/// A tuple of (SecNonce, PubNonce) - the secret and public nonces
pub fn generate_user_nonce(
    secret_key: musig2::secp::Scalar,
    session_id: [u8; 32],
    agg_pk: musig2::secp::Point,
    sighash: &crate::bitcoin::sighash::TapSighash,
    extra_input: &[u8],
) -> (musig2::SecNonce, PubNonce) {
    use crate::bitcoin::hashes::Hash as _;
    let message = sighash.to_byte_array();
    let sec_nonce =
        musig2::SecNonce::generate(session_id, secret_key, agg_pk, message, extra_input);
    let pub_nonce = sec_nonce.public_nonce();
    (sec_nonce, pub_nonce)
}

/// Create a partial signature for MuSig2 (Functional API)
///
/// This method uses the Functional API from the musig2 crate, which requires
/// manual SecNonce handling. It's kept for utxolib compatibility tests.
///
/// This method creates a partial signature given the secret nonce and signing parameters.
/// Both nonces (from all participants) must have been exchanged before calling this.
///
/// # Arguments
/// * `key_agg_ctx` - The key aggregation context (with taproot tweak applied)
/// * `secret_key` - The signer's secret key as a scalar
/// * `sec_nonce` - The secret nonce generated earlier
/// * `agg_nonce` - The aggregated public nonce (sum of all participants' public nonces)
/// * `message` - The message being signed (sighash)
///
/// # Returns
/// The partial signature
pub fn create_partial_signature(
    key_agg_ctx: &musig2::KeyAggContext,
    secret_key: musig2::secp::Scalar,
    sec_nonce: musig2::SecNonce,
    agg_nonce: &musig2::AggNonce,
    message: [u8; 32],
) -> Result<musig2::PartialSignature, Musig2Error> {
    musig2::sign_partial(key_agg_ctx, secret_key, sec_nonce, agg_nonce, message).map_err(|e| {
        Musig2Error::SignatureAggregation(format!("Failed to create partial signature: {:?}", e))
    })
}

/// Creates a deterministic MuSig2 nonce for a cosigner.
///
/// This implements the deterministic nonce generation algorithm from the BIP-327
/// reference implementation (see `bips/bip-0327/reference.py` function `deterministic_sign`
/// and `det_nonce_hash`), as well as the musig-js library.
///
/// This allows a cosigner to generate a nonce deterministically **after** seeing
/// other signers' nonces. This is useful for stateless cosigners that can derive
/// their nonce from the signing context without storing secret nonces.
///
/// The algorithm uses the tag `'MuSig/deterministic/nonce'` and hashes:
/// `secretKey || aggOtherNonce || aggPubKey || msgLength || msg || i`
///
/// **Security Note**: Unlike standard BIP-327 nonce generation, this approach
/// generates nonces after seeing other parties' nonces. This is safe because the
/// nonce is derived deterministically from all signing context, preventing nonce
/// reuse attacks. However, it requires that the other party has already committed
/// to their nonce before this function is called.
///
/// # Arguments
/// * `secret_key` - The signer's private key
/// * `agg_other_nonce` - Aggregate of all other signers' public nonces
/// * `internal_pub_key` - The untweaked aggregated public key (x-only, 32 bytes)
/// * `tap_tree_root` - The merkle root of the tap tree
/// * `sighash` - The taproot sighash (message to sign)
///
/// # Returns
/// The deterministic public nonce
///
/// # Reference
/// - BIP-327 reference implementation: `bips/bip-0327/reference.py`
/// - Function: `deterministic_sign()` and `det_nonce_hash()`
/// - musig-js: `deterministicSign()` function
fn create_musig2_deterministic_nonce(
    secret_key: &crate::bitcoin::secp256k1::SecretKey,
    agg_other_nonce: &PubNonce,
    internal_pub_key: &UntweakedPublicKey,
    tap_tree_root: &TapNodeHash,
    sighash: &TapSighash,
) -> Result<PubNonce, String> {
    use crate::bitcoin::hashes::{sha256, Hash as _, HashEngine};
    use musig2::secp::MaybeScalar;

    // BIP340-style tagged hash helper
    fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
        let tag_hash = sha256::Hash::hash(tag.as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag_hash.as_ref());
        engine.input(tag_hash.as_ref());
        engine.input(msg);
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    // Create tap output key (tweaked aggregated key)
    // Uses BIP341 taproot tweaking: P' = P + t*G where t = tagged_hash("TapTweak", P || merkle_root)
    let secp = secp256k1::Secp256k1::new();
    let (tweaked_key, _parity): (crate::bitcoin::key::TweakedPublicKey, Parity) =
        internal_pub_key.tap_tweak(&secp, Some(*tap_tree_root));
    let tap_output_key = tweaked_key.to_inner().serialize();

    // Serialize aggregate other nonce
    let agg_other_nonce_bytes = agg_other_nonce.serialize();

    // Get message bytes
    let msg = sighash.to_byte_array();

    // Get secret key bytes
    let secret_key_bytes = secret_key.secret_bytes();

    // Prepare message length prefix (8 bytes, big endian)
    let msg_length = (msg.len() as u64).to_be_bytes();

    // Generate two nonce pairs using the deterministic algorithm
    // This follows the BIP-327 reference implementation's det_nonce_hash() function
    let mut nonce_points = Vec::with_capacity(2);

    for i in 0u8..2 {
        // Compute deterministic nonce hash: det_nonce_hash(sk_, aggothernonce, aggpk, msg, i)
        // Tag: 'MuSig/deterministic/nonce'
        // Input: secretKey || aggOtherNonce || aggPubKey || msgLength || msg || i
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&secret_key_bytes);
        hash_input.extend_from_slice(&agg_other_nonce_bytes);
        hash_input.extend_from_slice(&tap_output_key);
        hash_input.extend_from_slice(&msg_length);
        hash_input.extend_from_slice(&msg);
        hash_input.push(i);

        let k_hash = tagged_hash("MuSig/deterministic/nonce", &hash_input);

        // Reduce hash to scalar mod n: k = det_nonce_hash(...) % n
        let k_scalar = MaybeScalar::from_slice(&k_hash)
            .map_err(|e| format!("Failed to create scalar from hash: {}", e))?;

        // Convert scalar to bytes for SecretKey
        let k_bytes = k_scalar.serialize();

        // Check for zero scalar (cannot occur except with negligible probability)
        let zero_bytes = [0u8; 32];
        if k_bytes == zero_bytes {
            return Err("Generated zero scalar for nonce".to_string());
        }

        // Compute public nonce point: R = k * G
        let nonce_secret = crate::bitcoin::secp256k1::SecretKey::from_slice(&k_bytes)
            .map_err(|e| format!("Failed to create secret key from scalar: {}", e))?;

        let nonce_public = PublicKey::from_secret_key(&secp, &nonce_secret);

        // Convert to Point for PubNonce
        let nonce_point = Point::try_from(&nonce_public.serialize()[..])
            .map_err(|e| format!("Failed to convert nonce to Point: {}", e))?;

        nonce_points.push(nonce_point);
    }

    // Create PubNonce from the two points
    Ok(PubNonce::new(nonce_points[0], nonce_points[1]))
}

/// Generate and set a deterministic nonce for testing (top-level wrapper)
///
/// This is a test-only convenience function that creates a Musig2Context
/// and calls the generate_and_set_deterministic_nonce method.
///
/// # Arguments
/// * `bitgo_psbt` - The PSBT to modify
/// * `input_index` - The index of the MuSig2 input
/// * `xpriv` - The signer's extended private key
/// * `counterparty_nonce` - The other party's public nonce
///
/// # Returns
/// The generated deterministic public nonce
///
/// # Note
/// This function should ONLY be used in tests.
pub fn generate_and_set_deterministic_nonce_from_psbt(
    bitgo_psbt: &mut BitGoPsbt,
    input_index: usize,
    xpriv: &crate::bitcoin::bip32::Xpriv,
    counterparty_nonce: &musig2::PubNonce,
) -> Result<musig2::PubNonce, String> {
    let mut ctx = musig2_context_unchecked(bitgo_psbt, input_index)?;
    generate_and_set_deterministic_nonce(&mut ctx, xpriv, counterparty_nonce)
        .map_err(|e| e.to_string())
}

/// Set nonces for both participants (user and BitGo) in a MuSig2 transaction,
/// simulating a round trip with the BitGo HSM.
///
/// This function generates and sets nonces for both the user and BitGo signers,
/// then verifies they match the expected fixture nonces.
///
/// # Arguments
/// * `user_xpriv` - User's extended private key
/// * `bitgo_xpriv` - BitGo's extended private key  
/// * `wallet_keys` - Root wallet keys for derivation
/// * `unsigned_bitgo_psbt` - Unsigned PSBT (will be mutated to add nonces)
/// * `expected_nonces_fixture` - Expected nonces from test fixture for verification
/// * `input_index` - Index of the MuSig2 input
///
/// # Returns
/// The user's secret nonce (needed for signing later)
pub fn set_nonce_musig2(
    user_xpriv: &crate::bitcoin::bip32::Xpriv,
    bitgo_xpriv: &crate::bitcoin::bip32::Xpriv,
    wallet_keys: &RootWalletKeys,
    unsigned_bitgo_psbt: &mut BitGoPsbt,
    expected_nonces_fixture: &[Musig2PubNonce],
    input_index: usize,
) -> Result<musig2::SecNonce, String> {
    // Get derived public keys for verification
    let psbt = unsigned_bitgo_psbt.clone().into_psbt();
    let tap_key_origins = &psbt.inputs[input_index].tap_key_origins;
    let derived_user_pub_key =
        derive_xpub_for_input_tap(wallet_keys.user_key(), tap_key_origins)?.to_pub();
    let derived_bitgo_pub_key =
        derive_xpub_for_input_tap(wallet_keys.bitgo_key(), tap_key_origins)?.to_pub();

    // Step 1: Generate and set user nonce using Functional API
    // Use deterministic session_id for reproducible tests (production should use random)
    let deterministic_session_id = [0u8; 32];
    let (user_sec_nonce, user_pub_nonce) = generate_and_set_user_nonce_from_psbt(
        unsigned_bitgo_psbt,
        input_index,
        user_xpriv,
        deterministic_session_id,
    )?;

    // Step 2: Generate and set BitGo nonce using deterministic test utility
    // This matches the behavior of the TypeScript test fixtures
    let bitgo_pub_nonce = generate_and_set_deterministic_nonce_from_psbt(
        unsigned_bitgo_psbt,
        input_index,
        bitgo_xpriv,
        &user_pub_nonce,
    )?;

    // Verify nonces match the expected fixture
    assert_eq!(
        expected_nonces_fixture.len(),
        2,
        "Expected 2 nonces in fixture"
    );

    let user_fixture_nonce = expected_nonces_fixture
        .iter()
        .find(|n| n.participant_pub_key == derived_user_pub_key)
        .expect("Failed to find user nonce in fixture");
    let bitgo_fixture_nonce = expected_nonces_fixture
        .iter()
        .find(|n| n.participant_pub_key == derived_bitgo_pub_key)
        .expect("Failed to find BitGo nonce in fixture");

    assert_eq!(
        user_pub_nonce.serialize(),
        user_fixture_nonce.pub_nonce.serialize(),
        "User nonce mismatch"
    );
    assert_eq!(
        bitgo_pub_nonce.serialize(),
        bitgo_fixture_nonce.pub_nonce.serialize(),
        "BitGo nonce mismatch"
    );

    Ok(user_sec_nonce)
}

/// Sign a MuSig2 input with the user's key and verify against expected signature
///
/// This function signs a MuSig2 input that already has nonces set, then verifies
/// the generated signature matches the expected fixture signature.
///
/// # Arguments
/// * `user_xpriv` - User's extended private key
/// * `user_sec_nonce` - User's secret nonce (from nonce generation step)
/// * `wallet_keys` - Root wallet keys for derivation
/// * `nonce_set_psbt` - PSBT with nonces already set (will be mutated to add signature)
/// * `expected_halfsigned_input` - Expected input state after user signing
/// * `input_index` - Index of the MuSig2 input
pub fn assert_half_sign_musig2(
    user_xpriv: &crate::bitcoin::bip32::Xpriv,
    user_sec_nonce: musig2::SecNonce,
    wallet_keys: &RootWalletKeys,
    nonce_set_psbt: &mut BitGoPsbt,
    expected_halfsigned_input: &Musig2Input,
    input_index: usize,
) -> Result<(), String> {
    // Get derived user public key for verification
    let psbt = nonce_set_psbt.clone().into_psbt();
    let tap_key_origins = &psbt.inputs[input_index].tap_key_origins;
    let derived_user_pub_key =
        derive_xpub_for_input_tap(wallet_keys.user_key(), tap_key_origins)?.to_pub();

    // Sign with user key using Functional API
    sign_musig2_input_from_psbt(nonce_set_psbt, input_index, user_xpriv, user_sec_nonce)?;

    // Verify the signed PSBT matches the expected halfsigned fixture
    let signed_psbt = nonce_set_psbt.clone().into_psbt();
    let signed_musig2_input = Musig2Input::from_input(&signed_psbt.inputs[input_index])
        .expect("Failed to parse signed Musig2 input");

    // Check that we have the user's partial signature and it matches the fixture
    let actual_user_partial_sig = signed_musig2_input
        .partial_sigs
        .iter()
        .find(|s| s.participant_pub_key == derived_user_pub_key)
        .expect("Failed to find user partial signature");

    let expected_user_partial_sig = expected_halfsigned_input
        .partial_sigs
        .iter()
        .find(|s| s.participant_pub_key == derived_user_pub_key)
        .expect("Failed to find expected user partial signature");

    assert_eq!(
        actual_user_partial_sig.partial_sig, expected_user_partial_sig.partial_sig,
        "User partial signature mismatch"
    );

    Ok(())
}

/// Set nonces and sign a MuSig2 keypath input with the user's key using Functional API
///
/// This is the utxolib-compatible test variant that uses the Functional API and validates
/// against fixtures. It combines nonce generation for both participants and user signing
/// in one call, verifying results match expected fixtures.
///
/// # Arguments
/// * `xpriv_triple` - Triple of extended private keys (user, backup, BitGo)
/// * `unsigned_bitgo_psbt` - Unsigned PSBT (will be mutated to add nonces and signature)
/// * `halfsigned_bitgo_psbt` - Expected halfsigned PSBT for verification
/// * `input_index` - Index of the MuSig2 input
pub fn assert_set_nonce_and_sign_musig2_keypath_utxolib(
    xpriv_triple: &crate::fixed_script_wallet::test_utils::fixtures::XprvTriple,
    unsigned_bitgo_psbt: &mut BitGoPsbt,
    halfsigned_bitgo_psbt: &BitGoPsbt,
    input_index: usize,
) -> Result<(), String> {
    // Verify this is actually a MuSig2 input by checking for proprietary keys
    let is_musig2 = match unsigned_bitgo_psbt {
        BitGoPsbt::BitcoinLike(psbt, _) => Musig2Input::is_musig2_input(&psbt.inputs[input_index]),
        BitGoPsbt::Dash(dash_psbt, _) => {
            Musig2Input::is_musig2_input(&dash_psbt.psbt.inputs[input_index])
        }
        BitGoPsbt::Zcash(_, _) => false,
    };

    if !is_musig2 {
        return Err(format!(
            "Expected MuSig2 input at index {} but found non-MuSig2 taproot input",
            input_index
        ));
    }

    // Parse expected fixture data
    let halfsigned_psbt = halfsigned_bitgo_psbt.clone().into_psbt();
    let expected_halfsigned_input = Musig2Input::from_input(&halfsigned_psbt.inputs[input_index])
        .expect("Failed to parse half-signed Musig2 input");

    let expected_nonces = &expected_halfsigned_input.nonces;
    let wallet_keys = &xpriv_triple.to_root_wallet_keys();

    // Step 1: Set nonces for both participants (Functional API)
    let user_sec_nonce = set_nonce_musig2(
        xpriv_triple.user_key(),
        xpriv_triple.bitgo_key(),
        wallet_keys,
        unsigned_bitgo_psbt,
        expected_nonces,
        input_index,
    )?;

    // Step 2: Sign with user key (Functional API)
    assert_half_sign_musig2(
        xpriv_triple.user_key(),
        user_sec_nonce,
        wallet_keys,
        unsigned_bitgo_psbt,
        &expected_halfsigned_input,
        input_index,
    )?;

    Ok(())
}

// Helper wrapper functions for BitGoPsbt

/// Generate and set a user nonce for a MuSig2 input (Functional API, BitGoPsbt wrapper)
pub fn generate_and_set_user_nonce_from_psbt(
    bitgo_psbt: &mut BitGoPsbt,
    input_index: usize,
    xpriv: &Xpriv,
    session_id: [u8; 32],
) -> Result<(musig2::SecNonce, musig2::PubNonce), String> {
    let mut ctx = musig2_context_unchecked(bitgo_psbt, input_index)?;
    generate_and_set_user_nonce(&mut ctx, xpriv, session_id).map_err(|e| e.to_string())
}

/// Sign a MuSig2 input with the user's key (Functional API, BitGoPsbt wrapper)
pub fn sign_musig2_input_from_psbt(
    bitgo_psbt: &mut BitGoPsbt,
    input_index: usize,
    xpriv: &Xpriv,
    sec_nonce: musig2::SecNonce,
) -> Result<(), String> {
    let mut ctx = musig2_context_unchecked(bitgo_psbt, input_index)?;

    // Check that we have both nonces
    if ctx.musig2_input.nonces.len() < 2 {
        return Err(format!(
            "Need 2 nonces to sign, but only have {}",
            ctx.musig2_input.nonces.len()
        ));
    }

    sign_and_set_partial_signature(&mut ctx, xpriv, sec_nonce).map_err(|e| e.to_string())
}
