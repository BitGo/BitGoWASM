use crate::error::WasmUtxoError;
use js_sys::Array;
use miniscript::bitcoin::hashes::{hash160, ripemd160};
use miniscript::bitcoin::psbt::{Input, SigningKeys, SigningKeysMap};
use miniscript::bitcoin::{PublicKey, XOnlyPublicKey};
use miniscript::descriptor::{DescriptorType, ShInner, SortedMultiVec, TapTree, Tr, WshInner};
use miniscript::{
    hash256, AbsLockTime, DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, Miniscript,
    MiniscriptKey, RelLockTime, ScriptContext, Terminal, Threshold,
};
use std::sync::Arc;
use wasm_bindgen::JsValue;

pub(crate) trait TryIntoJsValue {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError>;
}

macro_rules! js_obj {
    ( $( $key:expr => $value:expr ),* ) => {{
        let obj = js_sys::Object::new();
        $(
            js_sys::Reflect::set(&obj, &$key.into(), &$value.try_to_js_value()?.into())
                .map_err(|_| WasmUtxoError::new("Failed to set object property"))?;
        )*
        Ok(Into::<JsValue>::into(obj)) as Result<JsValue, WasmUtxoError>
    }};
}

macro_rules! js_arr {
    ( $( $value:expr ),* ) => {{
        let arr = js_sys::Array::new();
        $(
            arr.push(&$value.try_to_js_value()?);
        )*
        Into::<JsValue>::into(arr) as JsValue
    }};
}

impl From<WasmUtxoError> for JsValue {
    fn from(err: WasmUtxoError) -> Self {
        js_sys::Error::new(&err.to_string()).into()
    }
}

impl TryIntoJsValue for JsValue {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(self.clone())
    }
}

impl<T: TryIntoJsValue> TryIntoJsValue for Arc<T> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        self.as_ref().try_to_js_value()
    }
}

impl TryIntoJsValue for String {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_str(self))
    }
}

// array of TryToJsValue
impl<T: TryIntoJsValue> TryIntoJsValue for Vec<T> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let arr = Array::new();
        for item in self.iter() {
            arr.push(&item.try_to_js_value()?);
        }
        Ok(arr.into())
    }
}

impl<T: TryIntoJsValue> TryIntoJsValue for Option<T> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            Some(v) => v.try_to_js_value(),
            None => Ok(JsValue::NULL),
        }
    }
}

impl TryIntoJsValue for XOnlyPublicKey {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_str(&self.to_string()))
    }
}

impl TryIntoJsValue for PublicKey {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_str(&self.to_string()))
    }
}

impl TryIntoJsValue for AbsLockTime {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_f64(self.to_consensus_u32() as f64))
    }
}

impl TryIntoJsValue for RelLockTime {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_f64(self.to_consensus_u32() as f64))
    }
}

impl TryIntoJsValue for ripemd160::Hash {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_str(&self.to_string()))
    }
}

impl TryIntoJsValue for hash160::Hash {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_str(&self.to_string()))
    }
}

impl TryIntoJsValue for hash256::Hash {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_str(&self.to_string()))
    }
}

impl TryIntoJsValue for usize {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_f64(*self as f64))
    }
}

impl TryIntoJsValue for u32 {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(JsValue::from_f64(*self as f64))
    }
}

impl TryIntoJsValue for u64 {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(js_sys::BigInt::from(*self).into())
    }
}

impl TryIntoJsValue for Vec<u8> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        Ok(js_sys::Uint8Array::from(self.as_slice()).into())
    }
}

impl<T: TryIntoJsValue, const MAX: usize> TryIntoJsValue for Threshold<T, MAX> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let arr = Array::new();
        arr.push(&self.k().try_to_js_value()?);
        for v in self.iter() {
            arr.push(&v.try_to_js_value()?);
        }
        Ok(arr.into())
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue, Ctx: ScriptContext> TryIntoJsValue
    for Miniscript<Pk, Ctx>
{
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        self.node.try_to_js_value()
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue, Ctx: ScriptContext> TryIntoJsValue for Terminal<Pk, Ctx> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            Terminal::True => Ok(JsValue::TRUE),
            Terminal::False => Ok(JsValue::FALSE),
            Terminal::PkK(pk) => js_obj!("PkK" => pk),
            Terminal::PkH(pk) => js_obj!("PkH" => pk),
            Terminal::RawPkH(pkh) => js_obj!("RawPkH" => pkh),
            Terminal::After(v) => js_obj!("After" => js_obj!("absLockTime" => v)?),
            Terminal::Older(v) => js_obj!("Older" => js_obj!("relLockTime" => v)?),
            Terminal::Sha256(hash) => js_obj!("Sha256" => hash.to_string()),
            Terminal::Hash256(hash) => js_obj!("Hash256" => hash.to_string()),
            Terminal::Ripemd160(hash) => js_obj!("Ripemd160" => hash.to_string()),
            Terminal::Hash160(hash) => js_obj!("Hash160" => hash.to_string()),
            Terminal::Alt(node) => js_obj!("Alt" => node),
            Terminal::Swap(node) => js_obj!("Swap" => node),
            Terminal::Check(node) => js_obj!("Check" => node),
            Terminal::DupIf(node) => js_obj!("DupIf" => node),
            Terminal::Verify(node) => js_obj!("Verify" => node),
            Terminal::Drop(node) => js_obj!("Drop" => node),
            Terminal::NonZero(node) => js_obj!("NonZero" => node),
            Terminal::ZeroNotEqual(node) => js_obj!("ZeroNotEqual" => node),
            Terminal::AndV(a, b) => js_obj!("AndV" => js_arr!(a, b)),
            Terminal::AndB(a, b) => js_obj!("AndB" => js_arr!(a, b)),
            Terminal::AndOr(a, b, c) => js_obj!("AndOr" => js_arr!(a, b, c)),
            Terminal::OrB(a, b) => js_obj!("OrB" => js_arr!(a, b)),
            Terminal::OrD(a, b) => js_obj!("OrD" => js_arr!(a, b)),
            Terminal::OrC(a, b) => js_obj!("OrC" => js_arr!(a, b)),
            Terminal::OrI(a, b) => js_obj!("OrI" => js_arr!(a, b)),
            Terminal::Thresh(t) => js_obj!("Thresh" => t),
            Terminal::Multi(pks) => js_obj!("Multi" => pks),
            Terminal::MultiA(pks) => js_obj!("MultiA" => pks),
        }
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue, Ctx: ScriptContext> TryIntoJsValue
    for SortedMultiVec<Pk, Ctx>
{
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "k" => self.k(),
            "n" => self.n(),
            "pks" => self.pks().to_vec()
        )
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue> TryIntoJsValue for ShInner<Pk> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            ShInner::Wsh(v) => js_obj!("Wsh" => v.as_inner()),
            ShInner::Wpkh(v) => js_obj!("Wpkh" => v.as_inner()),
            ShInner::SortedMulti(v) => js_obj!("SortedMulti" => v),
            ShInner::Ms(v) => js_obj!("Ms" => v),
        }
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue> TryIntoJsValue for WshInner<Pk> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            WshInner::SortedMulti(v) => js_obj!("SortedMulti" => v),
            WshInner::Ms(v) => js_obj!("Ms" => v),
        }
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue> TryIntoJsValue for Tr<Pk> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let tap_tree_js: JsValue = match self.tap_tree() {
            Some(tree) => tree.try_to_js_value()?,
            None => JsValue::NULL,
        };
        Ok(js_arr!(self.internal_key(), tap_tree_js))
    }
}

use super::recursive_tap_tree::RecursiveTapTree;

impl<Pk: MiniscriptKey + TryIntoJsValue> TryIntoJsValue for RecursiveTapTree<Pk> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            RecursiveTapTree::Tree { left, right } => js_obj!("Tree" => js_arr!(left, right)),
            RecursiveTapTree::Leaf(ms) => ms.try_to_js_value(),
        }
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue> TryIntoJsValue for TapTree<Pk>
where
    Pk: Clone,
{
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        RecursiveTapTree::try_from(self)?.try_to_js_value()
    }
}

impl TryIntoJsValue for DescriptorPublicKey {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            DescriptorPublicKey::Single(_v) => js_obj!("Single" => self.to_string()),
            DescriptorPublicKey::XPub(_v) => js_obj!("XPub" => self.to_string()),
            DescriptorPublicKey::MultiXPub(_v) => js_obj!("MultiXPub" => self.to_string()),
        }
    }
}

impl TryIntoJsValue for DefiniteDescriptorKey {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        self.as_descriptor_public_key().try_to_js_value()
    }
}

impl<Pk: MiniscriptKey + TryIntoJsValue> TryIntoJsValue for Descriptor<Pk> {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            Descriptor::Bare(v) => js_obj!("Bare" => v.as_inner()),
            Descriptor::Pkh(v) => js_obj!("Pkh" => v.as_inner()),
            Descriptor::Wpkh(v) => js_obj!("Wpkh" => v.as_inner()),
            Descriptor::Sh(v) => js_obj!("Sh" => v.as_inner()),
            Descriptor::Wsh(v) => js_obj!("Wsh" => v.as_inner()),
            Descriptor::Tr(v) => js_obj!("Tr" => v),
        }
    }
}

impl TryIntoJsValue for DescriptorType {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let str_from_enum = format!("{:?}", self);
        Ok(JsValue::from_str(&str_from_enum))
    }
}

impl TryIntoJsValue for SigningKeys {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        match self {
            SigningKeys::Ecdsa(v) => {
                js_obj!("Ecdsa" => v)
            }
            SigningKeys::Schnorr(v) => {
                js_obj!("Schnorr" => v)
            }
        }
    }
}

impl TryIntoJsValue for SigningKeysMap {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        let obj = js_sys::Object::new();
        for (key, value) in self.iter() {
            js_sys::Reflect::set(&obj, &key.to_string().into(), &value.try_to_js_value()?)
                .map_err(|_| WasmUtxoError::new("Failed to set object property"))?;
        }
        Ok(obj.into())
    }
}

impl TryIntoJsValue for crate::fixed_script_wallet::bitgo_psbt::ScriptId {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "chain" => self.chain,
            "index" => self.index
        )
    }
}

impl TryIntoJsValue for crate::fixed_script_wallet::bitgo_psbt::InputScriptType {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::InputScriptType;
        let script_type = match self {
            InputScriptType::P2shP2pk => "p2shP2pk",
            InputScriptType::P2sh => "p2sh",
            InputScriptType::P2shP2wsh => "p2shP2wsh",
            InputScriptType::P2wsh => "p2wsh",
            InputScriptType::P2trLegacy => "p2trLegacy",
            InputScriptType::P2trMusig2ScriptPath => "p2trMusig2ScriptPath",
            InputScriptType::P2trMusig2KeyPath => "p2trMusig2KeyPath",
        };
        Ok(JsValue::from_str(script_type))
    }
}

impl TryIntoJsValue for crate::fixed_script_wallet::bitgo_psbt::ParsedInput {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "previousOutput" => js_obj!("txid" => self.previous_output.txid.to_string(), "vout" => self.previous_output.vout)?,
            "address" => self.address.clone(),
            "value" => self.value,
            "scriptId" => self.script_id,
            "scriptType" => self.script_type,
            "sequence" => self.sequence
        )
    }
}

impl TryIntoJsValue for crate::fixed_script_wallet::bitgo_psbt::ParsedOutput {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "address" => self.address.clone(),
            "script" => self.script.clone(),
            "value" => self.value,
            "scriptId" => self.script_id
        )
    }
}

impl TryIntoJsValue for crate::fixed_script_wallet::bitgo_psbt::ParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "inputs" => self.inputs.clone(),
            "outputs" => self.outputs.clone(),
            "spendAmount" => self.spend_amount,
            "minerFee" => self.miner_fee,
            "virtualSize" => self.virtual_size
        )
    }
}

impl TryIntoJsValue for crate::inscriptions::TapLeafScript {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "leafVersion" => self.leaf_version as u32,
            "script" => self.script.clone(),
            "controlBlock" => self.control_block.clone()
        )
    }
}

impl TryIntoJsValue for crate::inscriptions::InscriptionRevealData {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "outputScript" => self.output_script.clone(),
            "revealTransactionVSize" => self.reveal_transaction_vsize as u32,
            "tapLeafScript" => self.tap_leaf_script.clone()
        )
    }
}

/// A partial signature with its associated public key
#[derive(Clone)]
pub struct PartialSignature {
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl TryIntoJsValue for PartialSignature {
    fn try_to_js_value(&self) -> Result<JsValue, WasmUtxoError> {
        js_obj!(
            "pubkey" => self.pubkey.clone(),
            "signature" => self.signature.clone()
        )
    }
}

/// Collect all partial signatures from a PSBT input
///
/// This helper function extracts ECDSA, Taproot script path, and Taproot key path
/// signatures from a PSBT input and returns them as a vector of PartialSignature structs.
pub fn collect_partial_signatures(input: &Input) -> Vec<PartialSignature> {
    let mut signatures = Vec::new();

    // Add ECDSA partial signatures
    for (pubkey, sig) in &input.partial_sigs {
        signatures.push(PartialSignature {
            pubkey: pubkey.to_bytes(),
            signature: sig.signature.serialize_der().to_vec(),
        });
    }

    // Add taproot script path signatures
    for ((xonly_pubkey, _leaf_hash), sig) in &input.tap_script_sigs {
        signatures.push(PartialSignature {
            pubkey: xonly_pubkey.serialize().to_vec(),
            signature: sig.signature.serialize().to_vec(),
        });
    }

    // Add taproot key path signature if present
    if let Some(sig) = &input.tap_key_sig {
        if let Some(tap_internal_key) = &input.tap_internal_key {
            signatures.push(PartialSignature {
                pubkey: tap_internal_key.serialize().to_vec(),
                signature: sig.signature.serialize().to_vec(),
            });
        }
    }

    signatures
}
