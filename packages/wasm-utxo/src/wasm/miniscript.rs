use crate::error::WasmUtxoError;
use crate::wasm::try_from_js_value::get_field;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use miniscript::bitcoin::{PublicKey, XOnlyPublicKey};
use miniscript::miniscript::analyzable::ExtParams;
use miniscript::{bitcoin, Legacy, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Tap, Terminal};
use std::fmt;
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

// Define the macro to simplify operations on WrapMiniscriptEnum variants
// apply a func to the miniscript variant
macro_rules! unwrap_apply {
    ($self:expr, |$ms:ident| $func:expr) => {
        match $self {
            WrapMiniscriptEnum::Tap($ms) => $func,
            WrapMiniscriptEnum::Segwit($ms) => $func,
            WrapMiniscriptEnum::Legacy($ms) => $func,
        }
    };
}

pub enum WrapMiniscriptEnum {
    Tap(Miniscript<XOnlyPublicKey, Tap>),
    Segwit(Miniscript<PublicKey, Segwitv0>),
    Legacy(Miniscript<PublicKey, Legacy>),
}

#[wasm_bindgen]
pub struct WrapMiniscript(WrapMiniscriptEnum);

#[wasm_bindgen]
impl WrapMiniscript {
    #[wasm_bindgen(js_name = node)]
    pub fn node(&self) -> Result<JsValue, WasmUtxoError> {
        unwrap_apply!(&self.0, |ms| ms.try_to_js_value())
    }

    #[wasm_bindgen(js_name = toString)]
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    #[wasm_bindgen(js_name = encode)]
    pub fn encode(&self) -> Vec<u8> {
        unwrap_apply!(&self.0, |ms| ms.encode().into_bytes())
    }

    #[wasm_bindgen(js_name = toAsmString)]
    pub fn to_asm_string(&self) -> Result<String, WasmUtxoError> {
        unwrap_apply!(&self.0, |ms| Ok(ms.encode().to_asm_string()))
    }

    #[wasm_bindgen(js_name = fromString, skip_typescript)]
    pub fn from_string(script: &str, context_type: &str) -> Result<WrapMiniscript, WasmUtxoError> {
        match context_type {
            "tap" => Ok(WrapMiniscript::from(
                Miniscript::<XOnlyPublicKey, Tap>::from_str(script).map_err(WasmUtxoError::from)?,
            )),
            "segwitv0" => {
                let miniscript = Miniscript::<PublicKey, Segwitv0>::from_str(script)
                    .map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            "legacy" => {
                let miniscript =
                    Miniscript::<PublicKey, Legacy>::from_str(script).map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            _ => Err(WasmUtxoError::new("Invalid context type")),
        }
    }

    #[wasm_bindgen(js_name = fromBitcoinScript, skip_typescript)]
    pub fn from_bitcoin_script(
        script: &[u8],
        context_type: &str,
    ) -> Result<WrapMiniscript, WasmUtxoError> {
        let script = bitcoin::Script::from_bytes(script);
        match context_type {
            "tap" => Ok(WrapMiniscript::from(
                Miniscript::<XOnlyPublicKey, Tap>::decode(script).map_err(WasmUtxoError::from)?,
            )),
            "segwitv0" => {
                let miniscript = Miniscript::<PublicKey, Segwitv0>::decode(script)
                    .map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            "legacy" => {
                let miniscript =
                    Miniscript::<PublicKey, Legacy>::decode(script).map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            _ => Err(WasmUtxoError::new("Invalid context type")),
        }
    }

    #[wasm_bindgen(js_name = fromStringExt, skip_typescript)]
    pub fn from_string_ext(
        script: &str,
        context_type: &str,
        ext_params_config: JsValue,
    ) -> Result<WrapMiniscript, WasmUtxoError> {
        let allow_drop = context_type == "tap";
        let params = build_ext_params(&ext_params_config, allow_drop)?;
        match context_type {
            "tap" => Ok(WrapMiniscript::from(
                Miniscript::<XOnlyPublicKey, Tap>::from_str_ext(script, &params)
                    .map_err(WasmUtxoError::from)?,
            )),
            "segwitv0" => {
                let miniscript = Miniscript::<PublicKey, Segwitv0>::from_str_ext(script, &params)
                    .map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            "legacy" => {
                let miniscript = Miniscript::<PublicKey, Legacy>::from_str_ext(script, &params)
                    .map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            _ => Err(WasmUtxoError::new("Invalid context type")),
        }
    }

    #[wasm_bindgen(js_name = fromBitcoinScriptExt, skip_typescript)]
    pub fn from_bitcoin_script_ext(
        script: &[u8],
        context_type: &str,
        ext_params_config: JsValue,
    ) -> Result<WrapMiniscript, WasmUtxoError> {
        let allow_drop = context_type == "tap";
        let params = build_ext_params(&ext_params_config, allow_drop)?;
        let script = bitcoin::Script::from_bytes(script);
        match context_type {
            "tap" => Ok(WrapMiniscript::from(
                Miniscript::<XOnlyPublicKey, Tap>::decode_with_ext(script, &params)
                    .map_err(WasmUtxoError::from)?,
            )),
            "segwitv0" => {
                let miniscript = Miniscript::<PublicKey, Segwitv0>::decode_with_ext(script, &params)
                    .map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            "legacy" => {
                let miniscript = Miniscript::<PublicKey, Legacy>::decode_with_ext(script, &params)
                    .map_err(WasmUtxoError::from)?;
                Ok(WrapMiniscript::from(check_drop_context(miniscript, false)?))
            }
            _ => Err(WasmUtxoError::new("Invalid context type")),
        }
    }
}

// The pinned fork's contains_drop() misses PayloadDrop, so validate both variants here.
fn check_drop_context<Pk: MiniscriptKey, Ctx: ScriptContext>(
    miniscript: Miniscript<Pk, Ctx>,
    allow_drop: bool,
) -> Result<Miniscript<Pk, Ctx>, WasmUtxoError> {
    if !allow_drop
        && miniscript
            .iter()
            .any(|node| matches!(node.node, Terminal::Drop(_) | Terminal::PayloadDrop(_)))
    {
        return Err(WasmUtxoError::new(
            "Drop fragments are only supported in taproot context",
        ));
    }
    Ok(miniscript)
}

fn build_ext_params(config: &JsValue, allow_drop: bool) -> Result<ExtParams, WasmUtxoError> {
    let flag = |key| -> Result<bool, WasmUtxoError> {
        if config.is_undefined() || config.is_null() {
            return Ok(false);
        }
        Ok(get_field::<Option<bool>>(config, key)?.unwrap_or(false))
    };

    let mut params = ExtParams::sane();
    if allow_drop {
        params = params.drop();
    }
    if flag("topUnsafe")? {
        params = params.top_unsafe();
    }
    if flag("resourceLimitations")? {
        params = params.exceed_resource_limitations();
    }
    if flag("timelockMixing")? {
        params = params.timelock_mixing();
    }
    if flag("malleability")? {
        params = params.malleability();
    }
    if flag("repeatedPk")? {
        params = params.repeated_pk();
    }
    if flag("rawPkh")? {
        params = params.raw_pkh();
    }
    Ok(params)
}

impl From<Miniscript<XOnlyPublicKey, Tap>> for WrapMiniscript {
    fn from(miniscript: Miniscript<XOnlyPublicKey, Tap>) -> Self {
        WrapMiniscript(WrapMiniscriptEnum::Tap(miniscript))
    }
}

impl From<Miniscript<PublicKey, Segwitv0>> for WrapMiniscript {
    fn from(miniscript: Miniscript<PublicKey, Segwitv0>) -> Self {
        WrapMiniscript(WrapMiniscriptEnum::Segwit(miniscript))
    }
}

impl From<Miniscript<PublicKey, Legacy>> for WrapMiniscript {
    fn from(miniscript: Miniscript<PublicKey, Legacy>) -> Self {
        WrapMiniscript(WrapMiniscriptEnum::Legacy(miniscript))
    }
}

impl fmt::Display for WrapMiniscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unwrap_apply!(&self.0, |ms| write!(f, "{}", ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECDSA_KEY: &str = "02ae7c3c0ebc315a33151a1985ebb1fdcae72b3b91c38e3193c40ebabfffe9c343";
    const DROP_CONTEXT_ERROR: &str = "Drop fragments are only supported in taproot context";

    fn payload_drop_script(payload_size: usize) -> String {
        format!(
            "and_v(payload_drop({}),pk({ECDSA_KEY}))",
            "00".repeat(payload_size)
        )
    }

    #[test]
    fn rejects_520_and_521_byte_payload_drops_in_segwitv0() {
        for payload_size in [520, 521] {
            let script = payload_drop_script(payload_size);
            assert!(matches!(
                WrapMiniscript::from_string(&script, "segwitv0"),
                Err(error) if error.to_string() == DROP_CONTEXT_ERROR
            ));
        }
    }

    #[test]
    fn rejects_payload_drop_after_bitcoin_script_decode() {
        let script = payload_drop_script(521);
        let miniscript = Miniscript::<PublicKey, Segwitv0>::from_str_ext(
            &script,
            &ExtParams::sane().drop(),
        )
        .expect("the fork should parse the oversized push before the context guard");
        let script = miniscript.encode().into_bytes();

        assert!(matches!(
            WrapMiniscript::from_bitcoin_script(&script, "segwitv0"),
            Err(error) if error.to_string() == DROP_CONTEXT_ERROR
        ));
    }

    #[test]
    fn rejects_drop_fragments_in_legacy_context() {
        let script = "and_v(r:after(1024),pk(02ae7c3c0ebc315a33151a1985ebb1fdcae72b3b91c38e3193c40ebabfffe9c343))";
        assert!(WrapMiniscript::from_string(script, "legacy").is_err());
    }
}
