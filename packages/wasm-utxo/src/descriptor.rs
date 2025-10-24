use crate::error::WasmMiniscriptError;
use crate::try_into_js_value::TryIntoJsValue;
use miniscript::bitcoin::secp256k1::{Secp256k1, Signing};
use miniscript::bitcoin::ScriptBuf;
use miniscript::descriptor::KeyMap;
use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey};
use std::fmt;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

pub(crate) enum WrapDescriptorEnum {
    Derivable(Descriptor<DescriptorPublicKey>, KeyMap),
    Definite(Descriptor<DefiniteDescriptorKey>),
    String(Descriptor<String>),
}

#[wasm_bindgen]
pub struct WrapDescriptor(pub(crate) WrapDescriptorEnum);

#[wasm_bindgen]
impl WrapDescriptor {
    pub fn node(&self) -> Result<JsValue, WasmMiniscriptError> {
        Ok(match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.try_to_js_value()?,
            WrapDescriptorEnum::Definite(desc) => desc.try_to_js_value()?,
            WrapDescriptorEnum::String(desc) => desc.try_to_js_value()?,
        })
    }

    #[wasm_bindgen(js_name = toString)]
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        format!("{}", self)
    }

    #[wasm_bindgen(js_name = hasWildcard)]
    pub fn has_wildcard(&self) -> bool {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.has_wildcard(),
            WrapDescriptorEnum::Definite(_) => false,
            WrapDescriptorEnum::String(_) => false,
        }
    }

    #[wasm_bindgen(js_name = atDerivationIndex)]
    pub fn at_derivation_index(&self, index: u32) -> Result<WrapDescriptor, WasmMiniscriptError> {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _keys) => {
                let d = desc.at_derivation_index(index)?;
                Ok(WrapDescriptor(WrapDescriptorEnum::Definite(d)))
            }
            _ => Err(WasmMiniscriptError::new(
                "Cannot derive from a definite descriptor",
            )),
        }
    }

    #[wasm_bindgen(js_name = descType)]
    pub fn desc_type(&self) -> Result<JsValue, WasmMiniscriptError> {
        (match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.desc_type(),
            WrapDescriptorEnum::Definite(desc) => desc.desc_type(),
            WrapDescriptorEnum::String(desc) => desc.desc_type(),
        })
        .try_to_js_value()
    }

    #[wasm_bindgen(js_name = scriptPubkey)]
    pub fn script_pubkey(&self) -> Result<Vec<u8>, WasmMiniscriptError> {
        match &self.0 {
            WrapDescriptorEnum::Definite(desc) => Ok(desc.script_pubkey().to_bytes()),
            _ => Err(WasmMiniscriptError::new(
                "Cannot encode a derivable descriptor",
            )),
        }
    }

    fn explicit_script(&self) -> Result<ScriptBuf, WasmMiniscriptError> {
        match &self.0 {
            WrapDescriptorEnum::Definite(desc) => Ok(desc.explicit_script()?),
            WrapDescriptorEnum::Derivable(_, _) => Err(WasmMiniscriptError::new(
                "Cannot encode a derivable descriptor",
            )),
            WrapDescriptorEnum::String(_) => Err(WasmMiniscriptError::new(
                "Cannot encode a string descriptor",
            )),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WasmMiniscriptError> {
        Ok(self.explicit_script()?.to_bytes())
    }

    #[wasm_bindgen(js_name = toAsmString)]
    pub fn to_asm_string(&self) -> Result<String, WasmMiniscriptError> {
        Ok(self.explicit_script()?.to_asm_string())
    }

    #[wasm_bindgen(js_name = maxWeightToSatisfy)]
    pub fn max_weight_to_satisfy(&self) -> Result<u32, WasmMiniscriptError> {
        let weight = (match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => desc.max_weight_to_satisfy(),
            WrapDescriptorEnum::Definite(desc) => desc.max_weight_to_satisfy(),
            WrapDescriptorEnum::String(desc) => desc.max_weight_to_satisfy(),
        })?;
        weight
            .to_wu()
            .try_into()
            .map_err(|_| WasmMiniscriptError::new("Weight exceeds u32"))
    }

    fn from_string_derivable<C: Signing>(
        secp: &Secp256k1<C>,
        descriptor: &str,
    ) -> Result<WrapDescriptor, WasmMiniscriptError> {
        let (desc, keys) = Descriptor::parse_descriptor(secp, descriptor)?;
        Ok(WrapDescriptor(WrapDescriptorEnum::Derivable(desc, keys)))
    }

    fn from_string_definite(descriptor: &str) -> Result<WrapDescriptor, WasmMiniscriptError> {
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(descriptor)?;
        Ok(WrapDescriptor(WrapDescriptorEnum::Definite(desc)))
    }

    /// Parse a descriptor string with an explicit public key type.
    ///
    /// Note that this function permits parsing a non-derivable descriptor with a derivable key type.
    /// Use `from_string_detect_type` to automatically detect the key type.
    ///
    /// # Arguments
    /// * `descriptor` - A string containing the descriptor to parse
    /// * `pk_type` - The type of public key to expect:
    ///   - "derivable": For descriptors containing derivation paths (eg. xpubs)
    ///   - "definite": For descriptors with fully specified keys
    ///   - "string": For descriptors with string placeholders
    ///
    /// # Returns
    /// * `Result<WrapDescriptor, WasmMiniscriptError>` - The parsed descriptor or an error
    ///
    /// # Example
    /// ```
    /// let desc = WrapDescriptor::from_string(
    ///   "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/*)",
    ///   "derivable"
    /// );
    /// ```
    #[wasm_bindgen(js_name = fromString, skip_typescript)]
    pub fn from_string(
        descriptor: &str,
        pk_type: &str,
    ) -> Result<WrapDescriptor, WasmMiniscriptError> {
        match pk_type {
            "derivable" => WrapDescriptor::from_string_derivable(&Secp256k1::new(), descriptor),
            "definite" => WrapDescriptor::from_string_definite(descriptor),
            "string" => {
                let desc = Descriptor::<String>::from_str(descriptor)?;
                Ok(WrapDescriptor(WrapDescriptorEnum::String(desc)))
            }
            _ => Err(WasmMiniscriptError::new("Invalid descriptor type")),
        }
    }

    /// Parse a descriptor string, automatically detecting the appropriate public key type.
    /// This will check if the descriptor contains wildcards to determine if it should be
    /// parsed as derivable or definite.
    ///
    /// # Arguments
    /// * `descriptor` - A string containing the descriptor to parse
    ///
    /// # Returns
    /// * `Result<WrapDescriptor, WasmMiniscriptError>` - The parsed descriptor or an error
    ///
    /// # Example
    /// ```
    /// // Will be parsed as definite since it has no wildcards
    /// let desc = WrapDescriptor::from_string_detect_type(
    ///   "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
    /// );
    ///
    /// // Will be parsed as derivable since it contains a wildcard (*)
    /// let desc = WrapDescriptor::from_string_detect_type(
    ///   "pk(xpub.../0/*)"
    /// );
    /// ```
    #[wasm_bindgen(js_name = fromStringDetectType, skip_typescript)]
    pub fn from_string_detect_type(
        descriptor: &str,
    ) -> Result<WrapDescriptor, WasmMiniscriptError> {
        let secp = Secp256k1::new();
        let (descriptor, _key_map) = Descriptor::parse_descriptor(&secp, descriptor)
            .map_err(|_| WasmMiniscriptError::new("Invalid descriptor"))?;
        if descriptor.has_wildcard() {
            WrapDescriptor::from_string_derivable(&secp, &descriptor.to_string())
        } else {
            WrapDescriptor::from_string_definite(&descriptor.to_string())
        }
    }
}

impl fmt::Display for WrapDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            WrapDescriptorEnum::Derivable(desc, _) => write!(f, "{}", desc),
            WrapDescriptorEnum::Definite(desc) => write!(f, "{}", desc),
            WrapDescriptorEnum::String(desc) => write!(f, "{}", desc),
        }
    }
}

impl FromStr for WrapDescriptor {
    type Err = WasmMiniscriptError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WrapDescriptor::from_string_detect_type(s)
    }
}

#[cfg(test)]
mod tests {
    use crate::WrapDescriptor;

    #[test]
    fn test_detect_type() {
        let desc = WrapDescriptor::from_string_detect_type(
            "pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
        )
        .unwrap();

        assert!(!desc.has_wildcard());
        assert!(matches!(
            desc,
            WrapDescriptor {
                0: crate::descriptor::WrapDescriptorEnum::Definite(_),
            }
        ));
    }
}
