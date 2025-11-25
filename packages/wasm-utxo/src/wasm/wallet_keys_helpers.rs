use std::convert::TryInto;
use std::str::FromStr;

use crate::bitcoin::bip32::DerivationPath;
use crate::error::WasmUtxoError;
use crate::fixed_script_wallet::{xpub_triple_from_strings, RootWalletKeys, XpubTriple};
use crate::wasm::bip32::WasmBIP32;
use wasm_bindgen::JsValue;

pub fn xpub_triple_from_jsvalue(keys: &JsValue) -> Result<XpubTriple, WasmUtxoError> {
    let keys_array = js_sys::Array::from(keys);
    if keys_array.length() != 3 {
        return Err(WasmUtxoError::new("Expected exactly 3 xpub keys"));
    }

    let key_strings: Result<[String; 3], _> = (0..3)
        .map(|i| {
            keys_array
                .get(i)
                .as_string()
                .ok_or_else(|| WasmUtxoError::new(&format!("Key at index {} is not a string", i)))
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|v| {
            v.try_into()
                .map_err(|_| WasmUtxoError::new("Failed to convert to array"))
        });

    xpub_triple_from_strings(&key_strings?)
}

pub fn root_wallet_keys_from_jsvalue(keys: &JsValue) -> Result<RootWalletKeys, WasmUtxoError> {
    // Check if keys is an array (xpub strings) or an object (WalletKeys/RootWalletKeys)
    if js_sys::Array::is_array(keys) {
        // Handle array of xpub strings
        let xpubs = xpub_triple_from_jsvalue(keys)?;
        Ok(RootWalletKeys::new_with_derivation_prefixes(
            xpubs,
            [
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
            ],
        ))
    } else if keys.is_object() {
        // Handle WalletKeys/RootWalletKeys object
        let obj = js_sys::Object::from(keys.clone());

        // Get the triple property
        let triple = js_sys::Reflect::get(&obj, &JsValue::from_str("triple"))
            .map_err(|_| WasmUtxoError::new("Failed to get 'triple' property"))?;

        if !js_sys::Array::is_array(&triple) {
            return Err(WasmUtxoError::new("'triple' property must be an array"));
        }

        let triple_array = js_sys::Array::from(&triple);
        if triple_array.length() != 3 {
            return Err(WasmUtxoError::new("'triple' must contain exactly 3 keys"));
        }

        // Extract xpubs from BIP32Interface objects
        let xpubs: XpubTriple = (0..3)
            .map(|i| {
                let bip32_key = triple_array.get(i);
                WasmBIP32::from_bip32_interface(&bip32_key)
                    .and_then(|wasm_bip32| wasm_bip32.to_xpub())
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| WasmUtxoError::new("Failed to convert to array"))?;

        // Try to get derivationPrefixes if present (for RootWalletKeys)
        let derivation_prefixes =
            js_sys::Reflect::get(&obj, &JsValue::from_str("derivationPrefixes"))
                .ok()
                .and_then(|prefixes| {
                    if prefixes.is_undefined() || prefixes.is_null() {
                        return None;
                    }

                    if !js_sys::Array::is_array(&prefixes) {
                        return None;
                    }

                    let prefixes_array = js_sys::Array::from(&prefixes);
                    if prefixes_array.length() != 3 {
                        return None;
                    }

                    let prefix_strings: Result<[String; 3], _> = (0..3)
                        .map(|i| {
                            prefixes_array
                                .get(i)
                                .as_string()
                                .ok_or_else(|| WasmUtxoError::new("Prefix is not a string"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .and_then(|v| {
                            v.try_into()
                                .map_err(|_| WasmUtxoError::new("Failed to convert to array"))
                        });

                    prefix_strings.ok()
                });

        // Convert prefix strings to DerivationPath
        let derivation_paths = if let Some(prefixes) = derivation_prefixes {
            prefixes
                .iter()
                .map(|p| {
                    // Remove leading 'm/' if present and add it back
                    let p = p.strip_prefix("m/").unwrap_or(p);
                    DerivationPath::from_str(&format!("m/{}", p)).map_err(|e| {
                        WasmUtxoError::new(&format!("Invalid derivation prefix: {}", e))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| WasmUtxoError::new("Failed to convert derivation paths"))?
        } else {
            [
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
                DerivationPath::from_str("m/0/0").unwrap(),
            ]
        };

        Ok(RootWalletKeys::new_with_derivation_prefixes(
            xpubs,
            derivation_paths,
        ))
    } else {
        Err(WasmUtxoError::new(
            "Expected array of xpub strings or WalletKeys object",
        ))
    }
}
