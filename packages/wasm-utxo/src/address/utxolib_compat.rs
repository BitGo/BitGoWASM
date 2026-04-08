/// Helper structs for compatibility with npm @bitgo/utxo-lib
/// Long-term we should not use the `Network` objects from @bitgo/utxo-lib any longer,
/// but for now we need to keep this compatibility layer.
use crate::address::networks::{AddressFormat, OutputScriptSupport};
use crate::address::{bech32, cashaddr, Base58CheckCodec};
use crate::bitcoin::{Script, ScriptBuf};

pub use crate::address::AddressError;

type Result<T> = std::result::Result<T, AddressError>;

pub struct CashAddr {
    pub prefix: String,
    pub pub_key_hash: u32,
    pub script_hash: u32,
}

/// This maps to the structure of `utxolib.Network` so that we can use it for address encoding/decoding.
/// We also use it to infer the output script support for the network.
///
/// We cannot precisely map it to the proper `networks::Network` enum because certain
/// different networks are structurally identical (all bitcoin testnets).
pub struct UtxolibNetwork {
    pub pub_key_hash: u32,
    pub script_hash: u32,
    pub cash_addr: Option<CashAddr>,
    pub bech32: Option<String>,
}

impl UtxolibNetwork {
    pub fn output_script_support(&self) -> OutputScriptSupport {
        let segwit = self.bech32.is_some();

        // In the context of this library, only bitcoin supports taproot
        // See output_script_support in networks.rs for detailed references
        let taproot = segwit
            && self
                .bech32
                .as_ref()
                .is_some_and(|bech32| bech32 == "bc" || bech32 == "tb");

        // P2MR not supported via utxolib compat layer (only via Network enum)
        OutputScriptSupport {
            segwit,
            taproot,
            p2mr: false,
        }
    }
}

/// Convert output script to address string using a utxolib UtxolibNetwork object
pub fn from_output_script_with_network(
    script: &Script,
    network: &UtxolibNetwork,
    format: AddressFormat,
) -> Result<String> {
    network.output_script_support().assert_support(script)?;

    // Handle cashaddr format if requested
    if matches!(format, AddressFormat::Cashaddr) {
        if let Some(ref cash_addr) = network.cash_addr {
            if script.is_p2pkh() {
                let hash = &script.as_bytes()[3..23];
                return cashaddr::encode_cashaddr(hash, false, &cash_addr.prefix);
            } else if script.is_p2sh() {
                let hash = &script.as_bytes()[2..22];
                return cashaddr::encode_cashaddr(hash, true, &cash_addr.prefix);
            }
        } else {
            return Err(AddressError::UnsupportedScriptType(
                "Cashaddr format is only supported for Bitcoin Cash and eCash networks".to_string(),
            ));
        }
    }

    // Default format: use base58check for P2PKH/P2SH
    if script.is_p2pkh() || script.is_p2sh() {
        let codec = Base58CheckCodec::new(network.pub_key_hash, network.script_hash);
        use crate::address::AddressCodec;
        codec.encode(script)
    } else if script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr() {
        // For witness scripts, use bech32 if available
        if let Some(ref hrp) = network.bech32 {
            let (witness_version, program) = bech32::extract_witness_program(script)?;
            bech32::encode_witness_with_custom_hrp(program, witness_version, hrp)
        } else {
            Err(AddressError::UnsupportedScriptType(
                "Network does not support bech32 addresses".to_string(),
            ))
        }
    } else {
        Err(AddressError::UnsupportedScriptType(format!(
            "Unsupported script type for address encoding, length: {}",
            script.len()
        )))
    }
}

/// Convert address string to output script using a utxolib UtxolibNetwork object
pub fn to_output_script_with_network(address: &str, network: &UtxolibNetwork) -> Result<ScriptBuf> {
    use crate::address::AddressCodec;
    use crate::bitcoin::hashes::Hash;
    use crate::bitcoin::{PubkeyHash, ScriptHash};

    // Try base58check first (always available)
    let base58_codec = Base58CheckCodec::new(network.pub_key_hash, network.script_hash);
    if let Ok(script) = base58_codec.decode(address) {
        return Ok(script);
    }

    // Try bech32 if available
    if let Some(ref hrp) = network.bech32 {
        if let Ok(script_bytes) = bech32::decode_witness_with_custom_hrp(address, hrp) {
            return Ok(ScriptBuf::from_bytes(script_bytes));
        }
    }

    // Try cashaddr if available
    if let Some(ref cash_addr) = network.cash_addr {
        if let Ok((hash, is_p2sh)) = cashaddr::decode_cashaddr(address, &cash_addr.prefix) {
            let hash_array: [u8; 20] = hash
                .try_into()
                .map_err(|_| AddressError::CashaddrError("Invalid hash length".to_string()))?;

            return if is_p2sh {
                let script_hash = ScriptHash::from_byte_array(hash_array);
                Ok(ScriptBuf::new_p2sh(&script_hash))
            } else {
                let pubkey_hash = PubkeyHash::from_byte_array(hash_array);
                Ok(ScriptBuf::new_p2pkh(&pubkey_hash))
            };
        }
    }

    Err(AddressError::InvalidAddress(format!(
        "Could not decode address with any available codec: {}",
        address
    )))
}
