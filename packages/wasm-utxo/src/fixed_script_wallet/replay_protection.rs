use miniscript::bitcoin::{CompressedPublicKey, ScriptBuf};

use crate::fixed_script_wallet::wallet_scripts::ScriptP2shP2pk;

#[derive(Debug, Clone)]
pub struct ReplayProtection {
    pub permitted_output_scripts: Vec<ScriptBuf>,
}

impl ReplayProtection {
    pub fn new(permitted_output_scripts: Vec<ScriptBuf>) -> Self {
        Self {
            permitted_output_scripts,
        }
    }

    /// Create from public keys by deriving P2SH-P2PK output scripts
    /// This is useful for replay protection inputs where we know the public keys
    /// but want to automatically create the corresponding output scripts
    pub fn from_public_keys(public_keys: Vec<CompressedPublicKey>) -> Self {
        let output_scripts = public_keys
            .into_iter()
            .map(|key| {
                let script = ScriptP2shP2pk::new(key);
                script.output_script()
            })
            .collect();
        Self {
            permitted_output_scripts: output_scripts,
        }
    }

    pub fn is_replay_protection_input(&self, output_script: &ScriptBuf) -> bool {
        self.permitted_output_scripts.contains(output_script)
    }
}
