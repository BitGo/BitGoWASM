//! Types for intent-based transaction building.
//!
//! These types mirror the BitGo intent structures and are deserialized from JavaScript.

use serde::{Deserialize, Serialize};

/// Intent type discriminant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IntentType {
    Payment,
    GoUnstake,
    Stake,
    Unstake,
    Claim,
    Deactivate,
    Delegate,
    EnableToken,
    CloseAssociatedTokenAccount,
    Consolidate,
    Authorize,
    CustomTx,
}

/// Staking type for stake/unstake intents.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakingType {
    Native,
    Jito,
    Marinade,
}

/// Build parameters provided by wallet-platform.
/// These are NOT part of the intent but needed to build the transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildParams {
    /// Fee payer address (wallet root)
    pub fee_payer: String,
    /// Nonce configuration
    pub nonce: Nonce,
}

/// Nonce source for the transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Nonce {
    /// Recent blockhash (standard transactions)
    Blockhash { value: String },
    /// Durable nonce (offline signing)
    Durable {
        address: String,
        authority: String,
        value: String,
    },
}

/// Result from building a transaction from intent.
#[derive(Debug, Clone)]
pub struct IntentBuildResult {
    /// The built transaction
    pub transaction: solana_sdk::transaction::Transaction,
    /// Generated keypairs (for stake accounts, etc.)
    pub generated_keypairs: Vec<GeneratedKeypair>,
}

/// Purpose of a generated keypair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeypairPurpose {
    StakeAccount,
    UnstakeAccount,
    TransferAuthority,
}

/// Authorize type for stake account authority changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeType {
    Staker,
    Withdrawer,
}

/// A keypair generated during transaction building.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKeypair {
    /// Purpose of this keypair
    pub purpose: KeypairPurpose,
    /// Public address (base58)
    pub address: String,
    /// Secret key (base58)
    pub secret_key: String,
}

// =============================================================================
// Intent Types (match BitGo public-types shapes)
// =============================================================================

/// Base intent - all intents have intentType
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseIntent {
    pub intent_type: String,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Recipient for payment intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    pub address: Option<AddressWrapper>,
    pub amount: Option<AmountWrapper>,
    /// Mint address (base58) — if set, this is an SPL token transfer
    #[serde(default)]
    pub token_address: Option<String>,
    /// Token program ID (defaults to SPL Token Program)
    #[serde(default)]
    pub token_program_id: Option<String>,
    /// Decimal places for the token (required for transfer_checked)
    #[serde(default)]
    pub decimal_places: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressWrapper {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmountWrapper {
    /// Non-negative amount value (deserialized as u64)
    #[serde(deserialize_with = "deserialize_amount")]
    pub value: u64,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// The remaining-balance state used to decide whether an unstake can be split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemainingStakingAmountValue {
    /// The service reported a non-negative remaining balance.
    Amount(u64),
    /// The requested unstake exceeds the current balance.
    ExceedsBalance,
}

/// Remaining balance wrapper; negative values are compatibility signals here only.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemainingStakingAmount {
    #[serde(deserialize_with = "deserialize_remaining_staking_amount")]
    pub value: RemainingStakingAmountValue,
}

/// Deserialize a primary financial amount from a string or number.
///
/// Negative values are invalid for every primary amount field.
fn deserialize_amount<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct AmountVisitor;

    impl<'de> Visitor<'de> for AmountVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a non-negative u64 amount")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(v).map_err(|_| {
                E::invalid_value(de::Unexpected::Signed(v), &"a non-negative u64 amount")
            })
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<u64>().map_err(|_| {
                E::invalid_value(de::Unexpected::Str(v), &"a non-negative u64 amount")
            })
        }
    }

    deserializer.deserialize_any(AmountVisitor)
}

/// Preserve the service's negative remaining-balance signal only on its field.
fn deserialize_remaining_staking_amount<'de, D>(
    deserializer: D,
) -> Result<RemainingStakingAmountValue, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct RemainingStakingAmountVisitor;

    impl<'de> Visitor<'de> for RemainingStakingAmountVisitor {
        type Value = RemainingStakingAmountValue;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a signed or unsigned 64-bit remaining staking amount")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(RemainingStakingAmountValue::Amount(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v < 0 {
                Ok(RemainingStakingAmountValue::ExceedsBalance)
            } else {
                Ok(RemainingStakingAmountValue::Amount(v as u64))
            }
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if let Ok(amount) = v.parse::<u64>() {
                return Ok(RemainingStakingAmountValue::Amount(amount));
            }
            if let Ok(amount) = v.parse::<i64>() {
                if amount < 0 {
                    return Ok(RemainingStakingAmountValue::ExceedsBalance);
                }
                return Ok(RemainingStakingAmountValue::Amount(amount as u64));
            }
            Err(E::invalid_value(
                de::Unexpected::Str(v),
                &"a signed or unsigned 64-bit remaining staking amount",
            ))
        }
    }

    deserializer.deserialize_any(RemainingStakingAmountVisitor)
}

/// Payment intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentIntent {
    pub intent_type: String,
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Stake intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeIntent {
    pub intent_type: IntentType,
    pub validator_address: String,
    #[serde(default)]
    pub amount: Option<AmountWrapper>,
    #[serde(default)]
    pub staking_type: Option<StakingType>,
    #[serde(default)]
    pub stake_pool_config: Option<StakePoolConfig>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Stake pool configuration (for Jito and other stake pool programs)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakePoolConfig {
    #[serde(default)]
    pub stake_pool_address: Option<String>,
    #[serde(default)]
    pub withdraw_authority: Option<String>,
    #[serde(default)]
    pub reserve_stake: Option<String>,
    #[serde(default)]
    pub destination_pool_account: Option<String>,
    #[serde(default)]
    pub manager_fee_account: Option<String>,
    #[serde(default)]
    pub referral_pool_account: Option<String>,
    #[serde(default)]
    pub pool_mint: Option<String>,
    #[serde(default)]
    pub validator_list: Option<String>,
    #[serde(default)]
    pub source_pool_account: Option<String>,
    /// Whether to create an ATA for the pool mint before depositing (Jito staking)
    #[serde(default)]
    pub create_associated_token_account: Option<bool>,
}

/// Unstake intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnstakeIntent {
    pub intent_type: IntentType,
    /// Staking address - required for native/Jito, must NOT be set for Marinade
    #[serde(default)]
    pub staking_address: Option<String>,
    #[serde(default)]
    pub validator_address: Option<String>,
    #[serde(default)]
    pub amount: Option<AmountWrapper>,
    #[serde(default)]
    pub remaining_staking_amount: Option<RemainingStakingAmount>,
    #[serde(default)]
    pub staking_type: Option<StakingType>,
    #[serde(default)]
    pub stake_pool_config: Option<StakePoolConfig>,
    /// Recipients - used by Marinade unstake (transfer to contract address)
    #[serde(default)]
    pub recipients: Option<Vec<Recipient>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Claim intent (withdraw from deactivated stake)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimIntent {
    pub intent_type: String,
    pub staking_address: String,
    #[serde(default)]
    pub amount: Option<AmountWrapper>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Deactivate intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateIntent {
    pub intent_type: String,
    #[serde(default)]
    pub staking_address: Option<String>,
    #[serde(default)]
    pub staking_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Delegate intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateIntent {
    pub intent_type: String,
    pub validator_address: String,
    #[serde(default)]
    pub staking_address: Option<String>,
    #[serde(default)]
    pub staking_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Enable token intent (create ATA)
/// Supports both single token (tokenAddress) and multiple tokens (tokenAddresses array)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableTokenIntent {
    pub intent_type: String,
    #[serde(default)]
    pub recipient_address: Option<String>,
    /// Single token address (legacy format)
    #[serde(default)]
    pub token_address: Option<String>,
    /// Multiple token addresses (array format from wallet-platform)
    #[serde(default)]
    pub token_addresses: Option<Vec<String>>,
    /// Single token program ID (legacy format)
    #[serde(default)]
    pub token_program_id: Option<String>,
    /// Multiple token program IDs (array format, parallel to token_addresses)
    #[serde(default)]
    pub token_program_ids: Option<Vec<String>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Close ATA intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseAtaIntent {
    pub intent_type: String,
    #[serde(default)]
    pub token_account_address: Option<String>,
    #[serde(default)]
    pub token_program_id: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Consolidate intent - transfer from child address to root
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolidateIntent {
    pub intent_type: String,
    /// The child address to consolidate from (sender)
    pub receive_address: String,
    /// Recipients (root address for SOL, ATAs for tokens)
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub memo: Option<String>,
    /// When true, emit idempotent CreateAssociatedTokenAccount before each token transfer
    #[serde(default)]
    pub create_associated_token_account: Option<bool>,
    /// Owner of the destination ATA (wallet root address, NOT the sender/child address)
    #[serde(default)]
    pub ata_owner_address: Option<String>,
}

/// Authorize intent - pre-built transaction message
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeIntent {
    pub intent_type: String,
    /// Base64-encoded serialized Solana Message (bincode)
    pub transaction_message: String,
}

/// Custom transaction intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTxIntent {
    pub intent_type: String,
    /// Custom instructions to include in the transaction
    pub sol_instructions: Vec<CustomTxInstruction>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// A single custom instruction
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTxInstruction {
    /// Program ID (base58)
    pub program_id: String,
    /// Account keys for the instruction
    pub keys: Vec<CustomTxKey>,
    /// Instruction data (base64)
    pub data: String,
}

/// Account key for a custom instruction
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTxKey {
    /// Account public key (base58)
    pub pubkey: String,
    /// Whether this account must sign the transaction
    pub is_signer: bool,
    /// Whether this account is writable
    pub is_writable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn parse_primary_amount(value: Value) -> Result<AmountWrapper, serde_json::Error> {
        serde_json::from_value(json!({ "value": value }))
    }

    fn parse_remaining_amount(value: Value) -> Result<RemainingStakingAmount, serde_json::Error> {
        serde_json::from_value(json!({ "value": value }))
    }

    #[test]
    fn primary_amount_rejects_negative_number_and_string() {
        for value in [json!(-1), json!(i64::MIN), json!("-1")] {
            assert!(parse_primary_amount(value).is_err());
        }
    }

    #[test]
    fn primary_amount_preserves_zero_and_full_unsigned_range() {
        assert_eq!(parse_primary_amount(json!(0)).unwrap().value, 0);
        assert_eq!(
            parse_primary_amount(json!(u64::MAX)).unwrap().value,
            u64::MAX
        );
    }

    #[test]
    fn negative_remaining_amount_is_a_field_specific_exceeds_balance_state() {
        for value in [json!(-1), json!("-1")] {
            assert_eq!(
                parse_remaining_amount(value).unwrap().value,
                RemainingStakingAmountValue::ExceedsBalance
            );
        }
        assert_eq!(
            parse_remaining_amount(json!(0)).unwrap().value,
            RemainingStakingAmountValue::Amount(0)
        );
        assert_eq!(
            parse_remaining_amount(json!(1)).unwrap().value,
            RemainingStakingAmountValue::Amount(1)
        );
    }
}
