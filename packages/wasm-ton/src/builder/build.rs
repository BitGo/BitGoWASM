//! Transaction building from business-level intents.
//!
//! Dispatches on intent type, constructs the appropriate internal message(s),
//! wraps in a V4R2 signing body, and creates an unsigned external message.

use chrono::{DateTime, TimeZone, Utc};
use tlb_ton::MsgAddress;
use ton_contracts::wallet::v4r2::V4R2;
use ton_contracts::wallet::WalletVersion;

use crate::address::DEFAULT_WALLET_ID;
use crate::error::WasmTonError;
use crate::transaction::Transaction;

use super::jetton::build_jetton_transfer_action;
use super::staking::{
    build_single_nominator_withdraw_action, build_whales_deposit_action,
    build_whales_vesting_deposit_action, build_whales_vesting_withdraw_action,
    build_whales_withdraw_action,
};
use super::transfer::build_transfer_action;
use super::types::{TonStakingType, TonTransactionIntent};

/// Standard send mode: pay transfer fees separately + ignore errors.
const MODE_STANDARD: u8 = 3;

/// Send entire balance mode (for consolidation).
const MODE_SEND_ALL: u8 = 128;

/// Build a TON transaction from a business-level intent.
///
/// Returns an unsigned Transaction ready for signing.
pub fn build_transaction(intent: TonTransactionIntent) -> Result<Transaction, WasmTonError> {
    match intent {
        TonTransactionIntent::Payment {
            recipients,
            memo,
            bounceable,
            sender,
            seqno,
            expire_at,
            public_key,
            sender_jetton_address,
        } => {
            let wallet_addr = parse_address(&sender)?;
            let bounce = bounceable.unwrap_or(false);

            if recipients.is_empty() {
                return Err(WasmTonError::StringError(
                    "Payment intent requires at least one recipient".to_string(),
                ));
            }

            let recipient = &recipients[0];
            let dst = parse_address(&recipient.address)?;

            let action = if let Some(ref jetton_addr) = sender_jetton_address {
                let sender_jetton = parse_address(jetton_addr)?;
                build_jetton_transfer_action(
                    sender_jetton,
                    dst,
                    wallet_addr,
                    recipient.amount,
                    memo.as_deref(),
                    MODE_STANDARD,
                )?
            } else {
                build_transfer_action(
                    dst,
                    recipient.amount,
                    bounce,
                    memo.as_deref(),
                    MODE_STANDARD,
                )?
            };

            build_v4r2_transaction(wallet_addr, &public_key, seqno, expire_at, vec![action])
        }

        TonTransactionIntent::FillNonce {
            address,
            seqno,
            expire_at,
            public_key,
            sender_jetton_address,
        } => {
            let wallet_addr = parse_address(&address)?;

            let action = if let Some(ref jetton_addr) = sender_jetton_address {
                // Token fill nonce: send 0 jettons to self
                let sender_jetton = parse_address(jetton_addr)?;
                build_jetton_transfer_action(
                    sender_jetton,
                    wallet_addr,
                    wallet_addr,
                    0,
                    None,
                    MODE_STANDARD,
                )?
            } else {
                // Native fill nonce: send 0 TON to self
                build_transfer_action(wallet_addr, 0, false, None, MODE_STANDARD)?
            };

            build_v4r2_transaction(wallet_addr, &public_key, seqno, expire_at, vec![action])
        }

        TonTransactionIntent::Consolidate {
            recipients,
            sender,
            seqno,
            expire_at,
            public_key,
            sender_jetton_address,
        } => {
            let wallet_addr = parse_address(&sender)?;

            if recipients.is_empty() {
                return Err(WasmTonError::StringError(
                    "Consolidate intent requires at least one recipient".to_string(),
                ));
            }

            let recipient = &recipients[0];
            let dst = parse_address(&recipient.address)?;

            let action = if let Some(ref jetton_addr) = sender_jetton_address {
                let sender_jetton = parse_address(jetton_addr)?;
                build_jetton_transfer_action(
                    sender_jetton,
                    dst,
                    wallet_addr,
                    recipient.amount,
                    None,
                    MODE_STANDARD,
                )?
            } else {
                // Consolidation uses mode 128 (send entire balance) for native
                build_transfer_action(dst, recipient.amount, false, None, MODE_SEND_ALL)?
            };

            build_v4r2_transaction(wallet_addr, &public_key, seqno, expire_at, vec![action])
        }

        TonTransactionIntent::Delegate {
            validator_address,
            amount,
            staking_type,
            sender,
            seqno,
            expire_at,
            public_key,
            is_vesting,
            sub_wallet_id,
        } => {
            let wallet_addr = parse_address(&sender)?;
            let validator_addr = parse_address(&validator_address)?;
            let vesting = is_vesting.unwrap_or(false);

            if vesting && staking_type == TonStakingType::TonWhales {
                let wallet_id = sub_wallet_id.ok_or_else(|| {
                    WasmTonError::StringError(
                        "subWalletId is required for vesting delegate".to_string(),
                    )
                })?;
                let action =
                    build_whales_vesting_deposit_action(validator_addr, amount, MODE_STANDARD)?;
                return build_v3_transaction(wallet_addr, wallet_id, seqno, expire_at, action);
            }

            let action = match staking_type {
                TonStakingType::TonWhales => {
                    build_whales_deposit_action(validator_addr, amount, MODE_STANDARD)?
                }
                TonStakingType::SingleNominator => {
                    // Plain transfer to validator with bounceable=true
                    build_transfer_action(validator_addr, amount, true, None, MODE_STANDARD)?
                }
                TonStakingType::MultiNominator => {
                    // Transfer to validator with memo='d' and bounceable=true
                    build_transfer_action(validator_addr, amount, true, Some("d"), MODE_STANDARD)?
                }
            };

            build_v4r2_transaction(wallet_addr, &public_key, seqno, expire_at, vec![action])
        }

        TonTransactionIntent::Undelegate {
            validator_address,
            amount,
            withdrawal_amount,
            staking_type,
            sender,
            seqno,
            expire_at,
            public_key,
            is_vesting,
            sub_wallet_id,
        } => {
            let wallet_addr = parse_address(&sender)?;
            let validator_addr = parse_address(&validator_address)?;
            let vesting = is_vesting.unwrap_or(false);

            if vesting && staking_type == TonStakingType::TonWhales {
                let wallet_id = sub_wallet_id.ok_or_else(|| {
                    WasmTonError::StringError(
                        "subWalletId is required for vesting undelegate".to_string(),
                    )
                })?;
                let action =
                    build_whales_vesting_withdraw_action(validator_addr, amount, MODE_STANDARD)?;
                return build_v3_transaction(wallet_addr, wallet_id, seqno, expire_at, action);
            }

            let action = match staking_type {
                TonStakingType::TonWhales => {
                    let withdraw_amt = withdrawal_amount.unwrap_or(0);
                    build_whales_withdraw_action(
                        validator_addr,
                        amount,
                        withdraw_amt,
                        MODE_STANDARD,
                    )?
                }
                TonStakingType::SingleNominator => {
                    let withdraw_amt = withdrawal_amount.unwrap_or(amount);
                    // Dedicated withdraw message, sends 1 TON to validator for gas
                    build_single_nominator_withdraw_action(
                        validator_addr,
                        amount,
                        withdraw_amt,
                        MODE_STANDARD,
                    )?
                }
                TonStakingType::MultiNominator => {
                    // Transfer to validator with memo='w' and bounceable=true
                    build_transfer_action(validator_addr, amount, true, Some("w"), MODE_STANDARD)?
                }
            };

            build_v4r2_transaction(wallet_addr, &public_key, seqno, expire_at, vec![action])
        }
    }
}

// =========================================================================
// Helpers
// =========================================================================

/// Build a complete V4R2 unsigned external message transaction.
fn build_v4r2_transaction(
    wallet_address: MsgAddress,
    public_key_hex: &str,
    seqno: u32,
    expire_at_unix: u32,
    actions: Vec<tlb_ton::action::SendMsgAction>,
) -> Result<Transaction, WasmTonError> {
    let _pubkey = parse_public_key(public_key_hex)?;

    let expire_at: DateTime<Utc> = Utc
        .timestamp_opt(expire_at_unix as i64, 0)
        .single()
        .ok_or_else(|| {
            WasmTonError::StringError(format!("Invalid expire_at timestamp: {}", expire_at_unix))
        })?;

    // Create the V4R2 signing body
    let sign_body = V4R2::create_sign_body(DEFAULT_WALLET_ID, expire_at, seqno, actions);

    // Wrap with an empty signature (unsigned)
    let external_body = V4R2::wrap_signed_external(sign_body, [0u8; 64]);

    // Create the Transaction from components
    Transaction::from_components(wallet_address, None, external_body)
}

/// V3 signing body: wallet_id(32) + expire_at(32) + seqno(32) + send_mode(8) + msg_ref
///
/// Unlike V4R2, V3 has no op byte and only supports a single message.
struct V3SignBody {
    wallet_id: u32,
    expire_at: u32,
    seqno: u32,
    send_mode: u8,
    message: tlb_ton::Cell,
}

impl tlb_ton::ser::CellSerialize for V3SignBody {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use tlb_ton::bits::ser::BitWriterExt;
        builder.pack(self.wallet_id, ())?;
        builder.pack(self.expire_at, ())?;
        builder.pack(self.seqno, ())?;
        builder.pack(self.send_mode, ())?;
        builder.store_as::<_, tlb_ton::Ref>(&self.message, ())?;
        Ok(())
    }
}

/// Build a V3 (vesting contract) unsigned external message transaction.
fn build_v3_transaction(
    wallet_address: MsgAddress,
    wallet_id: u32,
    seqno: u32,
    expire_at_unix: u32,
    action: tlb_ton::action::SendMsgAction,
) -> Result<Transaction, WasmTonError> {
    use tlb_ton::ser::CellSerializeExt;

    let msg_cell = action.message.to_cell(()).map_err(|e| {
        WasmTonError::CellError(format!("Failed to build internal message cell: {}", e))
    })?;

    let sign_body = V3SignBody {
        wallet_id,
        expire_at: expire_at_unix,
        seqno,
        send_mode: action.mode,
        message: msg_cell,
    };

    let sign_body_cell = sign_body.to_cell(()).map_err(|e| {
        WasmTonError::CellError(format!("Failed to build V3 sign body cell: {}", e))
    })?;

    Transaction::from_raw_sign_body(wallet_address, sign_body_cell)
}

/// Parse a TON address from user-friendly or raw format.
fn parse_address(addr: &str) -> Result<MsgAddress, WasmTonError> {
    // Try user-friendly base64url format first
    if let Ok((msg_addr, _, _)) = MsgAddress::from_base64_url_flags(addr) {
        return Ok(msg_addr);
    }
    // Try standard base64
    if let Ok((msg_addr, _, _)) = MsgAddress::from_base64_std_flags(addr) {
        return Ok(msg_addr);
    }
    // Try raw hex format (workchain:hex)
    if addr.contains(':') {
        return MsgAddress::from_hex(addr)
            .map_err(|e| WasmTonError::InvalidAddress(format!("Invalid raw address: {}", e)));
    }
    Err(WasmTonError::InvalidAddress(format!(
        "Unrecognized address format: {}",
        addr
    )))
}

/// Parse a hex-encoded Ed25519 public key.
fn parse_public_key(hex_key: &str) -> Result<[u8; 32], WasmTonError> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| WasmTonError::InvalidPublicKey(format!("Invalid hex public key: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| WasmTonError::InvalidPublicKey("Public key must be 32 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode_address;
    use crate::parser::{self, TonTransactionType};

    // Test public key (deterministic)
    const TEST_PUBKEY: [u8; 32] = [1u8; 32];
    const TEST_PUBKEY_HEX: &str =
        "0101010101010101010101010101010101010101010101010101010101010101";

    fn test_sender_address() -> String {
        encode_address(&TEST_PUBKEY, false, false).unwrap()
    }

    fn test_recipient_address() -> String {
        let pubkey = [2u8; 32];
        encode_address(&pubkey, false, false).unwrap()
    }

    #[test]
    fn test_build_native_payment() {
        let sender = test_sender_address();
        let recipient = test_recipient_address();

        let intent = TonTransactionIntent::Payment {
            recipients: vec![super::super::types::Recipient {
                address: recipient,
                amount: 1_000_000_000,
            }],
            memo: None,
            bounceable: None,
            sender,
            seqno: 1,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            sender_jetton_address: None,
        };

        let tx = build_transaction(intent).unwrap();

        // Verify basic properties
        assert_eq!(tx.sign_body().seqno, 1);
        let payload = tx.signable_payload().unwrap();
        assert_eq!(payload.len(), 32);

        // Parse the built transaction and verify
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 1);
        assert_eq!(parsed.transaction_type, TonTransactionType::Send);
        assert_eq!(parsed.amount, 1_000_000_000);
    }

    #[test]
    fn test_build_native_payment_with_memo() {
        let sender = test_sender_address();
        let recipient = test_recipient_address();

        let intent = TonTransactionIntent::Payment {
            recipients: vec![super::super::types::Recipient {
                address: recipient,
                amount: 500_000_000,
            }],
            memo: Some("test memo".to_string()),
            bounceable: None,
            sender,
            seqno: 2,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            sender_jetton_address: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 2);
        assert_eq!(parsed.transaction_type, TonTransactionType::Send);
        assert_eq!(parsed.amount, 500_000_000);
        assert_eq!(parsed.memo, Some("test memo".to_string()));
    }

    #[test]
    fn test_build_fill_nonce() {
        let addr = test_sender_address();

        let intent = TonTransactionIntent::FillNonce {
            address: addr.clone(),
            seqno: 5,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            sender_jetton_address: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 5);
        assert_eq!(parsed.amount, 0);
        assert_eq!(parsed.transaction_type, TonTransactionType::Send);
    }

    #[test]
    fn test_build_consolidate() {
        let sender = test_sender_address();
        let recipient = test_recipient_address();

        let intent = TonTransactionIntent::Consolidate {
            recipients: vec![super::super::types::Recipient {
                address: recipient,
                amount: 2_000_000_000,
            }],
            sender,
            seqno: 3,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            sender_jetton_address: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 3);
        // Consolidation uses mode 128
        assert_eq!(parsed.send_mode, Some(MODE_SEND_ALL));
    }

    #[test]
    fn test_build_delegate_whales() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Delegate {
            validator_address: validator,
            amount: 5_000_000_000,
            staking_type: TonStakingType::TonWhales,
            sender,
            seqno: 10,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: None,
            sub_wallet_id: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 10);
        assert_eq!(
            parsed.transaction_type,
            TonTransactionType::TonWhalesDeposit
        );
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_delegate_single_nominator() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Delegate {
            validator_address: validator,
            amount: 3_000_000_000,
            staking_type: TonStakingType::SingleNominator,
            sender,
            seqno: 11,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: None,
            sub_wallet_id: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 11);
        assert_eq!(parsed.transaction_type, TonTransactionType::Send);
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_delegate_multi_nominator() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Delegate {
            validator_address: validator,
            amount: 4_000_000_000,
            staking_type: TonStakingType::MultiNominator,
            sender,
            seqno: 12,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: None,
            sub_wallet_id: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 12);
        assert_eq!(parsed.memo, Some("d".to_string()));
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_undelegate_whales() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Undelegate {
            validator_address: validator,
            amount: 1_000_000_000,
            withdrawal_amount: Some(5_000_000_000),
            staking_type: TonStakingType::TonWhales,
            sender,
            seqno: 20,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: None,
            sub_wallet_id: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 20);
        assert_eq!(
            parsed.transaction_type,
            TonTransactionType::TonWhalesWithdrawal
        );
    }

    #[test]
    fn test_build_undelegate_single_nominator() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Undelegate {
            validator_address: validator,
            amount: 1_000_000_000,
            withdrawal_amount: Some(3_000_000_000),
            staking_type: TonStakingType::SingleNominator,
            sender,
            seqno: 21,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: None,
            sub_wallet_id: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 21);
        assert_eq!(
            parsed.transaction_type,
            TonTransactionType::SingleNominatorWithdraw
        );
    }

    #[test]
    fn test_build_undelegate_multi_nominator() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Undelegate {
            validator_address: validator,
            amount: 2_000_000_000,
            withdrawal_amount: None,
            staking_type: TonStakingType::MultiNominator,
            sender,
            seqno: 22,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: None,
            sub_wallet_id: None,
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 22);
        assert_eq!(parsed.memo, Some("w".to_string()));
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_roundtrip_serialize_deserialize() {
        let sender = test_sender_address();
        let recipient = test_recipient_address();

        let intent = TonTransactionIntent::Payment {
            recipients: vec![super::super::types::Recipient {
                address: recipient,
                amount: 750_000_000,
            }],
            memo: Some("roundtrip test".to_string()),
            bounceable: None,
            sender,
            seqno: 99,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            sender_jetton_address: None,
        };

        let tx = build_transaction(intent).unwrap();

        // Serialize to bytes and deserialize back
        let bytes = tx.to_bytes().unwrap();
        let tx2 = Transaction::from_bytes(&bytes).unwrap();

        // Verify the deserialized tx matches
        let parsed = parser::parse_transaction(&tx2).unwrap();
        assert_eq!(parsed.seqno, 99);
        assert_eq!(parsed.amount, 750_000_000);
        assert_eq!(parsed.memo, Some("roundtrip test".to_string()));
    }

    #[test]
    fn test_build_jetton_payment() {
        let sender = test_sender_address();
        let recipient = test_recipient_address();
        // Use a different address for the jetton wallet
        let jetton_pubkey = [3u8; 32];
        let jetton_addr = encode_address(&jetton_pubkey, true, false).unwrap();

        let intent = TonTransactionIntent::Payment {
            recipients: vec![super::super::types::Recipient {
                address: recipient,
                amount: 5_000_000,
            }],
            memo: Some("jetton transfer".to_string()),
            bounceable: None,
            sender,
            seqno: 50,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            sender_jetton_address: Some(jetton_addr),
        };

        let tx = build_transaction(intent).unwrap();
        let parsed = parser::parse_transaction(&tx).unwrap();
        assert_eq!(parsed.seqno, 50);
        assert_eq!(parsed.transaction_type, TonTransactionType::SendToken);
        // The TON amount attached is the gas amount, not the jetton amount
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_vesting_delegate_whales() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Delegate {
            validator_address: validator,
            amount: 5_000_000_000,
            staking_type: TonStakingType::TonWhales,
            sender,
            seqno: 30,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: Some(true),
            sub_wallet_id: Some(268),
        };

        let tx = build_transaction(intent).unwrap();

        // Vesting uses raw cell format, not V4R2
        assert!(!tx.is_v4r2());

        // Verify signable payload is 32 bytes
        let payload = tx.signable_payload().unwrap();
        assert_eq!(payload.len(), 32);

        // Verify we can serialize and round-trip
        let bytes = tx.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Verify signing works
        let mut tx2 = tx;
        let fake_sig = [0xABu8; 64];
        tx2.add_signature(&fake_sig).unwrap();
        assert!(tx2.id().unwrap().is_some());
    }

    #[test]
    fn test_build_vesting_undelegate_whales() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Undelegate {
            validator_address: validator,
            amount: 1_000_000_000,
            withdrawal_amount: None,
            staking_type: TonStakingType::TonWhales,
            sender,
            seqno: 31,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: Some(true),
            sub_wallet_id: Some(268),
        };

        let tx = build_transaction(intent).unwrap();
        assert!(!tx.is_v4r2());

        let payload = tx.signable_payload().unwrap();
        assert_eq!(payload.len(), 32);

        let bytes = tx.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_vesting_requires_sub_wallet_id() {
        let sender = test_sender_address();
        let validator = test_recipient_address();

        let intent = TonTransactionIntent::Delegate {
            validator_address: validator,
            amount: 5_000_000_000,
            staking_type: TonStakingType::TonWhales,
            sender,
            seqno: 32,
            expire_at: 1700000000,
            public_key: TEST_PUBKEY_HEX.to_string(),
            is_vesting: Some(true),
            sub_wallet_id: None, // Missing!
        };

        let result = build_transaction(intent);
        assert!(result.is_err());
    }
}
