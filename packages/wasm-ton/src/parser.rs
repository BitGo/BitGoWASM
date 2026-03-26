//! Standalone transaction parser for TON.
//!
//! Provides `parse_transaction()` as a standalone function (NOT a method on TonTransaction).
//! Decodes the sign body actions to extract transaction type, recipient, amount, and payload.

use num_bigint::BigUint;
use tlb::{
    bits::{de::BitReaderExt, VarInt},
    de::CellParser,
    Cell,
};
use tlb_ton::{message::CommonMsgInfo, MsgAddress};
use ton_contracts::wallet::v4r2::WalletV4R2Op;

use crate::staking::{
    JETTON_TRANSFER_OPCODE, NOMINATOR_WITHDRAW_OPCODE, TEXT_COMMENT_OPCODE, WHALES_DEPOSIT_OPCODE,
    WHALES_WITHDRAW_OPCODE,
};
use crate::transaction::TonTransaction;
use crate::types::{ParsedPayload, ParsedTransaction, TonTransactionType};

/// Vesting contract wallet ID.
const VESTING_WALLET_ID: u32 = 268;

/// Parse a TonTransaction into structured data.
///
/// This is a STANDALONE function, not a method on TonTransaction,
/// following the wasm-solana pattern.
pub fn parse_transaction(tx: &TonTransaction) -> Result<ParsedTransaction, String> {
    let sign_body = tx.sign_body();
    let signature = tx.signature();

    // Format sender address (non-bounceable)
    let sender = format_address(tx.sender_addr(), false);

    // Format signature as hex
    let signature_hex = hex::encode(signature);

    // Extract public key from StateInit if present
    let public_key = tx
        .public_key_from_state_init()
        .map_err(|e| e.to_string())?
        .map(|pk| hex::encode(pk));

    // Get wallet metadata
    let seqno = sign_body.seqno;
    let wallet_id = sign_body.wallet_id;
    let expire_time = sign_body.expire_at.timestamp() as u64;
    let is_vesting = wallet_id == VESTING_WALLET_ID;

    // Extract the send action
    let WalletV4R2Op::Send(ref actions) = sign_body.op else {
        return Err("Expected Send op, got plugin operation".to_string());
    };

    if actions.is_empty() {
        return Err("No actions in transaction".to_string());
    }

    let action = &actions[0];

    // Extract internal message info
    let CommonMsgInfo::Internal(ref info) = action.message.info else {
        return Err("Expected internal message in action".to_string());
    };

    let recipient_addr = &info.dst;
    let bounceable = info.bounce;
    let amount = info.value.grams.clone();
    let recipient = format_address(recipient_addr, bounceable);

    // Parse the body payload
    let body_cell = &action.message.body;
    let payload = parse_payload(body_cell, is_vesting)?;

    // Determine transaction type and extract token-specific fields
    let (tx_type, memo, token_amount, token_recipient) = match &payload {
        ParsedPayload::Empty => (TonTransactionType::Send, None, None, None),
        ParsedPayload::TextComment(text) => {
            (TonTransactionType::Send, Some(text.clone()), None, None)
        }
        ParsedPayload::JettonTransfer {
            amount: token_amt,
            destination,
            ..
        } => (
            TonTransactionType::SendToken,
            None,
            Some(token_amt.clone()),
            Some(format_address(destination, false)),
        ),
        ParsedPayload::NominatorWithdraw { .. } => (
            TonTransactionType::SingleNominatorWithdraw,
            None,
            None,
            None,
        ),
        ParsedPayload::WhalesDeposit { .. } => {
            if is_vesting {
                (
                    TonTransactionType::TonWhalesVestingDeposit,
                    None,
                    None,
                    None,
                )
            } else {
                (TonTransactionType::TonWhalesDeposit, None, None, None)
            }
        }
        ParsedPayload::WhalesWithdraw { .. } => {
            if is_vesting {
                (
                    TonTransactionType::TonWhalesVestingWithdrawal,
                    None,
                    None,
                    None,
                )
            } else {
                (TonTransactionType::TonWhalesWithdrawal, None, None, None)
            }
        }
        ParsedPayload::VestingDeposit => (
            TonTransactionType::TonWhalesVestingDeposit,
            Some("Deposit".to_string()),
            None,
            None,
        ),
        ParsedPayload::VestingWithdrawal => (
            TonTransactionType::TonWhalesVestingWithdrawal,
            Some("Withdraw".to_string()),
            None,
            None,
        ),
        ParsedPayload::Unknown(_) => (TonTransactionType::Send, None, None, None),
    };

    Ok(ParsedTransaction {
        tx_type,
        sender,
        recipient,
        amount,
        bounceable,
        seqno,
        wallet_id,
        expire_time,
        memo,
        payload,
        signature: signature_hex,
        public_key,
        token_amount,
        token_recipient,
    })
}

/// Parse the inner message body to determine the payload type.
fn parse_payload(body_cell: &Cell, is_vesting: bool) -> Result<ParsedPayload, String> {
    // Check if body is empty (data has no bits)
    if body_cell.data.is_empty() {
        return Ok(ParsedPayload::Empty);
    }

    // Read the opcode (first 32 bits)
    let mut parser = body_cell.parser();
    let opcode: u32 = parser
        .unpack(())
        .map_err(|e| format!("Failed to read opcode: {e}"))?;

    match opcode {
        TEXT_COMMENT_OPCODE => {
            // Text comment: remaining bytes are UTF-8 text
            let text = parse_text_comment(&mut parser)?;
            if is_vesting {
                match text.as_str() {
                    "Deposit" => Ok(ParsedPayload::VestingDeposit),
                    "Withdraw" => Ok(ParsedPayload::VestingWithdrawal),
                    _ => Ok(ParsedPayload::TextComment(text)),
                }
            } else {
                Ok(ParsedPayload::TextComment(text))
            }
        }
        JETTON_TRANSFER_OPCODE => {
            // Jetton transfer: parse fields manually after opcode
            // The full JettonTransfer parse_fully may fail on some body encodings
            // since forward_payload is Either Cell ^Cell and not all fixtures have it
            let query_id: u64 = parser
                .unpack(())
                .map_err(|e| format!("Failed to read jetton query_id: {e}"))?;
            let amount: BigUint = parser
                .unpack_as::<_, VarInt<4>>(())
                .map_err(|e| format!("Failed to read jetton amount: {e}"))?;
            let destination: MsgAddress = parser
                .unpack(())
                .map_err(|e| format!("Failed to read jetton destination: {e}"))?;
            let response_destination: MsgAddress = parser
                .unpack(())
                .map_err(|e| format!("Failed to read jetton response_dst: {e}"))?;
            // custom_payload: Maybe ^Cell (1 bit flag + optional ref)
            let has_custom_payload: bool = parser
                .unpack(())
                .map_err(|e| format!("Failed to read jetton custom_payload flag: {e}"))?;
            if has_custom_payload {
                // Skip the custom payload ref
                let _: Cell = parser
                    .parse(())
                    .map_err(|e| format!("Failed to read jetton custom_payload: {e}"))?;
            }
            let forward_ton_amount: BigUint = parser
                .unpack_as::<_, VarInt<4>>(())
                .map_err(|e| format!("Failed to read jetton forward_ton_amount: {e}"))?;
            Ok(ParsedPayload::JettonTransfer {
                query_id,
                amount,
                destination,
                response_destination,
                forward_ton_amount,
            })
        }
        NOMINATOR_WITHDRAW_OPCODE => {
            let query_id: u64 = parser
                .unpack(())
                .map_err(|e| format!("Failed to read query_id: {e}"))?;
            let amount: BigUint = parser
                .unpack_as::<_, VarInt<4>>(())
                .map_err(|e| format!("Failed to read amount: {e}"))?;
            Ok(ParsedPayload::NominatorWithdraw { query_id, amount })
        }
        WHALES_DEPOSIT_OPCODE => {
            let query_id: u64 = parser
                .unpack(())
                .map_err(|e| format!("Failed to read query_id: {e}"))?;
            let _gas_limit: BigUint = parser
                .unpack_as::<_, VarInt<4>>(())
                .map_err(|e| format!("Failed to read gas_limit: {e}"))?;
            Ok(ParsedPayload::WhalesDeposit { query_id })
        }
        WHALES_WITHDRAW_OPCODE => {
            let query_id: u64 = parser
                .unpack(())
                .map_err(|e| format!("Failed to read query_id: {e}"))?;
            let _gas_limit: BigUint = parser
                .unpack_as::<_, VarInt<4>>(())
                .map_err(|e| format!("Failed to read gas_limit: {e}"))?;
            let unstake_amount: BigUint = parser
                .unpack_as::<_, VarInt<4>>(())
                .map_err(|e| format!("Failed to read unstake_amount: {e}"))?;
            Ok(ParsedPayload::WhalesWithdraw {
                query_id,
                unstake_amount,
            })
        }
        _ => Ok(ParsedPayload::Unknown(opcode)),
    }
}

/// Parse text comment from the remaining parser bits after the opcode.
fn parse_text_comment(parser: &mut CellParser<'_>) -> Result<String, String> {
    // Read remaining bytes as UTF-8 text
    let mut bytes = Vec::new();
    loop {
        match parser.unpack::<u8>(()) {
            Ok(b) => bytes.push(b),
            Err(_) => break,
        }
    }
    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in text comment: {e}"))
}

/// Format a MsgAddress as user-friendly base64url.
fn format_address(addr: &MsgAddress, bounceable: bool) -> String {
    let non_bounceable = !bounceable;
    addr.to_base64_url_flags(non_bounceable, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Same fixtures as transaction.rs tests
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    const SIGNED_NOMINATOR_TX: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    #[test]
    fn test_parse_send_transaction() {
        let tx = TonTransaction::from_boc(SIGNED_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.tx_type, TonTransactionType::Send);
        assert_eq!(parsed.seqno, 6);
        assert_eq!(parsed.wallet_id, 698983191);
        assert!(!parsed.bounceable);
        // Recipient should be UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBX1aD (non-bounceable since bounce=false)
        assert!(parsed.recipient.starts_with("UQ"));
    }

    #[test]
    fn test_parse_nominator_withdraw() {
        let tx = TonTransaction::from_boc(SIGNED_NOMINATOR_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.tx_type, TonTransactionType::SingleNominatorWithdraw);
        assert_eq!(parsed.seqno, 0);
        assert!(parsed.public_key.is_some());
    }

    // Whales deposit fixture
    const WHALES_DEPOSIT_TX: &str = "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    #[test]
    fn test_parse_whales_deposit() {
        let tx = TonTransaction::from_boc(WHALES_DEPOSIT_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.tx_type, TonTransactionType::TonWhalesDeposit);
        assert_eq!(parsed.seqno, 92);
        assert!(parsed.bounceable);
        match &parsed.payload {
            ParsedPayload::WhalesDeposit { query_id } => {
                assert_eq!(format!("{:016x}", query_id), "000000006942ba02");
            }
            _ => panic!("Expected WhalesDeposit payload"),
        }
    }

    // Whales withdrawal fixture
    const WHALES_WITHDRAWAL_TX: &str = "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    #[test]
    fn test_parse_whales_withdrawal() {
        let tx = TonTransaction::from_boc(WHALES_WITHDRAWAL_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.tx_type, TonTransactionType::TonWhalesWithdrawal);
        assert_eq!(parsed.seqno, 93);
        match &parsed.payload {
            ParsedPayload::WhalesWithdraw {
                query_id,
                unstake_amount,
            } => {
                assert_eq!(format!("{:016x}", query_id), "00000000694aa53c");
                assert_eq!(unstake_amount, &BigUint::from(10_000_000_000u64));
            }
            _ => panic!("Expected WhalesWithdraw payload"),
        }
    }

    // Whales full withdrawal fixture
    const WHALES_FULL_WITHDRAWAL_TX: &str = "te6cckEBAgEAuwAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwHSrLxEIwA9nyfxKqom8MsGbPCL5SfwqGDzHyYnKzJwU8ecNqb6xkB7u9gBwBrZdO3NvecF44nXe2Lm/+OL8Z4aU1NGLtKVgg4AAAC8AAcAQCKYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUrAy0O5rKAAudrTIw==";

    #[test]
    fn test_parse_whales_full_withdrawal() {
        let tx = TonTransaction::from_boc(WHALES_FULL_WITHDRAWAL_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.tx_type, TonTransactionType::TonWhalesWithdrawal);
        assert_eq!(parsed.seqno, 94);
        match &parsed.payload {
            ParsedPayload::WhalesWithdraw { unstake_amount, .. } => {
                assert_eq!(unstake_amount, &BigUint::ZERO);
            }
            _ => panic!("Expected WhalesWithdraw payload"),
        }
    }

    // Token send fixture
    const TOKEN_SEND_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    #[test]
    fn test_parse_token_send() {
        let tx = TonTransaction::from_boc(TOKEN_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.tx_type, TonTransactionType::SendToken);
        assert_eq!(parsed.seqno, 0);
        assert!(parsed.token_amount.is_some());
        assert!(parsed.token_recipient.is_some());
        assert_eq!(
            parsed.token_amount.unwrap(),
            BigUint::from(1_000_000_000u64)
        );
    }
}
