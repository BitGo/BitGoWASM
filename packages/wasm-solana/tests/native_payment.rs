use base64::{engine::general_purpose::STANDARD, Engine};
use wasm_solana::{
    instructions::ParsedInstruction,
    parser::parse_from_transaction,
    transaction::{Transaction, TransactionExt},
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../test/fixtures/native-payment.json")).unwrap()
}

fn bytes() -> Vec<u8> {
    STANDARD
        .decode(fixture()["transactionBase64"].as_str().unwrap())
        .unwrap()
}

#[test]
fn preserves_reference_message_signer_slots_and_native_payment() {
    let expected = fixture();
    let input = bytes();
    let tx = Transaction::from_bytes(&input).unwrap();
    assert_eq!(tx.to_bytes().unwrap(), input);
    assert_eq!(
        tx.signable_payload(),
        STANDARD
            .decode(expected["messageBase64"].as_str().unwrap())
            .unwrap()
    );
    assert_eq!(tx.signatures[0].as_ref(), &[0; 64]);
    assert_eq!(tx.signatures[1].as_ref(), &[9; 64]);
    assert_eq!(
        tx.signer_index(expected["source"].as_str().unwrap()),
        Some(0)
    );
    assert_eq!(
        tx.signer_index(expected["nonceAuthority"].as_str().unwrap()),
        Some(1)
    );

    let parsed = parse_from_transaction(&tx).unwrap();
    assert_eq!(parsed.instructions_data.len(), 5);
    match &parsed.instructions_data[0] {
        ParsedInstruction::NonceAdvance(nonce) => {
            assert_eq!(
                nonce.wallet_nonce_address,
                expected["nonceAccount"].as_str().unwrap()
            );
            assert_eq!(
                nonce.auth_wallet_address,
                expected["nonceAuthority"].as_str().unwrap()
            );
        }
        other => panic!("expected nonce advance, got {other:?}"),
    }
    for (index, amount) in [(3, 123_456_789), (4, 0)] {
        match &parsed.instructions_data[index] {
            ParsedInstruction::Transfer(transfer) => {
                assert_eq!(transfer.from_address, expected["source"].as_str().unwrap());
                assert_eq!(
                    transfer.to_address,
                    expected["destination"].as_str().unwrap()
                );
                assert_eq!(transfer.amount, amount);
            }
            other => panic!("expected native transfer, got {other:?}"),
        }
    }
}

#[test]
fn rejects_malformed_noncanonical_and_oversized_transactions() {
    let input = bytes();
    for end in 0..input.len() {
        assert!(
            Transaction::from_bytes(&input[..end]).is_err(),
            "truncation at {end}"
        );
    }
    let mut trailing = input.clone();
    trailing.push(0);
    assert!(Transaction::from_bytes(&trailing).is_err());
    assert!(Transaction::from_bytes(&vec![0; 1233]).is_err());
    assert!(Transaction::from_bytes(&[0xff, 0xff, 0x03]).is_err());

    let mut tx = Transaction::from_bytes(&input).unwrap();
    tx.message.header.num_required_signatures = 3;
    assert!(Transaction::from_bytes(&tx.to_bytes().unwrap()).is_err());
    let mut tx = Transaction::from_bytes(&input).unwrap();
    tx.message.instructions[0].accounts[0] = 255;
    assert!(Transaction::from_bytes(&tx.to_bytes().unwrap()).is_err());
    let mut tx = Transaction::from_bytes(&input).unwrap();
    tx.signatures.pop();
    assert!(Transaction::from_bytes(&tx.to_bytes().unwrap()).is_err());
}

#[test]
fn unknown_instruction_keeps_bytes_and_requested_roles() {
    let mut tx = Transaction::from_bytes(&bytes()).unwrap();
    tx.message.instructions[3].data.push(42); // trailing data must not become a Transfer
    let parsed = parse_from_transaction(&tx).unwrap();
    match &parsed.instructions_data[3] {
        ParsedInstruction::Unknown(instruction) => {
            assert_eq!(instruction.data, tx.message.instructions[3].data);
            assert_eq!(instruction.accounts.len(), 2);
            assert!(instruction.accounts[0].is_signer);
            assert!(instruction.accounts[0].is_writable);
            assert!(!instruction.accounts[1].is_signer);
            assert!(instruction.accounts[1].is_writable);
        }
        other => panic!("unexpected semantic claim: {other:?}"),
    }
}

#[test]
fn parser_does_not_silently_drop_unresolved_operands() {
    let mut tx = Transaction::from_bytes(&bytes()).unwrap();
    tx.message.instructions[3].accounts[1] = 255;
    assert!(parse_from_transaction(&tx).is_err());
}

#[test]
fn nonce_with_wrong_sysvar_remains_unknown() {
    let mut tx = Transaction::from_bytes(&bytes()).unwrap();
    tx.message.instructions[0].accounts[1] = 3;
    let parsed = parse_from_transaction(&tx).unwrap();
    assert!(matches!(
        parsed.instructions_data[0],
        ParsedInstruction::Unknown(_)
    ));
    assert!(parsed.durable_nonce.is_none());
}
