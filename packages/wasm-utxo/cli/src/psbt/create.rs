use anyhow::Result;
use wasm_utxo::bitcoin::locktime::absolute::LockTime;
use wasm_utxo::bitcoin::psbt::Psbt;
use wasm_utxo::bitcoin::transaction::{Transaction, Version};

use super::common::print_psbt;

pub fn handle_create_command(version: i32, lock_time: u32) -> Result<()> {
    let tx = Transaction {
        version: Version(version),
        lock_time: LockTime::from_consensus(lock_time),
        input: vec![],
        output: vec![],
    };
    let psbt = Psbt::from_unsigned_tx(tx).expect("empty transaction should be valid");
    print_psbt(&psbt);
    Ok(())
}
