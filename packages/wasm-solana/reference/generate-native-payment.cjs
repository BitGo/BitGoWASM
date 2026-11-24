// Test-only reference generator. Run with @solana/web3.js 1.66.1 on NODE_PATH.
// Every public key, signature byte and amount is independently invented.
const {
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
} = require("@solana/web3.js");

function key(byte) {
  return new PublicKey(Buffer.alloc(32, byte));
}

const source = key(1);
const nonceAuthority = key(2);
const nonceAccount = key(3);
const destination = key(4);
const blockhash = key(5).toBase58();
const memoProgram = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

const tx = new Transaction({ feePayer: source, recentBlockhash: blockhash });
tx.add(SystemProgram.nonceAdvance({ noncePubkey: nonceAccount, authorizedPubkey: nonceAuthority }));
tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 200000 }));
tx.add(
  new TransactionInstruction({ programId: memoProgram, keys: [], data: Buffer.from("synthetic") }),
);
tx.add(SystemProgram.transfer({ fromPubkey: source, toPubkey: destination, lamports: 123456789 }));
tx.add(SystemProgram.transfer({ fromPubkey: source, toPubkey: destination, lamports: 0 }));
tx.addSignature(nonceAuthority, Buffer.alloc(64, 9)); // unverified test bytes

const message = tx.compileMessage();
const output = {
  reference: "@solana/web3.js 1.66.1",
  transactionBase64: tx
    .serialize({ requireAllSignatures: false, verifySignatures: false })
    .toString("base64"),
  messageBase64: tx.serializeMessage().toString("base64"),
  source: source.toBase58(),
  nonceAuthority: nonceAuthority.toBase58(),
  nonceAccount: nonceAccount.toBase58(),
  destination: destination.toBase58(),
  blockhash,
  accountKeys: message.accountKeys.map((address) => address.toBase58()),
};
process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
