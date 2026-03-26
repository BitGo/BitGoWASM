import * as assert from "assert";
import { Transaction } from "../js/transaction.js";
import { parseTransaction, TransactionType } from "../js/parser.js";

// Fixtures from BitGoJS sdk-coin-ton/test/resources/ton.ts

const signedSendTransaction = {
  tx: "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==",
  txId: "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI=",
  recipient: {
    address: "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
    amount: "10000000",
  },
};

const v3CompatibleSignedSendTransaction = {
  txBounceable:
    "te6cckEBAgEAqAAB34gB6PRRbBG9U/w5zruVAiyjjtuAoJQrbKx6iNEFbGT4q1oHBW0S6HI3Mqn+qZUL6E/GLQEBfdhXuswqDfR0WMiOFLIpITCTcMwZNRZL6yKqMb7Zfzi/A8YXdkVVgxgakEPAaU1NGLtH0CDAAAAAGBwBAGZiAGcJlmF0UvErDsi5Rs21SP70rP1K36wtjBImqtbV96EuHMS0AAAAAAAAAAAAAAAAAAAiW72E",
  txIdBounceable: "4i1GCyN5IkQQ-vESvNl4Wp1ejp7LfazRlNWzUbtGwSA=",
  recipient: {
    address: "EQDOEyzC6KXiVh2Rco2bapH96Vn6lb9YWxgkTVWtq-9CXL0m",
    amount: "10000000",
  },
};

const signedTokenSendTransaction = {
  tx: "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==",
  txId: "J9ncpPEo7P5Lx3TLLhTFKQ2OroGQ53rv2nSB3jYgJLQ=",
  recipient: {
    address: "EQB-CM6DF-jpq9XVdiSdefAMU5KC1gpZuYBFp-Q65aUhnx5K",
    amount: "1000000000",
  },
};

const signedSingleNominatorWithdrawTransaction = {
  tx: "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==",
  txId: "n1rr-QL61WZ7UJN7ESH2iPQO7toTy9WLqXoSIG1JtXg=",
  recipient: {
    address: "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
    amount: "123400000",
  },
};

const signedTonWhalesDepositTransaction = {
  tx: "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=",
  seqno: 92,
  recipient: {
    address: "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq",
    amount: "10000000000",
  },
};

const signedTonWhalesWithdrawalTransaction = {
  tx: "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI",
  seqno: 93,
  recipient: {
    address: "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq",
    amount: "200000000",
  },
};

describe("parseTransaction", () => {
  it("should parse a V4R2 send transaction", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.ok(parsed.seqno > 0);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(parsed.recipients[0].amount, BigInt(signedSendTransaction.recipient.amount));
    assert.ok(parsed.recipients[0].address.length > 0);
    assert.strictEqual(parsed.id, signedSendTransaction.txId);
    assert.strictEqual(parsed.walletVersion, "V4R2");
  });

  it("should parse a V3R2 send transaction", () => {
    const tx = Transaction.fromBase64(v3CompatibleSignedSendTransaction.txBounceable);
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.Send);
    assert.ok(parsed.seqno > 0);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(
      parsed.recipients[0].amount,
      BigInt(v3CompatibleSignedSendTransaction.recipient.amount),
    );
    assert.strictEqual(parsed.id, v3CompatibleSignedSendTransaction.txIdBounceable);
    assert.strictEqual(parsed.walletVersion, "V3R2");
  });

  it("should parse a token send transaction", () => {
    const tx = Transaction.fromBase64(signedTokenSendTransaction.tx);
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.SendToken);
    assert.ok(parsed.jettonTransfer !== undefined);
    assert.strictEqual(parsed.jettonTransfer!.amount, "1000000000");
    assert.ok(parsed.jettonTransfer!.forwardPayloadComment !== undefined);
    assert.strictEqual(parsed.jettonTransfer!.forwardPayloadComment, "jetton testing");
    assert.strictEqual(parsed.id, signedTokenSendTransaction.txId);
  });

  it("should parse a single nominator withdraw transaction", () => {
    const tx = Transaction.fromBase64(signedSingleNominatorWithdrawTransaction.tx);
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.SingleNominatorWithdraw);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(
      parsed.recipients[0].amount,
      BigInt(signedSingleNominatorWithdrawTransaction.recipient.amount),
    );
    assert.strictEqual(parsed.id, signedSingleNominatorWithdrawTransaction.txId);
  });

  it("should parse a Ton Whales deposit transaction", () => {
    const tx = Transaction.fromBase64(signedTonWhalesDepositTransaction.tx);
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.TonWhalesDeposit);
    assert.strictEqual(parsed.seqno, signedTonWhalesDepositTransaction.seqno);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(
      parsed.recipients[0].amount,
      BigInt(signedTonWhalesDepositTransaction.recipient.amount),
    );
  });

  it("should parse a Ton Whales withdrawal transaction", () => {
    const tx = Transaction.fromBase64(signedTonWhalesWithdrawalTransaction.tx);
    const parsed = parseTransaction(tx);

    assert.strictEqual(parsed.transactionType, TransactionType.TonWhalesWithdrawal);
    assert.strictEqual(parsed.seqno, signedTonWhalesWithdrawalTransaction.seqno);
    assert.strictEqual(parsed.recipients.length, 1);
    assert.strictEqual(
      parsed.recipients[0].amount,
      BigInt(signedTonWhalesWithdrawalTransaction.recipient.amount),
    );
  });

  it("should have sender address on all parsed transactions", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const parsed = parseTransaction(tx);
    assert.ok(parsed.sender.length > 0);
  });

  it("should have expire time and wallet id", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const parsed = parseTransaction(tx);
    assert.ok(parsed.expireTime > 0);
    assert.ok(parsed.walletId !== 0);
  });

  it("recipient amounts should be bigint", () => {
    const tx = Transaction.fromBase64(signedSendTransaction.tx);
    const parsed = parseTransaction(tx);
    assert.strictEqual(typeof parsed.recipients[0].amount, "bigint");
  });
});
