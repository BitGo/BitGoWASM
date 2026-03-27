import { strict as assert } from "node:assert";
import { describe, it } from "mocha";
import { Transaction, parseTransaction } from "../js/index.js";

// =============================================================================
// Fixtures from BitGoJS sdk-coin-ton/test/resources/ton.ts
// =============================================================================

const signedSendTransaction = {
  tx: "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==",
  signable: "k4XUmjB65j3klMXCXdh5Vs3bJZzo3NSfnXK8NIYFayI=",
  recipient: {
    address: "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
    amount: "10000000",
  },
};

const signedTokenSendTransaction = {
  tx: "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==",
  signable: "rq4tq/sFuXVLcQSfyxDd7QuxOif/5BQwpm0gwOa+sOE=",
};

const signedWhalesDeposit = {
  tx: "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=",
  seqno: 92,
};

const signedWhalesWithdrawal = {
  tx: "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI",
  seqno: 93,
};

const signedSingleNominator = {
  tx: "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==",
  seqno: 0,
};

// =============================================================================
// Tests
// =============================================================================

describe("Transaction", () => {
  describe("fromBytes", () => {
    it("should deserialize a send transaction", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
      assert.equal(tx.seqno, 6);
      assert.equal(tx.hasStateInit, false);
    });

    it("should deserialize a token send transaction", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedTokenSendTransaction.tx, "base64"));
      assert.equal(tx.seqno, 0);
      assert.equal(tx.hasStateInit, true);
    });

    it("should deserialize a whales deposit", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedWhalesDeposit.tx, "base64"));
      assert.equal(tx.seqno, signedWhalesDeposit.seqno);
    });

    it("should deserialize a whales withdrawal", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedWhalesWithdrawal.tx, "base64"));
      assert.equal(tx.seqno, signedWhalesWithdrawal.seqno);
    });

    it("should deserialize a single nominator withdraw", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedSingleNominator.tx, "base64"));
      assert.equal(tx.seqno, signedSingleNominator.seqno);
      assert.equal(tx.hasStateInit, true);
    });
  });

  describe("signablePayload", () => {
    it("should match BitGoJS expected signable for send", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);

      // Convert to base64 and compare
      const b64 = btoa(String.fromCharCode(...payload));
      assert.equal(b64, signedSendTransaction.signable);
    });

    it("should match BitGoJS expected signable for token send", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedTokenSendTransaction.tx, "base64"));
      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);

      const b64 = btoa(String.fromCharCode(...payload));
      assert.equal(b64, signedTokenSendTransaction.signable);
    });
  });

  describe("addSignature + toBytes roundtrip", () => {
    it("should preserve transaction after add signature and re-serialize", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
      const originalPayload = tx.signablePayload();

      // Add a new signature
      const sig = new Uint8Array(64).fill(42);
      tx.addSignature(sig);

      // Re-serialize
      const bytes = tx.toBytes();
      const tx2 = Transaction.fromBytes(bytes);

      // Signable payload should be identical (signature doesn't affect sign body)
      const newPayload = tx2.signablePayload();
      assert.deepEqual(newPayload, originalPayload);
      assert.equal(tx2.seqno, tx.seqno);
    });
  });

  describe("toBroadcastFormat", () => {
    it("should return valid base64", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
      const broadcast = tx.toBroadcastFormat();

      // Should be a non-empty base64 string
      assert.ok(broadcast.length > 0);

      // Should parse back
      const tx2 = Transaction.fromBytes(Buffer.from(broadcast, "base64"));
      assert.equal(tx2.seqno, tx.seqno);
    });
  });

  describe("error handling", () => {
    it("should throw on invalid BOC content", () => {
      assert.throws(() => Transaction.fromBytes(Buffer.from("not-valid-boc", "utf-8")));
    });

    it("should throw on invalid BOC bytes", () => {
      assert.throws(() => Transaction.fromBytes(new Uint8Array([1, 2, 3, 4])));
    });

    it("should throw on invalid signature length", () => {
      const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
      assert.throws(() => tx.addSignature(new Uint8Array(63)));
      assert.throws(() => tx.addSignature(new Uint8Array(65)));
    });
  });
});

describe("parseTransaction", () => {
  it("should parse a send transaction", () => {
    const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
    const parsed = parseTransaction(tx);

    assert.equal(parsed.type, "Send");
    assert.equal(parsed.seqno, 6);
    assert.equal(parsed.outputs.length, 1);
    assert.equal(parsed.outputs[0].amount, 10_000_000n);
    assert.equal(parsed.outputAmount, 10_000_000n);
  });

  it("should parse a token send transaction", () => {
    const tx = Transaction.fromBytes(Buffer.from(signedTokenSendTransaction.tx, "base64"));
    const parsed = parseTransaction(tx);

    assert.equal(parsed.type, "SendToken");
    assert.equal(parsed.seqno, 0);
    assert.ok(parsed.jettonAmount !== undefined);
    assert.ok(parsed.jettonDestination !== undefined);
  });

  it("should parse a whales deposit", () => {
    const tx = Transaction.fromBytes(Buffer.from(signedWhalesDeposit.tx, "base64"));
    const parsed = parseTransaction(tx);

    assert.equal(parsed.type, "TonWhalesDeposit");
    assert.equal(parsed.seqno, signedWhalesDeposit.seqno);
    assert.equal(parsed.bounceable, true);
  });

  it("should parse a whales withdrawal", () => {
    const tx = Transaction.fromBytes(Buffer.from(signedWhalesWithdrawal.tx, "base64"));
    const parsed = parseTransaction(tx);

    assert.equal(parsed.type, "TonWhalesWithdrawal");
    assert.equal(parsed.seqno, signedWhalesWithdrawal.seqno);
    assert.equal(parsed.bounceable, true);
  });

  it("should parse a single nominator withdraw", () => {
    const tx = Transaction.fromBytes(Buffer.from(signedSingleNominator.tx, "base64"));
    const parsed = parseTransaction(tx);

    assert.equal(parsed.type, "SingleNominatorWithdraw");
    assert.equal(parsed.seqno, signedSingleNominator.seqno);
  });

  it("should return bigint amounts", () => {
    const tx = Transaction.fromBytes(Buffer.from(signedSendTransaction.tx, "base64"));
    const parsed = parseTransaction(tx);

    assert.equal(typeof parsed.outputAmount, "bigint");
    assert.equal(typeof parsed.expireTime, "bigint");
    assert.equal(typeof parsed.outputs[0].amount, "bigint");
  });
});
