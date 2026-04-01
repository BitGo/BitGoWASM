import { strict as assert } from "assert";
import { Transaction, parseTransaction } from "../js/index.js";

// Test fixtures from BitGoJS sdk-coin-ton
const signedSendTx =
  "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

const whalesDepositTx =
  "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

const singleNominatorWithdrawTx =
  "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

function fromBase64(b64: string): Transaction {
  return Transaction.fromBytes(Buffer.from(b64, "base64"));
}

describe("Transaction", () => {
  describe("fromBytes", () => {
    it("should deserialize a signed send transaction", () => {
      const tx = fromBase64(signedSendTx);
      assert.ok(tx);
      assert.ok(tx.destination);
    });

    it("should compute cell hash as transaction id", () => {
      const tx = fromBase64(signedSendTx);
      // Cell hash of the root external message cell, base64url with padding
      assert.equal(tx.id, "tuyOkyFUMv_neV_FeNBH24Nd4cML2jUgDP4zjGkuOFI=");
    });

    it("should compute correct id for single nominator withdraw", () => {
      const tx = fromBase64(singleNominatorWithdrawTx);
      // Must match legacy TonWeb hash, not the re-serialized cell hash
      assert.equal(tx.id, "n1rr-QL61WZ7UJN7ESH2iPQO7toTy9WLqXoSIG1JtXg=");
    });

    it("should get signable payload", () => {
      const tx = fromBase64(signedSendTx);
      const payload = tx.signablePayload();
      assert.equal(payload.length, 32);
    });

    it("should serialize to broadcast format", () => {
      const tx = fromBase64(signedSendTx);
      const broadcast = tx.toBroadcastFormat();
      assert.ok(broadcast.length > 0);
    });
  });

  describe("parseTransaction", () => {
    it("should parse a transfer transaction", () => {
      const tx = fromBase64(signedSendTx);
      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, "Transfer");
      assert.ok(parsed.sendActions.length > 0);
      assert.ok(parsed.sender);
      assert.ok(parsed.signature);
      assert.equal(parsed.sendActions[0].withdrawAmount, undefined);
    });

    it("should parse a whales deposit transaction", () => {
      const tx = fromBase64(whalesDepositTx);
      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, "WhalesDeposit");
      assert.ok(parsed.sendActions.length > 0);
      assert.equal(parsed.sendActions[0].withdrawAmount, undefined);
    });

    it("should parse a single nominator withdraw transaction with withdrawAmount", () => {
      const tx = fromBase64(singleNominatorWithdrawTx);
      const parsed = parseTransaction(tx);
      assert.equal(parsed.transactionType, "SingleNominatorWithdraw");
      assert.ok(parsed.sendActions.length > 0);
      assert.equal(typeof parsed.sendActions[0].withdrawAmount, "bigint");
      assert.equal(parsed.sendActions[0].withdrawAmount, 932178112330000n);
    });
  });
});
