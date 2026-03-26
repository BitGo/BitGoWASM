/**
 * Parser tests: verify parseTransaction output matches BitGoJS expectations.
 */
import * as assert from "assert";
import { Transaction } from "../js/transaction.js";
import { parseTransaction, TonTransactionType } from "../js/parser.js";

describe("parseTransaction", () => {
  // From BitGoJS sdk-coin-ton test/resources/ton.ts
  const SIGNED_SEND_TX =
    "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

  describe("simple send transaction", () => {
    it("should parse transaction type as Send", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.transactionType, TonTransactionType.Send);
    });

    it("should parse sender address", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.ok(parsed.sender);
      assert.strictEqual(typeof parsed.sender, "string");
      // Sender should be a base64url address
      assert.ok(parsed.sender.length > 0);
    });

    it("should parse destination address", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.ok(parsed.destination);
      assert.strictEqual(typeof parsed.destination, "string");
    });

    it("should parse amount as bigint", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(typeof parsed.amount, "bigint");
      // 10000000 nanoTON = 0.01 TON
      assert.strictEqual(parsed.amount, 10000000n);
    });

    it("should parse seqno", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(typeof parsed.seqno, "number");
      assert.strictEqual(parsed.seqno, 6);
    });

    it("should detect signed state", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.isSigned, true);
    });

    it("should have a transaction ID", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.ok(parsed.id);
      assert.strictEqual(typeof parsed.id, "string");
    });

    it("should parse expiration time as bigint", () => {
      const tx = Transaction.fromBase64(SIGNED_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(typeof parsed.expirationTime, "bigint");
      assert.ok(parsed.expirationTime > 0n);
    });
  });

  describe("bounceable send transaction", () => {
    // Bounceable version of the same send tx
    const BOUNCEABLE_SEND_TX =
      "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmYgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAYubM0w==";

    it("should parse bounceable destination", () => {
      const tx = Transaction.fromBase64(BOUNCEABLE_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.bounceable, true);
    });
  });

  describe("Whales deposit transaction", () => {
    const WHALES_DEPOSIT_TX =
      "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    it("should detect TonWhalesDeposit type", () => {
      const tx = Transaction.fromBase64(WHALES_DEPOSIT_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.transactionType, TonTransactionType.TonWhalesDeposit);
    });

    it("should parse as bounceable", () => {
      const tx = Transaction.fromBase64(WHALES_DEPOSIT_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.bounceable, true);
    });
  });

  describe("Whales withdrawal transaction", () => {
    const WHALES_WITHDRAW_TX =
      "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    it("should detect TonWhalesWithdrawal type", () => {
      const tx = Transaction.fromBase64(WHALES_WITHDRAW_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.transactionType, TonTransactionType.TonWhalesWithdrawal);
    });
  });

  describe("Single nominator withdraw transaction", () => {
    const SINGLE_NOMINATOR_TX =
      "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    it("should detect SingleNominatorWithdraw type", () => {
      const tx = Transaction.fromBase64(SINGLE_NOMINATOR_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.transactionType, TonTransactionType.SingleNominatorWithdraw);
    });
  });

  describe("Token send transaction", () => {
    const TOKEN_SEND_TX =
      "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    it("should detect SendToken type", () => {
      const tx = Transaction.fromBase64(TOKEN_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(parsed.transactionType, TonTransactionType.SendToken);
    });

    it("should parse amount as bigint", () => {
      const tx = Transaction.fromBase64(TOKEN_SEND_TX);
      const parsed = parseTransaction(tx);
      assert.strictEqual(typeof parsed.amount, "bigint");
    });
  });
});
