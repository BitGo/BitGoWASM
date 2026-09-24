import { test, expect } from "@playwright/test";

const MARINADE_STAKING_ACTIVATE =
  "AuRFS0r7hJ+/+WuDQbbwdjSgxfnKOWi94EnWEha9uaBPt8VZOXiOoSiSoES34VkyBNLlLqlfK0fP3d5eJR+srQvN04gqzpOZPTVzqiomyMXqwQ6FYoQg5nEkdiDVny8SsyhRnAeDMzexkKD+3rwSGP0E+XN/2crTL6PZRnip42YFAgADBUXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItBYnsvugEnYfm5Gbz5TLtMncgFHZ8JMpkxTTlJIzJovekAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAah2BeRN1QqmDQ3vf4qerJVf1NcinhyK2ikncAAAAAABqfVFxksXFEhjMlMPUrxf1ja7gibof1E49vZigAAAADjMtr5L6vs6LY/96RABeX9/Zr6FYdWthxalfkEs7jQgQICAgABNAAAAADgkwQAAAAAAMgAAAAAAAAABqHYF5E3VCqYNDe9/ip6slV/U1yKeHIraKSdwAAAAAADAgEEdAAAAACx+Xl4mhxH0TxI2HovJxcQ63+TJglRFzFikL1sKdr12UXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItBAAAAAAAAAAAAAAAAAAAAAEXlebz5JTz2i0ff8fs6OlwsIbrFsjwJrhKm4FVr8ItB";

test("stake initialization renders all lockup fields with a warning", async ({ page }) => {
  await page.goto("/#/wasm-solana/transaction");
  const parser = page.locator("solana-transaction-parser");
  await parser.locator("#tx-input").fill(MARINADE_STAKING_ACTIVATE);

  const instruction = parser
    .locator(".instruction-card")
    .filter({ hasText: "Stake Initialize" });
  await expect(instruction).toBeVisible();
  await expect(instruction.locator(".stake-lockup-warning")).toContainText(
    "Non-default stake lockup",
  );
  await expect(instruction.locator(".instruction-params > span")).toHaveText([
    "stakingAddress",
    "7dRuGFbU2y2kijP6o1LYNzVyz4yf13MooqoionCzv5Za",
    "staker",
    "CyjoLt3kjqB57K7ewCBHmnHq3UgEj3ak6A7m6EsBsuhA",
    "withdrawer",
    "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
    "lockup.unixTimestamp",
    "0",
    "lockup.epoch",
    "0",
    "lockup.custodian",
    "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
  ]);
});
