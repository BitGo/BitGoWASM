import * as wasm from "./wasm/wasm_ton.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as address from "./address.js";

// Transaction class
export { Transaction } from "./transaction.js";

// Parser function and types
export { parseTransaction } from "./parser.js";
export type { ParsedTransaction, TonTransactionType } from "./parser.js";

// Builder function and types
export { buildTransaction } from "./builder.js";
export type {
  TonIntent,
  TonBuildContext,
  PaymentIntent,
  JettonTransferIntent,
  SingleNominatorWithdrawIntent,
  TonWhalesDepositIntent,
  TonWhalesWithdrawalIntent,
  TonWhalesVestingDepositIntent,
  TonWhalesVestingWithdrawalIntent,
} from "./builder.js";

// Type exports
export type { AddressInfo } from "./address.js";
