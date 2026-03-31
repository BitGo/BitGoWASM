import * as wasm from "./wasm/wasm_ton.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports
export * as address from "./address.js";
export * as transaction from "./transaction.js";
export * as parser from "./parser.js";
export * as builder from "./builder.js";

// Top-level function exports
export { encodeAddress, encode, decode, validate } from "./address.js";
export { Transaction, transactionFromBytes } from "./transaction.js";
export { parseTransaction } from "./parser.js";
export { buildTransaction } from "./builder.js";

// Type exports
export type { DecodedAddress } from "./address.js";
export type { ParsedTransaction, ParsedSendAction, JettonTransferFields } from "./parser.js";
export type {
  BuildContext,
  PaymentIntent,
  TokenPaymentIntent,
  FillNonceIntent,
  ConsolidateIntent,
  DelegateIntent,
  UndelegateIntent,
  TonIntent,
} from "./builder.js";

export { TonStakingType, TonTransactionType } from "./builder.js";

// Constants
export { default_wallet_id as defaultWalletId } from "./wasm/wasm_ton.js";
