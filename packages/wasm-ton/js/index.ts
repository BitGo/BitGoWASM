import * as wasm from "./wasm/wasm_ton.js";

// Force webpack to include the WASM module
void wasm;

// Namespace exports for explicit imports
export * as address from "./address.js";
export * as builder from "./builder.js";
export * as parser from "./parser.js";

// Top-level function exports for convenience
export { encodeAddress, decodeAddress, validateAddress } from "./address.js";
export { buildTransaction } from "./builder.js";
export { parseTransaction } from "./parser.js";
export { Transaction } from "./transaction.js";

// Type exports
export type { WalletVersion, EncodeAddressOptions, DecodedAddress } from "./address.js";
export type {
  TransactionIntent,
  BuildContext,
  Recipient,
  PaymentIntent,
  FillNonceIntent,
  ConsolidateIntent,
  DelegateIntent,
  UndelegateIntent,
  TonStakingType,
} from "./builder.js";
export type {
  TransactionType,
  ParsedTransaction,
  ParsedRecipient,
  ParsedJettonTransfer,
} from "./parser.js";

// Re-export WASM namespace for advanced usage
export {
  AddressNamespace,
  BuilderNamespace,
  ParserNamespace,
  WasmTransaction,
} from "./wasm/wasm_ton.js";
