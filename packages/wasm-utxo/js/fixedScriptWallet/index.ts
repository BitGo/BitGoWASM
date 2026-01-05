export { RootWalletKeys, type WalletKeysArg, type IWalletKeys } from "./RootWalletKeys.js";
export { ReplayProtection, type ReplayProtectionArg } from "./ReplayProtection.js";
export { outputScript, address } from "./address.js";
export { Dimensions } from "./Dimensions.js";

// Bitcoin-like PSBT (for all non-Zcash networks)
export {
  BitGoPsbt,
  type NetworkName,
  type ScriptId,
  type InputScriptType,
  type ParsedInput,
  type ParsedOutput,
  type ParsedTransaction,
  type SignPath,
  type CreateEmptyOptions,
  type AddInputOptions,
  type AddOutputOptions,
  type AddWalletInputOptions,
  type AddWalletOutputOptions,
} from "./BitGoPsbt.js";

// Zcash-specific PSBT subclass
export {
  ZcashBitGoPsbt,
  type ZcashNetworkName,
  type CreateEmptyZcashOptions,
} from "./ZcashBitGoPsbt.js";
