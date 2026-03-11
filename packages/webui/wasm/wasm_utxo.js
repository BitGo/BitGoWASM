/* @ts-self-types="./wasm_utxo.d.ts" */

import * as wasm from "./wasm_utxo_bg.wasm";
import { __wbg_set_wasm } from "./wasm_utxo_bg.js";
__wbg_set_wasm(wasm);

export {
    AddressNamespace, Bip322Namespace, BitGoPsbt, FixedScriptWalletNamespace, InscriptionsNamespace, MessageNamespace, UtxolibCompatNamespace, WasmBIP32, WasmDashTransaction, WasmDimensions, WasmECPair, WasmReplayProtection, WasmRootWalletKeys, WasmTransaction, WasmZcashTransaction, WrapDescriptor, WrapMiniscript, WrapPsbt, isInspectEnabled, parsePsbtRawToJson, parsePsbtToJson, parseTxToJson
} from "./wasm_utxo_bg.js";
