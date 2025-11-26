import type { AddressFormat } from "./address.js";
import { UtxolibCompatNamespace } from "./wasm/wasm_utxo.js";

export type UtxolibName =
  | "bitcoin"
  | "testnet"
  | "bitcoinTestnet4"
  | "bitcoinPublicSignet"
  | "bitcoinBitGoSignet"
  | "bitcoincash"
  | "bitcoincashTestnet"
  | "ecash"
  | "ecashTest"
  | "bitcoingold"
  | "bitcoingoldTestnet"
  | "bitcoinsv"
  | "bitcoinsvTestnet"
  | "dash"
  | "dashTest"
  | "dogecoin"
  | "dogecoinTest"
  | "litecoin"
  | "litecoinTest"
  | "zcash"
  | "zcashTest";

export type UtxolibNetwork = {
  pubKeyHash: number;
  scriptHash: number;
  cashAddr?: {
    prefix: string;
    pubKeyHash: number;
    scriptHash: number;
  };
  bech32?: string;
};

export function fromOutputScript(
  script: Uint8Array,
  network: UtxolibNetwork,
  format?: AddressFormat,
): string {
  return UtxolibCompatNamespace.from_output_script(script, network, format);
}

export function toOutputScript(
  address: string,
  network: UtxolibNetwork,
  format?: AddressFormat,
): Uint8Array {
  return UtxolibCompatNamespace.to_output_script(address, network, format);
}
