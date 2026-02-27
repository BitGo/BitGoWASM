import * as bip39 from "bip39";
import { HDKey } from "@scure/bip32";

export function mnemonicToXprv(mnemonic: string): string {
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error("Invalid BIP39 mnemonic");
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  if (!master.privateExtendedKey) {
    throw new Error("Failed to derive private extended key from seed");
  }
  return master.privateExtendedKey;
}

export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic);
}
