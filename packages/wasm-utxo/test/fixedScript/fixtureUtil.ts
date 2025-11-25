import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import type { IWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import { BIP32, type BIP32Interface } from "../../js/bip32.js";
import { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import { ECPair } from "../../js/ecpair.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export type SignatureState = "unsigned" | "halfsigned" | "fullsigned";

export type Triple<T> = [T, T, T];

export type Bip32Derivation = {
  masterFingerprint: string;
  pubkey: string;
  path: string;
};

export type TapBip32Derivation = Bip32Derivation & {
  leafHashes: string[];
};

export type WitnessUtxo = {
  value: string;
  script: string;
};

export type TapLeafScript = {
  controlBlock: string;
  script: string;
  leafVersion: number;
};

export type PsbtInput = {
  type: string;
  sighashType: number;
  redeemScript?: string;
  witnessScript?: string;
  bip32Derivation?: Bip32Derivation[];
  tapBip32Derivation?: TapBip32Derivation[];
  witnessUtxo?: WitnessUtxo;
  tapLeafScript?: TapLeafScript[];
  tapInternalKey?: string;
  tapMerkleRoot?: string;
  musig2Participants?: {
    tapOutputKey: string;
    tapInternalKey: string;
    participantPubKeys: string[];
  };
  unknownKeyVals?: Array<{ key: string; value: string }>;
};

export type Input = {
  hash: string;
  index: number;
  sequence: number;
};

export type Output = {
  script: string;
  value: string;
  address?: string;
};

export type TapTreeLeaf = {
  depth: number;
  leafVersion: number;
  script: string;
};

export type PsbtOutput = {
  redeemScript?: string;
  witnessScript?: string;
  bip32Derivation?: Bip32Derivation[];
  tapBip32Derivation?: TapBip32Derivation[];
  tapInternalKey?: string;
  tapTree?: {
    leaves: TapTreeLeaf[];
  };
};

export type Fixture = {
  walletKeys: [string, string, string];
  psbtBase64: string;
  psbtBase64Finalized: string | null;
  inputs: Input[];
  psbtInputs: PsbtInput[];
  psbtInputsFinalized: PsbtInput[] | null;
  outputs: Output[];
  psbtOutputs: PsbtOutput[];
  extractedTransaction: string | null;
};

/**
 * Get PSBT buffer from a fixture
 */
export function getPsbtBuffer(fixture: Fixture): Buffer {
  return Buffer.from(fixture.psbtBase64, "base64");
}

/**
 * Load a PSBT fixture from JSON file
 */
export function loadPsbtFixture(network: string, signatureState: string): Fixture {
  const fixturePath = path.join(
    __dirname,
    "..",
    "fixtures",
    "fixed-script",
    `psbt-lite.${network}.${signatureState}.json`,
  );
  const fixtureContent = fs.readFileSync(fixturePath, "utf-8");
  return JSON.parse(fixtureContent) as Fixture;
}

/**
 * Load wallet keys from fixture
 */
export function loadWalletKeysFromFixture(fixture: Fixture): RootWalletKeys {
  // Parse xprvs and convert to xpubs
  const xpubs = fixture.walletKeys.map((xprv) => {
    const key = BIP32.fromBase58(xprv);
    return key.neutered();
  }) as unknown as Triple<BIP32Interface>;

  const walletKeysLike: IWalletKeys = {
    triple: xpubs,
    derivationPrefixes: ["0/0", "0/0", "0/0"],
  };

  return RootWalletKeys.from(walletKeysLike);
}

export function loadReplayProtectionKeyFromFixture(fixture: Fixture): ECPair {
  // underived user key
  const userBip32 = BIP32.fromBase58(fixture.walletKeys[0]);
  assert(userBip32.privateKey);
  const userECPair = ECPair.fromPrivateKey(Buffer.from(userBip32.privateKey));
  return userECPair;
}

/**
 * Get extracted transaction hex from fixture
 */
export function getExtractedTransactionHex(fixture: Fixture): string {
  if (fixture.extractedTransaction === null) {
    throw new Error("Fixture does not have an extracted transaction");
  }
  return fixture.extractedTransaction;
}
