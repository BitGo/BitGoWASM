import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import type { IWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import { BIP32, type BIP32Interface } from "../../js/bip32.js";
import { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import { ECPair } from "../../js/ecpair.js";
import { fixedScriptWallet } from "../../js/index.js";
import type { BitGoPsbt } from "../../js/fixedScriptWallet/index.js";
import type { CoinName } from "../../js/coinName.js";
import { getFixture } from "../fixtures.js";
import { generateAllStates } from "./generateFixture.js";
import type { TxFormat } from "../../js/testutils/AcidTest.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export type SignatureState = "unsigned" | "halfsigned" | "fullsigned";

export type Triple<T> = [T, T, T];

export type Bip32Derivation = {
  pubkey: string;
  path: string;
};

export type TapBip32Derivation = Bip32Derivation;

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
 * Get BitGoPsbt from a fixture
 * @param fixture - The test fixture
 * @param networkName - The network name for deserializing the PSBT
 * @returns A BitGoPsbt instance
 */
export function getBitGoPsbt(fixture: Fixture, networkName: CoinName): BitGoPsbt {
  return fixedScriptWallet.BitGoPsbt.fromBytes(getPsbtBuffer(fixture), networkName);
}

function getFixturePath(
  network: string,
  signatureState: string,
  txFormat: TxFormat = "psbt-lite",
): string {
  return path.join(
    __dirname,
    "..",
    "fixtures",
    "fixed-script",
    `${txFormat}.${network}.${signatureState}.json`,
  );
}

const SIGNATURE_STATES: SignatureState[] = ["unsigned", "halfsigned", "fullsigned"];

/**
 * Load a PSBT fixture from JSON file.
 * If the fixture does not exist, generates all three signature states
 * (unsigned, halfsigned, fullsigned) and writes them to disk.
 */
export async function loadPsbtFixture(
  network: CoinName,
  signatureState: SignatureState,
  txFormat: TxFormat = "psbt-lite",
): Promise<Fixture> {
  const fixturePath = getFixturePath(network, signatureState, txFormat);
  return getFixture(fixturePath, () => {
    const allStates = generateAllStates(network, txFormat);
    // Write sibling states so all three are consistent
    for (const state of SIGNATURE_STATES) {
      if (state !== signatureState) {
        const siblingPath = getFixturePath(network, state, txFormat);
        fs.mkdirSync(path.dirname(siblingPath), { recursive: true });
        fs.writeFileSync(siblingPath, JSON.stringify(allStates[state], null, 2));
      }
    }
    return allStates[signatureState];
  }) as Promise<Fixture>;
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
