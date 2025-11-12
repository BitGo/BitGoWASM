import * as fs from "node:fs";
import * as path from "node:path";
import * as utxolib from "@bitgo/utxo-lib";

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
  extractedTransaction: any | null;
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
export function loadWalletKeysFromFixture(network: string): utxolib.bitgo.RootWalletKeys {
  const fixturePath = path.join(
    __dirname,
    "..",
    "fixtures",
    "fixed-script",
    `psbt-lite.${network}.fullsigned.json`,
  );
  const fixtureContent = fs.readFileSync(fixturePath, "utf-8");
  const fixture = JSON.parse(fixtureContent) as Fixture;

  // Parse xprvs and convert to xpubs
  const xpubs = fixture.walletKeys.map((xprv) => {
    const key = utxolib.bip32.fromBase58(xprv);
    return key.neutered();
  });

  return new utxolib.bitgo.RootWalletKeys(xpubs as Triple<utxolib.BIP32Interface>);
}
