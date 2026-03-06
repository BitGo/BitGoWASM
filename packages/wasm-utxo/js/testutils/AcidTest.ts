import { BitGoPsbt, type SignerKey } from "../fixedScriptWallet/BitGoPsbt.js";
import { ZcashBitGoPsbt } from "../fixedScriptWallet/ZcashBitGoPsbt.js";
import { RootWalletKeys } from "../fixedScriptWallet/RootWalletKeys.js";
import { BIP32 } from "../bip32.js";
import { ECPair } from "../ecpair.js";
import { Transaction } from "../transaction.js";
import {
  ChainCode,
  createOpReturnScript,
  inputScriptTypes,
  outputScript,
  outputScriptTypes,
  p2shP2pkOutputScript,
  supportsScriptType,
  type InputScriptType,
  type OutputScriptType,
  type ScriptId,
} from "../fixedScriptWallet/index.js";
import type { CoinName } from "../coinName.js";
import { coinNames, isMainnet } from "../coinName.js";
import { getDefaultWalletKeys, getWalletKeysForSeed, getKeyTriple } from "./keys.js";
import type { Triple } from "../triple.js";

export const signStages = ["unsigned", "halfsigned", "fullsigned"] as const;
export type SignStage = (typeof signStages)[number];

export const txFormats = ["psbt", "psbt-lite"] as const;
export type TxFormat = (typeof txFormats)[number];

/**
 * Utility type to make union variants mutually exclusive.
 * For each variant T in the union, adds `?: never` for all keys from other variants.
 */
type Exclusive<T, U = T> = T extends unknown
  ? T & Partial<Record<Exclude<U extends unknown ? keyof U : never, keyof T>, never>>
  : never;

/** Base input fields */
type InputBase = {
  value: bigint;
  /** Wallet keys to use. Defaults to root wallet keys */
  walletKeys?: RootWalletKeys;
};

/** Input variant types */
type InputVariant = { scriptType: InputScriptType; index?: number } | { scriptId: ScriptId };

/**
 * Input configuration for AcidTest PSBT
 *
 * Either specify `scriptType` (chain derived from type, index defaults to position)
 * or specify `scriptId` (explicit chain + index).
 */
export type Input = InputBase & Exclusive<InputVariant>;

/** Base output fields */
type OutputBase = {
  value: bigint;
  /** Wallet keys to use. Defaults to root wallet keys. null = external output (no bip32 derivation) */
  walletKeys?: RootWalletKeys | null;
};

/** Output variant types */
type OutputVariant =
  | { scriptType: OutputScriptType; index?: number }
  | { scriptId: ScriptId }
  | { opReturn: string }
  | { address: string }
  | { script: Uint8Array };

/**
 * Output configuration for AcidTest PSBT
 *
 * Specify one of:
 * - `scriptType` (chain derived from type, index defaults to position)
 * - `scriptId` (explicit chain + index)
 * - `opReturn` for OP_RETURN data output
 * - `address` for address-based output
 * - `script` for raw script output
 */
export type Output = OutputBase & Exclusive<OutputVariant>;

type SuiteConfig = {
  /**
   * By default, we exclude p2trMusig2ScriptPath from the inputs since
   * it uses user + backup keys (not typical 2-of-3 with user + bitgo).
   * Set to true to include this input type.
   */
  includeP2trMusig2ScriptPath?: boolean;
};

// Re-export for convenience
export { inputScriptTypes, outputScriptTypes };

/** Map InputScriptType to the OutputScriptType used for chain code derivation */
function inputScriptTypeToOutputScriptType(scriptType: InputScriptType): OutputScriptType {
  switch (scriptType) {
    case "p2sh":
    case "p2shP2wsh":
    case "p2wsh":
    case "p2trLegacy":
      return scriptType;
    case "p2shP2pk":
      return "p2sh";
    case "p2trMusig2ScriptPath":
    case "p2trMusig2KeyPath":
      return "p2trMusig2";
  }
}

/**
 * Creates a valid PSBT with as many features as possible (kitchen sink).
 *
 * - Inputs:
 *   - All wallet script types supported by the network
 *   - A p2shP2pk input (for replay protection)
 * - Outputs:
 *   - All wallet script types supported by the network
 *   - A p2sh output with derivation info of a different wallet
 *   - A p2sh output with no derivation info (external output)
 *   - An OP_RETURN output
 *
 * Signature stages:
 * - unsigned: No signatures
 * - halfsigned: One signature per input (user key)
 * - fullsigned: Two signatures per input (user + bitgo)
 *
 * Transaction formats:
 * - psbt: Full PSBT with non_witness_utxo
 * - psbt-lite: Only witness_utxo (no non_witness_utxo)
 */
export class AcidTest {
  public readonly network: CoinName;
  public readonly signStage: SignStage;
  public readonly txFormat: TxFormat;
  public readonly rootWalletKeys: RootWalletKeys;
  public readonly otherWalletKeys: RootWalletKeys;
  public readonly inputs: Input[];
  public readonly outputs: Output[];
  // Store private keys for signing
  private readonly userXprv: BIP32;
  private readonly backupXprv: BIP32;
  private readonly bitgoXprv: BIP32;

  constructor(
    network: CoinName,
    signStage: SignStage,
    txFormat: TxFormat,
    rootWalletKeys: RootWalletKeys,
    otherWalletKeys: RootWalletKeys,
    inputs: Input[],
    outputs: Output[],
    xprvTriple: Triple<BIP32>,
  ) {
    this.network = network;
    this.signStage = signStage;
    this.txFormat = txFormat;
    this.rootWalletKeys = rootWalletKeys;
    this.otherWalletKeys = otherWalletKeys;
    this.inputs = inputs;
    this.outputs = outputs;
    this.userXprv = xprvTriple[0];
    this.backupXprv = xprvTriple[1];
    this.bitgoXprv = xprvTriple[2];
  }

  /**
   * Create an AcidTest with specific configuration
   */
  static withConfig(
    network: CoinName,
    signStage: SignStage,
    txFormat: TxFormat,
    suiteConfig: SuiteConfig = {},
  ): AcidTest {
    const rootWalletKeys = getDefaultWalletKeys();
    const otherWalletKeys = getWalletKeysForSeed("too many secrets");
    const coin = network;

    // Filter inputs based on network support
    const inputs: Input[] = inputScriptTypes
      .filter((scriptType) => {
        // p2shP2pk is always supported (single-sig replay protection)
        if (scriptType === "p2shP2pk") return true;

        // Map input script types to output script types for support check
        if (scriptType === "p2trMusig2KeyPath" || scriptType === "p2trMusig2ScriptPath") {
          return supportsScriptType(coin, "p2trMusig2");
        }
        return supportsScriptType(coin, scriptType);
      })
      .filter(
        (scriptType) =>
          (suiteConfig.includeP2trMusig2ScriptPath ?? false) ||
          scriptType !== "p2trMusig2ScriptPath",
      )
      .map((scriptType, index) => ({
        scriptType,
        value: BigInt(10000 + index * 10000), // Deterministic amounts
      }));

    // Filter outputs based on network support
    const outputs: Output[] = outputScriptTypes
      .filter((scriptType) => supportsScriptType(coin, scriptType))
      .map((scriptType, index) => ({
        scriptType,
        value: BigInt(900 + index * 100), // Deterministic amounts
      }));

    // Test other wallet output (with derivation info)
    outputs.push({ scriptType: "p2sh", value: BigInt(800), walletKeys: otherWalletKeys });

    // Test non-wallet output (no derivation info)
    outputs.push({ scriptType: "p2sh", value: BigInt(700), walletKeys: null });

    // Test OP_RETURN output
    outputs.push({ opReturn: "setec astronomy", value: BigInt(0) });

    // Get private keys for signing
    const xprvTriple = getKeyTriple("default");

    return new AcidTest(
      network,
      signStage,
      txFormat,
      rootWalletKeys,
      otherWalletKeys,
      inputs,
      outputs,
      xprvTriple,
    );
  }

  /**
   * Get a human-readable name for this test configuration
   */
  get name(): string {
    return `${this.network} ${this.signStage} ${this.txFormat}`;
  }

  /**
   * Get the BIP32 user key for replay protection (p2shP2pk)
   */
  getReplayProtectionKey(): BIP32 {
    return this.rootWalletKeys.userKey();
  }

  /**
   * Create the actual PSBT with all inputs and outputs
   */
  createPsbt(): BitGoPsbt {
    // Use ZcashBitGoPsbt for Zcash networks
    const isZcash = this.network === "zec" || this.network === "tzec";
    const psbt = isZcash
      ? ZcashBitGoPsbt.createEmpty(this.network, this.rootWalletKeys, {
          // Sapling activation height: mainnet=419200, testnet=280000
          blockHeight: this.network === "zec" ? 419200 : 280000,
        })
      : BitGoPsbt.createEmpty(this.network, this.rootWalletKeys, {
          version: 2,
          lockTime: 0,
        });

    // Build a fake previous transaction for non_witness_utxo (psbt format)
    const usePrevTx = this.txFormat === "psbt" && !isZcash;
    const buildPrevTx = (
      vout: number,
      script: Uint8Array,
      value: bigint,
    ): Uint8Array | undefined => {
      if (!usePrevTx) return undefined;
      const tx = Transaction.create();
      tx.addInput("0".repeat(64), 0xffffffff);
      for (let i = 0; i < vout; i++) {
        tx.addOutput(new Uint8Array(0), 0n);
      }
      tx.addOutput(script, value);
      return tx.toBytes();
    };

    // Add inputs with deterministic outpoints
    this.inputs.forEach((input, index) => {
      const walletKeys = input.walletKeys ?? this.rootWalletKeys;
      const outpoint = { txid: "0".repeat(64), vout: index, value: input.value };

      // scriptId variant: caller provides explicit chain + index
      if (input.scriptId) {
        const script = outputScript(
          walletKeys,
          input.scriptId.chain,
          input.scriptId.index,
          this.network,
        );
        psbt.addWalletInput(
          { ...outpoint, prevTx: buildPrevTx(index, script, input.value) },
          walletKeys,
          { scriptId: input.scriptId, signPath: { signer: "user", cosigner: "bitgo" } },
        );
        return;
      }

      const scriptType = input.scriptType ?? "p2sh";

      if (scriptType === "p2shP2pk") {
        const ecpair = ECPair.fromPublicKey(this.getReplayProtectionKey().publicKey);
        const script = p2shP2pkOutputScript(ecpair.publicKey);
        psbt.addReplayProtectionInput(
          { ...outpoint, prevTx: buildPrevTx(index, script, input.value) },
          ecpair,
        );
        return;
      }

      const scriptId: ScriptId = {
        chain: ChainCode.value(inputScriptTypeToOutputScriptType(scriptType), "external"),
        index: input.index ?? index,
      };
      const signPath: { signer: SignerKey; cosigner: SignerKey } =
        scriptType === "p2trMusig2ScriptPath"
          ? { signer: "user", cosigner: "backup" }
          : { signer: "user", cosigner: "bitgo" };
      const script = outputScript(walletKeys, scriptId.chain, scriptId.index, this.network);

      psbt.addWalletInput(
        { ...outpoint, prevTx: buildPrevTx(index, script, input.value) },
        walletKeys,
        { scriptId, signPath },
      );
    });

    // Add outputs
    this.outputs.forEach((output, index) => {
      if (output.opReturn !== undefined) {
        // OP_RETURN output
        const data = new TextEncoder().encode(output.opReturn);
        const script = createOpReturnScript(data);
        psbt.addOutput(script, output.value);
      } else if (output.address !== undefined) {
        // Address-based output
        psbt.addOutput(output.address, output.value);
      } else if (output.script !== undefined) {
        // Raw script output
        psbt.addOutput(output.script, output.value);
      } else {
        // Wallet output: resolve scriptId from scriptType or explicit scriptId
        const scriptId: ScriptId = output.scriptId ?? {
          chain: output.scriptType ? ChainCode.value(output.scriptType, "external") : 0,
          index: output.index ?? index,
        };

        if (output.walletKeys === null) {
          // External output (no wallet keys, no bip32 derivation)
          // Use high index for external outputs if not specified
          const externalScriptId: ScriptId = output.scriptId ?? {
            chain: scriptId.chain,
            index: output.index ?? 1000 + index,
          };
          const script = outputScript(
            this.rootWalletKeys,
            externalScriptId.chain,
            externalScriptId.index,
            this.network,
          );
          psbt.addOutput(script, output.value);
        } else {
          // Wallet output (with or without different wallet keys)
          const walletKeys = output.walletKeys ?? this.rootWalletKeys;
          psbt.addWalletOutput(walletKeys, {
            chain: scriptId.chain,
            index: scriptId.index,
            value: output.value,
          });
        }
      }
    });

    // Apply signing based on stage
    if (this.signStage !== "unsigned") {
      this.signPsbt(psbt);
    }

    return psbt;
  }

  /**
   * Sign the PSBT according to the sign stage
   */
  private signPsbt(psbt: BitGoPsbt): void {
    // Use private keys stored in constructor
    const userKey = this.userXprv;
    const backupKey = this.backupXprv;
    const bitgoKey = this.bitgoXprv;

    // Generate MuSig2 nonces for user if needed
    const hasMusig2Inputs = this.inputs.some(
      (input) =>
        input.scriptType === "p2trMusig2KeyPath" || input.scriptType === "p2trMusig2ScriptPath",
    );

    if (hasMusig2Inputs) {
      if (this.network === "zec" || this.network === "tzec") {
        throw new Error("Zcash does not support MuSig2/Taproot inputs");
      }

      // MuSig2 requires ALL participant nonces before ANY signing.
      // Generate nonces directly on the same PSBT for each participant key.
      psbt.generateMusig2Nonces(userKey);

      const hasKeyPath = this.inputs.some((input) => input.scriptType === "p2trMusig2KeyPath");
      const hasScriptPath = this.inputs.some(
        (input) => input.scriptType === "p2trMusig2ScriptPath",
      );

      // Key path uses user+bitgo, script path uses user+backup.
      // generateMusig2Nonces fails if the key isn't a participant in any musig2 input,
      // so we only call it for keys that match.
      if (hasKeyPath) {
        psbt.generateMusig2Nonces(bitgoKey);
      }
      if (hasScriptPath) {
        psbt.generateMusig2Nonces(backupKey);
      }
    }

    // Sign all wallet inputs with user key (bulk - more efficient)
    psbt.sign(userKey);

    // Sign replay protection inputs with raw private key
    const hasReplayProtection = this.inputs.some((input) => input.scriptType === "p2shP2pk");
    if (hasReplayProtection) {
      if (!userKey.privateKey) {
        throw new Error("User key must have private key for signing replay protection inputs");
      }
      psbt.sign(userKey.privateKey);
    }

    // For fullsigned, sign with cosigner
    if (this.signStage === "fullsigned") {
      const hasScriptPath = this.inputs.some(
        (input) => input.scriptType === "p2trMusig2ScriptPath",
      );

      if (hasScriptPath) {
        // Mixed case: script path uses backup, others use bitgo
        // Need per-input signing (slow) to handle different cosigners
        this.inputs.forEach((input, index) => {
          if (input.scriptType === "p2shP2pk") {
            // Replay protection is single-sig, already fully signed
            return;
          }
          if (input.scriptType === "p2trMusig2ScriptPath") {
            psbt.signInput(index, backupKey);
          } else {
            psbt.signInput(index, bitgoKey);
          }
        });
      } else {
        // No script path - can use bulk signing with bitgo (fast)
        psbt.sign(bitgoKey);
      }
    }
  }

  /**
   * Generate test suite for all networks, sign stages, and tx formats
   */
  static forAllNetworksSignStagesTxFormats(suiteConfig: SuiteConfig = {}): AcidTest[] {
    return coinNames
      .filter((network): network is CoinName => isMainnet(network) && network !== "bsv")
      .flatMap((network) =>
        signStages.flatMap((signStage) =>
          txFormats.map((txFormat) =>
            AcidTest.withConfig(network, signStage, txFormat, suiteConfig),
          ),
        ),
      );
  }
}
