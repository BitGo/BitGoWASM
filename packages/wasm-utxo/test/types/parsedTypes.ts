/**
 * Compile-time type tests for the generic parsed-input type parameter.
 *
 * Nothing here runs — these are type-level assertions checked by `tsc`; the exported
 * functions exist only to anchor the annotations. A mismatch fails `npm run build:test`.
 */
import {
  BitGoPsbt,
  type ParsedOutput,
  type ParsedTransaction,
} from "../../js/fixedScriptWallet/BitGoPsbt.js";
import {
  ZcashBitGoPsbt,
  type ZcashNetworkName,
  type ZcashParsedInput,
  type ZcashParsedOutput,
} from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import {
  ZcashIronwoodBitGoPsbt,
  type ZcashIronwoodParsedOutput,
  type ZcashIronwoodParsedTransaction,
} from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import type { ZcashShieldedSpend } from "../../js/fixedScriptWallet/ZcashIronwoodTypes.js";
import type { WalletKeysArg } from "../../js/fixedScriptWallet/RootWalletKeys.js";

/** A coin-specific output type a caller might plug into `BitGoPsbt<X>`. */
type CustomOutput = ParsedOutput & { extra: boolean };

// Existing `BitGoPsbt<X>` / `ParsedTransaction<X>` usages keep compiling (TInput defaults).
type ExistingTransaction = ParsedTransaction<CustomOutput>;
const existingTx: ExistingTransaction = {
  inputs: [],
  outputs: [
    {
      address: null,
      script: new Uint8Array(),
      value: 1n,
      scriptId: null,
      paygo: false,
      derivationPath: null,
      extra: true,
    },
  ],
  spendAmount: 1n,
  minerFee: 0n,
  virtualSize: 1,
};
// A `TInput` narrower than `ParsedInput` flows through the second parameter.
type CustomTransaction = ParsedTransaction<CustomOutput, ZcashParsedInput>;
const customInput: ZcashParsedInput = {
  previousOutput: { txid: "", vout: 0 },
  address: "",
  script: new Uint8Array(),
  value: 1n,
  scriptId: null,
  scriptType: "p2sh",
  sequence: 0,
  derivationPath: null,
  isShielded: false,
};
const customTx: CustomTransaction = { ...existingTx, inputs: [customInput] };
void customTx;
// `ZcashIronwoodBitGoPsbt.fromBytes(...)` is assignable to the generic base.
function fromBytesIsAssignable(): BitGoPsbt {
  return ZcashIronwoodBitGoPsbt.fromBytes(new Uint8Array(0), "zcashTest" as ZcashNetworkName);
}
void fromBytesIsAssignable;

// The Ironwood parse narrows on `inputKind`.
declare const ironwoodPsbt: ZcashIronwoodBitGoPsbt;
declare const ironwoodKeys: WalletKeysArg;

function narrowIronwoodParse(): ZcashIronwoodParsedOutput[] {
  const parsed: ZcashIronwoodParsedTransaction = ironwoodPsbt.parseTransactionWithWalletKeys(
    ironwoodKeys,
    {
      replayProtection: { publicKeys: [] },
    },
  );
  const outputs: ZcashIronwoodParsedOutput[] = parsed.outputs;
  if (parsed.inputKind === "shielded") {
    // `inputs` is exactly `[]` and `shieldedSpends` is a real (non-empty) array type.
    const emptyInputs: [] = parsed.inputs;
    const spends: ZcashShieldedSpend[] = parsed.shieldedSpends;
    void emptyInputs;
    void spends;
  } else {
    // `shieldedSpends` is exactly `[]` on the transparent arm.
    const emptySpends: [] = parsed.shieldedSpends;
    void emptySpends;
  }
  return outputs;
}
void narrowIronwoodParse;

// The Zcash base class keeps its parse surface with narrowed input/output types.
function zcashBaseParse(
  psbt: ZcashBitGoPsbt,
): ParsedTransaction<ZcashParsedOutput, ZcashParsedInput> {
  return psbt.parseTransactionWithWalletKeys(ironwoodKeys, {
    replayProtection: { publicKeys: [] },
  });
}
void zcashBaseParse;
