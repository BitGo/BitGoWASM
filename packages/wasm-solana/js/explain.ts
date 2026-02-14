/**
 * High-level transaction explanation.
 *
 * Builds on top of `parseTransaction` (WASM) to provide a structured
 * "explain" view of a Solana transaction: type, outputs, inputs, fee, etc.
 *
 * The WASM parser returns raw individual instructions. This module combines
 * related instruction sequences into higher-level operations and derives the
 * overall transaction type.
 */

import { parseTransaction } from "./parser.js";
import type { InstructionParams, ParsedTransaction } from "./parser.js";

// =============================================================================
// Public types
// =============================================================================

export interface ExplainOptions {
  lamportsPerSignature: bigint | number | string;
  tokenAccountRentExemptAmount?: bigint | number | string;
}

export interface ExplainedOutput {
  address: string;
  amount: string;
  tokenName?: string;
}

export interface ExplainedInput {
  address: string;
  value: string;
}

export interface ExplainedTransaction {
  /** Transaction ID (base58 signature). Undefined if the transaction is unsigned. */
  id: string | undefined;
  type: string;
  feePayer: string;
  fee: string;
  blockhash: string;
  durableNonce?: { walletNonceAddress: string; authWalletAddress: string };
  outputs: ExplainedOutput[];
  inputs: ExplainedInput[];
  outputAmount: string;
  memo?: string;
  /**
   * Maps ATA address → owner address for CreateAssociatedTokenAccount instructions.
   * Allows resolving newly-created token account ownership without an external lookup.
   */
  ataOwnerMap: Record<string, string>;
  numSignatures: number;
}

// =============================================================================
// Instruction combining
// =============================================================================

// Solana native staking requires 3 separate instructions:
//   CreateAccount (fund the stake account) + StakeInitialize (set authorities) + DelegateStake (pick validator)
// Semantically this is a single "activate stake" operation.
// Marinade staking uses only CreateAccount + StakeInitialize (no Delegate) because
// Marinade's staker authority is the Marinade program, not a validator.

interface CombinedStakeActivate {
  fromAddress: string;
  stakingAddress: string;
  amount: bigint;
}

/**
 * Scan for multi-instruction patterns that should be combined:
 *
 * 1. CreateAccount + StakeInitialize [+ StakingDelegate] → StakingActivate
 *    - With Delegate following = NATIVE staking
 *    - Without Delegate = MARINADE staking (Marinade's program handles delegation)
 */
function detectCombinedPattern(instructions: InstructionParams[]): CombinedStakeActivate | null {
  for (let i = 0; i < instructions.length - 1; i++) {
    const curr = instructions[i];
    const next = instructions[i + 1];

    if (curr.type === "CreateAccount" && next.type === "StakeInitialize") {
      return {
        fromAddress: curr.fromAddress,
        stakingAddress: curr.newAddress,
        amount: curr.amount,
      };
    }
  }

  return null;
}

// =============================================================================
// Transaction type derivation
// =============================================================================

function deriveTransactionType(
  instructions: InstructionParams[],
  combined: CombinedStakeActivate | null,
  memo: string | undefined,
): string {
  // Combined CreateAccount + StakeInitialize [+ Delegate] → StakingActivate
  if (combined) {
    return "StakingActivate";
  }

  // Marinade deactivate pattern: a Transfer instruction paired with a memo
  // containing "PrepareForRevoke". Marinade requires a small SOL transfer to
  // a program-owned account as part of its unstaking flow; the memo marks
  // the Transfer so we know it's a deactivation, not a real send.
  if (memo && memo.includes("PrepareForRevoke")) {
    return "StakingDeactivate";
  }

  let txType = "Send";

  for (const instr of instructions) {
    switch (instr.type) {
      case "StakingActivate":
        txType = "StakingActivate";
        break;

      // Jito liquid staking uses the SPL Stake Pool program.
      // StakePoolDepositSol deposits SOL into the Jito stake pool in exchange
      // for jitoSOL tokens, which is semantically a staking activation.
      case "StakePoolDepositSol":
        txType = "StakingActivate";
        break;

      case "StakingDeactivate":
        txType = "StakingDeactivate";
        break;

      // Jito's StakePoolWithdrawStake burns jitoSOL and returns a stake account,
      // which is semantically a staking deactivation.
      case "StakePoolWithdrawStake":
        txType = "StakingDeactivate";
        break;

      case "StakingWithdraw":
        txType = "StakingWithdraw";
        break;

      case "StakingAuthorize":
        txType = "StakingAuthorize";
        break;

      // StakingDelegate alone (without the preceding CreateAccount + StakeInitialize)
      // means re-delegation of an already-active stake account to a new validator.
      // It should not override StakingActivate if that was already determined.
      case "StakingDelegate":
        if (txType !== "StakingActivate") {
          txType = "StakingDelegate";
        }
        break;

      // CreateAssociatedTokenAccount, CloseAssociatedTokenAccount, Transfer,
      // TokenTransfer, Memo, etc. keep the default 'Send' type.
    }
  }

  return txType;
}

// =============================================================================
// Transaction ID extraction
// =============================================================================

// Base58 encoding of 64 zero bytes. Unsigned transactions have all-zero
// signatures which encode to this constant.
const ALL_ZEROS_BASE58 = "1111111111111111111111111111111111111111111111111111111111111111";

function extractTransactionId(signatures: string[]): string | undefined {
  const sig = signatures[0];
  if (!sig || sig === ALL_ZEROS_BASE58) return undefined;
  return sig;
}

// =============================================================================
// Main export
// =============================================================================

/**
 * Explain a Solana transaction.
 *
 * Takes raw transaction bytes and fee parameters, then returns a structured
 * explanation including transaction type, outputs, inputs, fee, memo, and
 * associated-token-account owner mappings.
 *
 * @param input - Raw transaction bytes (caller is responsible for decoding base64/hex)
 * @param options - Fee parameters for calculating the total fee
 * @returns An ExplainedTransaction with all fields populated
 *
 * @example
 * ```typescript
 * import { explainTransaction } from '@bitgo/wasm-solana';
 *
 * const txBytes = Buffer.from(txBase64, 'base64');
 * const explained = explainTransaction(txBytes, {
 *   lamportsPerSignature: 5000n,
 *   tokenAccountRentExemptAmount: 2039280n,
 * });
 * console.log(explained.type); // "Send", "StakingActivate", etc.
 * ```
 */
export function explainTransaction(
  input: Uint8Array,
  options: ExplainOptions,
): ExplainedTransaction {
  const { lamportsPerSignature, tokenAccountRentExemptAmount } = options;

  const parsed: ParsedTransaction = parseTransaction(input);

  // --- Transaction ID ---
  const id = extractTransactionId(parsed.signatures);

  // --- Fee calculation ---
  // Base fee = numSignatures × lamportsPerSignature
  let fee = BigInt(parsed.numSignatures) * BigInt(lamportsPerSignature);

  // Each CreateAssociatedTokenAccount instruction creates a new token account,
  // which requires a rent-exempt deposit. Add that to the fee.
  const ataCount = parsed.instructionsData.filter(
    (i) => i.type === "CreateAssociatedTokenAccount",
  ).length;
  if (ataCount > 0 && tokenAccountRentExemptAmount !== undefined) {
    fee += BigInt(ataCount) * BigInt(tokenAccountRentExemptAmount);
  }

  // --- Extract memo (needed before type derivation) ---
  let memo: string | undefined;
  for (const instr of parsed.instructionsData) {
    if (instr.type === "Memo") {
      memo = instr.memo;
    }
  }

  // --- Detect combined instruction patterns ---
  const combined = detectCombinedPattern(parsed.instructionsData);
  const txType = deriveTransactionType(parsed.instructionsData, combined, memo);

  // Marinade deactivate: Transfer + PrepareForRevoke memo.
  // The Transfer is a contract interaction (not a real value transfer),
  // so we skip it from outputs.
  const isMarinadeDeactivate =
    txType === "StakingDeactivate" && memo !== undefined && memo.includes("PrepareForRevoke");

  // --- Extract outputs and inputs ---
  const outputs: ExplainedOutput[] = [];
  const inputs: ExplainedInput[] = [];

  if (combined) {
    // Combined native/Marinade staking activate — the staking address receives
    // the full amount from the funding account.
    outputs.push({
      address: combined.stakingAddress,
      amount: String(combined.amount),
    });
    inputs.push({
      address: combined.fromAddress,
      value: String(combined.amount),
    });
  } else {
    // Process individual instructions for outputs/inputs
    for (const instr of parsed.instructionsData) {
      switch (instr.type) {
        case "Transfer":
          // Skip Transfer for Marinade deactivate — it's a program interaction,
          // not a real value transfer to an external address.
          if (isMarinadeDeactivate) break;
          outputs.push({
            address: instr.toAddress,
            amount: String(instr.amount),
          });
          inputs.push({
            address: instr.fromAddress,
            value: String(instr.amount),
          });
          break;

        case "TokenTransfer":
          outputs.push({
            address: instr.toAddress,
            amount: String(instr.amount),
            tokenName: instr.tokenAddress,
          });
          inputs.push({
            address: instr.fromAddress,
            value: String(instr.amount),
          });
          break;

        case "StakingActivate":
          outputs.push({
            address: instr.stakingAddress,
            amount: String(instr.amount),
          });
          inputs.push({
            address: instr.fromAddress,
            value: String(instr.amount),
          });
          break;

        case "StakingWithdraw":
          // Withdraw: SOL flows FROM the staking address TO the recipient.
          // `fromAddress` is the recipient (where funds go),
          // `stakingAddress` is the source.
          outputs.push({
            address: instr.fromAddress,
            amount: String(instr.amount),
          });
          inputs.push({
            address: instr.stakingAddress,
            value: String(instr.amount),
          });
          break;

        case "StakePoolDepositSol":
          // Jito liquid staking: SOL is deposited into the stake pool.
          // The funding account is debited. No traditional output because the
          // received jitoSOL pool tokens arrive via an ATA, not a direct transfer.
          inputs.push({
            address: instr.fundingAccount,
            value: String(instr.lamports),
          });
          break;

        // StakingDeactivate, StakingAuthorize, StakingDelegate,
        // StakePoolWithdrawStake, NonceAdvance, CreateAccount,
        // StakeInitialize, NonceInitialize, SetComputeUnitLimit,
        // SetPriorityFee, CreateAssociatedTokenAccount,
        // CloseAssociatedTokenAccount, Memo, Unknown
        // — no value inputs/outputs.
      }
    }
  }

  // --- Output amount ---
  const outputAmount = outputs.reduce((sum, o) => sum + BigInt(o.amount), 0n);

  // --- ATA owner mapping ---
  // Maps ATA address → owner address for each CreateAssociatedTokenAccount
  // instruction in this transaction. This is an improved version of the explain
  // response that allows consumers to resolve newly-created token account
  // addresses to their owner addresses without requiring an external DB lookup
  // (the ATA may not exist on-chain yet if it's being created in this tx).
  const ataOwnerMap: Record<string, string> = {};
  for (const instr of parsed.instructionsData) {
    if (instr.type === "CreateAssociatedTokenAccount") {
      ataOwnerMap[instr.ataAddress] = instr.ownerAddress;
    }
  }

  return {
    id,
    type: txType,
    feePayer: parsed.feePayer,
    fee: String(fee),
    blockhash: parsed.nonce,
    durableNonce: parsed.durableNonce,
    outputs,
    inputs,
    outputAmount: String(outputAmount),
    memo,
    ataOwnerMap,
    numSignatures: parsed.numSignatures,
  };
}
