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

import { parseTransactionData } from "./parser.js";
import type { InstructionParams, ParsedTransaction } from "./parser.js";

// =============================================================================
// Public types
// =============================================================================

export enum TransactionType {
  Send = "Send",
  StakingActivate = "StakingActivate",
  StakingDeactivate = "StakingDeactivate",
  StakingWithdraw = "StakingWithdraw",
  StakingAuthorize = "StakingAuthorize",
  StakingDelegate = "StakingDelegate",
  WalletInitialization = "WalletInitialization",
  AssociatedTokenAccountInitialization = "AssociatedTokenAccountInitialization",
}

/** Solana base fee per signature (protocol constant). */
const DEFAULT_LAMPORTS_PER_SIGNATURE = 5000n;

export interface ExplainOptions {
  /** Defaults to 5000 (Solana protocol constant). */
  lamportsPerSignature?: bigint | number | string;
  tokenAccountRentExemptAmount?: bigint | number | string;
}

export interface ExplainedOutput {
  address: string;
  amount: bigint;
  tokenName?: string;
}

export interface ExplainedInput {
  address: string;
  value: bigint;
}

export interface TokenEnablement {
  /** The ATA address being created */
  address: string;
  /** The SPL token mint address */
  mintAddress: string;
}

export interface StakingAuthorizeInfo {
  stakingAddress: string;
  oldAuthorizeAddress: string;
  newAuthorizeAddress: string;
  authorizeType: "Staker" | "Withdrawer";
  custodianAddress?: string;
}

export interface ExplainedTransaction {
  /** Transaction ID (base58 signature). Undefined if the transaction is unsigned. */
  id: string | undefined;
  type: TransactionType;
  feePayer: string;
  fee: bigint;
  blockhash: string;
  durableNonce?: { walletNonceAddress: string; authWalletAddress: string };
  outputs: ExplainedOutput[];
  inputs: ExplainedInput[];
  outputAmount: bigint;
  memo?: string;
  /**
   * Maps ATA address → owner address for CreateAssociatedTokenAccount instructions.
   * Allows resolving newly-created token account ownership without an external lookup.
   */
  ataOwnerMap: Record<string, string>;
  /**
   * Token enablements from CreateAssociatedTokenAccount instructions.
   * Contains the ATA address and mint address (consumer resolves token names).
   */
  tokenEnablements: TokenEnablement[];
  /** Staking authorize details, present when the transaction changes stake authority. */
  stakingAuthorize?: StakingAuthorizeInfo;
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
  kind: "StakingActivate";
  fromAddress: string;
  stakingAddress: string;
  amount: bigint;
}

interface CombinedWalletInit {
  kind: "WalletInitialization";
  fromAddress: string;
  nonceAddress: string;
  amount: bigint;
}

type CombinedPattern = CombinedStakeActivate | CombinedWalletInit;

/**
 * Scan for multi-instruction patterns that should be combined:
 *
 * 1. CreateAccount + StakeInitialize [+ StakingDelegate] → StakingActivate
 *    - With Delegate following = NATIVE staking
 *    - Without Delegate = MARINADE staking (Marinade's program handles delegation)
 * 2. CreateAccount + NonceInitialize → WalletInitialization
 *    - BitGo creates a nonce account during wallet initialization
 */
function detectCombinedPattern(instructions: InstructionParams[]): CombinedPattern | null {
  for (let i = 0; i < instructions.length - 1; i++) {
    const curr = instructions[i];
    const next = instructions[i + 1];

    if (curr.type === "CreateAccount" && next.type === "StakeInitialize") {
      return {
        kind: "StakingActivate",
        fromAddress: curr.fromAddress,
        stakingAddress: curr.newAddress,
        amount: curr.amount,
      };
    }

    if (curr.type === "CreateAccount" && next.type === "NonceInitialize") {
      return {
        kind: "WalletInitialization",
        fromAddress: curr.fromAddress,
        nonceAddress: curr.newAddress,
        amount: curr.amount,
      };
    }
  }

  return null;
}

// =============================================================================
// Transaction type derivation
// =============================================================================

const BOILERPLATE_TYPES = new Set([
  "NonceAdvance",
  "Memo",
  "SetComputeUnitLimit",
  "SetPriorityFee",
]);

function deriveTransactionType(
  instructions: InstructionParams[],
  combined: CombinedPattern | null,
  memo: string | undefined,
): TransactionType {
  if (combined) return TransactionType[combined.kind];

  // Marinade deactivate: Transfer + memo containing "PrepareForRevoke"
  if (memo?.includes("PrepareForRevoke")) return TransactionType.StakingDeactivate;

  // Jito pool operations map to staking types
  if (instructions.some((i) => i.type === "StakePoolDepositSol"))
    return TransactionType.StakingActivate;
  if (instructions.some((i) => i.type === "StakePoolWithdrawStake"))
    return TransactionType.StakingDeactivate;

  // ATA-only transactions (ignoring boilerplate like nonce/memo/compute budget)
  const meaningful = instructions.filter((i) => !BOILERPLATE_TYPES.has(i.type));
  if (meaningful.length > 0 && meaningful.every((i) => i.type === "CreateAssociatedTokenAccount")) {
    return TransactionType.AssociatedTokenAccountInitialization;
  }

  // For staking instructions, the instruction type IS the transaction type
  const staking = instructions.find((i) => i.type in TransactionType);
  if (staking) return TransactionType[staking.type as keyof typeof TransactionType];

  return TransactionType.Send;
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

  const parsed: ParsedTransaction = parseTransactionData(input);

  // --- Transaction ID ---
  const id = extractTransactionId(parsed.signatures);

  // --- Fee calculation ---
  // Base fee = numSignatures × lamportsPerSignature
  let fee =
    BigInt(parsed.numSignatures) *
    (lamportsPerSignature !== undefined
      ? BigInt(lamportsPerSignature)
      : DEFAULT_LAMPORTS_PER_SIGNATURE);

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
    txType === TransactionType.StakingDeactivate &&
    memo !== undefined &&
    memo.includes("PrepareForRevoke");

  // --- Extract outputs and inputs ---
  const outputs: ExplainedOutput[] = [];
  const inputs: ExplainedInput[] = [];

  if (combined?.kind === "StakingActivate") {
    // Combined native/Marinade staking activate — the staking address receives
    // the full amount from the funding account.
    outputs.push({
      address: combined.stakingAddress,
      amount: combined.amount,
    });
    inputs.push({
      address: combined.fromAddress,
      value: combined.amount,
    });
  } else if (combined?.kind === "WalletInitialization") {
    // Wallet initialization — funds the new nonce account.
    outputs.push({
      address: combined.nonceAddress,
      amount: combined.amount,
    });
    inputs.push({
      address: combined.fromAddress,
      value: combined.amount,
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
            amount: instr.amount,
          });
          inputs.push({
            address: instr.fromAddress,
            value: instr.amount,
          });
          break;

        case "TokenTransfer":
          outputs.push({
            address: instr.toAddress,
            amount: instr.amount,
            tokenName: instr.tokenAddress,
          });
          inputs.push({
            address: instr.fromAddress,
            value: instr.amount,
          });
          break;

        case "StakingActivate":
          outputs.push({
            address: instr.stakingAddress,
            amount: instr.amount,
          });
          inputs.push({
            address: instr.fromAddress,
            value: instr.amount,
          });
          break;

        case "StakingWithdraw":
          // Withdraw: SOL flows FROM the staking address TO the recipient.
          // `fromAddress` is the recipient (where funds go),
          // `stakingAddress` is the source.
          outputs.push({
            address: instr.fromAddress,
            amount: instr.amount,
          });
          inputs.push({
            address: instr.stakingAddress,
            value: instr.amount,
          });
          break;

        case "StakePoolDepositSol":
          // Jito liquid staking: SOL is deposited into the stake pool.
          // The funding account is debited; output goes to the pool address.
          outputs.push({
            address: instr.stakePool,
            amount: instr.lamports,
          });
          inputs.push({
            address: instr.fundingAccount,
            value: instr.lamports,
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
  // Only count native SOL outputs (no tokenName). Token amounts are in different
  // denominations and shouldn't be mixed with SOL lamports.
  const outputAmount = outputs.filter((o) => !o.tokenName).reduce((sum, o) => sum + o.amount, 0n);

  // --- ATA owner mapping and token enablements ---
  const ataOwnerMap: Record<string, string> = {};
  const tokenEnablements: TokenEnablement[] = [];
  for (const instr of parsed.instructionsData) {
    if (instr.type === "CreateAssociatedTokenAccount") {
      ataOwnerMap[instr.ataAddress] = instr.ownerAddress;
      tokenEnablements.push({
        address: instr.ataAddress,
        mintAddress: instr.mintAddress,
      });
    }
  }

  // --- Staking authorize ---
  let stakingAuthorize: StakingAuthorizeInfo | undefined;
  for (const instr of parsed.instructionsData) {
    if (instr.type === "StakingAuthorize") {
      stakingAuthorize = {
        stakingAddress: instr.stakingAddress,
        oldAuthorizeAddress: instr.oldAuthorizeAddress,
        newAuthorizeAddress: instr.newAuthorizeAddress,
        authorizeType: instr.authorizeType,
        custodianAddress: instr.custodianAddress,
      };
      break;
    }
  }

  return {
    id,
    type: txType,
    feePayer: parsed.feePayer,
    fee,
    blockhash: parsed.nonce,
    durableNonce: parsed.durableNonce,
    outputs,
    inputs,
    outputAmount,
    memo,
    ataOwnerMap,
    tokenEnablements,
    stakingAuthorize,
    numSignatures: parsed.numSignatures,
  };
}
