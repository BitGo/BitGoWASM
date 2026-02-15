/**
 * High-level transaction parsing.
 *
 * Provides types and functions for parsing Solana transactions into semantic data
 * matching BitGoJS's TxData format.
 *
 * All monetary amounts (amount, fee, lamports, poolTokens) are returned as bigint.
 */

import { ParserNamespace } from "./wasm/wasm_solana.js";

// =============================================================================
// Instruction Types - matching BitGoJS InstructionParams.
// =============================================================================

/** SOL transfer parameters */
export interface TransferParams {
  type: "Transfer";
  fromAddress: string;
  toAddress: string;
  amount: bigint;
}

/** Create account parameters */
export interface CreateAccountParams {
  type: "CreateAccount";
  fromAddress: string;
  newAddress: string;
  amount: bigint;
  space: number;
  owner: string;
}

/** Nonce advance parameters */
export interface NonceAdvanceParams {
  type: "NonceAdvance";
  walletNonceAddress: string;
  authWalletAddress: string;
}

/** Create nonce account parameters (combined type) */
export interface CreateNonceAccountParams {
  type: "CreateNonceAccount";
  fromAddress: string;
  nonceAddress: string;
  authAddress: string;
  amount: bigint;
}

/** Nonce initialize parameters (intermediate - combined into CreateNonceAccount) */
export interface NonceInitializeParams {
  type: "NonceInitialize";
  nonceAddress: string;
  authAddress: string;
}

/** Stake initialize parameters (intermediate - combined into StakingActivate) */
export interface StakeInitializeParams {
  type: "StakeInitialize";
  stakingAddress: string;
  staker: string;
  withdrawer: string;
}

/** Staking activate parameters (combined type) */
export interface StakingActivateParams {
  type: "StakingActivate";
  fromAddress: string;
  stakingAddress: string;
  amount: bigint;
  validator: string;
  stakingType: "NATIVE" | "JITO" | "MARINADE";
}

/** Staking deactivate parameters */
export interface StakingDeactivateParams {
  type: "StakingDeactivate";
  stakingAddress: string;
  fromAddress: string;
}

/** Staking withdraw parameters */
export interface StakingWithdrawParams {
  type: "StakingWithdraw";
  fromAddress: string;
  stakingAddress: string;
  amount: bigint;
}

/** Staking delegate parameters */
export interface StakingDelegateParams {
  type: "StakingDelegate";
  stakingAddress: string;
  fromAddress: string;
  validator: string;
}

/** Staking authorize parameters */
export interface StakingAuthorizeParams {
  type: "StakingAuthorize";
  stakingAddress: string;
  oldAuthorizeAddress: string;
  newAuthorizeAddress: string;
  authorizeType: "Staker" | "Withdrawer";
  custodianAddress?: string;
}

/** Stake initialize parameters (intermediate type) */
export interface StakeInitializeParams {
  type: "StakeInitialize";
  stakingAddress: string;
  staker: string;
  withdrawer: string;
}

/** Set compute unit limit parameters */
export interface SetComputeUnitLimitParams {
  type: "SetComputeUnitLimit";
  units: number;
}

/** Set priority fee parameters */
export interface SetPriorityFeeParams {
  type: "SetPriorityFee";
  fee: bigint;
}

/** Token transfer parameters */
export interface TokenTransferParams {
  type: "TokenTransfer";
  fromAddress: string;
  toAddress: string;
  amount: bigint;
  sourceAddress: string;
  tokenAddress?: string;
  programId: string;
  decimalPlaces?: number;
}

/** Create associated token account parameters */
export interface CreateAtaParams {
  type: "CreateAssociatedTokenAccount";
  mintAddress: string;
  ataAddress: string;
  ownerAddress: string;
  payerAddress: string;
  programId: string;
}

/** Close associated token account parameters */
export interface CloseAtaParams {
  type: "CloseAssociatedTokenAccount";
  accountAddress: string;
  destinationAddress: string;
  authorityAddress: string;
}

/** Memo parameters */
export interface MemoParams {
  type: "Memo";
  memo: string;
}

/** Stake pool deposit SOL parameters (Jito liquid staking) */
export interface StakePoolDepositSolParams {
  type: "StakePoolDepositSol";
  stakePool: string;
  withdrawAuthority: string;
  reserveStake: string;
  fundingAccount: string;
  destinationPoolAccount: string;
  managerFeeAccount: string;
  referralPoolAccount: string;
  poolMint: string;
  lamports: bigint;
}

/** Stake pool withdraw stake parameters (Jito liquid staking) */
export interface StakePoolWithdrawStakeParams {
  type: "StakePoolWithdrawStake";
  stakePool: string;
  validatorList: string;
  withdrawAuthority: string;
  validatorStake: string;
  destinationStake: string;
  destinationStakeAuthority: string;
  sourceTransferAuthority: string;
  sourcePoolAccount: string;
  managerFeeAccount: string;
  poolMint: string;
  poolTokens: bigint;
}

/** Account metadata for unknown instructions */
export interface AccountMeta {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}

/** Unknown instruction parameters */
export interface UnknownInstructionParams {
  type: "Unknown";
  programId: string;
  accounts: AccountMeta[];
  data: string; // base64 encoded
}

/** Union of all instruction parameter types */
export type InstructionParams =
  | TransferParams
  | CreateAccountParams
  | NonceAdvanceParams
  | CreateNonceAccountParams
  | NonceInitializeParams
  | StakingActivateParams
  | StakingDeactivateParams
  | StakingWithdrawParams
  | StakingDelegateParams
  | StakingAuthorizeParams
  | StakeInitializeParams
  | SetComputeUnitLimitParams
  | SetPriorityFeeParams
  | TokenTransferParams
  | CreateAtaParams
  | CloseAtaParams
  | MemoParams
  | StakePoolDepositSolParams
  | StakePoolWithdrawStakeParams
  | UnknownInstructionParams;

// =============================================================================
// ParsedTransaction - matching BitGoJS TxData
// =============================================================================

/** Durable nonce information */
export interface DurableNonce {
  walletNonceAddress: string;
  authWalletAddress: string;
}

/**
 * A fully parsed Solana transaction with decoded instructions.
 *
 * This structure matches BitGoJS's TxData interface for seamless integration.
 * All monetary amounts are returned as bigint directly from WASM.
 */
export interface ParsedTransaction {
  /** The fee payer address (base58) */
  feePayer: string;

  /** Number of required signatures */
  numSignatures: number;

  /** The blockhash or nonce value (base58) */
  nonce: string;

  /** If this is a durable nonce transaction, contains the nonce info */
  durableNonce?: DurableNonce;

  /** All decoded instructions with semantic types */
  instructionsData: InstructionParams[];

  /** All account keys (base58 strings) */
  accountKeys: string[];

  /** All signatures (base58 strings). Non-empty signatures indicate signed transaction. */
  signatures: string[];
}

// =============================================================================
// parseTransactionData function
// =============================================================================

/**
 * Parse raw transaction bytes into a plain data object with decoded instructions.
 *
 * This is the low-level parsing function. Most callers should use the top-level
 * `parseTransaction(bytes)` which returns a `Transaction` instance with both
 * inspection (`.parse()`) and signing (`.addSignature()`) capabilities.
 *
 * @param bytes - Raw transaction bytes
 * @returns A ParsedTransaction with all instructions decoded
 */
export function parseTransactionData(bytes: Uint8Array): ParsedTransaction {
  return ParserNamespace.parse_transaction(bytes) as ParsedTransaction;
}
