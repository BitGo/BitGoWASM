/**
 * Instruction decoders for Solana native programs.
 *
 * Provides decoders for:
 * - System Program (transfers, account creation, nonce operations)
 * - Stake Program (staking operations)
 * - ComputeBudget Program (fee and compute limit settings)
 *
 * Note: The underlying WASM decoder supports all instruction types from official
 * Solana crates. TypeScript types are provided for commonly used instructions.
 */

import {
  SystemInstructionDecoder as WasmSystemDecoder,
  StakeInstructionDecoder as WasmStakeDecoder,
  ComputeBudgetInstructionDecoder as WasmComputeBudgetDecoder,
} from "./wasm/wasm_solana.js";

// =============================================================================
// System Instruction Types (commonly used in BitGoJS)
// =============================================================================

export interface SystemCreateAccount {
  type: "CreateAccount";
  lamports: bigint;
  space: bigint;
  owner: string;
}

export interface SystemTransfer {
  type: "Transfer";
  lamports: bigint;
}

export interface SystemAdvanceNonceAccount {
  type: "AdvanceNonceAccount";
}

export interface SystemInitializeNonceAccount {
  type: "InitializeNonceAccount";
  authorized: string;
}

/** Union of commonly used System instruction types */
export type SystemInstruction =
  | SystemCreateAccount
  | SystemTransfer
  | SystemAdvanceNonceAccount
  | SystemInitializeNonceAccount
  | { type: string; [key: string]: unknown }; // Other instruction types

// =============================================================================
// Stake Instruction Types (commonly used in BitGoJS)
// =============================================================================

export interface StakeLockup {
  unixTimestamp: bigint;
  epoch: bigint;
  custodian: string;
}

export interface StakeInitialize {
  type: "Initialize";
  staker: string;
  withdrawer: string;
  lockup: StakeLockup;
}

export interface StakeAuthorize {
  type: "Authorize";
  newAuthority: string;
  stakeAuthorize: "Staker" | "Withdrawer";
}

export interface StakeDelegateStake {
  type: "DelegateStake";
}

export interface StakeSplit {
  type: "Split";
  lamports: bigint;
}

export interface StakeWithdraw {
  type: "Withdraw";
  lamports: bigint;
}

export interface StakeDeactivate {
  type: "Deactivate";
}

export interface StakeMerge {
  type: "Merge";
}

/** Union of commonly used Stake instruction types */
export type StakeInstruction =
  | StakeInitialize
  | StakeAuthorize
  | StakeDelegateStake
  | StakeSplit
  | StakeWithdraw
  | StakeDeactivate
  | StakeMerge
  | { type: string; [key: string]: unknown }; // Other instruction types

// =============================================================================
// ComputeBudget Instruction Types
// =============================================================================

export interface ComputeBudgetSetComputeUnitLimit {
  type: "SetComputeUnitLimit";
  units: number;
}

export interface ComputeBudgetSetComputeUnitPrice {
  type: "SetComputeUnitPrice";
  microLamports: bigint;
}

/** Union of commonly used ComputeBudget instruction types */
export type ComputeBudgetInstruction =
  | ComputeBudgetSetComputeUnitLimit
  | ComputeBudgetSetComputeUnitPrice
  | { type: string; [key: string]: unknown }; // Other instruction types

// =============================================================================
// System Instruction Decoder
// =============================================================================

/** System Program ID */
export const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

/**
 * Check if a program ID is the System Program
 * @param programId - The program ID to check (base58 string)
 */
export function isSystemProgram(programId: string): boolean {
  return WasmSystemDecoder.is_system_program(programId);
}

/**
 * Decode a System program instruction from raw bytes.
 * Supports all System instruction types via official Solana crates.
 * @param data - The instruction data bytes
 * @returns The decoded instruction with type discriminant
 * @throws Error if the instruction cannot be decoded
 */
export function decodeSystemInstruction(data: Uint8Array): SystemInstruction {
  return WasmSystemDecoder.decode(data) as SystemInstruction;
}

// =============================================================================
// Stake Instruction Decoder
// =============================================================================

/** Stake Program ID */
export const STAKE_PROGRAM_ID = "Stake11111111111111111111111111111111111111";

/**
 * Check if a program ID is the Stake Program
 * @param programId - The program ID to check (base58 string)
 */
export function isStakeProgram(programId: string): boolean {
  return WasmStakeDecoder.is_stake_program(programId);
}

/**
 * Decode a Stake program instruction from raw bytes.
 * Supports all Stake instruction types via official Solana crates.
 * @param data - The instruction data bytes
 * @returns The decoded instruction with type discriminant
 * @throws Error if the instruction cannot be decoded
 */
export function decodeStakeInstruction(data: Uint8Array): StakeInstruction {
  return WasmStakeDecoder.decode(data) as StakeInstruction;
}

// =============================================================================
// ComputeBudget Instruction Decoder
// =============================================================================

/** ComputeBudget Program ID */
export const COMPUTE_BUDGET_PROGRAM_ID =
  "ComputeBudget111111111111111111111111111111";

/**
 * Check if a program ID is the ComputeBudget Program
 * @param programId - The program ID to check (base58 string)
 */
export function isComputeBudgetProgram(programId: string): boolean {
  return WasmComputeBudgetDecoder.is_compute_budget_program(programId);
}

/**
 * Decode a ComputeBudget program instruction from raw bytes.
 * Supports all ComputeBudget instruction types via official Solana crates.
 * @param data - The instruction data bytes
 * @returns The decoded instruction with type discriminant
 * @throws Error if the instruction cannot be decoded
 */
export function decodeComputeBudgetInstruction(
  data: Uint8Array
): ComputeBudgetInstruction {
  return WasmComputeBudgetDecoder.decode(data) as ComputeBudgetInstruction;
}
