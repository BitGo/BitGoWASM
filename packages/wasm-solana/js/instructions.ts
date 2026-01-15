import {
  SystemInstructionDecoder as WasmSystemDecoder,
  StakeInstructionDecoder as WasmStakeDecoder,
  ComputeBudgetInstructionDecoder as WasmComputeBudgetDecoder,
} from "./wasm/wasm_solana.js";

// =============================================================================
// System Program Types (only types used by BitGo)
// =============================================================================

export type SystemInstructionType =
  | "CreateAccount"
  | "Assign"
  | "Transfer"
  | "AdvanceNonceAccount"
  | "InitializeNonceAccount"
  | "Allocate";

export interface CreateAccountInstruction {
  type: "CreateAccount";
  lamports: bigint;
  space: bigint;
  owner: string;
}

export interface AssignInstruction {
  type: "Assign";
  owner: string;
}

export interface TransferInstruction {
  type: "Transfer";
  lamports: bigint;
}

export interface AdvanceNonceAccountInstruction {
  type: "AdvanceNonceAccount";
}

export interface InitializeNonceAccountInstruction {
  type: "InitializeNonceAccount";
  authorized: string;
}

export interface AllocateInstruction {
  type: "Allocate";
  space: bigint;
}

export type DecodedSystemInstruction =
  | CreateAccountInstruction
  | AssignInstruction
  | TransferInstruction
  | AdvanceNonceAccountInstruction
  | InitializeNonceAccountInstruction
  | AllocateInstruction;

// =============================================================================
// Stake Program Types (only types used by BitGo)
// =============================================================================

export type StakeInstructionType =
  | "Initialize"
  | "Authorize"
  | "DelegateStake"
  | "Split"
  | "Withdraw"
  | "Deactivate";

export type StakeAuthorize = "Staker" | "Withdrawer";

export interface Lockup {
  unixTimestamp: bigint;
  epoch: bigint;
  custodian: string;
}

export interface InitializeStakeInstruction {
  type: "Initialize";
  staker: string;
  withdrawer: string;
  lockup?: Lockup;
}

export interface AuthorizeStakeInstruction {
  type: "Authorize";
  newAuthority: string;
  stakeAuthorize: StakeAuthorize;
}

export interface DelegateStakeInstruction {
  type: "DelegateStake";
}

export interface SplitStakeInstruction {
  type: "Split";
  lamports: bigint;
}

export interface WithdrawStakeInstruction {
  type: "Withdraw";
  lamports: bigint;
}

export interface DeactivateStakeInstruction {
  type: "Deactivate";
}

export type DecodedStakeInstruction =
  | InitializeStakeInstruction
  | AuthorizeStakeInstruction
  | DelegateStakeInstruction
  | SplitStakeInstruction
  | WithdrawStakeInstruction
  | DeactivateStakeInstruction;

// =============================================================================
// ComputeBudget Program Types (only types used by BitGo)
// =============================================================================

export type ComputeBudgetInstructionType = "SetComputeUnitLimit" | "SetComputeUnitPrice";

export interface SetComputeUnitLimitInstruction {
  type: "SetComputeUnitLimit";
  units: number;
}

export interface SetComputeUnitPriceInstruction {
  type: "SetComputeUnitPrice";
  microLamports: bigint;
}

export type DecodedComputeBudgetInstruction =
  | SetComputeUnitLimitInstruction
  | SetComputeUnitPriceInstruction;

// =============================================================================
// Decoder Classes
// =============================================================================

/**
 * System Program instruction decoder
 */
export class SystemInstruction {
  static readonly PROGRAM_ID = WasmSystemDecoder.program_id;

  static isSystemProgram(programId: string): boolean {
    return WasmSystemDecoder.is_system_program(programId);
  }

  static decode(data: Uint8Array): DecodedSystemInstruction {
    return WasmSystemDecoder.decode(data) as DecodedSystemInstruction;
  }
}

/**
 * Stake Program instruction decoder
 */
export class StakeInstruction {
  static readonly PROGRAM_ID = WasmStakeDecoder.program_id;

  static isStakeProgram(programId: string): boolean {
    return WasmStakeDecoder.is_stake_program(programId);
  }

  static decode(data: Uint8Array): DecodedStakeInstruction {
    return WasmStakeDecoder.decode(data) as DecodedStakeInstruction;
  }
}

/**
 * ComputeBudget Program instruction decoder
 */
export class ComputeBudgetInstruction {
  static readonly PROGRAM_ID = WasmComputeBudgetDecoder.program_id;

  static isComputeBudgetProgram(programId: string): boolean {
    return WasmComputeBudgetDecoder.is_compute_budget_program(programId);
  }

  static decode(data: Uint8Array): DecodedComputeBudgetInstruction {
    return WasmComputeBudgetDecoder.decode(data) as DecodedComputeBudgetInstruction;
  }
}
