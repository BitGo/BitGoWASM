/**
 * Transaction building from high-level intents.
 *
 * Provides types and functions for building Solana transactions from a
 * declarative intent structure, without requiring the full @solana/web3.js dependency.
 */

import { BuilderNamespace } from "./wasm/wasm_solana.js";
import { Transaction } from "./transaction.js";
import { VersionedTransaction } from "./versioned.js";

// =============================================================================
// Nonce Types
// =============================================================================

/** Use a recent blockhash for the transaction */
export interface BlockhashNonceSource {
  type: "blockhash";
  /** The recent blockhash value (base58) */
  value: string;
}

/** Use a durable nonce account for the transaction */
export interface DurableNonceSource {
  type: "durable";
  /** The nonce account address (base58) */
  address: string;
  /** The nonce authority address (base58) */
  authority: string;
  /** The nonce value stored in the account (base58) - this becomes the blockhash */
  value: string;
}

/** Nonce source for the transaction */
export type NonceSource = BlockhashNonceSource | DurableNonceSource;

// =============================================================================
// Address Lookup Table Types (Versioned Transactions)
// =============================================================================

/**
 * Address Lookup Table data for versioned transactions.
 *
 * ALTs allow transactions to reference more accounts than the legacy format
 * by storing account addresses in on-chain lookup tables.
 */
export interface AddressLookupTable {
  /** The lookup table account address (base58) */
  accountKey: string;
  /** Indices of writable accounts in the lookup table */
  writableIndexes: number[];
  /** Indices of readonly accounts in the lookup table */
  readonlyIndexes: number[];
}

// =============================================================================
// Instruction Types
// =============================================================================

/** SOL transfer instruction */
export interface TransferInstruction {
  type: "transfer";
  /** Source account (base58) */
  from: string;
  /** Destination account (base58) */
  to: string;
  /** Amount in lamports */
  lamports: bigint;
}

/** Create new account instruction */
export interface CreateAccountInstruction {
  type: "createAccount";
  /** Funding account (base58) */
  from: string;
  /** New account address (base58) */
  newAccount: string;
  /** Lamports to transfer */
  lamports: bigint;
  /** Space to allocate in bytes */
  space: number;
  /** Owner program (base58) */
  owner: string;
}

/** Advance durable nonce instruction */
export interface NonceAdvanceInstruction {
  type: "nonceAdvance";
  /** Nonce account address (base58) */
  nonce: string;
  /** Nonce authority (base58) */
  authority: string;
}

/** Initialize nonce account instruction */
export interface NonceInitializeInstruction {
  type: "nonceInitialize";
  /** Nonce account address (base58) */
  nonce: string;
  /** Nonce authority (base58) */
  authority: string;
}

/** Allocate space instruction */
export interface AllocateInstruction {
  type: "allocate";
  /** Account to allocate (base58) */
  account: string;
  /** Space to allocate in bytes */
  space: number;
}

/** Assign account to program instruction */
export interface AssignInstruction {
  type: "assign";
  /** Account to assign (base58) */
  account: string;
  /** New owner program (base58) */
  owner: string;
}

/** Memo instruction */
export interface MemoInstruction {
  type: "memo";
  /** The memo message */
  message: string;
}

/** Compute budget instruction */
export interface ComputeBudgetInstruction {
  type: "computeBudget";
  /** Compute unit limit (optional) */
  unitLimit?: number;
  /** Compute unit price in micro-lamports (optional) */
  unitPrice?: number;
}

// =============================================================================
// Stake Program Instructions
// =============================================================================

/** Initialize a stake account instruction */
export interface StakeInitializeInstruction {
  type: "stakeInitialize";
  /** Stake account address (base58) */
  stake: string;
  /** Authorized staker pubkey (base58) */
  staker: string;
  /** Authorized withdrawer pubkey (base58) */
  withdrawer: string;
}

/** Delegate stake to a validator instruction */
export interface StakeDelegateInstruction {
  type: "stakeDelegate";
  /** Stake account address (base58) */
  stake: string;
  /** Vote account (validator) to delegate to (base58) */
  vote: string;
  /** Stake authority (base58) */
  authority: string;
}

/** Deactivate a stake account instruction */
export interface StakeDeactivateInstruction {
  type: "stakeDeactivate";
  /** Stake account address (base58) */
  stake: string;
  /** Stake authority (base58) */
  authority: string;
}

/** Withdraw from a stake account instruction */
export interface StakeWithdrawInstruction {
  type: "stakeWithdraw";
  /** Stake account address (base58) */
  stake: string;
  /** Recipient address (base58) */
  recipient: string;
  /** Amount in lamports to withdraw */
  lamports: bigint;
  /** Withdraw authority (base58) */
  authority: string;
}

/** Change stake account authorization instruction */
export interface StakeAuthorizeInstruction {
  type: "stakeAuthorize";
  /** Stake account address (base58) */
  stake: string;
  /** New authority pubkey (base58) */
  newAuthority: string;
  /** Authorization type: "staker" or "withdrawer" */
  authorizeType: "staker" | "withdrawer";
  /** Current authority (base58) */
  authority: string;
}

/** Split stake account instruction (for partial deactivation) */
export interface StakeSplitInstruction {
  type: "stakeSplit";
  /** Source stake account address (base58) */
  stake: string;
  /** Destination stake account (must be uninitialized/created first) (base58) */
  splitStake: string;
  /** Stake authority (base58) */
  authority: string;
  /** Amount in lamports to split */
  lamports: bigint;
}

// =============================================================================
// SPL Token Instructions
// =============================================================================

/** Transfer tokens instruction (uses TransferChecked) */
export interface TokenTransferInstruction {
  type: "tokenTransfer";
  /** Source token account (base58) */
  source: string;
  /** Destination token account (base58) */
  destination: string;
  /** Token mint address (base58) */
  mint: string;
  /** Amount of tokens (in smallest units) */
  amount: bigint;
  /** Number of decimals for the token */
  decimals: number;
  /** Owner/authority of the source account (base58) */
  authority: string;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

/** Create an Associated Token Account instruction */
export interface CreateAssociatedTokenAccountInstruction {
  type: "createAssociatedTokenAccount";
  /** Payer for account creation (base58) */
  payer: string;
  /** Owner of the new ATA (base58) */
  owner: string;
  /** Token mint address (base58) */
  mint: string;
  /** Token program ID (optional, defaults to SPL Token) */
  tokenProgramId?: string;
}

/** Close an Associated Token Account instruction */
export interface CloseAssociatedTokenAccountInstruction {
  type: "closeAssociatedTokenAccount";
  /** Token account to close (base58) */
  account: string;
  /** Destination for remaining lamports (base58) */
  destination: string;
  /** Authority of the account (base58) */
  authority: string;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

/** Mint tokens to an account instruction */
export interface MintToInstruction {
  type: "mintTo";
  /** Token mint address (base58) */
  mint: string;
  /** Destination token account (base58) */
  destination: string;
  /** Mint authority (base58) */
  authority: string;
  /** Amount of tokens to mint (in smallest units) */
  amount: bigint;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

/** Burn tokens from an account instruction */
export interface BurnInstruction {
  type: "burn";
  /** Token mint address (base58) */
  mint: string;
  /** Source token account to burn from (base58) */
  account: string;
  /** Token account authority (base58) */
  authority: string;
  /** Amount of tokens to burn (in smallest units) */
  amount: bigint;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

/** Approve a delegate to transfer tokens instruction */
export interface ApproveInstruction {
  type: "approve";
  /** Token account to approve delegation for (base58) */
  account: string;
  /** Delegate address (who can transfer) (base58) */
  delegate: string;
  /** Token account owner (base58) */
  owner: string;
  /** Amount of tokens to approve (in smallest units) */
  amount: bigint;
  /** Token program ID (optional, defaults to SPL Token) */
  programId?: string;
}

// =============================================================================
// Jito Stake Pool Instructions
// =============================================================================

/** Deposit SOL into a stake pool (Jito liquid staking) */
export interface StakePoolDepositSolInstruction {
  type: "stakePoolDepositSol";
  /** Stake pool address (base58) */
  stakePool: string;
  /** Withdraw authority PDA (base58) */
  withdrawAuthority: string;
  /** Reserve stake account (base58) */
  reserveStake: string;
  /** Funding account (SOL source, signer) (base58) */
  fundingAccount: string;
  /** Destination for pool tokens (base58) */
  destinationPoolAccount: string;
  /** Manager fee account (base58) */
  managerFeeAccount: string;
  /** Referral pool account (base58) */
  referralPoolAccount: string;
  /** Pool mint address (base58) */
  poolMint: string;
  /** Amount in lamports to deposit */
  lamports: bigint;
}

/** Withdraw stake from a stake pool (Jito liquid staking) */
export interface StakePoolWithdrawStakeInstruction {
  type: "stakePoolWithdrawStake";
  /** Stake pool address (base58) */
  stakePool: string;
  /** Validator list account (base58) */
  validatorList: string;
  /** Withdraw authority PDA (base58) */
  withdrawAuthority: string;
  /** Validator stake account to split from (base58) */
  validatorStake: string;
  /** Destination stake account (uninitialized) (base58) */
  destinationStake: string;
  /** Authority for the destination stake account (base58) */
  destinationStakeAuthority: string;
  /** Source pool token account authority (signer) (base58) */
  sourceTransferAuthority: string;
  /** Source pool token account (base58) */
  sourcePoolAccount: string;
  /** Manager fee account (base58) */
  managerFeeAccount: string;
  /** Pool mint address (base58) */
  poolMint: string;
  /** Amount of pool tokens to burn */
  poolTokens: bigint;
}

// =============================================================================
// Custom Instruction
// =============================================================================

/** Account metadata for custom instructions */
export interface CustomAccountMeta {
  /** Account public key (base58) */
  pubkey: string;
  /** Whether the account is a signer */
  isSigner: boolean;
  /** Whether the account is writable */
  isWritable: boolean;
}

/**
 * Custom instruction for invoking any program.
 * Enables passthrough of arbitrary instructions for extensibility.
 */
export interface CustomInstruction {
  type: "custom";
  /** The program ID to invoke (base58) */
  programId: string;
  /** Account metas for the instruction */
  accounts: CustomAccountMeta[];
  /** Instruction data (base64 or hex encoded) */
  data: string;
  /** Encoding of the data field: "base64" (default) or "hex" */
  encoding?: "base64" | "hex";
}

/** Union of all instruction types */
export type Instruction =
  | TransferInstruction
  | CreateAccountInstruction
  | NonceAdvanceInstruction
  | NonceInitializeInstruction
  | AllocateInstruction
  | AssignInstruction
  | MemoInstruction
  | ComputeBudgetInstruction
  | StakeInitializeInstruction
  | StakeDelegateInstruction
  | StakeDeactivateInstruction
  | StakeWithdrawInstruction
  | StakeAuthorizeInstruction
  | StakeSplitInstruction
  | TokenTransferInstruction
  | CreateAssociatedTokenAccountInstruction
  | CloseAssociatedTokenAccountInstruction
  | MintToInstruction
  | BurnInstruction
  | ApproveInstruction
  | StakePoolDepositSolInstruction
  | StakePoolWithdrawStakeInstruction
  | CustomInstruction;

// =============================================================================
// TransactionIntent
// =============================================================================

/**
 * A declarative intent to build a Solana transaction.
 *
 * @example
 * ```typescript
 * const intent: TransactionIntent = {
 *   feePayer: 'DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB',
 *   nonce: {
 *     type: 'blockhash',
 *     value: 'GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4'
 *   },
 *   instructions: [
 *     { type: 'transfer', from: '...', to: '...', lamports: '1000000' }
 *   ]
 * };
 * ```
 */
export interface TransactionIntent {
  /** The fee payer's public key (base58) */
  feePayer: string;
  /** The nonce source (blockhash or durable nonce) */
  nonce: NonceSource;
  /** List of instructions to include */
  instructions: Instruction[];

  // ===== Versioned Transaction Fields (MessageV0) =====
  // If addressLookupTables is provided, a versioned transaction is built.

  /**
   * Address Lookup Tables for versioned transactions.
   * If provided, builds a MessageV0 transaction instead of legacy.
   */
  addressLookupTables?: AddressLookupTable[];

  /**
   * Static account keys (for versioned transaction round-trip).
   * These are the accounts stored directly in the message.
   */
  staticAccountKeys?: string[];
}

// =============================================================================
// buildTransaction function
// =============================================================================

/**
 * Build a Solana transaction from a high-level intent.
 *
 * This function takes a declarative TransactionIntent and produces a Transaction
 * object that can be inspected, signed, and serialized.
 *
 * The returned transaction is unsigned - signatures should be added via
 * `addSignature()` before serializing with `toBytes()` and broadcasting.
 *
 * @param intent - The transaction intent describing what to build
 * @returns A Transaction object that can be inspected, signed, and serialized
 * @throws Error if the intent cannot be built (e.g., invalid addresses)
 *
 * @example
 * ```typescript
 * import { buildTransaction } from '@bitgo/wasm-solana';
 *
 * // Build a simple SOL transfer
 * const tx = buildTransaction({
 *   feePayer: sender,
 *   nonce: { type: 'blockhash', value: blockhash },
 *   instructions: [
 *     { type: 'transfer', from: sender, to: recipient, lamports: 1000000n }
 *   ]
 * });
 *
 * // Inspect the transaction
 * console.log(tx.feePayer);
 * console.log(tx.recentBlockhash);
 *
 * // Get the signable payload for signing
 * const payload = tx.signablePayload();
 *
 * // Add signature and serialize
 * tx.addSignature(signerPubkey, signature);
 * const txBytes = tx.toBytes();
 * ```
 *
 * @example
 * ```typescript
 * // Build with durable nonce and priority fee
 * const tx = buildTransaction({
 *   feePayer: sender,
 *   nonce: { type: 'durable', address: nonceAccount, authority: sender, value: nonceValue },
 *   instructions: [
 *     { type: 'computeBudget', unitLimit: 200000, unitPrice: 5000 },
 *     { type: 'transfer', from: sender, to: recipient, lamports: 1000000n },
 *     { type: 'memo', message: 'BitGo transfer' }
 *   ]
 * });
 * ```
 */
export function buildTransaction(intent: TransactionIntent): Transaction {
  const wasm = BuilderNamespace.build_transaction(intent);
  return Transaction.fromWasm(wasm);
}

// =============================================================================
// Raw Versioned Transaction Data Types (for fromVersionedTransactionData path)
// =============================================================================

/**
 * A pre-compiled versioned instruction (uses indexes, not pubkeys).
 * This is the format used in MessageV0 transactions.
 */
export interface VersionedInstruction {
  /** Index into the account keys array for the program ID */
  programIdIndex: number;
  /** Indexes into the account keys array for instruction accounts */
  accountKeyIndexes: number[];
  /** Instruction data (base58 encoded) */
  data: string;
}

/**
 * Message header for versioned transactions.
 * Describes the structure of the account keys array.
 */
export interface MessageHeader {
  /** Number of required signatures */
  numRequiredSignatures: number;
  /** Number of readonly signed accounts */
  numReadonlySignedAccounts: number;
  /** Number of readonly unsigned accounts */
  numReadonlyUnsignedAccounts: number;
}

/**
 * Raw versioned transaction data for direct serialization.
 * This is used when we have pre-formed MessageV0 data that just needs to be serialized.
 * No instruction compilation is needed - just serialize the raw structure.
 */
export interface RawVersionedTransactionData {
  /** Static account keys (base58 encoded public keys) */
  staticAccountKeys: string[];
  /** Address lookup tables */
  addressLookupTables: AddressLookupTable[];
  /** Pre-compiled instructions with index-based account references */
  versionedInstructions: VersionedInstruction[];
  /** Message header */
  messageHeader: MessageHeader;
  /** Recent blockhash (base58) */
  recentBlockhash: string;
}

/**
 * Build a versioned transaction directly from raw MessageV0 data.
 *
 * This function is used for the `fromVersionedTransactionData()` path where we already
 * have pre-compiled versioned data (indexes + ALT refs). No instruction compilation
 * is needed - we just serialize the raw structure.
 *
 * @param data - Raw versioned transaction data
 * @returns A VersionedTransaction object that can be inspected, signed, and serialized
 * @throws Error if the data is invalid
 *
 * @example
 * ```typescript
 * import { buildFromVersionedData } from '@bitgo/wasm-solana';
 *
 * const tx = buildFromVersionedData({
 *   staticAccountKeys: ['pubkey1', 'pubkey2', ...],
 *   addressLookupTables: [
 *     { accountKey: 'altPubkey', writableIndexes: [0, 1], readonlyIndexes: [2] }
 *   ],
 *   versionedInstructions: [
 *     { programIdIndex: 0, accountKeyIndexes: [1, 2], data: 'base58EncodedData' }
 *   ],
 *   messageHeader: {
 *     numRequiredSignatures: 1,
 *     numReadonlySignedAccounts: 0,
 *     numReadonlyUnsignedAccounts: 3
 *   },
 *   recentBlockhash: 'blockhash'
 * });
 *
 * // Inspect, sign, and serialize
 * console.log(tx.feePayer);
 * tx.addSignature(signerPubkey, signature);
 * const txBytes = tx.toBytes();
 * ```
 */
export function buildFromVersionedData(data: RawVersionedTransactionData): VersionedTransaction {
  const wasm = BuilderNamespace.build_from_versioned_data(data);
  return VersionedTransaction.fromWasm(wasm);
}
