export enum ScriptType {
  P2SH = "p2sh",
  P2SH_P2WSH = "p2shP2wsh",
  P2WSH = "p2wsh",
  P2TR = "p2tr",
  P2TR_MUSIG2 = "p2trMusig2",
}

export enum WalletMode {
  FixedScript = "fixedScript",
  Descriptor = "descriptor",
}

export interface Wallet {
  id: string;
  name: string;
  mode: WalletMode;
  /** Fixed-script mode: 3 xpubs (wallet supports all script types via chain codes) */
  userXpub: string;
  backupXpub: string;
  bitgoXpub: string;
  /** Descriptor mode: raw descriptor string (e.g., wsh(multi(2, xpub1/0/*, xpub2/0/*, xpub3/0/*))) */
  descriptor?: string;
  network: "bitcoin" | "testnet";
  hasUserKey: boolean;
  createdAt: string;
}

export interface ParsedInput {
  address: string;
  value: bigint;
  scriptId: { chain: number; index: number } | null;
}

export interface ParsedOutput {
  address: string;
  value: bigint;
  scriptId: { chain: number; index: number } | null;
  isChange: boolean;
}

export interface ParsedTransaction {
  inputs: ParsedInput[];
  outputs: ParsedOutput[];
  spendAmount: bigint;
  minerFee: bigint;
}

/** Opaque handle for a parsed PSBT held by the WASM layer. Do not access _inner directly. */
export interface PsbtHandle {
  readonly _tag: "PsbtHandle";
  readonly _mode: WalletMode;
  /** @internal */
  readonly _inner: unknown;
}

/** Opaque handle for RootWalletKeys created from 3 xpubs. Do not access _inner directly. */
export interface WalletKeysHandle {
  readonly _tag: "WalletKeysHandle";
  /** @internal */
  readonly _inner: unknown;
}

/** Opaque handle for a descriptor map used in descriptor wallet mode. Do not access _inner directly. */
export interface DescriptorMapHandle {
  readonly _tag: "DescriptorMapHandle";
  /** @internal */
  readonly _inner: unknown;
}

export interface SignatureInfo {
  current: number;
  required: number;
}

export enum WasmState {
  Uninitialized = "uninitialized",
  Loading = "loading",
  Ready = "ready",
  Error = "error",
}
