# wasm-dot Implementation Plan

> Rust/WASM module for Polkadot (DOT) transaction parsing, signing, and building

---

## Overview

This plan outlines the implementation of `@bitgo/wasm-dot`, a WASM module that replaces the heavy `@polkadot/api` and `@substrate/txwrapper-*` dependencies in BitGoJS with a lightweight Rust implementation.

**Goals (in priority order):**
1. Parse DOT transactions (replace `explainTransaction`)
2. Add signatures to transactions (replace `TransactionBuilder.addSignature()` flow)
3. Build transactions from intents (replace Factory→Builder chain)

---

## Project Setup (Copy from wasm-utxo)

Before writing any code, copy the following config files from `packages/wasm-utxo/`:

| File | Purpose |
|------|---------|
| `.prettierrc` | Prettier config for TypeScript formatting |
| `.prettierignore` | Prettier ignore patterns |
| `.eslintrc.js` | ESLint config for TypeScript linting |
| `rustfmt.toml` | Rust formatter config |
| `.cargo/config.toml` | Cargo config (if present) |
| `Makefile` | Build targets for WASM compilation |
| `tsconfig.json` | TypeScript config for ESM |
| `tsconfig.cjs.json` | TypeScript config for CommonJS |

**Before committing, always run:**
```bash
# Rust
cargo fmt

# TypeScript
npx prettier --write js/ test/
```

---

## Research Summary

### Transaction Types to Support

| Category | Methods |
|----------|---------|
| **Transfers** | `balances.transferKeepAlive`, `balances.transferAll` |
| **Staking** | `staking.bond`, `staking.bondExtra`, `staking.unbond`, `staking.withdrawUnbonded`, `staking.chill`, `staking.payoutStakers` |
| **Proxy** | `proxy.addProxy`, `proxy.removeProxy`, `proxy.proxy` |
| **Batch** | `utility.batch`, `utility.batchAll` |

### Key Technical Details

- **Key Curve**: Ed25519 (32-byte public keys)
- **Address Format**: SS58 encoding (prefix 0=mainnet, 42=testnet)
- **Serialization**: SCALE codec
- **Extrinsic Version**: V4 (0x84 for signed)
- **Signature Format**: `0x00` prefix + 64-byte Ed25519 signature

### DOT-Specific Challenge: External Context

Unlike Solana where everything is in the serialized bytes, DOT transactions require external context:

```typescript
interface DotContext {
  // Material metadata (from chain)
  material: {
    genesisHash: string;      // e.g., "0x91b171bb158e2d..."
    chainName: string;        // "Polkadot", "Westend"
    specName: string;         // "polkadot", "westmint"
    specVersion: number;      // e.g., 9150
    txVersion: number;        // e.g., 9
    metadata: string;         // SCALE-encoded runtime metadata
  };

  // Validity window
  validity: {
    firstValid: number;       // Block number
    maxDuration?: number;     // Era period (default: 2400)
  };

  // Reference block
  referenceBlock: string;     // Block hash

  // Sender (not always in unsigned tx)
  sender?: string;            // SS58 address
}
```

---

## Architecture

### Directory Structure

```
packages/wasm-dot/
├── Cargo.toml
├── Makefile
├── package.json
├── tsconfig.json
├── tsconfig.cjs.json
├── .gitignore
├── src/
│   ├── lib.rs                    # Crate root
│   ├── error.rs                  # WasmDotError
│   ├── types.rs                  # Shared types (Material, Validity, etc.)
│   ├── address.rs                # SS58 encoding/decoding
│   ├── transaction.rs            # Core transaction logic
│   ├── parser.rs                 # Transaction parsing (decode extrinsic)
│   ├── builder/
│   │   ├── mod.rs
│   │   ├── types.rs              # Intent types (serde tagged enums)
│   │   ├── transfer.rs           # Transfer building
│   │   ├── staking.rs            # Staking operations
│   │   ├── proxy.rs              # Proxy operations
│   │   └── batch.rs              # Batch transactions
│   └── wasm/
│       ├── mod.rs
│       ├── transaction.rs        # WasmTransaction
│       ├── parser.rs             # ParserNamespace
│       ├── builder.rs            # BuilderNamespace
│       └── try_into_js_value.rs  # Rust→JS conversion
├── js/
│   ├── index.ts
│   ├── transaction.ts
│   ├── parser.ts
│   ├── builder.ts
│   └── types.ts
└── test/
    ├── transaction.ts
    ├── parser.ts
    └── builder.ts
```

### Rust Crates

```toml
[dependencies]
# WASM
wasm-bindgen = "0.2"
js-sys = "0.3"
getrandom = { version = "0.2", features = ["js"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde-wasm-bindgen = "0.6"

# Substrate/Polkadot
subxt = { version = "0.35", default-features = false }
sp-core = { version = "31", default-features = false }
sp-runtime = { version = "34", default-features = false }
parity-scale-codec = { version = "3.6", features = ["derive"] }
scale-info = { version = "2.10", default-features = false }

# Crypto
blake2 = "0.10"
```

**Note**: We'll use `subxt` for SCALE encoding/decoding and metadata handling, `sp-core` for SS58 and crypto primitives.

---

## Phase 1: Core Infrastructure & Parsing

### 1.1 Error Type

```rust
// src/error.rs
pub enum WasmDotError {
    InvalidAddress(String),
    InvalidTransaction(String),
    InvalidSignature(String),
    ScaleDecodeError(String),
    MissingContext(String),
}
```

### 1.2 Address Module

```rust
// src/address.rs
pub fn encode_ss58(public_key: &[u8], prefix: u16) -> Result<String, WasmDotError>;
pub fn decode_ss58(address: &str) -> Result<(Vec<u8>, u16), WasmDotError>;
pub fn validate_address(address: &str, expected_prefix: Option<u16>) -> bool;
```

### 1.3 Transaction Parsing

Parse unsigned and signed extrinsics:

```rust
// src/parser.rs
pub struct ParsedTransaction {
    pub id: Option<String>,           // Tx hash (if signed)
    pub sender: String,               // SS58 address
    pub nonce: u32,
    pub tip: u128,
    pub era: Era,                     // Mortal or Immortal
    pub method: ParsedMethod,         // Decoded call
    pub signature: Option<Signature>, // If signed
}

pub struct ParsedMethod {
    pub pallet: String,               // e.g., "balances"
    pub name: String,                 // e.g., "transferKeepAlive"
    pub args: serde_json::Value,      // Method-specific args
}

pub fn parse_transaction(
    bytes: &[u8],
    context: Option<&ParseContext>,
) -> Result<ParsedTransaction, WasmDotError>;
```

### 1.4 ParsedTransaction → JS (TryIntoJsValue)

```rust
impl TryIntoJsValue for ParsedTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "id" => self.id,
            "sender" => self.sender,
            "nonce" => self.nonce as u64,
            "tip" => self.tip,  // u128 → BigInt
            "era" => self.era,
            "method" => self.method,
            "outputs" => self.extract_outputs(),
            "fee" => js_obj!("fee" => self.tip, "type" => "tip")
        )
    }
}
```

---

## Phase 2: Signature Operations

### 2.1 Transaction Struct

```rust
// src/transaction.rs
pub struct Transaction {
    unsigned: UnsignedTransaction,    // Decoded extrinsic payload
    signature: Option<[u8; 64]>,      // Ed25519 signature
    signer: Option<[u8; 32]>,         // Public key
    context: TransactionContext,      // Material, validity, etc.
}

impl Transaction {
    pub fn from_bytes(bytes: &[u8], context: Option<ParseContext>) -> Result<Self, WasmDotError>;
    pub fn to_bytes(&self) -> Result<Vec<u8>, WasmDotError>;
    pub fn signable_payload(&self) -> Vec<u8>;
    pub fn add_signature(&mut self, pubkey: &[u8], signature: &[u8]) -> Result<(), WasmDotError>;
    pub fn id(&self) -> Option<String>;  // Blake2-256 hash of signed tx
}
```

### 2.2 Signable Payload

The signable payload for DOT is the SCALE-encoded `ExtrinsicPayload`:

```rust
pub fn signable_payload(&self) -> Vec<u8> {
    let payload = ExtrinsicPayload {
        call: self.unsigned.method.clone(),
        era: self.unsigned.era,
        nonce: self.unsigned.nonce,
        tip: self.unsigned.tip,
        spec_version: self.context.material.spec_version,
        transaction_version: self.context.material.tx_version,
        genesis_hash: self.context.material.genesis_hash,
        block_hash: self.context.reference_block,
    };

    let encoded = payload.encode();

    // If payload > 256 bytes, hash it first
    if encoded.len() > 256 {
        blake2_256(&encoded).to_vec()
    } else {
        encoded
    }
}
```

### 2.3 Add Signature

```rust
pub fn add_signature(&mut self, pubkey: &[u8], signature: &[u8]) -> Result<(), WasmDotError> {
    if pubkey.len() != 32 {
        return Err(WasmDotError::InvalidSignature("pubkey must be 32 bytes".into()));
    }
    if signature.len() != 64 {
        return Err(WasmDotError::InvalidSignature("signature must be 64 bytes".into()));
    }

    self.signer = Some(pubkey.try_into().unwrap());
    self.signature = Some(signature.try_into().unwrap());
    Ok(())
}
```

### 2.4 Serialize Signed Transaction

```rust
pub fn to_bytes(&self) -> Result<Vec<u8>, WasmDotError> {
    match (&self.signature, &self.signer) {
        (Some(sig), Some(signer)) => {
            // Build signed extrinsic
            let signed = SignedExtrinsic {
                signature: MultiSignature::Ed25519(*sig),
                signer: MultiAddress::Id(*signer),
                era: self.unsigned.era,
                nonce: self.unsigned.nonce,
                tip: self.unsigned.tip,
                call: self.unsigned.method.clone(),
            };
            Ok(signed.encode())
        }
        _ => {
            // Return unsigned extrinsic
            Ok(self.unsigned.encode())
        }
    }
}
```

---

## Phase 3: Transaction Building

### 3.1 Intent Types

```rust
// src/builder/types.rs
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TransactionIntent {
    Transfer(TransferIntent),
    TransferAll(TransferAllIntent),
    Stake(StakeIntent),
    Unstake(UnstakeIntent),
    WithdrawUnbonded(WithdrawIntent),
    AddProxy(AddProxyIntent),
    RemoveProxy(RemoveProxyIntent),
    Batch(BatchIntent),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferIntent {
    pub to: String,           // SS58 address
    pub amount: u128,         // In planck
    pub keep_alive: bool,     // Use transferKeepAlive vs transfer
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeIntent {
    pub amount: u128,
    pub controller: String,
    pub payee: StakePayee,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StakePayee {
    Staked,
    Stash,
    Controller,
    Account { address: String },
}
```

### 3.2 Build Context

```rust
// src/builder/types.rs
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildContext {
    pub sender: String,
    pub nonce: u32,
    pub tip: Option<u128>,
    pub material: Material,
    pub validity: Validity,
    pub reference_block: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Material {
    pub genesis_hash: String,
    pub chain_name: String,
    pub spec_name: String,
    pub spec_version: u32,
    pub tx_version: u32,
    // Note: metadata is NOT passed to WASM — too large
    // Instead, we hardcode pallet/method indices for known operations
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Validity {
    pub first_valid: u32,
    pub max_duration: Option<u32>,  // Default: 2400
}
```

### 3.3 Build Function

```rust
// src/builder/mod.rs
pub fn build_transaction(
    intent: TransactionIntent,
    context: BuildContext,
) -> Result<Transaction, WasmDotError> {
    let call = match intent {
        TransactionIntent::Transfer(t) => build_transfer_call(&t, &context)?,
        TransactionIntent::Stake(s) => build_stake_call(&s, &context)?,
        TransactionIntent::Batch(b) => build_batch_call(&b, &context)?,
        // ... etc
    };

    let unsigned = UnsignedTransaction {
        method: call,
        era: compute_era(context.validity),
        nonce: context.nonce,
        tip: context.tip.unwrap_or(0),
    };

    Ok(Transaction {
        unsigned,
        signature: None,
        signer: None,
        context: context.into(),
    })
}
```

### 3.4 Hardcoded Call Indices

Since we can't parse the full metadata in WASM (too large), we'll hardcode known pallet/method indices:

```rust
// src/builder/indices.rs
pub struct CallIndex {
    pub pallet: u8,
    pub method: u8,
}

// Polkadot mainnet indices (specVersion 9150+)
pub mod polkadot {
    pub const BALANCES_TRANSFER_KEEP_ALIVE: CallIndex = CallIndex { pallet: 5, method: 3 };
    pub const BALANCES_TRANSFER_ALL: CallIndex = CallIndex { pallet: 5, method: 4 };
    pub const STAKING_BOND: CallIndex = CallIndex { pallet: 7, method: 0 };
    pub const STAKING_UNBOND: CallIndex = CallIndex { pallet: 7, method: 2 };
    // ... etc
}

// Westend testnet indices
pub mod westend {
    // Similar structure, different indices
}
```

**Note**: Indices can change between runtime upgrades. We'll need to maintain versioned indices or fetch them dynamically.

---

## TypeScript API

> **Design principle**: DOT uses extrinsic calls (pallet methods), not instructions.
> Don't copy Solana's instruction-based pattern. Design the transaction abstraction
> to match the blockchain's native model — extrinsics have call data (pallet + method + args)
> plus an envelope (nonce, tip, era, spec version) for signing context.

### Transaction Class

```typescript
// js/transaction.ts
export class DotTransaction {
  static fromHex(hex: string, network?: Network): DotTransaction;
  toHex(): string;

  get id(): string | null;
  get sender(): string;

  // Parsed call data (immutable — determined by the extrinsic)
  get call(): { pallet: string; method: string; args: unknown };
  get type(): TransactionType;
  get outputs(): { address: string; amount: string }[];

  // Envelope fields (mutable before signing)
  get nonce(): number;
  setNonce(nonce: number): void;
  get tip(): bigint;
  setTip(tip: bigint): void;
  get era(): { mortal: { period: number; phase: number } } | 'immortal';

  // Signing context (spec version, genesis hash, etc.)
  setContext(context: SigningContext): void;

  // Signing
  signablePayload(): Uint8Array;
  addSignature(pubkey: string, signature: Uint8Array): void;
  get signature(): Uint8Array | null;
}
```

### Parse Function

The primary parse API is `DotParser.parseTransactionHex()` from `@bitgo/wasm-dot`,
which is already integrated via `explainTransactionFromHex()` in `sdk-coin-dot`.

```typescript
// js/parser.ts — DotParser wraps the WASM parser
export class DotParser {
  static parseTransactionHex(hex: string, network?: Network): ParsedTransaction;
}

export interface ParsedTransaction {
  id: string | null;
  sender: string;
  nonce: number;
  tip: bigint;
  era: { mortal: { period: number; phase: number } } | 'immortal';
  call: {
    pallet: string;
    method: string;
    args: unknown;
  };
  outputs: { address: string; amount: string }[];
  fee: { fee: string; type: 'tip' };
  type: TransactionType;
}
```

### Build Function

```typescript
// js/builder.ts
export function buildTransaction(
  intent: TransactionIntent,
  context: BuildContext,
): DotTransaction;

export type TransactionIntent =
  | { type: 'transfer'; to: string; amount: bigint; keepAlive?: boolean }
  | { type: 'transferAll'; to: string; keepAlive?: boolean }
  | { type: 'stake'; amount: bigint; controller: string; payee: StakePayee }
  | { type: 'unstake'; amount: bigint }
  | { type: 'withdrawUnbonded'; slashingSpans: number }
  | { type: 'addProxy'; delegate: string; proxyType: ProxyType; delay: number }
  | { type: 'removeProxy'; delegate: string; proxyType: ProxyType; delay: number }
  | { type: 'batch'; calls: TransactionIntent[]; atomic?: boolean };
```

---

## Test Plan

### Test Fixtures

Use fixtures from BitGoJS:
- `/Users/luiscovarrubias/BitGoJS/modules/sdk-coin-dot/test/resources/index.ts`
- `/Users/luiscovarrubias/BitGoJS/modules/sdk-coin-dot/test/resources/materialData.json`

### Test Categories

1. **Address Tests**
   - SS58 encode/decode roundtrip
   - Mainnet vs testnet prefix
   - Invalid address rejection

2. **Parser Tests**
   - Parse unsigned transfer
   - Parse signed transfer
   - Parse staking transactions
   - Parse batch transactions
   - Parse proxy transactions

3. **Signature Tests**
   - Add signature to unsigned tx
   - Verify signature placement
   - Signable payload matches BitGoJS

4. **Builder Tests**
   - Build transfer intent
   - Build staking intent
   - Build batch intent
   - Roundtrip: build → serialize → parse

5. **Compatibility Tests**
   - Compare parseTransaction output with BitGoJS explainTransaction
   - Compare built tx bytes with BitGoJS output

---

## Implementation Order

1. **Week 1: Core Infrastructure**
   - [ ] Set up package structure (Cargo.toml, package.json, Makefile)
   - [ ] Implement error types
   - [ ] Implement SS58 address encoding/decoding
   - [ ] Set up TryIntoJsValue and js_obj! macro

2. **Week 2: Transaction Parsing**
   - [ ] Implement SCALE decoding for extrinsics
   - [ ] Parse unsigned transactions
   - [ ] Parse signed transactions
   - [ ] Extract method/args for known call types
   - [ ] TypeScript wrapper for parseTransaction

3. **Week 3: Signature Operations**
   - [ ] Implement Transaction struct
   - [ ] Implement signable_payload()
   - [ ] Implement add_signature()
   - [ ] Implement to_bytes() for signed tx
   - [ ] TypeScript Transaction class

4. **Week 4: Transaction Building**
   - [ ] Define intent types with serde
   - [ ] Implement transfer building
   - [ ] Implement staking operations
   - [ ] Implement batch transactions
   - [ ] TypeScript buildTransaction

5. **Week 5: Testing & Integration**
   - [ ] Port test fixtures from BitGoJS
   - [ ] Compatibility tests
   - [ ] Integration with BitGoJS sdk-coin-dot

---

## Open Questions

1. **Metadata Handling**: Full runtime metadata is ~1MB. Options:
   - a) Hardcode pallet indices (brittle across upgrades)
   - b) Pass minimal metadata subset from wallet-platform
   - c) Use metadata V15 pruning (experimental)

2. **Multi-chain Support**: Need to support Polkadot, Kusama, Westend, Asset Hubs. Each has different pallet indices. How to handle?

3. **Proxy Transactions**: The `proxy.proxy` call wraps another call. Need to handle nested decoding.

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| SCALE codec complexity | Use `parity-scale-codec` crate, well-tested |
| Runtime upgrade breaks indices | Version pallet indices by specVersion |
| Large metadata size | Don't pass metadata to WASM; hardcode indices |
| subxt crate too heavy for WASM | Use only codec/types features, disable runtime |

---

*Plan created: 2026-02-05*
*Based on research from BitGoJS sdk-coin-dot and wallet-platform DOT controller*
