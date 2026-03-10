# BitGoWasm Code Conventions

This file documents API design and architecture patterns from code reviews. Following these conventions prevents review churn and keeps the codebase consistent across wasm-utxo, wasm-solana, wasm-mps, and future packages.

## These are hard rules, not suggestions. If you're unsure about a pattern, check the existing implementations in wasm-utxo.

## 1. Prefer Uint8Array, avoid unnecessary base conversions

**What:** Generally, binary formats like transactions should use `Uint8Array`. Avoid base conversions in the wasm interface.

**Why:** Type safety at the boundary. If a method accepts or returns transaction bytes, it's always `Uint8Array`. String encodings (hex, base64) belong in serialization/API layers, not in the core transaction model. This prevents API bloat where we have to add encoding and decoding variants for various base conversion formats, as well as inefficiencies due to round-tripping binary data through two base conversions.

### Exception: 0x-prefixed hex from external systems

When a chain's canonical wire format is 0x-prefixed hex (Substrate `state_getMetadata`, Ethereum JSON-RPC, etc.), accept hex strings directly rather than forcing callers to convert to `Uint8Array` at every boundary. The hex-to-bytes decode should happen once, internally in the WASM layer. This avoids the `Buffer.from('0x...', 'hex')` footgun (silently returns empty buffer with `0x` prefix) and removes pointless conversion friction when hex is how the data naturally flows through the system.

Two concrete examples:

#### `fromHex` on Substrate chains (DOT)

Substrate tooling (txwrapper, polkadot.js) always produces 0x-prefixed hex. The `fromHex()` method strips the prefix in the Rust/WASM layer before hex-decoding, avoiding the JavaScript footgun entirely. Use `fromHex()` as the primary entry point for Substrate chain deserialization. Use `fromBytes()` only when you already have raw bytes.

#### Metadata stays as a hex string

Runtime metadata (`Material.metadata`) is returned as a 0x-prefixed hex string from the Substrate `state_getMetadata` RPC and is stored/transported as hex through JSON APIs (coinSpecific, material cache, etc.). Forcing callers to convert to `Uint8Array` at every boundary adds friction and no value — the hex-to-bytes decode happens once, internally in the WASM layer, right before SCALE decoding.

**Good:**

```typescript
class Transaction {
  static fromBytes(bytes: Uint8Array): Transaction { ... }
  toBytes(): Uint8Array { ... }
  signablePayload(): Uint8Array { ... }
}

// Encoding happens at the boundary
const txBytes = Buffer.from(txHex, 'hex');
const tx = Transaction.fromBytes(txBytes);
```

**Bad:**

```typescript
// ❌ Don't accept/return hex strings on Transaction (except fromHex for Substrate)
class Transaction {
  toHex(): string { ... }
}

// ❌ Don't mix encodings
static fromBytes(bytes: Uint8Array | string): Transaction { ... }
```

**See:** `packages/wasm-solana/js/transaction.ts`, `packages/wasm-utxo/js/transaction.ts`, `packages/wasm-dot/js/transaction.ts` (fromHex exception)

---

## 2. bigint for amounts, never string

**What:** All monetary amounts, lamports, satoshis, token quantities, fees — use `bigint`. Never `number` or `string`.

**Why:**

- `number` loses precision above 2^53 (unsafe for large amounts)
- `string` delays type errors to runtime (no compile-time safety)
- `bigint` is exact, type-safe, and enforces correctness at compile time

Conversions between external representations (API strings, JSON numbers) and `bigint` are the caller's responsibility, outside the `wasm-*` package boundary. The wasm package API accepts and returns `bigint` only — no `string` or `number` overloads for amounts.

**Good:**

```typescript
export interface ExplainedOutput {
  address: string;
  amount: bigint; // ✅
}

const fee = 5000n;
const total = amount + fee; // Type-safe bigint arithmetic
```

**Bad:**

```typescript
export interface ExplainedOutput {
  address: string;
  amount: string; // ❌ Runtime errors, no type safety
}

const fee = "5000"; // ❌ Can't do arithmetic
const total = parseInt(amount) + parseInt(fee); // ❌ Loses precision
```

**See:** `packages/wasm-solana/js/explain.ts` (lines 40-43), `CLAUDE.md`

---

## 3. Const arrays for union types, not magic strings

**What:** Use `as const` arrays to define finite sets of known values. Never use bare string literals for types, opcodes, instruction names, etc.

**Why:**

- Compile-time checking (typos caught at build time)
- IDE autocomplete
- Exhaustiveness checking in switch statements
- Less repetitive than `enum` (no `Key = "Key"` duplication)

**Good:**

```typescript
export const TransactionType = ["Send", "StakingActivate", "StakingDeactivate"] as const;
export type TransactionType = (typeof TransactionType)[number];

function handleTx(type: TransactionType) {
  switch (type) {
    case "Send":
    // ...
    case "StakingActivate":
    // ...
    // TypeScript warns if you miss a case
  }
}
```

**Bad:**

```typescript
// ❌ No type safety, typos not caught
function handleTx(type: string) {
  if (type === "send") {
    // Oops, wrong case
    // ...
  }
}

// ❌ Magic strings scattered everywhere
const txType = "Send";
```

**See:** `packages/wasm-solana/js/explain.ts` (lines 19-28)

---

## 4. Return Transaction objects, not bytes (builders)

**What:** Builder functions and transaction constructors return `Transaction` objects, not raw `Uint8Array`. The caller serializes when they need bytes.

**Why:** Transaction objects can be inspected and further modified (`.addSignature()`, `.signWithKeypair()`). Returning bytes forces the caller to re-parse if they need to inspect or modify.

**Good:**

```typescript
export function buildFromIntent(params: BuildParams): Transaction {
  const wasm = BuilderNamespace.build_from_intent(...);
  return Transaction.fromWasm(wasm);
}

// Caller has full control
const tx = buildFromIntent(intent);
console.log(tx.feePayer);  // Inspect
tx.addSignature(pubkey, sig);  // Modify
const bytes = tx.toBytes();  // Serialize when ready
```

**Bad:**

```typescript
// ❌ Forces caller to re-parse for inspection
export function buildFromIntent(params: BuildParams): Uint8Array {
  const wasm = BuilderNamespace.build_from_intent(...);
  return wasm.to_bytes();
}

const bytes = buildFromIntent(intent);
const tx = Transaction.fromBytes(bytes);  // Unnecessary round-trip
```

**See:** `packages/wasm-solana/js/intentBuilder.ts`, `packages/wasm-solana/js/builder.ts`

---

## 5. Parsing separate from Transaction, context at deserialization time

**What:** Transaction deserialization (for signing) and transaction parsing (decoding instructions) are separate operations with separate entry points. `Transaction.fromBytes()` deserializes for signing. `parseTransaction()` is a standalone function that decodes a `Transaction` into structured data.

**Why:**

- Separation of concerns: deserialization is a protocol-level concept, parsing is a BitGo-level concept
- `parseTransaction` accepts a `Transaction` object (not raw bytes) to avoid double-deserialization — the caller typically already has a `Transaction` from `fromBytes()` for the signing flow

### Context/material must be passed at deserialization time

For chains where the byte layout depends on runtime configuration (e.g. Substrate signed extensions), the deserializer needs chain material/metadata to correctly identify field boundaries in the extrinsic bytes. This context must be passed to `fromHex()`/`fromBytes()`, not to `parseTransaction()`.

If you deserialize without material and the chain has non-standard extensions (e.g. Westend's `AuthorizeCall`, `StorageWeightReclaim`), the call_data boundary lands in the wrong place. At that point the damage is done — `tx.callData` returns wrong bytes. `parseTransaction()` only uses context for name resolution (pallet index → name) and address formatting, not for re-parsing the byte layout.

```typescript
// ✅ Material passed at deserialization time
const tx = DotTransaction.fromHex(hex, material);
const parsed = parseTransaction(tx, { material });

// ❌ Material passed only at parse time — call_data boundaries are already wrong
const tx = DotTransaction.fromHex(hex); // Wrong boundaries baked in
const parsed = parseTransaction(tx, { material }); // Can't fix it
```

**Good:**

```typescript
// Typical flow: decode once, use for both parsing and signing
const tx = Transaction.fromBytes(txBytes);
const parsed = parseTransaction(tx);
if (!validateParsed(parsed, buildParams)) {
  throw new Error();
}
tx.addSignature(pubkey, signature);
const signedBytes = tx.toBytes();

// Parsed data is for inspection only
for (const instr of parsed.instructionsData) {
  if (instr.type === "Transfer") {
    console.log(`${instr.amount} to ${instr.toAddress}`);
  }
}
```

**Bad:**

```typescript
// ❌ Don't accept raw bytes — forces redundant deserialization
const parsed = parseTransaction(txBytes);

// ❌ Transaction does not have a .parse() method
const tx = Transaction.fromBytes(txBytes);
const parsed = tx.parse(); // Doesn't exist

// ❌ Don't use parseTransaction result for signing
const parsed = parseTransaction(tx);
parsed.addSignature(pubkey, sig); // Wrong object type
```

**See:** `packages/wasm-solana/js/parser.ts` (parseTransaction function), `packages/wasm-solana/js/transaction.ts` (Transaction.fromBytes), `packages/wasm-dot/js/parser.ts`

---

## 6. Use wrapper classes

**What:** Wrap WASM-generated types in TypeScript classes that provide better type signatures, `camelCase` naming, and encapsulation. Don't expose raw WASM bindings to consumers.

**Why:** `wasm-bindgen` emits loose types (`any`, `string | null`) and `snake_case` naming. Wrapper classes provide precise TypeScript types, idiomatic JS naming, and hide WASM implementation details. Two patterns exist: namespace wrappers for stateless utilities, class wrappers for stateful objects.

**See:** [`packages/wasm-utxo/js/README.md`](https://github.com/BitGo/BitGoWASM/blob/master/packages/wasm-utxo/js/README.md#purpose) for the full rationale and examples of both patterns.

---

## 7. Follow wasm-utxo conventions (get wasm(), fromBytes, toBytes, toBroadcastFormat)

**What:** All wrapper classes follow the same API pattern:

- `static fromBytes(bytes: Uint8Array)` — deserialize
- `toBytes(): Uint8Array` — serialize
- `toBroadcastFormat(): string` — serialize to broadcast-ready format (0x-prefixed hex for Substrate, hex for UTXO, base64 for Solana)
- `getId(): string` — transaction ID / hash
- `get wasm(): WasmType` (internal) — access underlying WASM instance

`toBroadcastFormat()` is the standard name for "give me the string I submit to the network". The encoding varies by chain but the method name is consistent. Don't add `toHex()` as a separate method — if callers want hex they can do `Buffer.from(tx.toBytes()).toString('hex')`.

**Why:**

- Consistency across packages (wasm-utxo, wasm-solana, wasm-dot, wasm-mps all work the same way)
- Predictable API for consumers
- `get wasm()` allows package-internal code to access WASM without exposing it publicly

**Good:**

```typescript
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  static fromBytes(bytes: Uint8Array): Transaction {
    return new Transaction(WasmTransaction.from_bytes(bytes));
  }

  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  toBroadcastFormat(): string {
    return this._wasm.to_hex(); // or to_base64(), etc.
  }

  getId(): string {
    return this._wasm.id;
  }

  /** @internal */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
```

**Bad:**

```typescript
// ❌ Inconsistent naming
export class Transaction {
  static parse(bytes: Uint8Array): Transaction { ... }  // Should be fromBytes
  serialize(): Uint8Array { ... }  // Should be toBytes
  toHex(): string { ... }  // Should be toBroadcastFormat
  getTransactionId(): string { ... }  // Should be getId
}
```

**See:** `packages/wasm-utxo/js/transaction.ts`, `packages/wasm-solana/js/transaction.ts`, `packages/wasm-dot/js/transaction.ts`

---

## 8. Explain logic belongs in BitGoJS, not in the wasm package

**What:** The wasm package provides `parseTransaction()` which returns raw decoded data (pallet, method, args, nonce, tip, era). The explain logic — deriving transaction types, extracting outputs/inputs, mapping to BitGoJS `TransactionExplanation` format — belongs in the `sdk-coin-*` module in BitGoJS.

**Why:**

- `parseTransaction()` is chain-level: it decodes what the bytes contain
- `explainTransaction()` is BitGo-level: it interprets what the transaction means in the context of BitGo's wallet operations (transaction types, output extraction, fee handling)
- Keeping explain in the wasm package creates a dependency on BitGoJS types (`TransactionType`, `TransactionExplanation`) inside a package that should be chain-generic
- Changes to explain logic (adding a new transaction type, adjusting output extraction) should be a BitGoJS PR, not a wasm package publish cycle

The wasm package exports `parseTransaction(tx) → ParsedTransaction`. BitGoJS imports it and builds `explainTransaction` on top in `wasmParser.ts`.

**Good:**

```typescript
// In @bitgo/wasm-dot (wasm package)
export function parseTransaction(tx: DotTransaction, context?: ParseContext): ParsedTransaction;

// In sdk-coin-dot (BitGoJS) — wasmParser.ts
import { DotTransaction, parseTransaction } from "@bitgo/wasm-dot";

function buildExplanation(params) {
  const tx = DotTransaction.fromHex(params.txHex, params.material);
  const parsed = parseTransaction(tx, { material: params.material });
  // derive transaction type, extract outputs, map to TransactionExplanation...
}
```

**Bad:**

```typescript
// ❌ Don't put explain logic in the wasm package
// In @bitgo/wasm-dot
import { TransactionType } from "@bitgo/sdk-core"; // Wrong dependency direction

export function explainTransaction(hex, context): TransactionExplanation {
  // BitGo-specific business logic doesn't belong here
}
```

**See:** `packages/wasm-dot/js/parser.ts`, BitGoJS `modules/sdk-coin-dot/src/lib/wasmParser.ts`

---

## Summary

These 8 conventions define how BitGoWasm packages structure their APIs. They're architectural patterns enforced in code reviews — not general software practices or build requirements.

When in doubt, look at wasm-solana and wasm-utxo — they're the reference implementations. Following these patterns from the start prevents review churn and keeps all packages consistent.
