# Migration Guide: utxo-core/descriptor to wasm-utxo/descriptorWallet

This module provides descriptor wallet functionality that was previously in `@bitgo/utxo-core`.

## Import Changes

### Before (utxo-core)

```typescript
import {
  DescriptorMap,
  toDescriptorMap,
  findDescriptorForInput,
  createPsbt,
  parse,
  getDescriptorAtIndex,
  createScriptPubKeyFromDescriptor,
  getVirtualSize,
} from "@bitgo/utxo-core/descriptor";
```

### After (wasm-utxo)

```typescript
import { descriptorWallet } from "@bitgo/wasm-utxo";

const {
  toDescriptorMap,
  findDescriptorForInput,
  createPsbt,
  parse,
  getDescriptorAtIndex,
  createScriptPubKeyFromDescriptor,
  getVirtualSize,
} = descriptorWallet;
```

## API Changes

### PSBT Creation

The `createPsbt` function returns a `wasm-utxo.Psbt` instead of `utxolib.bitgo.UtxoPsbt`.

```typescript
// Before: Returns utxolib.bitgo.UtxoPsbt
const psbt = createPsbt(params, inputs, outputs);

// After: Returns wasm-utxo Psbt
const psbt = descriptorWallet.createPsbt(params, inputs, outputs);
```

### Address Creation

The `createAddressFromDescriptor` function takes a `CoinName` instead of `utxolib.Network`:

```typescript
// Before
createAddressFromDescriptor(descriptor, index, utxolib.networks.bitcoin);

// After
descriptorWallet.createAddressFromDescriptor(descriptor, index, "Bitcoin");
```

### Signing

Use `signWithKey` from the descriptorWallet module:

```typescript
// Before
tx.signInputHD(vin, signerKeychain);

// After
descriptorWallet.signWithKey(psbt, signerKeychain);
```

## Not Ported

The following are intentionally **not** included in this migration:

- `fromFixedScriptWallet` - Converting fixed-script wallets to descriptors should remain in utxo-core or abstract-utxo

## Network Support

Descriptor wallets are currently only supported for Bitcoin mainnet and testnet.
Altcoin descriptor wallets should continue using the fixed-script wallet approach.
