# BitGo PSBT Signer

Offline PSBT signing app for BitGo 2-of-3 multisig bitcoin wallets. Parses PSBTs,
verifies all inputs belong to the wallet, displays transaction details, and signs
with the user's key after biometric authentication.

Built with React + TypeScript + Vite, using [`@bitgo/wasm-utxo`](https://github.com/BitGo/BitGoWasm/tree/master/packages/wasm-utxo)
for all Bitcoin operations (PSBT parsing, key derivation, signing, signature verification).

Windows 95 retro UI via [react95](https://github.com/React95/React95).

## Quick start

```bash
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

## How it works

1. **Add a wallet** — paste your 3 xpubs (user, backup, BitGo) or an output descriptor
2. **Import your key** — paste an xprv or BIP39 mnemonic (stored in browser localStorage for now)
3. **Load a PSBT** — paste hex or base64, or scan a QR code
4. **Review** — app verifies all inputs belong to your wallet, shows outputs, change, fees
5. **Sign** — biometric prompt, then the app signs with your user key via WASM
6. **Export** — copy the signed PSBT hex or display as QR code

## Stack

| Layer          | Technology                                   |
| -------------- | -------------------------------------------- |
| UI             | React 19, react95, styled-components         |
| Build          | Vite 7, TypeScript 5.9                       |
| Bitcoin        | @bitgo/wasm-utxo (Rust compiled to WASM)     |
| Key derivation | @scure/bip32, bip39                          |
| QR             | html5-qrcode (scan), qrcode.react (display)  |
| Mobile shell   | Capacitor (iOS/Android — not yet configured) |

## Project structure

```
src/
  App.tsx              — WASM init, routing, global styles
  types/index.ts       — Wallet, ParsedTransaction, SignatureInfo, etc.
  services/
    wasm.ts            — WASM wrapper (parse, sign, verify, count sigs)
    keyStore.ts        — Key storage (localStorage stub, Secure Enclave later)
    walletStore.ts     — Wallet CRUD (localStorage)
    qrScanner.ts       — Camera QR scanning via html5-qrcode
  hooks/
    usePsbt.ts         — PSBT flow state machine (idle→parsed→signed)
    useWallets.ts      — Wallet list context + hook
    useBiometric.ts    — Biometric auth (browser stub, Capacitor later)
  screens/
    WalletList.tsx     — Home screen, wallet cards
    AddWallet.tsx      — Create wallet (3 xpubs or descriptor)
    WalletDetail.tsx   — Wallet info, PSBT input
    PsbtReview.tsx     — Transaction review before signing
    SignedExport.tsx    — Signed PSBT output (hex, QR, file)
    ImportKey.tsx       — xprv / mnemonic import
  components/
    Win95Window.tsx    — Reusable window chrome
    PsbtInput.tsx      — Scan QR / paste PSBT (hex or base64)
    QrDisplay.tsx      — QR code renderer
    WalletCard.tsx     — Wallet list item
  utils/
    format.ts          — formatBtc(), formatAddress()
    mnemonic.ts        — BIP39 mnemonic → xprv derivation
vendor/
  bitgo-wasm-utxo-*.tgz  — Vendored WASM package (no external registry needed)
```

## WASM dependency

The `@bitgo/wasm-utxo` package is vendored as a tarball in `vendor/`. This means
`npm install` works without access to the BitGo npm registry or the monorepo.

To update the vendored package:

```bash
# From the wasm-utxo source (if you have the monorepo)
cd /path/to/BitGoWasm/packages/wasm-utxo
npm run build
npm pack --pack-destination /path/to/bitgo-psbt-signer/vendor

# Then update the version in package.json
```

## Scripts

| Command           | Description                      |
| ----------------- | -------------------------------- |
| `npm run dev`     | Start dev server with HMR        |
| `npm run build`   | Type-check + production build    |
| `npm run preview` | Preview production build locally |
| `npm run lint`    | ESLint                           |

## Current limitations

- **Key storage**: localStorage (plaintext). Production will use iOS Secure Enclave / Android StrongBox to encrypt keys at rest.
- **Biometric auth**: Browser stub (auto-approves). Real biometric gating requires Capacitor on device.
- **Network**: No network calls — fully offline capable, but no way to broadcast transactions (by design).
- **Descriptor wallets**: Can store descriptors but PSBT verification currently only works with fixed-script (3 xpub) wallets.
- **Mobile packaging**: Capacitor is a dependency but iOS/Android projects are not yet generated (`npx cap add ios`).
