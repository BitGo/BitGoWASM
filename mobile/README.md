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

| Layer          | Technology                                  |
| -------------- | ------------------------------------------- |
| UI             | React 19, react95, styled-components        |
| Build          | Vite 7, TypeScript 5.9                      |
| Bitcoin        | @bitgo/wasm-utxo (Rust compiled to WASM)    |
| Key derivation | @scure/bip32, bip39                         |
| QR             | html5-qrcode (scan), qrcode.react (display) |
| Mobile shell   | Capacitor 8.1 (iOS + Android)               |

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

## Running on iOS (Xcode)

### Prerequisites

- **Xcode 15+** (Swift 5.9, iOS 15+ deployment target)
- **Node.js** and npm (for building the web app)
- An Apple Developer account if you want to run on a physical device

### Steps

```bash
# 1. Install dependencies (from mobile/)
npm install

# 2. Build the web app
npm run build

# 3. Sync the build output + Capacitor plugins to the iOS project
npx cap sync ios

# 4. Open the Xcode project
npx cap open ios
```

This opens `ios/App/App.xcodeproj` in Xcode. From there:

1. Xcode will resolve Swift Package Manager dependencies (Capacitor 8.1) on first open — this can take a minute
2. **Select a simulator** from the toolbar dropdown (e.g. "iPhone 16 Pro")
3. **Hit Run** (Cmd+R)

The app loads as a Capacitor webview pointing at the built `dist/` files bundled into the app.

### Running on your iPhone

To run on a physical device you need a signing identity and provisioning profile. A free Apple ID works — you don't need a paid $99/year Developer Program membership (but apps expire after 7 days with a free account).

#### 1. Add your Apple ID to Xcode

- Open **Xcode → Settings → Accounts** (Cmd+,)
- Click **+** → "Apple ID" and sign in
- Your personal team ("Your Name (Personal Team)") appears in the list

#### 2. Configure signing in the project

- In Xcode, select the **App** target in the project navigator (blue icon at the top)
- Go to the **Signing & Capabilities** tab
- Check **Automatically manage signing**
- Under **Team**, select your personal team (or your org's team if you have one)
- **Bundle Identifier**: must be globally unique. If `com.bitgo.psbtsigner` conflicts, change it to something like `com.yourname.psbtsigner`

Xcode will automatically create a development provisioning profile and signing certificate the first time you build for a device.

#### 3. Connect and trust your device

- Plug in your iPhone via USB (or use wireless debugging — see below)
- On your iPhone: **Settings → General → VPN & Device Management** — tap the developer certificate and hit "Trust"
- Your phone should appear in Xcode's device dropdown (top toolbar)

> **First time only**: if your phone shows "Developer Mode is not enabled", go to **Settings → Privacy & Security → Developer Mode** and toggle it on. The phone will restart.

#### 4. Build and run

- Select your phone from the Xcode toolbar dropdown
- Hit **Run** (Cmd+R)
- Xcode builds, installs the app on your phone, and launches it

#### Wireless debugging (no USB cable)

After the first USB connection:

1. In Xcode, go to **Window → Devices and Simulators**
2. Select your phone and check **Connect via network**
3. Your phone now appears as a wireless target in the toolbar as long as both devices are on the same network

#### Notes on free vs paid accounts

|                        | Free Apple ID      | Apple Developer Program ($99/yr) |
| ---------------------- | ------------------ | -------------------------------- |
| Simulator              | yes                | yes                              |
| Deploy to your phone   | yes (7-day expiry) | yes (1-year expiry)              |
| TestFlight / App Store | no                 | yes                              |
| Provisioning profiles  | auto-managed only  | manual + auto                    |
| Team sharing           | no                 | yes                              |

With a free account, the app expires after 7 days and you'll need to re-run from Xcode. This is fine for development.

### Live reload (optional)

To iterate faster without rebuilding/resyncing every time:

```bash
npx cap run ios --livereload --external
```

This starts the Vite dev server and points the iOS webview at your machine's local IP. Changes in `src/` hot-reload on the simulator/device. Requires the device to be on the same network.

### Native features

On a real device (or simulator with biometric enrollment):

- **Face ID / Touch ID** — the `SecureKeyStorePlugin` stores private keys in the iOS Keychain with biometric access control. The simulator supports enrolled biometrics via Features → Face ID / Touch ID in the menu bar.
- **Camera QR scanning** — works on physical devices only (simulator has no camera)

### Troubleshooting

- **SPM resolution fails**: Xcode needs to fetch `capacitor-swift-pm` from GitHub. Make sure you have network access. If packages are stuck, try File → Packages → Reset Package Caches.
- **Signing errors**: Make sure you selected a team under Signing & Capabilities. If the bundle ID conflicts, change it to something unique. For simulators, signing works without any Apple account.
- **"Untrusted Developer" on device**: Go to Settings → General → VPN & Device Management on the phone and trust the certificate.
- **Developer Mode not enabled**: iOS 16+ requires Developer Mode. Settings → Privacy & Security → Developer Mode → toggle on, restart.
- **Stale web assets**: If changes aren't showing up, run `npm run build && npx cap sync ios` again. The `ios/App/App/public/` folder is what gets bundled.
- **App expired (free account)**: Just re-run from Xcode. The 7-day provisioning profile auto-renews on build.

## Current limitations

- **Key storage**: localStorage (plaintext) on web. On iOS, keys are stored in the Keychain with Face ID gating via `SecureKeyStorePlugin`.
- **Biometric auth**: Browser stub (auto-approves). Real biometric gating works on iOS/Android via Capacitor.
- **Network**: No network calls — fully offline capable, but no way to broadcast transactions (by design).
- **Descriptor wallets**: Can store descriptors but PSBT verification currently only works with fixed-script (3 xpub) wallets.
