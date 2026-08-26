# wasm-dkls-vrf

WASM bindings for the VRF key generation and MPC hard derivation protocols in Silence Labs'
[dkls23-ll](https://github.com/silence-laboratories/silent-shard-dkls23-ll).

Silence Labs gates both protocols behind the non-default `vrf` cargo feature and does not
enable it when building their npm packages, so no published
`@silencelaboratories/dkls-wasm-ll-*` version contains `VrfKeygenSession`, `VrfKeyshare` or
`HardDeriveSession`. This package builds that feature and nothing else: **signing DKG and DSG
are not wrapped here** and stay on Silence Labs' published package.

## API

| class               | purpose                                                             |
| ------------------- | ------------------------------------------------------------------- |
| `VrfDkgSession`     | 2-round DKG producing a Ristretto VRF key share                     |
| `VrfKeyshare`       | the resulting key share, with `fromBytes`/`toBytes` and getters     |
| `HardDeriveSession` | 2-round hard derivation of a DKLS key share from a root + VRF share |
| `DerivedKeyshare`   | the derived DKLS key share plus its public key and chain code       |

Every message is a broadcast and carries its own sender id, so the round handlers take the
whole batch the caller has - our own message included - and filter it internally where the
protocol wants peers only.

```ts
import { VrfDkgSession, HardDeriveSession } from "@bitgo/wasm-dkls-vrf";

// VRF DKG - 2 of 3, party 0
const dkg = new VrfDkgSession(3, 2, 0, seed);
const msg1 = dkg.createFirstMessage(seed);
const msg2 = dkg.handleRound1Messages(allMsg1s, seed); // needs one msg1 per party
const vrfKeyshare = dkg.handleRound2Messages(allMsg2s); // needs one msg2 per party

// hard derivation - quorum of `threshold` parties
const hd = new HardDeriveSession(rootKeyshareBytes, vrfKeyshare.toBytes(), path, seed);
const msg0 = hd.createFirstMessage();
const msgA = hd.handleRound1Messages(quorumMsg0s, seed); // exactly `threshold` messages
const derived = hd.handleRound2Messages(quorumMsg1s);
// derived.keyshare goes straight into Silence Labs' `Keyshare.fromBytes()`
```

`path` is an opaque VRF input label, passed through unparsed. Every party must pass
byte-identical bytes: differing paths derive different keys and no error is raised. BitGo's
convention is the ASCII bytes of `m/<index>'`.

Sessions serialize between rounds with `toBytes()`/`fromBytes()`. Each blob carries a domain
separation prefix, so a round-1 state cannot be replayed into round 2 and a VRF DKG state
cannot be fed to hard derivation.

## Secret material

`VrfKeyshare.toBytes()`, `VrfDkgSession.toBytes()`, `HardDeriveSession.toBytes()` and
`DerivedKeyshare.keyshare` all contain secret key material. Hard-derivation session bytes are
the worst of the set: they embed the entire root key share. Never log them, never persist them
in the clear.

## Why hard derivation lives here and not in TypeScript

The tweak combines the root key share's secret scalar with the secret VRF evaluation output
inside `handle_msg1`. Splitting that across two wasm modules would mean exporting one of those
secrets into the JS heap. TypeScript only ever drives the rounds.

## Key share format compatibility

Hard derivation makes the CBOR DKLS key share a bidirectional interface with Silence Labs'
published wasm:

```
SL wasm:  KeygenSession -> Keyshare.toBytes()  ->  ours:    HardDeriveSession
ours:     DerivedKeyshare.keyshare             ->  SL wasm: Keyshare.fromBytes() -> SignSession
```

`test/hardDerive.ts` exercises exactly that loop against
`@silencelaboratories/dkls-wasm-ll-node` and signs with the result. Re-run it whenever the
pinned `dkls23-ll` rev moves - format drift breaks at runtime, not at compile time.

## Development

```sh
npm run build   # wasm-pack (bundler, node, web) + tsc
npm test        # mocha
npm run lint    # cargo fmt --check && cargo clippy
cargo test      # protocol-level Rust tests
```

macOS needs `brew install llvm`; the Makefile picks it up automatically.
