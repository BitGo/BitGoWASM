# ZIP-316 Unified Address encoding (vendored reference)

This is a self-contained reference for the exact encoding that
[`src/zcash/unified_address.rs`](../src/zcash/unified_address.rs) parses. It is
distilled from the canonical sources so review does not depend on an external link:

- ZIP-316 "Unified Addresses and Unified Viewing Keys" — <https://zips.z.cash/zip-0316>
- F4Jumble reference implementation — the `f4jumble` crate (Zcash Foundation) and
  <https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/f4jumble.py>
- Unified-address test vectors — `zcash_address` crate
  (`kind/unified/address/test_vectors.rs`) and
  <https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/unified_address.py>

We implement **decoding only** (parse a UA → receivers). Encoding is not needed.

---

## 1. Overall structure

A Unified Address is a Bech32m string whose data part is an **F4Jumbled** byte
sequence. Decoding reverses the pipeline:

```
UA string
  ── Bech32m decode ─────────────▶ jumbled bytes   (HRP checked against network)
  ── F4Jumble⁻¹ ────────────────▶ padded bytes
  ── strip 16-byte HRP padding ─▶ receivers blob
  ── parse TLV records ─────────▶ [ (typecode, data), … ]
```

### Human-readable parts (HRP)

| Network                      | HRP     |
| ---------------------------- | ------- |
| Mainnet (`zec`/`zcash`)      | `u`     |
| Testnet (`tzec`/`zcashTest`) | `utest` |

(Regtest `uregtest` exists in ZIP-316 but is intentionally unsupported here — there
is no corresponding transparent base58check codec in this crate, so supporting it
for UA parsing but not for transparent-address comparison would be inconsistent.)

### Receiver TLV records

The un-jumbled, un-padded blob is a sequence of receivers, each:

```
CompactSize(typecode) ‖ CompactSize(length) ‖ data[length]
```

Receivers MUST appear in **strictly ascending typecode order**.

| Typecode | Receiver            | `data`                                        |
| -------- | ------------------- | --------------------------------------------- |
| `0x00`   | P2PKH (transparent) | 20-byte pubkey hash                           |
| `0x01`   | P2SH (transparent)  | 20-byte script hash                           |
| `0x02`   | Sapling             | 43 bytes (11-byte diversifier + 32-byte pk_d) |
| `0x03`   | Orchard             | 43 bytes (11-byte diversifier + 32-byte pk_d) |

**Ironwood (NU6.3) reuses the Orchard receiver (`0x03`)** — no new typecode. An
Orchard unified receiver routes to the Ironwood pool once NU6.3 rules are active.

A transparent receiver here is reduced to its scriptPubKey: P2PKH →
`OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`, P2SH → `OP_HASH160 <20> OP_EQUAL`.

### Padding

After the last receiver, 16 bytes of padding are appended: the HRP as ASCII,
zero-extended to 16 bytes. On decode we strip the last 16 bytes and verify they
equal `HRP ‖ 0x00…`.

---

## 2. F4Jumble

F4Jumble is a length-preserving, unkeyed **4-round Feistel** network over two
unequal halves, giving cascading (avalanche) behavior so a single altered character
changes the whole decoded output. Valid message length is `48 ..= 4_194_368` bytes.

### Split

```
ℓ        = len(message)
left_len = min(64, ℓ / 2)          # 64 = BLAKE2b output size (OUTBYTES)
left     = message[..left_len]
right    = message[left_len..]
```

### Round functions

Both use BLAKE2b with a 16-byte personalization.

```
H(i):  hash = BLAKE2b(personal = b"UA_F4Jumble_H" ‖ [i, 0, 0],
                      out_len   = len(left))            over `right`
       left ^= hash

G(i):  for j in 0 .. ceil(len(right) / 64):
           hash = BLAKE2b(personal = b"UA_F4Jumble_G" ‖ [i, j_lo, j_hi],
                          out_len  = 64)                over `left`
           right[j*64 ..] ^= hash
```

`j_lo`/`j_hi` are the little-endian bytes of the `u16` block index `j`.
Note the output length is folded into BLAKE2b's parameter block, so it is part of
the domain — not a truncation (see `blake2b_var_personal`).

### Round order

```
apply    F4Jumble    :  G(0) H(0) G(1) H(1)
apply    F4Jumble⁻¹  :  H(1) G(1) H(0) G(0)     # what we implement
```

---

## 3. Test vectors used

- **F4Jumble⁻¹** is checked against the 48-byte vector from the `f4jumble` crate
  (`test_vectors.rs`, vector 0).
- **UA parsing** is checked against an official ZIP-316 mainnet vector (P2PKH +
  Orchard receivers) and a real testnet wallet vector (UA ↔ transparent address ↔
  raw Ironwood receiver), both in `test/fixtures/zcash/unified_address.json`.
