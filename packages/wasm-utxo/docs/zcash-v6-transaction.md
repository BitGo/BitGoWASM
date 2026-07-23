# Zcash v6 (Ironwood / NU6.3) transaction format

Reference for the v6 wire codec in [`src/zcash/v6.rs`](../src/zcash/v6.rs) and its
ZIP-244 txid, distilled from the canonical sources so review does not depend on an
external link:

- ZIP-225 (v5 tx format, the base v6 extends) — <https://zips.z.cash/zip-0225>
- ZIP-244 (txid / sighash digest tree) — <https://zips.z.cash/zip-0244>
- Cross-checked against **`zebra-chain` 11.2** (`Transaction::V6` / `ironwood_shielded_data`),
  an independent NU6.3 implementation: the `zebra_oracle` tests in `src/zcash/v6.rs` decode
  each golden fixture with zebra and assert zebra's `hash()` (ZIP-244 txid) equals ours, plus
  matching transparent I/O and Ironwood action counts. The golden transactions in
  `test/fixtures/zcash/` (shield / self-send / unshield) originate from a Zebra node on
  branch id `37a5165b`.

## Wire layout

The v6 header is **reordered** relative to v4: `consensusBranchId`, `lockTime`, and
`expiryHeight` move to the front, before the transparent I/O. Two shielded slots are
appended after Sapling — a v6-personalized Orchard slot (empty for BitGo flows) and
the new Ironwood slot. All integers little-endian; `varint` = CompactSize.

```
Header:      version(4)=0x80000006  versionGroupId(4)=0xD884B698
             consensusBranchId(4)  lockTime(4)  expiryHeight(4)
Transparent: tx_in_count(varint) tx_in[]   tx_out_count(varint) tx_out[]
Sapling:     nSpendsSapling(varint=0)  nOutputsSapling(varint=0)
Orchard v6:  nActionsOrchard(varint=0)                    // body only if > 0
Ironwood:    nActionsIronwood(varint) actions[820×n] flags(1) valueBalance(8)
             anchor(32) proofsSize(varint) proofs[] spendAuthSigs[64×n] bindingSig(64)
             // whole block present only if nActionsIronwood > 0
```

Each Ironwood action is 820 bytes: `cv(32) nullifier(32) rk(32) cmx(32) epk(32)
encCiphertext(580) outCiphertext(80)`. This codec supports empty Sapling/Orchard
slots plus a populated Ironwood bundle; non-empty Sapling/Orchard are rejected with a
clear error rather than mis-parsed. The action count is validated against the
remaining input length before allocating, so a malformed `nActionsIronwood` cannot
trigger an unbounded pre-allocation.

## ZIP-244 txid (five-component tree)

```
txid = BLAKE2b-256("ZcashTxHash_" ‖ consensusBranchId(LE),
         header_digest ‖ transparent_digest ‖ sapling_digest
         ‖ orchard_v6_digest ‖ ironwood_digest)
```

`ironwood_digest` is a three-way split (compact / memos / non-compact per-action byte
ranges) combined with the flag byte and value balance; the anchor, proof, and
signatures are **excluded**. `compute_v6_txid` returns internal byte order; the
`ZcashV6Transaction.getId()` wrapper reverses it to the canonical display form.

## Integration with the build-transaction endpoint (planned)

The indexer's build flow (`@ims-utxo/utxo-core/buildTransaction` →
`createPsbt`/`responseBuilder`) drives wasm-utxo through the `ZcashBitGoPsbt` wrapper:
`createEmpty({ blockHeight })`, `addWalletInput`, `addWalletOutput`/`addOutput`,
`serialize()`, and `psbt.unsignedTxId()`. Reusing that flow for **shielding**
(transparent → Ironwood) needs, in follow-up PRs:

1. **v6 creation** — `ZcashBitGoPsbt.createEmpty` gains a version/era selector so
   `createEmptyPsbt` can build a v6 skeleton (`{ blockHeight, txVersion: 6 }`).
2. **v6 serialize + txid through the wrapper** — `serialize()` emits v6 wire and
   `unsignedTxId()` version-gates to the ZIP-244 txid. This PR lands the codec and the
   `getId()` shape those methods will delegate to (an instance method returning the
   display-order id — no static-over-bytes, no manual reversing).
3. **ZIP-244 transparent sighash (T2)** — the transparent inputs the build flow
   already handles must sign the v6 sighash (which includes `ironwood_digest`), not
   ZIP-243. This is the true next milestone for shielding.
4. **Ironwood bundle attach (T3)** — `set_ironwood_bundle` / `finalize_ironwood_bundle`
   apply the server (KMS) proof + actions before final serialize.

The shielded recipient itself is resolved with `ZcashUnifiedAddress` (its Orchard
receiver), and its value becomes `valueBalanceIronwood` rather than a transparent
`TxOut` — an indexer-side change in `buildTransaction` that reuses the existing
unspent-selection / fee / change / response code unchanged.
