# Zcash v6 (Ironwood / NU6.3) transaction format

Reference for the v6 wire codec in [`src/zcash/v6.rs`](../src/zcash/v6.rs) and its
ZIP-244 txid, distilled from the canonical sources so review does not depend on an
external link:

- ZIP-225 (v5 tx format, the base v6 extends) — <https://zips.z.cash/zip-0225>
- ZIP-244 (txid / sighash digest tree) — <https://zips.z.cash/zip-0244>
- Cross-checked against **`zebra-chain`**, an independent Ironwood implementation: the
  `zebra_oracle` tests in `src/zcash/v6.rs` decode each golden fixture with zebra and assert
  zebra's `hash()` (ZIP-244 txid) equals ours, plus matching transparent I/O and Ironwood
  action counts.
- The golden transactions in `test/fixtures/zcash/` are all mined Zcash testnet transactions
  (see "Capturing golden fixtures" below):
  - `shield`, `selfsend`, `shield1zec` — taken from a Zebra node under branch id `37a5165b`
    (NU6.3);
  - `shield_multisig` — a 2-of-3 P2SH multisig shield built with this codebase's CLI, mined
    under branch id `37a5165b` (NU6.3);
  - `unshield` (deshield: Ironwood → transparent P2PKH payout, `valueBalance > 0`) and
    `shielded_transfer` (shielded → shielded, no transparent I/O) — built, signed and proven
    with this codebase's CLI and mined under branch id `77190ad9` (NU7). Their
    `*_details.json` record the provenance (block height, spent/output values, anchor, flags,
    proof size).

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

The `flags` byte: bit 0 `enableSpends`, bit 1 `enableOutputs`, bit 2
`enableCrossAddress` (Ironwood-only; reserved-and-zero in the Orchard slot). A bundle
built here sets spends/outputs exactly when it carries real spends/outputs — a
shielding build is `0x06` (its one spend per output is the fabricated value-0 dummy),
a deshield is `0x05` (its unpaired output halves are value-0 dummies), and a
shielded transfer is `0x07`. The mined `unshield` and `shield*` goldens predate this and
carry `0x07` (all three enables, as the reference wallet sets). Both forms are valid:
a disabled side only adds a value-0 constraint.

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
   apply the server proof + actions before final serialize.

The shielded recipient itself is resolved with `ZcashUnifiedAddress` (its Orchard
receiver), and its value becomes `valueBalanceIronwood` rather than a transparent
`TxOut` — an indexer-side change in `buildTransaction` that reuses the existing
unspent-selection / fee / change / response code unchanged.

## Capturing golden fixtures

Golden fixtures live in `test/fixtures/zcash/` as a `(v6_<name>_rawtx.hex,
v6_<name>_txid.hex[, v6_<name>_details.json])` triple, and every one is asserted three ways:
`assert_golden` (decode → byte-identical re-encode → canonical txid), the `zebra_oracle`
cross-check (zebra's independent decode and ZIP-244 txid agree), and the TypeScript fixture
loop in `test/fixedScript/zcashV6Transaction.ts`.

The spend goldens (`unshield`, `shielded_transfer`) were produced end-to-end with this
codebase, which is also how a new fixture is produced:

1. **Generate a wallet** (testnet-only keys). `ironwood_keygen` writes `orchard_sk.hex`,
   `orchard_fvk.hex`, `orchard_receiver.hex` and a `wallet.json` with the receiver's Unified
   Address, the 2-of-3 funding address and the P2PKH payout address; `ironwood_derive` prints
   further receivers:

   ```bash
   cargo run -p wasm-utxo-cli --example ironwood_keygen -- <dir>
   cargo run -p wasm-utxo-cli --example ironwood_derive -- <dir>/orchard_sk.hex <count>
   ```

2. **Fund the receiver** with a v6 (Ironwood) shielded send from any Ironwood-aware wallet.
   Note the funding txid and wait for it to confirm.
3. **Recover the note and its witness** from chain data. Save the funding transaction
   (`getrawtransaction <txid> 1`) and decrypt the received note with the FVK; node-JSON mode
   reads both the Ironwood and Orchard bundles. Then witness the note's `cmx`:
   `z_gettreestate <fundingHeight - 1>` gives the pre-block frontier (`finalState`), the
   Ironwood `cmx` of every action from the funding block up to the anchor block (block,
   transaction, then action order; `getblock <hash> 2`) gives the leaves, and
   `z_gettreestate <anchorHeight>` gives the anchor root (`finalRoot`). `ironwood_tree` folds
   them through `shardtree::ShardTree` and prints the `{position, authPath, anchor}` witness:

   ```bash
   cargo run -p wasm-utxo-cli --example ironwood_scan_note -- <node-tx.json> <fvk-file>
   cargo run -p wasm-utxo-cli --example ironwood_tree -- \
       <preBlockState> <anchorRoot> --append <leaves.json> --target <cmx>
   ```

4. **Build, sign, prove and broadcast** one of the two spend shapes with the command sequence
   in [`cli/README.md`](../cli/README.md): `create-zcash-v6` → `add-shielded-input` (notes
   file: `anchor`, and `spends` with `recipient`/`value`/`rho`/`rseed`/`cmx`/`witness`) →
   `out-ciphertexts` → `set-spend-randomizer` → `add-spend-signature` → `prove` →
   `combine-ironwood-proof`, then `sendrawtransaction` on the node. A transparent payout yields
   the `unshield` shape; a shielded output yields `shielded_transfer`.
5. **Record the mined transaction**: `getrawtransaction <txid> 0` → `v6_<name>_rawtx.hex`;
   its txid (which the zebra oracle re-derives independently) → `v6_<name>_txid.hex`; and a
   `v6_<name>_details.json` in the shape of the existing ones (description with provenance,
   network, txid, block height, consensus branch id, header fields, spent/output values, fee,
   `value_balance_zat`, anchor, flags, action count, proof size).
6. **Wire the fixture in**: `assert_golden("<name>")` (plus `assert_spend_golden_details` for
   a spend), a `cross_check("<name>")` and an entry in `golden_branch_ids_match_both_networks`
   in `src/zcash/v6.rs`, and the name in the TypeScript fixture loop.

A mainnet golden is captured the same way against a mainnet node. The v6 wire carries no
network field, so a txid is network-independent; only the provenance (the branch id in force
at the mined height) differs, and `golden_branch_ids_match_both_networks` checks that each
golden's branch id is valid on both networks.
