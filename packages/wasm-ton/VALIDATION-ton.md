# wasm-ton Scratch Validation

**Wallet:** EQADv83lwmUUwZJgVPPliEt_F04Gn7EH1JX_5aoaGItA45AP
**Testnet:** TON Testnet
**Date:** 2026-03-25
**Seed:** 0xfaceb00c (deterministic, testnet only)

## Results

| Intent | Status | TxID | Explorer |
|--------|--------|------|----------|
| payment | pass | `vT6gjV7_PH6WIEpnH34Mhkbc31tFZUGOn4_mARnVVIQ=` | https://testnet.tonscan.org/tx/vT6gjV7_PH6WIEpnH34Mhkbc31tFZUGOn4_mARnVVIQ= |
| delegate (MULTI_NOMINATOR) | pass | `FoB3evMYWAcQHRP8L6WThu9qy3UEHiiqve4V5aLKM24=` | https://testnet.tonscan.org/tx/FoB3evMYWAcQHRP8L6WThu9qy3UEHiiqve4V5aLKM24= |

## Parse Round-trip

| Intent | Build → Parse | Fields Verified |
|--------|--------------|-----------------|
| payment | pass | sender, recipient, amount (100000000), bounceable=false, transactionType=Send |
| delegate | pass | sender, recipient, amount (500000000), bounceable=true, transactionType=TonWhalesDeposit |

## Notes

- seqno=0 payment also deployed the wallet contract (state_init included automatically). Wallet went `uninitialized` → `active`.
- `runGetMethod` (seqno query) requires POST — fixed in scratch script.
- `TonStakingType` was only exported as a type, not as a value — fixed in `js/index.ts`.
