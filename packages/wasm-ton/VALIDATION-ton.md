# wasm-ton Scratch Validation

**Wallet:** EQADv83lwmUUwZJgVPPliEt_F04Gn7EH1JX_5aoaGItA45AP
**Testnet:** TON Testnet
**Date:** 2026-03-25
**Seed:** 0xfaceb00c (deterministic, testnet only)

## Results

| Intent | Status | TxID |
|--------|--------|------|
| payment | pass | `vT6gjV7_PH6WIEpnH34Mhkbc31tFZUGOn4_mARnVVIQ=` |
| fillNonce | pass | `LcQMrp192D_eK2jBDSbn0X093zzuDinqFn0G8g4xJT4=` |
| consolidate | pass | `MBuzYEQVjGDCkrboSirv1B-bNw_2tJv6Jsm_NW619wY=` |
| delegate (MULTI_NOMINATOR) | pass | `FoB3evMYWAcQHRP8L6WThu9qy3UEHiiqve4V5aLKM24=` |
| delegate (SINGLE_NOMINATOR) | pass | `w0yc2VvAiPE5rBJcT03XCe6yNT296T9USzxfz91OrZM=` |
| delegate (TON_WHALES) | pass | `DB8eFyqWkZKXyOdt1N0_rZVuGmDKA7XMrZCP7SKDE1I=` |
| undelegate (MULTI_NOMINATOR) | pass | `yW1Y6xMbNH3pHlt5sR-UIxjPYR8bNUkHzwoSTFdTlBU=` |
| undelegate (SINGLE_NOMINATOR) | pass | `xDvJEe-X_9tqdf72VX_F-V9_LHofvVD6CWAZVurgOUk=` |
| undelegate (TON_WHALES) | pass | `Hl0_JTAnUyk4ChQFIKX4R9UDyaDDqB8WtLWicZRCxwA=` |

## Parse Round-trip

| Intent | Build → Parse | Fields Verified |
|--------|--------------|-----------------|
| payment | pass | sender, recipient, amount, bounceable=false, transactionType=Send |
| fillNonce | pass | sender=recipient, amount=0, transactionType=Send |
| consolidate | pass | sender, recipient, amount, transactionType=Send |
| delegate (MULTI_NOMINATOR) | pass | recipient, amount, memo='d', transactionType=Send |
| delegate (SINGLE_NOMINATOR) | pass | recipient, amount, bounceable=true, transactionType=Send |
| delegate (TON_WHALES) | pass | recipient, amount, transactionType=TonWhalesDeposit |
| undelegate (MULTI_NOMINATOR) | pass | recipient, amount, memo='w', transactionType=Send |
| undelegate (SINGLE_NOMINATOR) | pass | recipient, amount=1TON (gas), transactionType=SingleNominatorWithdraw |
| undelegate (TON_WHALES) | pass | recipient, amount, transactionType=TonWhalesWithdrawal |

## Notes

- seqno=0 payment deployed the wallet contract (state_init included automatically). Wallet went `uninitialized` → `active`.
- `runGetMethod` requires POST — fixed in scratch script.
- `TonStakingType` was only exported as a type, not as a value — fixed in `js/index.ts`.
- `getAddressInformation` occasionally returns a transient API error after confirmation — balance still reads correctly.
