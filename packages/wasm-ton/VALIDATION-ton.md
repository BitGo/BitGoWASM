# wasm-ton Scratch Validation

**Wallet:** EQDuPYX8CRn1vCwjaWaua8UCnV7H93kk17eDuCzICC6H0Agk
**Testnet:** TON testnet (toncenter v2 API)
**Date:** 2026-03-27
**Public Key:** 0x71519a80b6034586824a2571f59b78e9d2258818091ae43151ce6fce217805f7

## Results

| Intent                       | Status | TxHash                                       | Seqno |
| ---------------------------- | ------ | -------------------------------------------- | ----- |
| payment (native, 0.01 TON)   | pass   | uPFLE1pBTeW/YAqchGkBmd+4Z0kDES7WtJW6FdaDrZs= | 0→1   |
| fillNonce (native)           | pass   | HrdOUp4XaT33ikzi9ZJ+L8jgEL/6MQIKnmpJQKZnqB8= | 1→2   |
| consolidate (native)         | pass   | vyFUjysPh8UgXy0GbvtnTe1f3vC1NBiic0LIACe+0yE= | 2→3   |
| delegate (TonWhales)         | pass   | Rj7ZE3npPJiP7phh4o+ApjUPaS6BF+Qi/zfQl2FQw2c= | 3→4   |
| undelegate (TonWhales)       | pass   | diYXhAYCMeXewaugrLtSQv5Ti2p2+2Zqp6F4c6jlbBk= | 4→5   |
| delegate (SingleNominator)   | pass   | KPH0m6VXfVdMBjmQwyjoF/0UPnHWJIn6Js4yiTN8wMc= | 5→6   |
| undelegate (SingleNominator) | pass   | HuLjS4rn9K9BOZy8tPGGe5kqXN0/+0toDZPi72o1KKs= | 6→7   |

## Parse Round-trip

| Intent                       | Build -> Parse | Fields Verified                                                                |
| ---------------------------- | -------------- | ------------------------------------------------------------------------------ |
| payment                      | pass           | recipient, amount (10000000), memo ("wasm-ton scratch test"), bounce (false)   |
| fillNonce                    | pass           | recipient (self), amount (1 nanoton)                                           |
| consolidate                  | pass           | recipient (self), amount (1 nanoton)                                           |
| delegate (TonWhales)         | pass           | transactionType (WhalesDeposit), amount (1000000000), opcode (0x7bcd1fef)      |
| undelegate (TonWhales)       | pass           | transactionType (WhalesWithdraw), amount (200000000), opcode (0xda803efd)      |
| delegate (SingleNominator)   | pass           | transactionType (Transfer), amount (1000000000), bounce (true)                 |
| undelegate (SingleNominator) | pass           | transactionType (SingleNominatorWithdraw), amount (200000000), opcode (0x1000) |

## Notes

- First transaction (payment) deployed the wallet contract via StateInit (BOC 980 bytes vs ~185 bytes for subsequent txs)
- Token intents (tokenPayment, tokenFillNonce, tokenConsolidate) not tested: require a deployed Jetton contract on testnet
- MultiNominator delegate/undelegate not tested separately (uses simple transfer with memo, same code path as SingleNominator delegate)
- Staking intents sent to own address as "validator" (no real validator contracts on testnet), but tx structure and opcodes are correct
- Explorer: https://testnet.tonviewer.com/EQDuPYX8CRn1vCwjaWaua8UCnV7H93kk17eDuCzICC6H0Agk
