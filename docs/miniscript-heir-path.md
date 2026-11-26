# Miniscript heir path (Signet test, Plan 2)

Status: tested on Signet only. Not audited. vault.js refuses mainnet.

## What it does
A coin the owner can spend at any time, or the heir can spend after a delay.
Credit: decaying-timelock miniscript wallets were pioneered by Liana (Wizardsardine). BTCGuardiansHQ follows the same idea in a small, offline-first tool.

## Policy
or(pk(OWNER),and(pk(HEIR),older(6)))

## Descriptor (Bitcoin Core, watch-only wallet bgh-miniscript)
wsh(or_d(pk(OWNER/0/*),and_v(v:pkh(HEIR/0/*),older(6))))

6 blocks is for testing only. A real setup would use a much longer delay (e.g. about 26,000 blocks, roughly 6 months).

## How signing works
- Core builds the PSBT in the watch-only wallet.
- vault.js signs offline on Tails from shares (PR #15 added findWshKey for P2WSH miniscript inputs).
- Core finalizes and broadcasts.
- The heir's PSBT input must set sequence 6.

## Signet results (25-26 Nov 2026)
- Test A, owner spends any time: PASSED. tx 6bd1e2cd837dffc7000a8d3f4d56ec44e738ec97b128c15d37366d95279a1f85
- Test B, heir before 6 blocks: REFUSED by testmempoolaccept (non-BIP68-final), as expected.
- Test C, heir after 6 blocks: PASSED, same signed tx now valid. tx 9c8fb9e36dc0f8543f70ae0a59696404119d66e64d0cf8eeb112bcecd7dfa544

Note: finalizepsbt completes even before the delay. The network enforces the timelock (BIP68) at broadcast.

## Limits
- Signet/testnet only. Fake/test keys only.
- No outside audit yet.
- Hardware wallet signing not tested yet.
