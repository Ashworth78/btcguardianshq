# Miniscript inheritance test on signet

> **Signet only.** These are test coins with no value. None of the keys, seeds or shares used here will ever touch mainnet. They have been shredded.

## What we set out to prove

Can a seed made **offline** by `vault.js` work as the **heir's recovery key** in a timelocked miniscript wallet, and can the heir spend **alone** once the timelock has passed?

**Result: yes.** Proven end to end on 2 November 2026 (heir5, 12-word path through Liana) and again on 6 November 2026 (heir6b, 24-word path signed in Bitcoin Core).

## Setup

| Part | Tool |
|---|---|
| Heir seed generation | `vault.js create` on Tails, offline |
| Reading the heir's xpub (tpub) | Sparrow 2.5.6, **signet mode** |
| Inheritance wallet | Liana 15.0, *Simple inheritance*, Liana Connect backend |
| 24-word signing (heir6b) | Bitcoin Core signet wallet + `walletprocesspsbt` |
| Network | Bitcoin signet |

The policy Liana builds is of the form:

```
wsh(or_d(pk(@0),and_v(v:pkh(@1),older(N))))
```

In plain words, the owner's key (`@0`) can spend at any time. The heir's key (`@1`) can spend only after the coins have been unmoved for **N blocks** (`older(N)`, a relative timelock using CSV). A real setup would use a much longer delay, such as months.

## Test runs

| Run | Heir key | Outcome |
|---|---|---|
| heir2 | Sparrow-made test key (fingerprint `413e4c20`) | ✅ Heir signed alone through the CSV 3 recovery path. Tx `3114c3e5fa76f995be731e1d6e328296c37e6cc1607f1a6489e6f8deae38bcbe` |
| heir3 | `vault.js` **24-word** seed (fingerprint `4adc83da`) | ❌ Funded, but the recovery could not be signed. Liana's mnemonic import accepts only **12 words**, and Sparrow can't sign Liana's script. |
| heir4 | First `--words 12` attempt | Superseded by heir5 |
| heir5 | `vault.js create --words 12` (fingerprint `d2c24a58`) | ✅ **Full chain proven via Liana.** The heir signed alone and broadcast the transaction. Tx `3f066cece5a0a3dad0156625fdc3a70986a1102a06a84b993b3c4a13c0e42c7c`, confirmed in signet block 329,166 |
| heir6b | `vault.js` **24-word** seed (fingerprint `a5fb6890`) | ✅ **Full chain proven via Bitcoin Core.** Heir key imported with Loïc's split A/B descriptor method; Core `walletprocesspsbt` returned complete true; `sendrawtransaction` broadcast. Tx `6d0560d0a24bdde008bea957cccc885bfd53a53b0ab694081f610b57b3a6bcf3`, confirmed in signet block 329,615 (`older(6)` CSV) |

heir5 details:
- Wallet "BTCGH heir5 test", funded with 0.02235655 sBTC
- Owner hot key fingerprint `433d63fd`
- Heir key path `m/84'/1'/0'` (signet/testnet coin type `1'`)

heir6b details:
- 24-word heir from offline `vault.js create` (default)
- Fingerprint `a5fb6890`
- Signed outside Liana: Bitcoin Core signet wallet + Loïc's split A/B descriptor import (Bitcoin Stack Exchange answer on the Liana 24-word heir question)
- Check the tx: https://mempool.space/signet/tx/6d0560d0a24bdde008bea957cccc885bfd53a53b0ab694081f610b57b3a6bcf3

## Method that works (heir5, 12 words via Liana)

1. **Tails, offline:** `node vault.js create --words 12` makes the shares and the 12-word heir seed.
2. **Sparrow (signet mode):** import the 12 words and copy the key in `[fingerprint/84'/1'/0']tpub…` format.
 - If Sparrow shows `xpub` or `m/84'/0'/0'`, it's on **mainnet**. Use Tools → Restart In → Signet.
3. **Liana:** create a *Simple inheritance* wallet. The owner key is the primary key, and the pasted heir key is the recovery key with the timelock.
4. **Fund it** from a signet faucet, or from another signet wallet.
5. **Wait for the timelock** to pass (3 blocks here).
6. **Recover as the heir:**
 1. In Liana, delete the wallet **locally only**. Leave "delete from Liana Connect" **unticked**.
 2. Choose *Add existing wallet* and load it from **Liana Connect**. Importing the `.bed` file again gives a **422 "same descriptor"** error.
 3. On the *Import mnemonic* screen, enter the **heir's 12 words**.
 4. Recovery → Sign → Broadcast.

## Method that works (heir6b, 24 words via Bitcoin Core)

1. **Tails, offline:** `node vault.js create` (default 24 words) in a fresh test folder; recover with 3 of 5 shares to confirm the words.
2. **Sparrow (signet mode):** import the 24 words, note the fingerprint, copy `[fingerprint/84'/1'/0']tpub…`.
3. **Bitcoin Core:** run a separate **signet** instance (`bitcoind -signet`). Create a signet descriptor wallet for the heir. Import the heir key with Loïc's **split A/B descriptor** method (not Liana's 12-word mnemonic screen).
4. **Liana:** *Simple inheritance* wallet with a new owner hot key and the heir6 tpub as recovery (short timelock; heir6b used `older(6)`).
5. **Fund**, wait for the timelock, then in Liana draft the recovery and **export the PSBT**.
6. **Core:** `bitcoin-cli -signet -rpcwallet=<heir_wallet> walletprocesspsbt <psbt>` until complete is true, then broadcast (`sendrawtransaction` or re-import the signed PSBT in Liana and Broadcast).
7. **Verify** on your own node or on mempool.space signet. Shred the test folder and unload/delete the signet heir wallet.

## Lessons

- **Use 12 words for Liana's mnemonic import.** Liana's mnemonic import takes 12 words only, which is why `--words 12` was added to `vault.js create`.
- **24-word heirs can still recover:** sign the Liana recovery PSBT in Bitcoin Core after importing the heir with a split A/B descriptor (thanks to Loïc on Bitcoin Stack Exchange).
- **Check the network every time.** `tpub` and `/1'/` mean signet or testnet. `xpub` and `/0'/` mean mainnet. Keep signet Core separate from the mainnet archival node.
- **Don't import the descriptor a second time into Liana.** Load the wallet from Liana Connect instead.
- **Shred test material after each run.** Shred all `test-heir*` folders on Tails, and delete the signet Core wallets that held a tprv.

## Possible next steps

- `vault.js xpub --network signet` to print the heir's tpub directly, so the Sparrow step can be skipped
- Repeat the test with a longer timelock
- Try hardware-wallet heir keys (Trezor One)

*This is a functional test on signet, not a security audit.*
