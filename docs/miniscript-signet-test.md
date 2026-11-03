# Miniscript inheritance test on signet

> **Signet only.** These are test coins with no value. None of the keys, seeds or shares used here will ever touch mainnet. They have been shredded.

## What we set out to prove

Can a seed made **offline** by `vault.js` work as the **heir's recovery key** in a timelocked miniscript wallet, and can the heir spend **alone** once the timelock has passed?

**Result: yes.** It was proven end to end on 2 November 2026 (heir5 below).

## Setup

| Part | Tool |
|---|---|
| Heir seed generation | `vault.js create` on Tails, offline |
| Reading the heir's xpub (tpub) | Sparrow 2.5.6, **signet mode** |
| Inheritance wallet | Liana 15.0, *Simple inheritance*, Liana Connect backend |
| Network | Bitcoin signet |

The policy Liana builds is:

```
wsh(or_d(pk(@0),and_v(v:pkh(@1),older(3))))
```

In plain words, the owner's key (`@0`) can spend at any time. The heir's key (`@1`) can spend only after the coins have been unmoved for **3 blocks** (`older(3)`, a relative timelock using CSV). A real setup would use a much longer delay, such as months.

## Test runs

| Run | Heir key | Outcome |
|---|---|---|
| heir2 | Sparrow-made test key (fingerprint `413e4c20`) | ✅ Heir signed alone through the CSV 3 recovery path. Tx `3114c3e5fa76f995be731e1d6e328296c37e6cc1607f1a6489e6f8deae38bcbe` |
| heir3 | `vault.js` **24-word** seed (fingerprint `4adc83da`) | ❌ Funded, but the recovery could not be signed. Liana's mnemonic import accepts only **12 words**, and Sparrow can't sign Liana's script. |
| heir4 | First `--words 12` attempt | Superseded by heir5 |
| heir5 | `vault.js create --words 12` (fingerprint `d2c24a58`) | ✅ **Full chain proven.** The heir signed alone and broadcast the transaction. Tx `3f066cece5a0a3dad0156625fdc3a70986a1102a06a84b993b3c4a13c0e42c7c`, confirmed in signet block 329,166 |

heir5 details:
- Wallet "BTCGH heir5 test", funded with 0.02235655 sBTC
- Owner hot key fingerprint `433d63fd`
- Heir key path `m/84'/1'/0'` (signet/testnet coin type `1'`)

## Method that works (heir5)

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

## Lessons

- **Use 12 words for Liana heir keys.** Liana's mnemonic import takes 12 words only, which is why `--words 12` was added to `vault.js create`.
- **Check the network every time.** `tpub` and `/1'/` mean signet or testnet. `xpub` and `/0'/` mean mainnet.
- **Don't import the descriptor a second time.** Load the wallet from Liana Connect instead.
- **Shred test material after each run.** All `test-heir*` folders have been shredded on Tails.

## Possible next steps

- `vault.js xpub --network signet` to print the heir's tpub directly, so the Sparrow step can be skipped
- Repeat the test with a longer timelock
- Try hardware-wallet heir keys (Trezor One)

*This is a functional test on signet, not a security audit.*
