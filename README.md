# BTCGuardiansHQ

**Your bitcoin shouldn't die with you.**

Bitcoin has no "forgot password" button. If the one person who holds the keys dies and nobody can reach them, the coins are gone for good.

> **Unaudited prototype. Not for real funds.**
>
> `vault.js` has not been independently reviewed and is not production-ready. Do not trust real bitcoin to it. Test with fake data only. `vault.js` refuses mainnet until it has had an outside review.

Free, open-source tools to help your family inherit your bitcoin. No custodian, no KYC, no token. Nothing to trust, because you can check everything yourself.

Website: [btcguardianshq.info](https://btcguardianshq.info)

We don't ask for trust. We ask you to verify.

## What it is

- **An inheritance prototype (`vault/vault.js`).** A command-line tool for air-gapped use (for example Tails, with networking off). It splits a BIP39 seed into encrypted Shamir shares. The usual scheme is 3-of-5: any three shares plus the passphrase rebuild the seed; one or two shares alone reveal nothing. New vaults use Argon2id and AES-256-GCM. Older scrypt vaults still open with `--legacy`.
- **A self-hosted verification stack.** Your own archival [Bitcoin Core](https://bitcoincore.org/) node, and a private, LAN-only Mempool explorer. The explorer is not public and is not linked here. Node proofs are in [docs/Node-proofs.md](docs/Node-proofs.md).

The core tool is the offline shares. A miniscript heir path has also been proven on Signet only (see below). It is not ready for mainnet. This is not a hosted wallet, not a custodian, and has no token.

## Quick start

Use throwaway data only on a normal computer. Run real vault operations only in a clean Tails session with networking disabled. Never commit share files; the repo already ignores `share-*.json`.

```bash
cd vault
npm ci
node vault.js --help
```

Create a test vault (default scheme is 3-of-5, default length is 24 words):

```bash
node vault.js create --out /tmp/test
```

The passphrase is prompted and hidden, never taken from the command line, and must be at least 12 characters.

Rebuild the seed with any 3 of the 5 shares:

```bash
node vault.js reconstruct /tmp/test/share-1.json /tmp/test/share-3.json /tmp/test/share-5.json
```

To print the mnemonic (only do this offline):

```bash
node vault.js reconstruct --show /tmp/test/share-1.json /tmp/test/share-3.json /tmp/test/share-5.json
```

Other commands (`node vault.js --help`):

```bash
# Other thresholds, or a 12-word test seed
node vault.js create --scheme 2/3|3/4|3/5|4/5 --words 12|24 --out DIR

# Built-in create-and-reconstruct check (fake data, throwaway folder)
node vault.js test

# Inspect a PSBT (read-only), Signet or testnet only (default: signet)
node vault.js sign --psbt FILE --network signet

# Sign that PSBT from shares, after you type yes. Writes FILE.signed.psbt
node vault.js sign --psbt FILE --network signet share-1.json share-3.json share-5.json

# Show the receive address, or a descriptor, from shares
node vault.js address share-1.json share-3.json share-5.json
node vault.js descriptor --network signet share-1.json share-3.json share-5.json

# Old v1 (scrypt) shares
node vault.js reconstruct --legacy --show FILE_OR_STRING ...
```

`--network` accepts `signet` or `testnet` only. Mainnet is refused.

A watch-only helper, `vault/countdown.js`, prints how many blocks are left on an `older(N)` heir path from a `listunspent` JSON file (public data only: no keys, no shares, no RPC):

```bash
node countdown.js <N blocks> <listunspent.json>
```

For non-technical heirs, see [docs/heir-runbook.md](docs/heir-runbook.md). Store each share in a separate physical place.

## Works now / Not yet

**Works now**

- 3-of-5 Shamir shares of a BIP39 seed (2/3, 3/4 and 4/5 are also supported)
- Argon2id + AES-256-GCM encryption
- Fully offline use on Tails
- [Heir runbook](docs/heir-runbook.md) in plain English
- Timelocked heir recovery on Signet: a vault.js seed as the Liana heir key, spent alone after the timelock ([test results](docs/miniscript-signet-test.md))
- Miniscript heir path in vault.js on Signet: the owner can spend at once, or the heir after `older(6)`. 6 blocks is test-only. ([write-up](docs/miniscript-heir-path.md))
- Own archival Bitcoin Core node ([proofs](docs/Node-proofs.md))
- Private, LAN-only Mempool explorer

**Not yet**

- Multisig
- Miniscript inheritance on mainnet (`vault.js` refuses mainnet until an outside review)
- Hardware-wallet signing of the miniscript path
- Long `after()` locks (for example a 20-year delay)
- Independent review completed

## Signet miniscript heir path

Completed 26 Nov 2026, on Signet test coins with no value. This is a functional test, not an audit. Credit: decaying-timelock miniscript wallets were pioneered by [Liana](https://wizardsardine.com/liana/) (Wizardsardine). BTCGuardiansHQ follows the same idea in a small, offline-first tool.

Policy:

```text
or(pk(OWNER),and(pk(HEIR),older(6)))
```

Descriptor (Bitcoin Core, watch-only):

```text
wsh(or_d(pk(OWNER/0/*),and_v(v:pkh(HEIR/0/*),older(6))))
```

6 blocks is for testing only. A real setup would use a much longer delay.

Core builds the PSBT in a watch-only wallet. `vault.js` signs it offline on Tails from shares ([PR #15](https://github.com/Ashworth78/btcguardianshq/pull/15) added `findWshKey` in `vault/psbt-sign.js` for P2WSH miniscript inputs). Core finalises and broadcasts. The heir input must set sequence 6.

Results (25–26 Nov 2026) are in [docs/miniscript-heir-path.md](docs/miniscript-heir-path.md) ([PR #16](https://github.com/Ashworth78/btcguardianshq/pull/16)):

- **Test A**, owner spends at any time: passed. `6bd1e2cd837dffc7000a8d3f4d56ec44e738ec97b128c15d37366d95279a1f85`
- **Test B**, heir before 6 blocks: refused by `testmempoolaccept` (`non-BIP68-final`), as expected.
- **Test C**, heir after 6 blocks: passed. `9c8fb9e36dc0f8543f70ae0a59696404119d66e64d0cf8eeb112bcecd7dfa544`

Earlier Signet tests, using a vault.js seed as the Liana heir key, are in [docs/miniscript-signet-test.md](docs/miniscript-signet-test.md).

Limits: Signet (or testnet) only, fake or test keys only, no outside review yet, and hardware-wallet signing of this path has not been tested.

## What's next

In this order. No dates promised.

1. **Hardware-wallet signing of the miniscript path.** Test it on Signet with a real device and fake coins.
2. **Long `after()` locks on Signet.** The relative `older()` timelock tops out at about 15 months. A 20-year delay needs an absolute `after()` lock, and that is untested.
3. **Outside review.** Independent eyes on `vault.js`. This is where you come in.
4. **Mainnet, only after review.** Not before. If review says no, it stays a prototype.

## Why Signet, not testnet

Signet blocks are signed by known signers, so they arrive steadily, about every 10 minutes, like mainnet. Testnet block timing can swing from minutes to hours, which makes timelock tests unreliable. Signet coins are worthless, so mistakes cost nothing.

Signet does not prove everything works on mainnet. That needs more work, and an outside review, first.

## Security and review

Independent volunteer review is wanted. This is not a paid audit, and there is no bounty.

- Scope and threat model: [REVIEW.md](REVIEW.md)
- Start here: [issue #3](https://github.com/Ashworth78/btcguardianshq/issues/3)
- Report anything that could lose funds privately: [SECURITY.md](SECURITY.md)

Please test with fake data only. Do not paste seeds, shares, passphrases, or RPC secrets into issues or pull requests.

## Docs

| Doc | What it is |
| --- | --- |
| [docs/heir-runbook.md](docs/heir-runbook.md) | Step-by-step recovery for non-technical heirs |
| [docs/miniscript-heir-path.md](docs/miniscript-heir-path.md) | Plan 2 Signet write-up (vault.js miniscript path) |
| [docs/miniscript-signet-test.md](docs/miniscript-signet-test.md) | Earlier Signet tests with a vault.js seed in Liana |
| [docs/Node-proofs.md](docs/Node-proofs.md) | Read-only proofs from the archival Bitcoin Core node |
| [docs/opsec.md](docs/opsec.md) | Operational security rules |
| [docs/vault-recovery.md](docs/vault-recovery.md) · [docs/funding-your-vault.md](docs/funding-your-vault.md) · [docs/architecture.md](docs/architecture.md) | Recovery overview, how coins relate to the seed, and a high-level layout |
| [REVIEW.md](REVIEW.md) · [SECURITY.md](SECURITY.md) | Review scope, threat model, and how to report a vulnerability |

## Credits

BTCGuardiansHQ stands on the work of others. Thank you.

- [Liana](https://wizardsardine.com/liana/) by Wizardsardine, who pioneered decaying-timelock miniscript wallets. Early Signet tests used a vault.js seed as the Liana heir key. The later vault.js miniscript path follows the same idea.
- [Sparrow Wallet](https://sparrowwallet.com/), used to read and check heir keys and fingerprints.
- [Bitcoin Core](https://bitcoincore.org/), which runs the archival node and builds or finalises PSBTs.
- [Tails](https://tails.net/), the offline system where vault.js runs.
- [mempool.space](https://mempool.space/), whose open-source explorer sits behind the private LAN explorer, and how node block hashes are checked.
- [Contributors](https://github.com/Ashworth78/btcguardianshq/graphs/contributors).

These projects are credited for the tools we use. They do not endorse BTCGuardiansHQ.

## Sponsor

Keeps the work free. No perks, just thanks.

[GitHub Sponsors](https://github.com/sponsors/Ashworth78), or send bitcoin to:

`1sXyCoMdHmPi2axsmXqLeNSkRi7RXkfPQ`

## Licence

[MIT](LICENSE)
