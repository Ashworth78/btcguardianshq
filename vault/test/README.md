# Offline CLI regressions (fake data only)

With the project's locked dependencies installed, run from `vault/`:

```sh
npm test
```

The suite uses Node's built-in test runner (Node 20+) and invokes the real
`vault.js` in separate, sequential processes. It does not import CLI helpers,
replace Argon2, use a wallet/node/service, or create transactions. Each case owns
and removes a temporary directory. Child processes use a dummy passphrase,
non-TTY input, a 15-second timeout and a 256 KiB output limit. They do not inherit
`NODE_OPTIONS`, test-passphrase, native-loader or npm configuration overrides.

Coverage includes:

- Five-share v2 format, unique IVs, per-vault salt, POSIX permissions, and direct
  Argon2/AES-GCM decryption outside CLI helpers.
- All ten unordered 3-of-5 subsets, plus four/five shares and reordered input;
  exact recovery, not merely a successful exit or valid-looking mnemonic.
- A public BIP39 zero-entropy test vector independently encrypted as v2 and as
  legacy scrypt/AES-GCM input; legacy raw/file/JSON wrapper compatibility.
- Wrong passwords, insufficient/duplicate/mixed shares, malformed data, bounded
  metadata/KDF tampering, and authenticated header/ciphertext changes.
- Default mnemonic suppression, explicit `--show`, CLI errors, no-TTY rejection,
  existing-file/symlink preservation, and missing-Argon2 fail-closed behavior.

Dummy passphrases are generated in memory for each run. The public BIP39
zero-entropy test vector is derived at runtime and checked against a fixed digest;
Shamir shares are generated in memory by the real locked library. No passphrase,
mnemonic text or share fixture is committed. Only test-owned temporary files
contain encrypted fixtures, and the suite removes them. Fixture encryption uses
Node crypto and the documented wire format, not CLI helpers. Fixed salt/IVs are
only for disposable fixture encoding; real CLI randomness is not overridden.

This is finite regression coverage, not property-based testing, an independent
review of Argon2/Shamir/BIP39, a timing/leakage audit, or an assurance of financial
safety. Interactive terminal behavior, concurrent filesystem races, hostile
large positive KDF costs and other operating systems are not covered. Never use
real funds, real mnemonics or real passphrases in this suite.
