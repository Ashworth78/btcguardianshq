#!/usr/bin/env node
/*
 * BTCGuardiansHQ vault.js - air-gapped Shamir split of a BIP39 mnemonic.
 *
 * STATUS: UNAUDITED PROTOTYPE. Do not rely on it for real funds without
 * independent review. Run only on an offline (air-gapped) machine.
 *
 * Supported schemes: 2/3, 3/4, 3/5, 4/5
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

let argon2;
try {
  argon2 = require('argon2');
} catch (e) {
  argon2 = null;
}
const bip39 = require('bip39');
const secrets = require('secrets.js-grempe');

const FORMAT_VERSION = 2;
const MIN_PASS_LEN = 12;
const KDF_DEFAULT = { name: 'argon2id', m: 65536, t: 3, p: 1, len: 32 };
const LEGACY_SALT = 'btcguardianshq-salt-v1';
const TEST_ENV = 'VAULT_TEST_PASSPHRASE';
const WORDS_TO_BITS = { 12: 128, 24: 256 };
const WORDS_DEFAULT = 24;

const SCHEMES = {
  '2/3': { total: 3, threshold: 2 },
  '3/4': { total: 4, threshold: 3 },
  '3/5': { total: 5, threshold: 3 },
  '4/5': { total: 5, threshold: 4 },
};

const MINISCRIPT_EXAMPLE =
  'or(pk(owner),and(older(52560),multi(3,heir1,heir2,heir3,heir4,heir5)))';

function die(msg, code = 1) {
  process.stderr.write('ERROR: ' + msg + '\n');
  process.exit(code);
}

function help() {
  console.log(`BTCGuardiansHQ vault (UNAUDITED PROTOTYPE - use air-gapped only)

Usage:
  node vault.js create   [--scheme 2/3|3/4|3/5|4/5] [--out DIR] [--words 12|24] [--show]
  node vault.js reconstruct [--show] FILE FILE FILE [...]
  node vault.js reconstruct --legacy [--show] FILE_OR_STRING ...
  node vault.js test     [--scheme 2/3|3/4|3/5|4/5] [--words 12|24]
  node vault.js --help

Schemes:
  2/3   → any 2 of 3 shares recover the mnemonic
  3/4   → any 3 of 4 shares recover the mnemonic
  3/5   → any 3 of 5 shares recover the mnemonic (default)
  4/5   → any 4 of 5 shares recover the mnemonic

Options:
  --scheme S  Threshold scheme (default: 3/5)
  --out DIR   Folder for share files (default: current folder)
  --words N   12 or 24 (default 24)
  --show      Print the mnemonic
  --legacy    Read old v1 shares

Passphrase is always prompted (hidden). For tests only, set ${TEST_ENV}.
`);
}

function parseArgs(argv) {
  const opts = {
    cmd: null,
    show: false,
    legacy: false,
    out: '.',
    words: null,
    scheme: '3/5',
    files: [],
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--show') opts.show = true;
    else if (a === '--legacy') opts.legacy = true;
    else if (a === '--out') {
      if (i + 1 >= argv.length) die('--out needs a folder');
      opts.out = argv[++i];
    } else if (a === '--words') {
      if (i + 1 >= argv.length) die('--words needs 12 or 24');
      const w = argv[++i];
      if (!/^(12|24)$/.test(w)) die('--words must be 12 or 24');
      opts.words = Number(w);
    } else if (a === '--scheme') {
      if (i + 1 >= argv.length) die('--scheme needs 2/3, 3/4, 3/5 or 4/5');
      let s = argv[++i].toLowerCase().replace('of', '/');
      if (!SCHEMES[s]) die('Unknown scheme: ' + argv[i] + ' (use 2/3, 3/4, 3/5 or 4/5)');
      opts.scheme = s;
    } else if (a.startsWith('--')) die('Unknown option: ' + a);
    else if (!opts.cmd) opts.cmd = a;
    else opts.files.push(a);
  }
  return opts;
}

function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new Error('No terminal available for a hidden passphrase prompt.'));
      return;
    }
    process.stderr.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') {
          cleanup();
          process.stderr.write('\n');
          resolve(buf);
          return;
        } else if (ch === '\u0003') {
          cleanup();
          process.stderr.write('\n');
          process.exit(130);
        } else if (ch === '\u007f' || ch === '\b') {
          buf = buf.slice(0, -1);
        } else {
          buf += ch;
        }
      }
    };
    function cleanup() {
      stdin.removeListener('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
    }
    stdin.on('data', onData);
  });
}

async function getPassphrase(confirm) {
  if (process.env[TEST_ENV] !== undefined) {
    process.stderr.write(`WARNING: using passphrase from ${TEST_ENV}. For automated tests with FAKE data only.\n`);
    const p = process.env[TEST_ENV];
    if (confirm && p.length < MIN_PASS_LEN) die(`Passphrase must be at least ${MIN_PASS_LEN} characters.`);
    return p;
  }
  let p;
  try {
    p = await promptHidden('Passphrase: ');
    if (confirm) {
      if (p.length < MIN_PASS_LEN) die(`Passphrase must be at least ${MIN_PASS_LEN} characters.`);
      const p2 = await promptHidden('Repeat passphrase: ');
      if (p !== p2) die('Passphrases do not match.');
    }
  } catch (e) {
    die(e.message);
  }
  if (!p) die('Empty passphrase.');
  return p;
}

function requireArgon2() {
  if (!argon2) {
    die('The argon2 module could not be loaded. Run "npm install" first.');
  }
}

async function deriveKey(passphrase, salt, kdf) {
  if (!kdf || kdf.name !== 'argon2id') die('Unsupported KDF');
  requireArgon2();
  return argon2.hash(passphrase, {
    type: argon2.argon2id,
    salt,
    memoryCost: kdf.m,
    timeCost: kdf.t,
    parallelism: kdf.p,
    hashLength: kdf.len,
    raw: true,
  });
}

async function create(opts) {
  requireArgon2();
  const { total, threshold } = SCHEMES[opts.scheme];
  const outDir = path.resolve(opts.out);

  if (!fs.existsSync(outDir)) die('Output folder does not exist: ' + outDir);

  const targets = [];
  for (let i = 1; i <= total; i++) {
    targets.push(path.join(outDir, `share-${i}.json`));
  }
  const existing = targets.filter((f) => fs.existsSync(f));
  if (existing.length) {
    die('Refusing to overwrite existing share files:\n  ' + existing.join('\n  '));
  }

  console.error('Reminder: run this only on an air-gapped machine.');
  const passphrase = await getPassphrase(true);

  const words = opts.words || WORDS_DEFAULT;
  const mnemonic = bip39.generateMnemonic(WORDS_TO_BITS[words]);
  const hex = secrets.str2hex(mnemonic);
  const shares = secrets.share(hex, total, threshold);

  const salt = crypto.randomBytes(16);
  const kdf = { ...KDF_DEFAULT };
  const key = await deriveKey(passphrase, salt, kdf);

  shares.forEach((share, i) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const header = {
      v: FORMAT_VERSION,
      index: i + 1,
      threshold,
      total,
      scheme: opts.scheme,
    };
    cipher.setAAD(Buffer.from(JSON.stringify(header)));
    const data = Buffer.concat([cipher.update(share, 'utf8'), cipher.final()]);
    const obj = {
      ...header,
      kdf,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
    fs.writeFileSync(targets[i], JSON.stringify(obj, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  });
  key.fill(0);

  console.log(`\nWrote ${total} encrypted shares (${opts.scheme} → any ${threshold} recover it):`);
  targets.forEach((t) => console.log('  ' + t));
  console.log('\nMiniscript example (placeholder only):\n  ' + MINISCRIPT_EXAMPLE);

  if (opts.show) {
    console.log('\nMNEMONIC:\n' + mnemonic);
  } else {
    console.log('\nMnemonic was NOT shown. Use --show if needed.');
  }
  console.log('\nStore each share separately. Keep the passphrase separate from the shares.');
}

function loadV2(file) {
  let obj;
  try {
    obj = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    die(`Cannot read share file ${file}: ${e.message}`);
  }
  if (obj.v !== FORMAT_VERSION) {
    die(`${file}: unsupported format version ${obj.v} (try --legacy)`);
  }
  for (const k of ['index', 'threshold', 'total', 'kdf', 'salt', 'iv', 'tag', 'data']) {
    if (obj[k] === undefined) die(`${file}: missing field "${k}"`);
  }
  return { file, obj };
}

async function reconstruct(opts) {
  if (opts.files.length === 0) die('Give the share files (see --help)');
  const loaded = opts.files.map(loadV2);

  const first = loaded[0].obj;
  const ref = JSON.stringify({
    salt: first.salt,
    kdf: first.kdf,
    threshold: first.threshold,
    total: first.total,
  });
  const seen = new Set();

  for (const { file, obj } of loaded) {
    const cur = JSON.stringify({
      salt: obj.salt,
      kdf: obj.kdf,
      threshold: obj.threshold,
      total: obj.total,
    });
    if (cur !== ref) die(`${file}: shares from different vaults`);
    if (seen.has(obj.index)) die(`Duplicate share index ${obj.index}`);
    seen.add(obj.index);
  }

  if (loaded.length < first.threshold) {
    die(`Need at least ${first.threshold} shares, got ${loaded.length}`);
  }

  console.error('Reminder: run this only on an air-gapped machine.');
  const passphrase = await getPassphrase(false);
  const key = await deriveKey(passphrase, Buffer.from(first.salt, 'base64'), first.kdf);

  const plain = loaded.map(({ file, obj }) => {
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(obj.iv, 'base64')
      );
      const header = {
        v: obj.v,
        index: obj.index,
        threshold: obj.threshold,
        total: obj.total,
        scheme: obj.scheme,
      };
      decipher.setAAD(Buffer.from(JSON.stringify(header)));
      decipher.setAuthTag(Buffer.from(obj.tag, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(obj.data, 'base64')),
        decipher.final(),
      ]).toString('utf8');
    } catch (e) {
      die(`${file}: decryption failed (wrong passphrase or damaged share)`);
    }
  });
  key.fill(0);
  finish(plain, opts.show);
}

function finish(plainShares, show) {
  let mnemonic;
  try {
    mnemonic = secrets.hex2str(secrets.combine(plainShares));
  } catch (e) {
    die('Could not combine shares: ' + e.message);
  }
  if (!bip39.validateMnemonic(mnemonic)) {
    die('Combined result is not a valid BIP39 mnemonic');
  }
  console.log('Recovered a valid ' + mnemonic.split(' ').length + '-word BIP39 mnemonic.');
  if (show) console.log('\nMNEMONIC:\n' + mnemonic);
  else console.log('Not shown. Re-run with --show to print it.');
}

function readLegacyInput(x) {
  let s = x;
  if (fs.existsSync(x)) {
    s = fs.readFileSync(x, 'utf8').trim();
    try {
      const j = JSON.parse(s);
      if (typeof j === 'string') s = j;
      else if (j && j.share) s = j.share;
    } catch (_) {}
  }
  const parts = s.trim().split(':');
  if (parts.length !== 3 || !parts.every((p) => /^[0-9a-fA-F]+$/.test(p))) {
    die(`Not a legacy share: ${x.slice(0, 40)}...`);
  }
  return {
    src: x,
    iv: Buffer.from(parts[0], 'hex'),
    tag: Buffer.from(parts[1], 'hex'),
    data: Buffer.from(parts[2], 'hex'),
  };
}

async function reconstructLegacy(opts) {
  if (opts.files.length === 0) die('Give the legacy shares');
  const items = opts.files.map(readLegacyInput);
  console.error('LEGACY MODE: old v1 shares');
  const passphrase = await getPassphrase(false);
  const key = crypto.scryptSync(passphrase, LEGACY_SALT, 32);
  const plain = items.map((it) => {
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', key, it.iv);
      d.setAuthTag(it.tag);
      return Buffer.concat([d.update(it.data), d.final()]).toString('utf8');
    } catch (e) {
      die('Legacy decryption failed');
    }
  });
  key.fill(0);
  finish(plain, opts.show);
}

// ---------- TEST command ----------
async function runTest(opts) {
  requireArgon2();
  const { total, threshold } = SCHEMES[opts.scheme];
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'btcguardians-test-'));

  console.log(`\n=== BTCGuardiansHQ TEST (${opts.scheme}) ===`);
  console.log(`Temporary folder: ${tmpDir}`);

  const originalEnv = process.env[TEST_ENV];
  process.env[TEST_ENV] = 'test-passphrase-for-automated-run-123';

  try {
    // 1. Create
    await create({ ...opts, out: tmpDir, show: false });

    // 2. Successful reconstruction with enough shares
    const enoughFiles = [];
    for (let i = 1; i <= threshold; i++) {
      enoughFiles.push(path.join(tmpDir, `share-${i}.json`));
    }

    console.log(`\n→ Reconstructing with ${threshold} shares (should succeed)...`);
    await reconstruct({ files: enoughFiles, show: false, legacy: false });

    // 3. Too-few-shares test (must fail)
    if (threshold > 1) {
      const tooFewFiles = enoughFiles.slice(0, threshold - 1);
      console.log(`\n→ Reconstructing with only ${threshold - 1} shares (must be refused)...`);

      // We expect this to call die() / exit(1)
      const originalExit = process.exit;
      let refused = false;
      process.exit = (code) => {
        if (code === 1) refused = true;
        throw new Error('__EXPECTED_DIE__');
      };

      try {
        await reconstruct({ files: tooFewFiles, show: false, legacy: false });
      } catch (e) {
        if (e.message !== '__EXPECTED_DIE__') throw e;
      } finally {
        process.exit = originalExit;
      }

      if (!refused) {
        throw new Error('Too-few-shares test failed – it did not refuse!');
      }
      console.log('Correctly refused (too few shares).');
    }

    console.log('\n✓✓✓ PASSED ✓✓✓');
    console.log(`Scheme ${opts.scheme} works correctly (including too-few-shares check).`);
  } catch (err) {
    console.error('\n✗ TEST FAILED');
    console.error(err.message || err);
    process.exit(1);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {}
    if (originalEnv === undefined) delete process.env[TEST_ENV];
    else process.env[TEST_ENV] = originalEnv;
  }
}

// ---------- main ----------
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || !opts.cmd) {
    help();
    return;
  }

  if (opts.cmd === 'create') {
    if (opts.files.length) die('create does not take file arguments');
    if (opts.legacy) die('--legacy only works with reconstruct');
    await create(opts);
  } else if (opts.cmd === 'reconstruct') {
    if (opts.words !== null) die('--words only works with create');
    if (opts.legacy) await reconstructLegacy(opts);
    else await reconstruct(opts);
  } else if (opts.cmd === 'test') {
    await runTest(opts);
  } else {
    die('Unknown command: ' + opts.cmd);
  }
}

main().catch((e) => die(e && e.message ? e.message : String(e)));
