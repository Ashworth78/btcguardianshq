#!/usr/bin/env node
/*
 * BTCGuardiansHQ vault.js - air-gapped Shamir split of a BIP39 mnemonic.
 *
 * STATUS: UNAUDITED PROTOTYPE. Do not rely on it for real funds without
 * independent review. Run only on an offline (air-gapped) machine.
 *
 * What it does:
 *   create       Generates a 24-word (default) or 12-word BIP39 mnemonic, splits it 3-of-5 with
 *                Shamir (secrets.js-grempe), encrypts each share with
 *                AES-256-GCM using a key from Argon2id (random salt per vault),
 *                and writes share-1.json .. share-5.json.
 *   reconstruct  Decrypts >= 3 shares and recombines the mnemonic.
 *   --legacy     Reads the old v1 "iv:tag:hex" shares (scrypt + fixed salt).
 *
 * Miniscript: PLANNED, NOT IMPLEMENTED. The printed policy is an example
 * template with placeholder keys only.
 *
 * Deps: argon2, bip39, secrets.js-grempe (plus Node's crypto/fs).
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let argon2;
try {
  argon2 = require('argon2');
} catch (e) {
  argon2 = null; // checked where needed; NEVER silently fall back to another KDF
}
const bip39 = require('bip39');
const secrets = require('secrets.js-grempe');

const FORMAT_VERSION = 2;
const SHARES_TOTAL = 5;
const SHARES_THRESHOLD = 3;
const MIN_PASS_LEN = 12;
const KDF_DEFAULT = { name: 'argon2id', m: 65536, t: 3, p: 1, len: 32 };
const LEGACY_SALT = 'btcguardianshq-salt-v1';
const TEST_ENV = 'VAULT_TEST_PASSPHRASE';
// BIP39 word count -> entropy bits (24 words = 256 bits, 12 words = 128 bits).
const WORDS_TO_BITS = { 12: 128, 24: 256 };
const WORDS_DEFAULT = 24;

const MINISCRIPT_EXAMPLE =
  'or(pk(owner),and(older(52560),multi(3,heir1,heir2,heir3,heir4,heir5)))';

function die(msg, code = 1) {
  process.stderr.write('ERROR: ' + msg + '\n');
  process.exit(code);
}

function help() {
  console.log(`BTCGuardiansHQ vault (UNAUDITED PROTOTYPE - use air-gapped only)

Usage:
  node vault.js create [--out DIR] [--words 12|24] [--show]
  node vault.js reconstruct [--show] FILE FILE FILE [...]
  node vault.js reconstruct --legacy [--show] FILE_OR_STRING ...
  node vault.js --help

Options:
  --out DIR   Folder for share-1.json..share-5.json (default: current folder).
              Refuses to overwrite existing share files.
  --words N   Mnemonic length for create: 24 (default, 256-bit) or 12 (128-bit,
              e.g. for Liana hot-key import). reconstruct detects it automatically.
  --show      Print the mnemonic on screen. Without it, the mnemonic is not shown.
  --legacy    Read old v1 shares ("iv:tag:hex", scrypt with fixed salt).

The passphrase is always asked for with a hidden prompt (min ${MIN_PASS_LEN} chars,
asked twice on create). It is never taken from the command line.
For automated tests only, ${TEST_ENV} can supply it (a warning is printed).
`);
}

// ---------- argv parsing (no commander) ----------
function parseArgs(argv) {
  const opts = { cmd: null, show: false, legacy: false, out: '.', words: null, files: [], help: false };
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
      if (!/^(12|24)$/.test(w)) die('--words must be 12 or 24, got: ' + w);
      opts.words = Number(w);
    } else if (a.startsWith('--')) die('Unknown option: ' + a + ' (see --help)');
    else if (!opts.cmd) opts.cmd = a;
    else opts.files.push(a);
  }
  return opts;
}

// ---------- hidden passphrase prompt ----------
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
        } else if (ch === '\u0003') { // Ctrl+C
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

// ---------- KDF ----------
function requireArgon2() {
  if (!argon2) {
    die('The argon2 module could not be loaded. Refusing to continue.\n' +
        'No fallback KDF is used, because a different KDF would make shares unrecoverable.\n' +
        'Fix: run "npm install" (with network, before going offline) on a matching Node version.');
  }
}

async function deriveKey(passphrase, salt, kdf) {
  if (!kdf || kdf.name !== 'argon2id') die('Unsupported KDF in share file: ' + JSON.stringify(kdf));
  requireArgon2();
  for (const k of ['m', 't', 'p', 'len']) {
    if (!Number.isInteger(kdf[k]) || kdf[k] <= 0) die('Bad KDF parameter ' + k + ' in share file.');
  }
  if (kdf.len !== 32) die('KDF length must be 32 for AES-256.');
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

// ---------- create ----------
async function create(opts) {
  requireArgon2();
  const outDir = path.resolve(opts.out);
  if (!fs.existsSync(outDir)) die('Output folder does not exist: ' + outDir);
  const targets = [];
  for (let i = 1; i <= SHARES_TOTAL; i++) targets.push(path.join(outDir, `share-${i}.json`));
  const existing = targets.filter((f) => fs.existsSync(f));
  if (existing.length) die('Refusing to overwrite existing share files:\n  ' + existing.join('\n  '));

  console.error('Reminder: run this only on an air-gapped machine (networking OFF).');
  const passphrase = await getPassphrase(true);

  const words = opts.words || WORDS_DEFAULT;
  const mnemonic = bip39.generateMnemonic(WORDS_TO_BITS[words]);
  if (mnemonic.split(' ').length !== words) die('Internal error: unexpected mnemonic length.');
  const hex = secrets.str2hex(mnemonic);
  const shares = secrets.share(hex, SHARES_TOTAL, SHARES_THRESHOLD);

  const salt = crypto.randomBytes(16);
  const kdf = { ...KDF_DEFAULT };
  const key = await deriveKey(passphrase, salt, kdf);

  shares.forEach((share, i) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const header = { v: FORMAT_VERSION, index: i + 1, threshold: SHARES_THRESHOLD, total: SHARES_TOTAL };
    // Bind the header fields to the ciphertext so they cannot be edited unnoticed.
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

  console.log(`Wrote ${SHARES_TOTAL} encrypted shares of a ${words}-word mnemonic (any ${SHARES_THRESHOLD} recover it):`);
  targets.forEach((t) => console.log('  ' + t));
  console.log('\nMiniscript - EXAMPLE TEMPLATE ONLY - placeholder keys, not a spendable policy, not tested:');
  console.log('  ' + MINISCRIPT_EXAMPLE);
  if (opts.show) {
    console.log('\nMNEMONIC (write it down offline, then clear the screen):\n' + mnemonic);
  } else {
    console.log('\nMnemonic was split into shares and NOT shown. Use --show if you need to see it.');
  }
  console.log('\nStore each share in a separate place. Keep the passphrase separate from the shares.');
}

// ---------- reconstruct ----------
function loadV2(file) {
  let obj;
  try { obj = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { die(`Cannot read share file ${file}: ${e.message}`); }
  if (obj.v !== FORMAT_VERSION) die(`${file}: unsupported format version ${obj.v} (old shares? try --legacy).`);
  for (const k of ['index', 'threshold', 'total', 'kdf', 'salt', 'iv', 'tag', 'data']) {
    if (obj[k] === undefined) die(`${file}: missing field "${k}".`);
  }
  return { file, obj };
}

async function reconstruct(opts) {
  if (opts.files.length === 0) die('Give the share files to use (see --help).');
  const loaded = opts.files.map(loadV2);

  const first = loaded[0].obj;
  const ref = JSON.stringify({ salt: first.salt, kdf: first.kdf, threshold: first.threshold, total: first.total });
  const seen = new Set();
  for (const { file, obj } of loaded) {
    const cur = JSON.stringify({ salt: obj.salt, kdf: obj.kdf, threshold: obj.threshold, total: obj.total });
    if (cur !== ref) die(`${file}: salt/KDF/threshold differ from the first share - shares are from different vaults.`);
    if (seen.has(obj.index)) die(`Duplicate share index ${obj.index} (${file}).`);
    seen.add(obj.index);
  }
  if (loaded.length < first.threshold) {
    die(`Need at least ${first.threshold} different shares, got ${loaded.length}.`);
  }

  console.error('Reminder: run this only on an air-gapped machine (networking OFF).');
  const passphrase = await getPassphrase(false);
  const key = await deriveKey(passphrase, Buffer.from(first.salt, 'base64'), first.kdf);

  const plain = loaded.map(({ file, obj }) => {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(obj.iv, 'base64'));
      const header = { v: obj.v, index: obj.index, threshold: obj.threshold, total: obj.total };
      decipher.setAAD(Buffer.from(JSON.stringify(header)));
      decipher.setAuthTag(Buffer.from(obj.tag, 'base64'));
      return Buffer.concat([decipher.update(Buffer.from(obj.data, 'base64')), decipher.final()]).toString('utf8');
    } catch (e) {
      die(`${file}: decryption failed (wrong passphrase or damaged/tampered share).`);
    }
  });
  key.fill(0);
  finish(plain, opts.show);
}

function finish(plainShares, show) {
  let mnemonic;
  try { mnemonic = secrets.hex2str(secrets.combine(plainShares)); }
  catch (e) { die('Could not combine shares: ' + e.message); }
  if (!bip39.validateMnemonic(mnemonic)) {
    die('Combined result is not a valid BIP39 mnemonic (not enough shares, or shares from different vaults).');
  }
  console.log('Recovered a valid ' + mnemonic.split(' ').length + '-word BIP39 mnemonic.');
  if (show) console.log('\nMNEMONIC:\n' + mnemonic);
  else console.log('Not shown. Re-run with --show to print it (air-gapped only).');
}

// ---------- legacy (v1) ----------
function readLegacyInput(x) {
  let s = x;
  if (fs.existsSync(x)) {
    s = fs.readFileSync(x, 'utf8').trim();
    try { const j = JSON.parse(s); if (typeof j === 'string') s = j; else if (j && j.share) s = j.share; } catch (_) {}
  }
  const parts = s.trim().split(':');
  if (parts.length !== 3 || !parts.every((p) => /^[0-9a-fA-F]+$/.test(p))) {
    die(`Not a legacy "iv:tag:hex" share: ${x.length > 40 ? x.slice(0, 40) + '...' : x}`);
  }
  return { src: x, iv: Buffer.from(parts[0], 'hex'), tag: Buffer.from(parts[1], 'hex'), data: Buffer.from(parts[2], 'hex') };
}

async function reconstructLegacy(opts) {
  if (opts.files.length === 0) die('Give the legacy shares (files or iv:tag:hex strings).');
  const items = opts.files.map(readLegacyInput);
  console.error('LEGACY MODE: old v1 shares (scrypt, fixed salt). Re-split this vault with "create" afterwards.');
  console.error('Reminder: run this only on an air-gapped machine (networking OFF).');
  const passphrase = await getPassphrase(false);
  const key = crypto.scryptSync(passphrase, LEGACY_SALT, 32);
  const plain = items.map((it) => {
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', key, it.iv);
      d.setAuthTag(it.tag);
      return Buffer.concat([d.update(it.data), d.final()]).toString('utf8');
    } catch (e) {
      die(`Legacy share decryption failed (wrong passphrase or damaged share).`);
    }
  });
  key.fill(0);
  if (new Set(plain).size !== plain.length) die('Duplicate legacy shares given.');
  finish(plain, opts.show);
}

// ---------- main ----------
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || !opts.cmd) { help(); return; }
  if (opts.cmd === 'create') {
    if (opts.files.length) die('create does not take extra arguments. The passphrase is asked for with a hidden prompt.');
    if (opts.legacy) die('--legacy only works with reconstruct.');
    await create(opts);
  } else if (opts.cmd === 'reconstruct') {
    if (opts.words !== null) die('--words only works with create (reconstruct detects the length).');
    if (opts.legacy) await reconstructLegacy(opts);
    else await reconstruct(opts);
  } else {
    die('Unknown command: ' + opts.cmd + ' (see --help)');
  }
}

main().catch((e) => die(e && e.message ? e.message : String(e)));
