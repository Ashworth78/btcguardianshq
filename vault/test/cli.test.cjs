'use strict';

// FAKE DATA ONLY. This suite does not contact a node, create transactions, or
// establish that this unaudited prototype is suitable for real funds.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const argon2 = require('argon2');
const bip39 = require('bip39');
const secrets = require('secrets.js-grempe');

const CLI = path.resolve(__dirname, '..', 'vault.js');
const PASSWORD = crypto.randomBytes(24).toString('hex');
const WRONG_PASSWORD = PASSWORD + crypto.randomBytes(8).toString('hex');
// Public zero-entropy test vector, derived only at runtime: no stored mnemonic,
// passphrase or Shamir share fixture is committed. Production RNG is untouched.
const MNEMONIC = bip39.entropyToMnemonic(Buffer.alloc(32));
const golden = {
  shares: secrets.share(secrets.str2hex(MNEMONIC), 5, 3),
  otherShares: secrets.share(secrets.str2hex(bip39.entropyToMnemonic(Buffer.alloc(32, 0xff))), 5, 3),
};
const KDF = { name: 'argon2id', m: 65536, t: 3, p: 1, len: 32 };
const NAMES = [1, 2, 3, 4, 5].map(i => `share-${i}.json`);

function scratch(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'btc-vault-fake-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function cli(args, { cwd, password = PASSWORD, executable = CLI, nodePath = process.env.NODE_PATH || '', noGlobalPaths = false } = {}) {
  // Deliberately do not inherit NODE_OPTIONS, loader/native/KDF overrides,
  // npm settings, credentials or the caller's VAULT_TEST_PASSPHRASE.
  const env = { PATH: process.env.PATH || '', NODE_PATH: nodePath };
  if (password !== null) env.VAULT_TEST_PASSPHRASE = password;
  const result = spawnSync(process.execPath, [...(noGlobalPaths ? ['--no-global-search-paths'] : []), executable, ...args], {
    cwd, env, encoding: 'utf8', timeout: 15000, maxBuffer: 256 * 1024,
    input: '', windowsHide: true,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `CLI killed by ${result.signal}`);
  result.output = result.stdout + result.stderr;
  for (const secret of new Set([PASSWORD, WRONG_PASSWORD, password].filter(Boolean))) {
    assert.ok(!result.output.includes(secret), 'CLI must not echo a test passphrase');
  }
  return result;
}

function ok(result) {
  assert.equal(result.status, 0, result.output);
}

function rejected(result, message, forbidden = []) {
  assert.notEqual(result.status, 0, 'invalid input must fail');
  assert.match(result.stderr, /ERROR:/, result.output);
  assert.match(result.stderr, message, result.output);
  assert.doesNotMatch(result.stdout, /MNEMONIC:|Recovered a valid/);
  for (const text of [MNEMONIC, ...forbidden]) assert.ok(!result.output.includes(text));
}

function shownMnemonic(result) {
  const match = /\nMNEMONIC[^\n]*:\n([^\n]+)/.exec(result.stdout);
  assert.ok(match, 'explicit --show must include the mnemonic');
  return match[1];
}

function copyV2(dir, values) {
  return values.map((value, i) => {
    const file = path.join(dir, NAMES[i]);
    fs.writeFileSync(file, JSON.stringify(value) + '\n', { mode: 0o600 });
    return file;
  });
}

function readV2(dir) {
  return NAMES.map(name => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')));
}

function snapshot(files) {
  return files.map(file => ({ file, bytes: fs.readFileSync(file), mode: fs.statSync(file).mode }));
}

function unchanged(before) {
  for (const { file, bytes, mode } of before) {
    assert.deepEqual(fs.readFileSync(file), bytes, `must preserve ${path.basename(file)}`);
    assert.equal(fs.statSync(file).mode, mode);
  }
}

function flipBase64(encoded) {
  const bytes = Buffer.from(encoded, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

async function keyFor(salt) {
  // Explicit contract, not deriveKey() from the CLI.
  return argon2.hash(PASSWORD, {
    type: argon2.argon2id, salt, memoryCost: 65536, timeCost: 3,
    parallelism: 1, hashLength: 32, raw: true,
  });
}

async function decryptOutsideCLI(values) {
  const key = await keyFor(Buffer.from(values[0].salt, 'base64'));
  try {
    return values.map(value => {
      const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(value.iv, 'base64'));
      // Independent wire-format oracle; property order is part of v2 AAD.
      const aad = `{"v":2,"index":${value.index},"threshold":3,"total":5}`;
      d.setAAD(Buffer.from(aad));
      d.setAuthTag(Buffer.from(value.tag, 'base64'));
      return Buffer.concat([d.update(Buffer.from(value.data, 'base64')), d.final()]).toString('utf8');
    });
  } finally { key.fill(0); }
}

async function knownV2() {
  const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const key = await keyFor(salt);
  try {
    return golden.shares.map((share, i) => {
      const iv = Buffer.alloc(12); iv.writeUInt32BE(i + 1, 8);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(Buffer.from(`{"v":2,"index":${i + 1},"threshold":3,"total":5}`));
      const data = Buffer.concat([c.update(share, 'utf8'), c.final()]);
      return { v: 2, index: i + 1, threshold: 3, total: 5, kdf: { ...KDF },
        salt: salt.toString('base64'), iv: iv.toString('base64'),
        tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
    });
  } finally { key.fill(0); }
}

function knownLegacy(shares = golden.shares) {
  // Compatibility fixture generated without importing or executing CLI helpers.
  const key = crypto.scryptSync(PASSWORD, 'btcguardianshq-salt-v1', 32);
  try {
    return shares.map((share, i) => {
      const iv = Buffer.alloc(12); iv.writeUInt32BE(i + 11, 8);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      const data = Buffer.concat([c.update(share, 'utf8'), c.final()]);
      return [iv, c.getAuthTag(), data].map(x => x.toString('hex')).join(':');
    });
  } finally { key.fill(0); }
}

// Sequential subtests keep at most one child/KDF operation active. Every case
// has a fresh directory; shared fixture *values* contain only public dummy data.
test('offline vault CLI regression suite', { concurrency: false }, async t => {
  // Fixed known-vector digest is independent of both the CLI and the runtime
  // library conversion; this catches an incorrect expected mnemonic as well.
  assert.equal(crypto.createHash('sha256').update(MNEMONIC).digest('hex'),
    '69be79ef3c28f55d7cb84db2dd3c18dfff45eeefebd09b8c5f7f3489b8ba09ac');
  assert.equal(secrets.hex2str(secrets.combine(golden.shares.slice(0, 3))), MNEMONIC);
  const known = await knownV2();
  const legacy = knownLegacy();
  let created;
  let createdMnemonic;
  let otherVault;

  // Breaks caught: wrong share count/index, missing mode/AAD, bad encryption,
  // non-24-word seed, repeated IV, or passphrase echo.
  await t.test('create emits five independently decryptable 0600 v2 shares', async t => {
    const dir = scratch(t);
    const result = cli(['create', '--out', dir, '--show'], { cwd: dir });
    ok(result);
    createdMnemonic = shownMnemonic(result);
    assert.equal(createdMnemonic.split(' ').length, 24);
    assert.ok(bip39.validateMnemonic(createdMnemonic));
    assert.match(result.stderr, /WARNING:.*VAULT_TEST_PASSPHRASE/);
    assert.deepEqual(fs.readdirSync(dir).sort(), NAMES);
    created = readV2(dir);
    for (const [i, value] of created.entries()) {
      assert.deepEqual(Object.keys(value).sort(), ['data', 'index', 'iv', 'kdf', 'salt', 'tag', 'threshold', 'total', 'v']);
      assert.deepEqual([value.v, value.index, value.threshold, value.total], [2, i + 1, 3, 5]);
      assert.deepEqual(value.kdf, KDF);
      for (const [field, bytes] of [['salt', 16], ['iv', 12], ['tag', 16]]) {
        const decoded = Buffer.from(value[field], 'base64');
        assert.equal(decoded.length, bytes);
        assert.equal(decoded.toString('base64'), value[field]);
      }
      assert.equal(value.salt, created[0].salt);
      assert.ok(Buffer.from(value.data, 'base64').length > 0);
      if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(dir, NAMES[i])).mode & 0o777, 0o600);
    }
    assert.equal(new Set(created.map(value => value.iv)).size, 5);
    const plain = await decryptOutsideCLI(created);
    for (const [i, share] of plain.entries()) {
      assert.match(share, /^[0-9a-f]+$/i);
      assert.equal(Number.parseInt(share.slice(0, 1), 36), 8);
      assert.equal(Number.parseInt(share.slice(1, 3), 16), i + 1);
    }
    assert.equal(secrets.hex2str(secrets.combine(plain.slice(0, 3))), createdMnemonic);
  });

  // Breaks caught: default seed disclosure; fixed/reused per-vault salt.
  await t.test('create defaults to no mnemonic and a fresh salt', async t => {
    const dir = scratch(t);
    const result = cli(['create', '--out', dir], { cwd: dir });
    ok(result);
    otherVault = readV2(dir);
    const plain = await decryptOutsideCLI(otherVault);
    const mnemonic = secrets.hex2str(secrets.combine(plain.slice(0, 3)));
    assert.ok(bip39.validateMnemonic(mnemonic));
    assert.ok(!result.output.includes(mnemonic));
    assert.doesNotMatch(result.stdout, /MNEMONIC[^\n]*:/);
    assert.notEqual(otherVault[0].salt, created[0].salt);
  });

  // Finite exhaustive enumeration, not a property-based proof or crypto audit.
  for (let a = 0; a < 3; a++) for (let b = a + 1; b < 4; b++) for (let c = b + 1; c < 5; c++) {
    const subset = [a, b, c];
    await t.test(`3-of-5 recovery: indices ${subset.map(i => i + 1).join(',')}`, t => {
      const dir = scratch(t);
      const files = copyV2(dir, created);
      const before = snapshot(files);
      const result = cli(['reconstruct', '--show', ...subset.map(i => files[i])], { cwd: dir });
      ok(result);
      assert.equal(shownMnemonic(result), createdMnemonic);
      unchanged(before);
    });
  }
  for (const indices of [[0, 1, 2, 3], [0, 1, 2, 3, 4], [4, 2, 0]]) {
    await t.test(`larger/reordered recovery: ${indices.map(i => i + 1).join(',')}`, t => {
      const dir = scratch(t);
      const files = copyV2(dir, created);
      const result = cli(['reconstruct', '--show', ...indices.map(i => files[i])], { cwd: dir });
      ok(result);
      assert.equal(shownMnemonic(result), createdMnemonic);
    });
  }

  await t.test('independently encrypted known BIP39 fixture recovers exact text', t => {
    const dir = scratch(t);
    const files = copyV2(dir, known);
    const result = cli(['reconstruct', '--show', ...files.slice(0, 3)], { cwd: dir });
    ok(result);
    assert.equal(shownMnemonic(result), MNEMONIC);
  });
  await t.test('reconstruct defaults to no mnemonic', t => {
    const dir = scratch(t);
    const files = copyV2(dir, known);
    const result = cli(['reconstruct', ...files.slice(0, 3)], { cwd: dir });
    ok(result);
    assert.match(result.stdout, /Recovered a valid 24-word/);
    assert.ok(!result.output.includes(MNEMONIC));
    assert.doesNotMatch(result.stdout, /MNEMONIC[^\n]*:/);
  });

  // Breaks caught: accepted wrong password, insufficient/duplicate/mixed shares.
  for (const count of [0, 1, 2]) {
    await t.test(`rejects ${count} v2 shares`, t => {
      const dir = scratch(t);
      const files = copyV2(dir, known);
      const before = snapshot(files);
      rejected(cli(['reconstruct', '--show', ...files.slice(0, count)], { cwd: dir }), /Give the share files|Need at least 3/);
      unchanged(before);
    });
  }
  await t.test('rejects wrong password without revealing or modifying data', t => {
    const dir = scratch(t);
    const files = copyV2(dir, known);
    const before = snapshot(files);
    rejected(cli(['reconstruct', '--show', ...files.slice(0, 3)], { cwd: dir, password: WRONG_PASSWORD }), /decryption failed/);
    unchanged(before);
  });
  for (const copied of [false, true]) {
    await t.test(`rejects duplicate ${copied ? 'index in a copied file' : 'file'}`, t => {
      const dir = scratch(t);
      const files = copyV2(dir, known);
      let duplicate = files[0];
      if (copied) { duplicate = path.join(dir, 'copy.json'); fs.copyFileSync(files[0], duplicate); }
      const before = snapshot([...files, ...(copied ? [duplicate] : [])]);
      rejected(cli(['reconstruct', '--show', files[0], files[1], duplicate], { cwd: dir }), /Duplicate share index/);
      unchanged(before);
    });
  }
  await t.test('rejects shares from separate vaults', t => {
    const dir = scratch(t);
    const values = clone(created); values[2] = otherVault[2];
    const files = copyV2(dir, values);
    const before = snapshot(files);
    rejected(cli(['reconstruct', '--show', ...files.slice(0, 3)], { cwd: dir }), /different vaults/, [createdMnemonic]);
    unchanged(before);
  });

  // Changes are bounded: no large positive KDF costs are ever executed.
  const mutations = [
    ['ciphertext', v => { v[0].data = flipBase64(v[0].data); }, /decryption failed/],
    ['tag', v => { v[0].tag = flipBase64(v[0].tag); }, /decryption failed/],
    ['IV', v => { v[0].iv = flipBase64(v[0].iv); }, /decryption failed/],
    ['version', v => { v[0].v = 99; }, /unsupported format version/],
    ['authenticated index', v => { v[0].index = 4; }, /decryption failed/],
    ['authenticated threshold', v => v.forEach(x => { x.threshold = 2; }), /decryption failed/],
    ['authenticated total', v => v.forEach(x => { x.total = 6; }), /decryption failed/],
    ['salt mismatch', v => { v[1].salt = flipBase64(v[1].salt); }, /different vaults/],
    ['consistent salt tamper', v => v.forEach(x => { x.salt = flipBase64(x.salt); }), /decryption failed/],
    ['KDF mismatch', v => { v[1].kdf.t = 2; }, /different vaults/],
    ['unsupported KDF', v => v.forEach(x => { x.kdf.name = 'not-argon2'; }), /Unsupported KDF/],
    ...['m', 't', 'p', 'len'].flatMap(field => [0, -1, 1.5].map(value =>
      [`KDF ${field}=${value}`, v => v.forEach(x => { x.kdf[field] = value; }), /Bad KDF parameter/])),
    ['wrong AES key length', v => v.forEach(x => { x.kdf.len = 16; }), /KDF length must be 32/],
    ...['index', 'threshold', 'total', 'kdf', 'salt', 'iv', 'tag', 'data'].map(field =>
      [`missing ${field}`, v => { delete v[0][field]; }, /missing field/]),
  ];
  for (const [name, mutate, message] of mutations) {
    await t.test(`rejects ${name}`, t => {
      const dir = scratch(t);
      const values = clone(known.slice(0, 3)); mutate(values);
      const files = copyV2(dir, values);
      const before = snapshot(files);
      rejected(cli(['reconstruct', '--show', ...files], { cwd: dir }), message);
      unchanged(before);
    });
  }
  await t.test('rejects malformed JSON without changing files', t => {
    const dir = scratch(t);
    const files = copyV2(dir, known.slice(0, 3));
    fs.writeFileSync(files[0], '{not JSON');
    const before = snapshot(files);
    rejected(cli(['reconstruct', '--show', ...files], { cwd: dir }), /Cannot read share file/);
    unchanged(before);
  });
  await t.test('rejects missing share file', t => {
    const dir = scratch(t);
    rejected(cli(['reconstruct', '--show', path.join(dir, 'absent.json')], { cwd: dir }), /Cannot read share file/);
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  // Breaks caught: overwriting even one existing target, partial replacement,
  // symlink following, or creating output before validating create arguments.
  for (const indices of [[1, 2, 3, 4, 5], [3]]) {
    await t.test(`create preserves preexisting targets ${indices.join(',')}`, t => {
      const dir = scratch(t);
      const files = indices.map(i => {
        const file = path.join(dir, `share-${i}.json`);
        fs.writeFileSync(file, `FAKE existing sentinel ${i}\n`); return file;
      });
      const before = snapshot(files);
      rejected(cli(['create', '--out', dir, '--show'], { cwd: dir }), /Refusing to overwrite/);
      unchanged(before);
      assert.deepEqual(fs.readdirSync(dir).sort(), files.map(f => path.basename(f)).sort());
    });
  }
  await t.test('create preserves a symlink target inside the owned directory', { skip: process.platform === 'win32' }, t => {
    const dir = scratch(t);
    const sentinel = path.join(dir, 'sentinel');
    fs.writeFileSync(sentinel, 'FAKE symlink target must survive\n');
    const link = path.join(dir, 'share-3.json');
    fs.symlinkSync(sentinel, link);
    const before = snapshot([sentinel]);
    rejected(cli(['create', '--out', dir], { cwd: dir }), /Refusing to overwrite/);
    unchanged(before);
    assert.ok(fs.lstatSync(link).isSymbolicLink());
    assert.equal(fs.readlinkSync(link), sentinel);
    assert.deepEqual(fs.readdirSync(dir).sort(), ['sentinel', 'share-3.json']);
  });
  const invalidCreate = [
    ['missing directory', dir => ['create', '--out', path.join(dir, 'missing')], PASSWORD, /Output folder does not exist/],
    ['short password', dir => ['create', '--out', dir], crypto.randomBytes(3).toString('hex'), /at least 12 characters/],
    ['extra argument', dir => ['create', '--out', dir, 'extra-create-arg'], PASSWORD, /does not take extra arguments/],
    ['legacy create', dir => ['create', '--legacy', '--out', dir], PASSWORD, /only works with reconstruct/],
    ['no terminal', dir => ['create', '--out', dir], null, /No terminal available/],
    ['missing out value', () => ['create', '--out'], PASSWORD, /needs a folder/],
  ];
  for (const [name, args, password, message] of invalidCreate) {
    await t.test(`create rejects ${name} without writing files`, t => {
      const dir = scratch(t);
      rejected(cli(args(dir), { cwd: dir, password }), message);
      assert.deepEqual(fs.readdirSync(dir), []);
    });
  }

  // Breaks caught: incompatible legacy parsing/scrypt/AES parameters, missing
  // opt-in, authentication/duplicate checks, or default mnemonic disclosure.
  for (const kind of ['raw', 'file', 'JSON string file', 'JSON object file']) {
    await t.test(`legacy known fixture recovers from ${kind}`, t => {
      const dir = scratch(t);
      const inputs = legacy.slice(0, 3).map((value, i) => {
        if (kind === 'raw') return value;
        const file = path.join(dir, `legacy-${i}.txt`);
        const content = kind === 'file' ? value : kind === 'JSON string file' ? JSON.stringify(value) : JSON.stringify({ share: value });
        fs.writeFileSync(file, content + '\n'); return file;
      });
      const result = cli(['reconstruct', '--legacy', '--show', ...inputs], { cwd: dir });
      ok(result);
      assert.equal(shownMnemonic(result), MNEMONIC);
      assert.match(result.stderr, /LEGACY MODE/);
    });
  }
  await t.test('legacy requires explicit opt-in', t => {
    const dir = scratch(t);
    const files = legacy.slice(0, 3).map((value, i) => {
      const file = path.join(dir, `legacy-${i}.txt`); fs.writeFileSync(file, value); return file;
    });
    rejected(cli(['reconstruct', '--show', ...files], { cwd: dir }), /Cannot read share file/);
  });
  await t.test('legacy defaults to no mnemonic', t => {
    const dir = scratch(t);
    const result = cli(['reconstruct', '--legacy', ...legacy.slice(0, 3)], { cwd: dir });
    ok(result);
    assert.ok(!result.output.includes(MNEMONIC));
    assert.doesNotMatch(result.stdout, /MNEMONIC:/);
  });
  const brokenLegacy = [...legacy];
  const parts = brokenLegacy[0].split(':');
  const data = Buffer.from(parts[2], 'hex'); data[0] ^= 1; parts[2] = data.toString('hex'); brokenLegacy[0] = parts.join(':');
  const otherLegacy = knownLegacy(golden.otherShares);
  const legacyRejections = [
    ['wrong password', legacy.slice(0, 3), WRONG_PASSWORD, /Legacy share decryption failed/],
    ['tampering', brokenLegacy.slice(0, 3), PASSWORD, /Legacy share decryption failed/],
    ['duplicates', [legacy[0], legacy[1], legacy[0]], PASSWORD, /Duplicate legacy shares/],
    ['zero shares', [], PASSWORD, /Give the legacy shares/],
    ['one share', legacy.slice(0, 1), PASSWORD, /not a valid BIP39 mnemonic/],
    ['two shares', legacy.slice(0, 2), PASSWORD, /not a valid BIP39 mnemonic/],
    ['mixed vaults', [legacy[0], legacy[1], otherLegacy[2]], PASSWORD, /not a valid BIP39 mnemonic/],
    ['malformed input', ['bad:input'], PASSWORD, /Not a legacy/],
  ];
  for (const [name, inputs, password, message] of legacyRejections) {
    await t.test(`legacy rejects ${name}`, t => {
      const dir = scratch(t);
      rejected(cli(['reconstruct', '--legacy', '--show', ...inputs], { cwd: dir, password }), message);
      assert.deepEqual(fs.readdirSync(dir), []);
    });
  }

  await t.test('help succeeds without passphrase or output files', t => {
    const dir = scratch(t);
    const result = cli(['--help'], { cwd: dir, password: null });
    ok(result); assert.match(result.stdout, /Usage:/); assert.match(result.stdout, /UNAUDITED PROTOTYPE/);
    assert.deepEqual(fs.readdirSync(dir), []);
  });
  for (const [args, message] of [[['unknown-command'], /Unknown command/], [['--unknown-option'], /Unknown option/]]) {
    await t.test(`rejects ${args[0]}`, t => {
      const dir = scratch(t); rejected(cli(args, { cwd: dir }), message);
      assert.deepEqual(fs.readdirSync(dir), []);
    });
  }

  await t.test('missing Argon2 fails closed without a fallback KDF', t => {
    const dir = scratch(t);
    const isolated = path.join(dir, 'isolated'); fs.mkdirSync(isolated);
    const isolatedCli = path.join(isolated, 'vault.js'); fs.copyFileSync(CLI, isolatedCli);
    const modules = path.join(isolated, 'node_modules'); fs.mkdirSync(modules);
    // Copy only the actual bip39/Shamir closure. No mock or failing replacement
    // module is installed, and the project's dependency tree is never edited.
    for (const name of ['bip39', 'secrets.js-grempe', '@noble/hashes']) {
      const sourceDir = name === '@noble/hashes'
        ? path.dirname(require.resolve(name))
        : path.dirname(require.resolve(`${name}/package.json`));
      const target = path.join(modules, name); fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.cpSync(sourceDir, target, { recursive: true });
    }
    const out = path.join(dir, 'out'); fs.mkdirSync(out);
    const result = cli(['create', '--out', out], { cwd: out, executable: isolatedCli, nodePath: '', noGlobalPaths: true });
    rejected(result, /argon2 module could not be loaded/);
    assert.match(result.stderr, /No fallback KDF is used/);
    assert.deepEqual(fs.readdirSync(out), []);
  });
});
