'use strict';
// vault.js "sign" command, READ-ONLY step: decode a PSBT and show what it
// would spend. No keys, no seed words, no signing, nothing written.
const fs = require('fs');
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
bitcoin.initEccLib(ecc);

function signReadOnly(psbtFile, netName = 'signet') {
  if (netName === 'mainnet' || netName === 'bitcoin') {
    throw new Error('Refusing: mainnet is not allowed in this test build.');
  }
  if (netName !== 'signet' && netName !== 'testnet') {
    throw new Error('Unknown network: ' + netName + ' (use signet or testnet)');
  }
  const network = bitcoin.networks.testnet; // signet shares tb1 addresses
  if (!fs.existsSync(psbtFile)) throw new Error('PSBT file not found: ' + psbtFile);
  const text = fs.readFileSync(psbtFile, 'utf8').trim();
  if (!text.startsWith('cHNidP8')) throw new Error('Not a base64 PSBT (should start cHNidP8).');
  const psbt = bitcoin.Psbt.fromBase64(text, { network });
  const isMainPath = (d) => /^m\/\d+'\/0'/.test(d.path);
  const all = [...psbt.data.inputs, ...psbt.data.outputs];
  if (all.some((x) => [...(x.bip32Derivation || []), ...(x.tapBip32Derivation || [])].some(isMainPath))) {
    throw new Error('Refusing: PSBT has mainnet key paths (coin type 0).');
  }
  let inTotal = 0n;
  console.log('READ-ONLY: nothing will be signed.');
  console.log('Network:', netName);
  console.log('Inputs:', psbt.inputCount);
  psbt.data.inputs.forEach((inp, i) => {
    const txin = psbt.txInputs[i];
    const txid = Buffer.from(txin.hash).reverse().toString('hex');
    let utxo = inp.witnessUtxo;
    if (!utxo && inp.nonWitnessUtxo) {
      const prev = bitcoin.Transaction.fromBuffer(inp.nonWitnessUtxo);
      if (prev.getId() !== txid) throw new Error(`Input ${i}: nonWitnessUtxo does not match txid.`);
      utxo = prev.outs[txin.index];
    }
    if (!utxo) throw new Error(`Input ${i} has no UTXO data; cannot check amount.`);
    const v = BigInt(utxo.value);
    inTotal += v;
    let addr = '(unknown script)';
    try { addr = bitcoin.address.fromOutputScript(utxo.script, network); } catch {}
    const sigs = (inp.partialSig || []).length;
    console.log(`  #${i} ${txid}:${txin.index}  ${v} sats  ${addr}  partial sigs: ${sigs}`);
  });
  let outTotal = 0n;
  console.log('Outputs:', psbt.txOutputs.length);
  psbt.txOutputs.forEach((o, i) => {
    const v = BigInt(o.value);
    outTotal += v;
    console.log(`  #${i} ${o.address || '(non-address script)'}  ${v} sats`);
  });

  const fee = inTotal - outTotal;
  if (fee < 0n) throw new Error('Outputs exceed inputs: invalid PSBT.');
  console.log('Total in: ', inTotal.toString(), 'sats');
  console.log('Total out:', outTotal.toString(), 'sats');
  console.log('Fee:      ', fee.toString(), 'sats');
  if (fee > 50000n) console.log('WARNING: fee is over 50,000 sats. Check carefully.');
  return { inTotal, outTotal, fee, psbt };
}

// Find which of our keys owns an input: check the first 20 receive
// and change addresses on m/84'/1'/0' (signet/testnet BIP84).
function findKey(root, script, network) {
  for (const chain of [0, 1]) {
    for (let n = 0; n < 20; n++) {
      const child = root.derivePath(`m/84'/1'/0'/${chain}/${n}`);
      const pay = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network });
      if (Buffer.from(pay.output).equals(Buffer.from(script))) return child;
    }
  }
  return null;
}

function signWithMnemonic(psbtFile, netName, mnemonic, outFile) {
  const bip39 = require('bip39');
  const { BIP32Factory } = require('bip32');
  const network = bitcoin.networks.testnet;
  if (fs.existsSync(outFile)) throw new Error('Output file already exists: ' + outFile);
  const { psbt } = signReadOnly(psbtFile, netName);
  const root = BIP32Factory(ecc).fromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
  let signed = 0;
  psbt.data.inputs.forEach((inp, i) => {
    const txin = psbt.txInputs[i];
    const utxo = inp.witnessUtxo ||
      (inp.nonWitnessUtxo && bitcoin.Transaction.fromBuffer(inp.nonWitnessUtxo).outs[txin.index]);
    const key = findKey(root, utxo.script, network);
    if (!key) { console.log(`  #${i} not ours, skipped`); return; }
    psbt.signInput(i, key);
    if (!psbt.validateSignaturesOfInput(i, (pub, hash, sig) => ecc.verify(hash, pub, sig))) {
      throw new Error(`Input ${i}: signature check failed.`);
    }
    console.log(`  #${i} signed`);
    signed++;
  });
  if (signed === 0) throw new Error('No inputs belong to these shares. Nothing signed.');
  fs.writeFileSync(outFile, psbt.toBase64() + '\n');
  console.log(`Signed ${signed} input(s). Wrote ${outFile}`);
}

function showAddress(mnemonic) {
  const bip39 = require('bip39');
  const { BIP32Factory } = require('bip32');
  const network = bitcoin.networks.testnet;
  const root = BIP32Factory(ecc).fromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
  const child = root.derivePath("m/84'/1'/0'/0/0");
  const pay = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(child.publicKey), network });
  console.log("Receive address (m/84'/1'/0'/0/0, signet/testnet):");
  console.log(pay.address);
}
  module.exports = { signReadOnly, signWithMnemonic, showAddress };
