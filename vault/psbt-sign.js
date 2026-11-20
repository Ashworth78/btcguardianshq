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
  return { inTotal, outTotal, fee };
}

module.exports = { signReadOnly };
