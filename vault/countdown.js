#!/usr/bin/env node
'use strict';
// countdown.js - heir countdown for older(N). Public data only: no keys, no shares, no RPC.
const fs = require('fs');
const args = process.argv.slice(2);
if (args[0] === '--help' || args.length !== 2) {
console.log('Usage: node countdown.js <N blocks> <listunspent.json>');
console.log('N = the older() value in the heir path (52560 = about 1 year).');
process.exit(args[0] === '--help' ? 0 : 1);
}
const N = Number(args[0]);
if (!Number.isInteger(N) || N < 1 || N > 65535) {
console.error('N must be a whole number from 1 to 65535.');
process.exit(1);
}
let coins;
try {
coins = JSON.parse(fs.readFileSync(args[1], 'utf8'));
} catch (e) {
console.error('Could not read JSON file: ' + e.message);
process.exit(1);
}
if (!Array.isArray(coins)) {
console.error('Expected the array that listunspent gives.');
process.exit(1);
}
console.log('Heir countdown: older(' + N + ') = about ' + (N / 144).toFixed(1) + ' days');
console.log('');
let openCount = 0;
for (const c of coins) {
const conf = Number(c.confirmations);
const id = String(c.txid || '?').slice(0, 12) + '...:' + c.vout;
if (!Number.isInteger(conf) || conf < 0) {
console.log(id + '  skipped (bad confirmations value)');
continue;
}
const left = Math.max(0, N - conf);
const amt = c.amount !== undefined ? c.amount + ' BTC' : '? BTC';
if (left === 0) {
openCount++;
console.log(id + '  ' + amt + '  OPEN - heir path usable now');
} else if (conf === 0) {
console.log(id + '  ' + amt + '  unconfirmed - timer not started');
} else {
console.log(id + '  ' + amt + '  ' + left + ' blocks left (about ' + (left / 144).toFixed(1) + ' days)');
}
}
console.log('');
console.log(openCount + ' of ' + coins.length + ' coins open to the heir path.');
console.log('Spending a coin with your main keys resets its timer.');
