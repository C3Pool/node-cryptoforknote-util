"use strict";
let u = require('../build/Release/cryptoforknote');

const b = Buffer.from(
'0202fdaca8b906b1670506d0dc45b11cbc87f9ceedfd0cbfa56c14da72ccc27c45105391d2340300000000020001ffbabe0501a1ca9fab2a035c20fce0617f61abf3872058e15b90650b2ac812bf344766f56ee54b680f571e0353414c3c863401618163d383093580900f735ea9ad5d3d0029dd94c2f2a35db88ec37dc32e863302110000bcdd9d15420000000000000000000001c8f2e7ca0a00020001ffbabe05002301bb1086494863ac8de0987e09f7193ac85a356f8abf8725202cbf4dea8b2611f20400020000'
, 'hex');
const b2 = u.convert_blob(b, 15);
const h1 = b2.toString('hex');

if (h1 === '0202fdaca8b906b1670506d0dc45b11cbc87f9ceedfd0cbfa56c14da72ccc27c45105391d2340300000000604ec6923c81b6477bb224a9c53158cea5c5aee36100aad59c498d3dab92750402') {
  console.log('PASSED');
} else {
  console.log('FAILED: ' + h1);
  process.exit(1);
}