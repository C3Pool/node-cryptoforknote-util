"use strict";
let u = require('../build/Release/cryptoforknote');

const b = Buffer.from(
'0909bcb7ecb406e417dd02e55e8c3f6368749df3e761b000f87001e28ccb9c24f1d65f2cc848d70000000003e5f93701ffa9f9370181a0f693710231510ef639f6848581cc3df0ab1783f73fd401d4ab03df62dfad68f8557bad943401f3cc08c30d31a225b46514edfccc4b3c0d429cac30b23e1e4fd9e1c514f5b350021100000000000000000000000000000000000000'
, 'hex');
const b2 = u.convert_blob(b, 4);
const h1 = b2.toString('hex');

if (h1 === '0909bcb7ecb406e417dd02e55e8c3f6368749df3e761b000f87001e28ccb9c24f1d65f2cc848d7000000008c95c259fa076f11347c4129bf1020da140d44f3948410c0f3a77d1b4d18a21f01') {
  console.log('PASSED');
} else {
  console.log('FAILED: ' + h1);
  process.exit(1);
}
