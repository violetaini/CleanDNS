import assert from 'node:assert/strict';
import { dnssecCacheProfile, dnssecRequestState, enableDnssecRequest } from '../dnssec.js';

const plain = buildQuery('example.com', 1);
assert.deepEqual(dnssecRequestState(plain), { ad: false, do: false });
assert.equal(dnssecCacheProfile(plain), 'plain');

const enabled = enableDnssecRequest(plain);
assert.notEqual(enabled, plain);
assert.equal(enabled.length, plain.length + 11);
assert.equal(enabled.readUInt16BE(10), 1);
assert.deepEqual(dnssecRequestState(enabled), { ad: true, do: true });
assert.equal(dnssecCacheProfile(enabled), 'dnssec');
assert.equal(dnssecCacheProfile(plain, true), 'dnssec');
assert.equal(enableDnssecRequest(enabled), enabled);

const customOption = Buffer.from([0, 12, 0, 2, 0xaa, 0xbb]);
const withOpt = buildQuery('example.com', 28, buildOpt(customOption));
const withOptEnabled = enableDnssecRequest(withOpt);
assert.equal(withOptEnabled.length, withOpt.length);
assert.equal(withOptEnabled.readUInt16BE(10), 1);
assert.deepEqual(withOptEnabled.subarray(-customOption.length), customOption);
assert.deepEqual(dnssecRequestState(withOptEnabled), { ad: true, do: true });

const doOnly = Buffer.from(withOptEnabled);
doOnly.writeUInt16BE(doOnly.readUInt16BE(2) & ~0x0020, 2);
assert.deepEqual(dnssecRequestState(doOnly), { ad: false, do: true });
const doOnlyEnabled = enableDnssecRequest(doOnly);
assert.equal(doOnlyEnabled.length, doOnly.length);
assert.deepEqual(dnssecRequestState(doOnlyEnabled), { ad: true, do: true });

const malformed = Buffer.from(plain);
malformed.writeUInt16BE(1, 10);
assert.equal(enableDnssecRequest(malformed), malformed);
assert.deepEqual(dnssecRequestState(malformed), { ad: false, do: false });

console.log('dnssec tests passed');

function buildQuery(name, type, additional = null) {
  const labels = name.split('.');
  const questionName = Buffer.concat(labels.map((label) => {
    const bytes = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  }).concat(Buffer.from([0])));
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(additional ? 1 : 0, 10);
  const question = Buffer.alloc(4);
  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(1, 2);
  return Buffer.concat([header, questionName, question, additional || Buffer.alloc(0)]);
}

function buildOpt(options) {
  const record = Buffer.alloc(11);
  record.writeUInt16BE(41, 1);
  record.writeUInt16BE(1232, 3);
  record.writeUInt16BE(options.length, 9);
  return Buffer.concat([record, options]);
}
