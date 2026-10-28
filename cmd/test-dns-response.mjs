import assert from 'node:assert/strict';
import { decodeDnsResponse, rcodeName } from '../dns-response.js';

const question = Buffer.concat([encodeName('example.com'), u16(1), u16(1)]);
const aResponse = responsePacket(0x81a0, 1, [answerRecord(1, 60, Buffer.from([203, 0, 113, 42]))]);
const decodedA = decodeDnsResponse(aResponse);
assert.equal(decodedA.status, 'NOERROR');
assert.equal(decodedA.question, 'example.com');
assert.equal(decodedA.answerCount, 1);
assert.deepEqual(decodedA.answers[0], { name: 'example.com', type: 'A', ttl: 60, value: '203.0.113.42' });
assert.equal(decodedA.flags.recursionAvailable, true);
assert.equal(decodedA.flags.authenticatedData, true);

const cnameResponse = responsePacket(0x8180, 1, [answerRecord(5, 120, encodeName('target.example'))]);
assert.equal(decodeDnsResponse(cnameResponse).answers[0].value, 'target.example');

const txt = Buffer.from('clean dns', 'utf8');
const txtResponse = responsePacket(0x8180, 1, [answerRecord(16, 30, Buffer.concat([Buffer.from([txt.length]), txt]))]);
assert.equal(decodeDnsResponse(txtResponse).answers[0].value, 'clean dns');

const manyAnswers = Array.from({ length: 20 }, (_, index) => answerRecord(1, index + 1, Buffer.from([192, 0, 2, index])));
const limited = decodeDnsResponse(responsePacket(0x8180, manyAnswers.length, manyAnswers), { maxAnswers: 16 });
assert.equal(limited.answerCount, 20);
assert.equal(limited.answers.length, 16);
assert.equal(limited.answersTruncated, true);

const nxdomain = responsePacket(0x8183, 0, []);
assert.equal(decodeDnsResponse(nxdomain).status, 'NXDOMAIN');
assert.equal(rcodeName(5), 'REFUSED');
assert.equal(rcodeName(15), 'RCODE_15');

console.log('dns response tests passed');

function responsePacket(flags, answerCount, answers) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answerCount, 6);
  return Buffer.concat([header, question, ...answers]);
}

function answerRecord(type, ttl, data) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0xc00c, 0);
  header.writeUInt16BE(type, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt32BE(ttl, 6);
  header.writeUInt16BE(data.length, 10);
  return Buffer.concat([header, data]);
}

function encodeName(name) {
  return Buffer.concat(name.split('.').flatMap((label) => [Buffer.from([label.length]), Buffer.from(label, 'ascii')]).concat(Buffer.from([0])));
}

function u16(value) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
}
