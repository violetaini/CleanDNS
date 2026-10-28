import assert from 'node:assert/strict';
import {
  buildSafeSearchCnameResponse,
  matchSafeSearch,
  normalizeSafeSearchConfig,
  safeSearchRuleCount
} from '../safe-search.js';

const defaults = normalizeSafeSearchConfig({});
assert.deepEqual(defaults, {
  enabled: false,
  bing: true,
  duckduckgo: true,
  ecosia: true,
  google: true,
  pixabay: true,
  yandex: true,
  youtube: true
});
assert.equal(safeSearchRuleCount(), 258);
assert.equal(matchSafeSearch('www.google.com', 1, defaults), null);

const enabled = normalizeSafeSearchConfig({ enabled: true });
assert.deepEqual(matchSafeSearch('WWW.GOOGLE.COM.', 1, enabled), {
  service: 'google',
  kind: 'cname',
  value: 'forcesafesearch.google.com',
  rule: 'safe-search:google'
});
assert.equal(matchSafeSearch('www.google.example.com', 1, enabled), null);
assert.equal(matchSafeSearch('www.google.com', 15, enabled), null);
assert.equal(matchSafeSearch('www.youtube.com', 28, enabled)?.value, 'restrictmoderate.youtube.com');
assert.equal(matchSafeSearch('www.yandex.com', 1, enabled)?.kind, 'ip');
assert.equal(matchSafeSearch('www.yandex.com', 28, enabled)?.kind, 'nodata');
assert.equal(matchSafeSearch('www.bing.com', 1, normalizeSafeSearchConfig({ enabled: true, bing: false })), null);

const original = buildQuery('www.google.com', 1, 0x1234);
const targetQuery = buildQuery('forcesafesearch.google.com', 1, 0x5678);
const targetAnswer = Buffer.concat([
  Buffer.from(targetQuery.subarray(0, 2)),
  Buffer.from([0x81, 0xa0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
  targetQuery.subarray(12),
  Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 216, 239, 38, 120])
]);
const parsed = parseQuestion(original);
const response = buildSafeSearchCnameResponse(original, parsed, 'forcesafesearch.google.com', targetAnswer);

assert.equal(response.readUInt16BE(0), 0x1234);
assert.equal(response.readUInt16BE(4), 1);
assert.equal(response.readUInt16BE(6), 2);
assert.equal(response.readUInt16BE(2) & 0x0020, 0, 'AD must be cleared after rewriting');
assert.equal(parseQuestion(response).name, 'www.google.com');

let offset = parsed.questionEnd;
const cnameOwner = readName(response, offset);
assert.equal(cnameOwner.name, 'www.google.com');
offset = cnameOwner.offset;
assert.equal(response.readUInt16BE(offset), 5);
const cnameLength = response.readUInt16BE(offset + 8);
const cname = readName(response, offset + 10);
assert.equal(cname.name, 'forcesafesearch.google.com');
offset += 10 + cnameLength;

const addressOwner = readName(response, offset);
assert.equal(addressOwner.name, 'forcesafesearch.google.com');
offset = addressOwner.offset;
assert.equal(response.readUInt16BE(offset), 1);
assert.deepEqual([...response.subarray(offset + 10, offset + 14)], [216, 239, 38, 120]);

console.log('safe-search tests passed');

function buildQuery(name, qtype, id) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, encodeName(name), u16(qtype), u16(1)]);
}

function parseQuestion(packet) {
  const question = readName(packet, 12);
  return {
    id: packet.readUInt16BE(0),
    name: question.name,
    qtype: packet.readUInt16BE(question.offset),
    questionEnd: question.offset + 4
  };
}

function encodeName(name) {
  return Buffer.concat([
    ...name.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')])),
    Buffer.from([0])
  ]);
}

function readName(packet, offset, depth = 0) {
  assert.ok(depth <= 16);
  const labels = [];
  let cursor = offset;
  while (cursor < packet.length) {
    const length = packet[cursor];
    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | packet[cursor + 1];
      labels.push(...readName(packet, pointer, depth + 1).name.split('.').filter(Boolean));
      return { name: labels.join('.'), offset: cursor + 2 };
    }
    if (length === 0) return { name: labels.join('.'), offset: cursor + 1 };
    cursor += 1;
    labels.push(packet.subarray(cursor, cursor + length).toString('ascii'));
    cursor += length;
  }
  throw new Error('invalid dns name');
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
}
