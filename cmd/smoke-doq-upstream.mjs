import assert from 'node:assert/strict';
import net from 'node:net';
import { closeUpstreamTransports, queryDnsUpstream } from '../upstream.js';

const endpoint = String(process.env.CLEANDNS_DOQ_TEST_UPSTREAM || '').trim();
const name = String(process.env.CLEANDNS_DOQ_TEST_NAME || 'example.com').trim().toLowerCase();
const connectAddress = String(process.env.CLEANDNS_DOQ_TEST_ADDRESS || '').trim();
if (!endpoint) throw new Error('CLEANDNS_DOQ_TEST_UPSTREAM is required');
if (connectAddress && !net.isIP(connectAddress)) throw new Error('CLEANDNS_DOQ_TEST_ADDRESS must be an IP address');

const query = buildQuery(name, 0xc1ea);
try {
  const options = connectAddress ? { lookup: fixedLookup(connectAddress) } : {};
  const response = await queryDnsUpstream(endpoint, query, 10_000, options);
  assert.equal(response.readUInt16BE(0), query.readUInt16BE(0), 'DNS message ID was not restored');
  assert.ok((response[2] & 0x80) !== 0, 'DNS response QR bit is missing');
  const rcode = response[3] & 0x0f;
  assert.ok(rcode === 0 || rcode === 3, `unexpected DNS response code ${rcode}`);
  console.log(JSON.stringify({ ok: true, endpoint, name, bytes: response.length, rcode }));
} finally {
  closeUpstreamTransports();
}

function fixedLookup(address) {
  const family = net.isIP(address);
  return (_hostname, options, callback) => {
    if (options?.all === true) return callback(null, [{ address, family }]);
    callback(null, address, family);
  };
}

function buildQuery(domain, id) {
  const labels = domain.replace(/\.$/, '').split('.');
  if (!labels.length || labels.some((label) => !label || label.length > 63 || !/^[a-z0-9-]+$/.test(label))) {
    throw new Error('invalid test domain');
  }
  const qname = Buffer.concat(labels.map((label) => {
    const value = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([value.length]), value]);
  }));
  const header = Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
  return Buffer.concat([header, qname, Buffer.from([0, 0, 1, 0, 1])]);
}
