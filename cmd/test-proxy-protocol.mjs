import assert from 'node:assert/strict';
import { parseProxyV2 } from '../proxy-protocol.js';

const signature = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);

function proxyPacket(familyProtocol, addresses, dns = Buffer.from([0, 0, 1, 0])) {
  const tlv = Buffer.from([0x01, 0x00, 0x03, 0x64, 0x6f, 0x71]);
  const header = Buffer.alloc(16 + addresses.length + tlv.length);
  signature.copy(header, 0);
  header[12] = 0x21;
  header[13] = familyProtocol;
  header.writeUInt16BE(addresses.length + tlv.length, 14);
  addresses.copy(header, 16);
  tlv.copy(header, 16 + addresses.length);
  return Buffer.concat([header, dns]);
}

const ipv4Addresses = Buffer.alloc(12);
Buffer.from([203, 0, 113, 9]).copy(ipv4Addresses, 0);
Buffer.from([192, 0, 2, 9]).copy(ipv4Addresses, 4);
ipv4Addresses.writeUInt16BE(53000, 8);
ipv4Addresses.writeUInt16BE(5642, 10);
const ipv4 = proxyPacket(0x12, ipv4Addresses);
assert.deepEqual(parseProxyV2(ipv4), {
  srcIp: '203.0.113.9',
  offset: 34,
  alpn: 'doq',
  protocol: 'doq'
});

const ipv6Addresses = Buffer.alloc(36);
Buffer.from('20010db8000000000000000000000009', 'hex').copy(ipv6Addresses, 0);
Buffer.from('20010db8000000000000000000000010', 'hex').copy(ipv6Addresses, 16);
ipv6Addresses.writeUInt16BE(53001, 32);
ipv6Addresses.writeUInt16BE(5642, 34);
const ipv6 = parseProxyV2(proxyPacket(0x22, ipv6Addresses));
assert.equal(ipv6.srcIp, '2001:db8:0:0:0:0:0:9');
assert.equal(ipv6.alpn, 'doq');
assert.equal(ipv6.protocol, 'doq');
assert.equal(ipv6.offset, 58);

const malformed = Buffer.from(ipv4);
malformed.writeUInt16BE(0xffff, 14);
assert.equal(parseProxyV2(malformed), null);
assert.equal(parseProxyV2(Buffer.from('not proxy protocol')), null);

console.log('proxy protocol tests passed');
