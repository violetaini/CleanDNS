import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import {
  normalizeUpstreamAddress,
  parseUpstreamAddress,
  queryDnsUpstream,
  upstreamProtocol
} from '../upstream.js';

const query = buildQuery('example.com');
const expectedAddress = '203.0.113.10';
const udp = dgram.createSocket('udp4');
const truncatedUdp = dgram.createSocket('udp4');
const tcp = net.createServer((socket) => {
  let received = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    received = Buffer.concat([received, chunk]);
    if (received.length < 2) return;
    const length = received.readUInt16BE(0);
    if (received.length < length + 2) return;
    const response = buildAnswer(received.subarray(2, length + 2));
    const frame = Buffer.alloc(response.length + 2);
    frame.writeUInt16BE(response.length, 0);
    response.copy(frame, 2);
    socket.end(frame);
  });
});

udp.on('message', (packet, info) => {
  udp.send(buildAnswer(packet), info.port, info.address);
});
truncatedUdp.on('message', (packet, info) => {
  truncatedUdp.send(buildTruncatedAnswer(packet), info.port, info.address);
});

try {
  await bindUdp(udp);
  await listenTcp(tcp);
  const udpPort = udp.address().port;
  const tcpPort = tcp.address().port;
  await bindUdp(truncatedUdp, tcpPort);

  assert.equal(normalizeUpstreamAddress('8.8.8.8'), '8.8.8.8');
  assert.equal(normalizeUpstreamAddress('[2001:4860:4860::8888]'), '2001:4860:4860::8888');
  assert.equal(normalizeUpstreamAddress('1.1.1.1:5353'), 'udp://1.1.1.1:5353');
  assert.equal(normalizeUpstreamAddress('dot://dns.google'), 'tls://dns.google');
  assert.equal(normalizeUpstreamAddress('doh://dns.google/dns-query'), 'https://dns.google/dns-query');
  assert.equal(normalizeUpstreamAddress('doq://dns.example.com'), 'quic://dns.example.com');
  assert.equal(upstreamProtocol('tcp://1.1.1.1'), 'tcp');
  assert.deepEqual(parseUpstreamAddress('tls://one.one.one.one'), {
    value: 'tls://one.one.one.one',
    protocol: 'tls',
    host: 'one.one.one.one',
    port: 853,
    url: ''
  });
  assert.deepEqual(parseUpstreamAddress('quic://dns.example.com'), {
    value: 'quic://dns.example.com',
    protocol: 'quic',
    host: 'dns.example.com',
    port: 853,
    url: ''
  });
  assert.throws(() => normalizeUpstreamAddress('sdns://invalid'), /unsupported_upstream_protocol/);
  assert.throws(() => normalizeUpstreamAddress('https://dns.google/'), /bad_doh_path/);

  const udpResponse = await queryDnsUpstream(`udp://127.0.0.1:${udpPort}`, query, 1000);
  assert.equal(firstIpv4Answer(udpResponse), expectedAddress);

  const lookup = (hostname, options, callback) => {
    assert.equal(hostname, 'resolver.example');
    if (options?.all) return callback(null, [{ address: '127.0.0.1', family: 4 }]);
    callback(null, '127.0.0.1', 4);
  };
  const bootstrapUdpResponse = await queryDnsUpstream(`udp://resolver.example:${udpPort}`, query, 1000, { lookup });
  assert.equal(firstIpv4Answer(bootstrapUdpResponse), expectedAddress);

  const tcpResponse = await queryDnsUpstream(`tcp://127.0.0.1:${tcpPort}`, query, 1000);
  assert.equal(firstIpv4Answer(tcpResponse), expectedAddress);

  const bootstrapTcpResponse = await queryDnsUpstream(`tcp://resolver.example:${tcpPort}`, query, 1000, { lookup });
  assert.equal(firstIpv4Answer(bootstrapTcpResponse), expectedAddress);

  let doqRequest = null;
  const doqResponse = await queryDnsUpstream('quic://resolver.example:8853', query, 1000, {
    lookup,
    queryDoq: async (request) => {
      doqRequest = request;
      return buildAnswer(request.packet);
    }
  });
  assert.equal(firstIpv4Answer(doqResponse), expectedAddress);
  assert.equal(doqRequest.address, '127.0.0.1:8853');
  assert.equal(doqRequest.serverName, 'resolver.example');
  assert.ok(doqRequest.timeoutMs > 0 && doqRequest.timeoutMs <= 1000);
  assert.deepEqual(doqRequest.packet, query);

  let systemLookupDoqRequest = null;
  const systemLookupDoqResponse = await queryDnsUpstream('quic://localhost:8853', query, 1000, {
    queryDoq: async (request) => {
      systemLookupDoqRequest = request;
      return buildAnswer(request.packet);
    }
  });
  assert.equal(firstIpv4Answer(systemLookupDoqResponse), expectedAddress);
  assert.match(systemLookupDoqRequest.address, /^(127\.0\.0\.1|\[::1\]):8853$/);
  assert.equal(systemLookupDoqRequest.serverName, 'localhost');

  const fallbackResponse = await queryDnsUpstream(`udp://127.0.0.1:${tcpPort}`, query, 1000);
  assert.equal(firstIpv4Answer(fallbackResponse), expectedAddress);

  const originalFetch = globalThis.fetch;
  let dohRequest = null;
  globalThis.fetch = async (url, options) => {
    dohRequest = { url: String(url), method: options.method, accept: options.headers.accept };
    return new Response(buildAnswer(Buffer.from(options.body)), {
      status: 200,
      headers: { 'content-type': 'application/dns-message' }
    });
  };
  try {
    const dohResponse = await queryDnsUpstream('https://dns.example.com/dns-query', query, 1000);
    assert.equal(firstIpv4Answer(dohResponse), expectedAddress);
    assert.deepEqual(dohRequest, {
      url: 'https://dns.example.com/dns-query',
      method: 'POST',
      accept: 'application/dns-message'
    });
  } finally {
    globalThis.fetch = originalFetch;
  }

  console.log('upstream transport tests passed');
} finally {
  udp.close();
  truncatedUdp.close();
  await new Promise((resolve) => tcp.close(resolve));
}

function bindUdp(socket, port = 0) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, '127.0.0.1', resolve);
  });
}

function listenTcp(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function buildQuery(name) {
  const labels = name.split('.').flatMap((label) => [label.length, ...Buffer.from(label, 'ascii')]);
  return Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1]);
}

function buildAnswer(packet) {
  let questionEnd = 12;
  while (questionEnd < packet.length && packet[questionEnd] !== 0) questionEnd += packet[questionEnd] + 1;
  questionEnd += 5;
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 10]);
  return Buffer.concat([header, packet.subarray(12, questionEnd), answer]);
}

function buildTruncatedAnswer(packet) {
  let questionEnd = 12;
  while (questionEnd < packet.length && packet[questionEnd] !== 0) questionEnd += packet[questionEnd] + 1;
  questionEnd += 5;
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8380, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, packet.subarray(12, questionEnd)]);
}

function firstIpv4Answer(packet) {
  if (packet.readUInt16BE(6) < 1) return '';
  return [...packet.subarray(-4)].join('.');
}
