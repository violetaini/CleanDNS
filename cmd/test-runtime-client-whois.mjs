import assert from 'node:assert/strict';
import net from 'node:net';
import {
  isPublicWhoisAddress,
  normalizeWhoisInfo,
  parseWhoisResponse,
  RuntimeWhoisResolver
} from '../runtime-client-whois.js';

assert.deepEqual(parseWhoisResponse(`
% registry comment
netname: FALLBACK-NET
OrgName: Example Network Incorporated
City: Mountain View
Country: US
ReferralServer: whois://whois.example.net:43
`), {
  orgname: 'Example Network Incorporated',
  city: 'Mountain View',
  country: 'US',
  whois: 'whois.example.net:43'
});
assert.deepEqual(normalizeWhoisInfo({ orgname: ' Example ', city: '', country: 'US', ignored: 'x' }), {
  orgname: 'Example',
  country: 'US'
});
assert.equal(isPublicWhoisAddress('8.8.8.8'), true);
assert.equal(isPublicWhoisAddress('2606:4700:4700::1111'), true);
for (const value of ['127.0.0.1', '10.0.0.1', '100.64.0.1', '169.254.1.1', '192.0.2.1', '198.51.100.1', '203.0.113.1', '::1', 'fc00::1', 'fe80::1', '2001:db8::1']) {
  assert.equal(isPublicWhoisAddress(value), false, value);
}

const registry = await startWhoisServer((query) => `
NetName: TEST-NETWORK
OrgName: CleanDNS Test Network
City: Shanghai
Country: CN
Query-Echo: ${query}
`);
const resolver = new RuntimeWhoisResolver({
  server: `127.0.0.1:${registry.port}`,
  allowPrivateServer: true,
  timeoutMs: 500,
  cacheTtlMs: 60_000,
  concurrency: 2
});

try {
  const first = await resolver.lookup('8.8.8.8');
  assert.equal(first.status, 'resolved');
  assert.deepEqual(first.info, { orgname: 'CleanDNS Test Network', city: 'Shanghai', country: 'CN' });
  assert.equal(first.cached, false);
  assert.equal(registry.queries[0], '8.8.8.8');

  const second = await resolver.lookup('8.8.8.8');
  assert.equal(second.status, 'resolved');
  assert.equal(second.cached, true);
  assert.equal(registry.queries.length, 1);

  const privateResult = await resolver.lookup('192.168.1.2');
  assert.equal(privateResult.status, 'not-applicable');
  assert.equal(privateResult.info, null);
  assert.equal(registry.queries.length, 1);

  const status = resolver.status();
  assert.equal(status.cacheEntries, 1);
  assert.equal(status.concurrency, 2);
} finally {
  resolver.close();
  await registry.close();
}

const referral = await startWhoisServer(() => 'OrgName: Referral Registry\nCountry: JP\n');
const root = await startWhoisServer(() => `ReferralServer: whois://127.0.0.1:${referral.port}\n`);
const redirectResolver = new RuntimeWhoisResolver({
  server: `127.0.0.1:${root.port}`,
  allowPrivateServer: true,
  timeoutMs: 500
});
try {
  const result = await redirectResolver.lookup('1.1.1.1');
  assert.equal(result.status, 'resolved');
  assert.deepEqual(result.info, { orgname: 'Referral Registry', country: 'JP' });
  assert.equal(root.queries.length, 1);
  assert.equal(referral.queries.length, 1);
} finally {
  redirectResolver.close();
  await root.close();
  await referral.close();
}

console.log('runtime client WHOIS tests passed');

async function startWhoisServer(response) {
  const queries = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (!data.includes('\n')) return;
      const query = data.trim();
      queries.push(query);
      socket.end(response(query));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    queries,
    close: () => new Promise((resolve) => {
      for (const socket of sockets) socket.destroy();
      server.close(resolve);
    })
  };
}
