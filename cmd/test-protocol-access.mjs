import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempBase = path.resolve(os.tmpdir());
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-protocol-access-'));
let child, upstream, output = '', queries = 0;
const password = 'isolated-protocol-access-test';
let httpPort, corePort, plainPort, cookie;
const jsonHeaders = () => ({ cookie, 'content-type': 'application/json' });
const code = packet => Buffer.from(packet).readUInt16BE(2) & 15;
const policy = (mode, allowedClients = [], blockedClients = []) => ({ mode, allowedClients, blockedClients });
const baseUrl = () => `http://127.0.0.1:${httpPort}`;
async function getSettings() { return (await fetch(baseUrl() + '/api/settings', { headers: jsonHeaders() })).json(); }
async function update(body, expected = 200) {
  const r = await fetch(baseUrl() + '/api/settings', { method: 'POST', headers: jsonHeaders(), body: JSON.stringify(body) });
  const value = await r.json();
  assert.equal(r.status, expected, JSON.stringify(value));
  return value;
}

try {
  await fixture();
  await launch();
  if (process.env.CLEANDNS_PROTOCOL_ACCESS_UI_FIXTURE === '1') {
    console.log('FIXTURE_READY ' + JSON.stringify({ baseUrl: baseUrl(), password }));
    process.stdin.resume();
    await new Promise(resolve => process.stdin.once('end', resolve));
  } else {
    assert.deepEqual((await getSettings()).accessProtocols, Object.fromEntries(['plain', 'doh', 'doq'].map(name => [name, policy('inherit')])));
    await update({ accessBlockedClients: ['127.0.0.1'] });
    await assertTransport('plain UDP inherits global deny', udp(plainPort), 5);
    await assertTransport('plain TCP inherits global deny', tcp(), 5);
    await assertTransport('legacy core UDP inherits global deny', udp(corePort), 5);
    await assertTransport('DoH POST inherits global deny', doh(), 5);
    await assertTransport('DoH GET inherits global deny', doh(true), 5);
    await assertTransport('DoQ inherits global deny', doq('127.0.0.1'), 5);
    assert.equal(queries, 0, 'denied requests must not reach an upstream');

    await update({ accessProtocols: { doh: policy('custom', ['127.0.0.1']) } });
    await assertTransport('DoH custom permits its source', doh(), 0);
    const warmQueries = queries;
    await assertTransport('plain cannot reuse DoH warm cache past its ACL', udp(plainPort), 5);
    await assertTransport('DoQ remains inherited', doq('127.0.0.1'), 5);
    assert.equal(queries, warmQueries);
    await update({ accessProtocols: { doh: policy('custom', ['127.0.0.1/8'], ['127.0.0.1']) } });
    assert.deepEqual((await getSettings()).accessProtocols.doh.allowedClients, ['127.0.0.0/8']);
    await assertTransport('deny wins over matching DoH allow CIDR', doh(), 5);
    await assertTransport('GET cannot override the DoH policy through parameters or forwarding headers', doh(true, { 'x-forwarded-for': '203.0.113.10', 'x-dns-protocol': 'doq' }), 5);

    await update({ accessProtocols: { doq: policy('custom', ['203.0.113.0/24'], ['203.0.113.9']) } });
    await assertTransport('DoQ original IPv4 deny takes precedence', doq('203.0.113.9'), 5);
    await assertTransport('DoQ original IPv4 CIDR permits another peer', doq('203.0.113.10'), 0);
    await assertTransport('DoQ checks the original peer, not helper loopback', doq('192.0.2.1'), 5);
    assert.equal((await getSettings()).accessProtocols.doh.blockedClients[0], '127.0.0.1', 'a partial DoQ update must preserve DoH');
    await update({ accessProtocols: { doq: policy('custom', ['2001:db8::/32'], ['2001:db8::1']) } });
    await assertTransport('DoQ original IPv6 deny', doq('2001:db8::1'), 5);
    await assertTransport('DoQ original IPv6 CIDR allow', doq('2001:db8::2'), 0);

    await update({ accessProtocols: { plain: policy('custom', ['127.0.0.0/8']) } });
    await assertTransport('ordinary UDP custom', udp(plainPort), 0);
    await assertTransport('ordinary TCP uses the same custom group', tcp(), 0);
    await assertTransport('core ordinary DNS uses plain group', udp(corePort), 0);
    await assertTransport('plain custom cannot change DoH deny', doh(), 5);
    await update({ accessProtocols: { plain: { blockedClients: ['127.0.0.1'] }, doq: { mode: 'unrestricted' } } });
    const beforeSpoof = queries;
    const innerQuery = query(); innerQuery.writeUInt16BE(0x1234);
    const spoofResponse = await udp(plainPort, proxyPacket(innerQuery, '203.0.113.10'));
    assert.notEqual(spoofResponse.readUInt16BE(0), innerQuery.readUInt16BE(0), 'plain DNS must not unwrap a forged PROXY header');
    assert.equal(code(spoofResponse), 5, 'forged metadata must still use the plain source policy');
    assert.equal(queries, beforeSpoof, 'a public plain listener must not accept PROXY transport metadata');
    await update({ accessProtocols: { plain: { blockedClients: [] }, doq: policy('custom', ['2001:db8::/32'], ['2001:db8::1']) } });

    await update({ accessAllowedClients: ['192.0.2.1'], accessBlockedClients: ['127.0.0.1'], accessBlockedHosts: ['blocked.test'], accessProtocols: { doh: { mode: 'unrestricted' } } });
    await assertTransport('unrestricted DoH bypasses global source lists', doh(), 0);
    await assertTransport('unrestricted DoH still checks global blocked hostnames', doh(false, {}, 'sub.blocked.test'), 5);
    await assertTransport('unrestricted DoH still runs DNS filtering', doh(false, {}, 'filtered.test'), 3);
    assert.deepEqual((await getSettings()).accessProtocols.doh.blockedClients, ['127.0.0.1'], 'switching modes preserves dormant lists');
    const valid = (await getSettings()).accessProtocols;
    const originalOnDisk = fs.readFileSync(path.join(root, 'config.json'), 'utf8');
    for (const accessProtocols of [null, [], { dns: {} }, { doh: null }, { doh: { mode: 'open' } }, { doh: { allowedClients: ['not-an-ip'] } }, { doh: { allowedClients: ['127.0.0.1/'] } }, { doh: { allowedClients: ['127.0.0.1/8/9'] } }, { doh: { blockedClients: [42] } }, { doh: { allowedClients: null } }, { doh: { blockedHosts: [] } }]) {
      await update({ accessProtocols }, 400);
      assert.deepEqual((await getSettings()).accessProtocols, valid);
      assert.equal(fs.readFileSync(path.join(root, 'config.json'), 'utf8'), originalOnDisk, 'invalid settings must be atomic');
    }
    await update({ accessProtocols: { doh: { allowedClients: '# comment\n127.0.0.1\n127.0.0.1', mode: 'custom', blockedClients: [] } } });
    assert.deepEqual((await getSettings()).accessProtocols.doh.allowedClients, ['127.0.0.1']);
    const saved = (await getSettings()).accessProtocols;
    await update({ accessBlockedClients: ['192.0.2.2'] });
    assert.deepEqual((await getSettings()).accessProtocols, saved, 'legacy settings writes must preserve all protocol policies');
    await stop(); await launch();
    assert.deepEqual((await getSettings()).accessProtocols, saved, 'policies persist across restart');
    await assertTransport('DoQ after persisted restart', doq('2001:db8::2'), 0);
    await assertTransport('plain TCP after persisted restart', tcp(), 0);
    await assertTransport('DoH after persisted restart', doh(), 0);
    await update({ accessProtocols: { doh: { mode: 'inherit' } } });
    await assertTransport('switching back to inherit uses current global allow list', doh(), 5);
    const settings = await getSettings();
    assert.equal(settings.plainDnsEnabled, true);
    assert.equal(settings.doqEnabled, false, 'editing an ACL must not enable DoQ');
    console.log('protocol access tests passed: independent transports, IPv4/IPv6 CIDRs, deny priority, cache boundary, invalid/partial settings and persistence');
  }
} finally {
  await stop();
  if (upstream) await new Promise(resolve => upstream.close(resolve));
  const resolved = path.resolve(root);
  assert.ok(resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-protocol-access-'));
  fs.rmSync(resolved, { recursive: true, force: true });
}

async function assertTransport(message, response, expected) { assert.equal(code(await response), expected, message); }
function query(name = 'warm-cache.test') {
  const head = Buffer.alloc(12); head.writeUInt16BE(crypto.randomInt(65536)); head.writeUInt16BE(0x100, 2); head.writeUInt16BE(1, 4);
  return Buffer.concat([head, ...name.split('.').map(s => Buffer.concat([Buffer.from([s.length]), Buffer.from(s)])), Buffer.from([0, 0, 1, 0, 1])]);
}
function udp(port, packet = query()) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4'); let done = false;
    const timer = setTimeout(() => finish(new Error('UDP timeout')), 3000);
    function finish(err, value) { if (done) return; done = true; clearTimeout(timer); socket.close(); err ? reject(err) : resolve(value); }
    socket.once('error', finish); socket.once('message', value => finish(null, value)); socket.send(packet, port, '127.0.0.1', e => { if (e) finish(e); });
  });
}
function tcp() {
  return new Promise((resolve, reject) => {
    const socket = net.connect(plainPort, '127.0.0.1'), packet = query(), size = Buffer.alloc(2); size.writeUInt16BE(packet.length); let received = Buffer.alloc(0);
    socket.setTimeout(3000, () => socket.destroy(new Error('TCP timeout'))); socket.once('error', reject);
    socket.once('connect', () => socket.write(Buffer.concat([size, packet])));
    socket.on('data', value => { received = Buffer.concat([received, value]); if (received.length >= 2 && received.length >= received.readUInt16BE(0) + 2) { resolve(received.subarray(2, received.readUInt16BE(0) + 2)); socket.destroy(); } });
  });
}
async function doh(get = false, headers = {}, name) {
  const packet = query(name), url = baseUrl() + '/dns-query?protocol=plain' + (get ? '&dns=' + packet.toString('base64url') : '');
  const r = await fetch(url, { method: get ? 'GET' : 'POST', headers: { 'content-type': 'application/dns-message', ...headers }, ...(get ? {} : { body: packet }) });
  assert.equal(r.status, 200); return Buffer.from(await r.arrayBuffer());
}
function proxyPacket(packet, ip) {
  const v6 = ip.includes(':'), address = Buffer.alloc(v6 ? 36 : 12);
  if (v6) Buffer.from('20010db800000000000000000000000' + (ip.endsWith('::1') ? '1' : '2'), 'hex').copy(address);
  else Buffer.from(ip.split('.').map(Number)).copy(address);
  const tlv = Buffer.from([1, 0, 3, 100, 111, 113]), header = Buffer.alloc(16);
  Buffer.from('0d0a0d0a000d0a515549540a', 'hex').copy(header); header[12] = 0x21; header[13] = v6 ? 0x22 : 0x12; header.writeUInt16BE(address.length + tlv.length, 14);
  return Buffer.concat([header, address, tlv, packet]);
}
function doq(ip) { return udp(corePort, proxyPacket(query(), ip)); }
async function freePort(udp = false) {
  const socket = udp ? dgram.createSocket('udp4') : net.createServer();
  await new Promise((resolve, reject) => { socket.once('error', reject); udp ? socket.bind(0, '127.0.0.1', resolve) : socket.listen(0, '127.0.0.1', resolve); });
  const port = socket.address().port; await new Promise(resolve => socket.close(resolve)); return port;
}
async function fixture() {
  httpPort = await freePort(); corePort = await freePort(true); plainPort = await freePort();
  upstream = dgram.createSocket('udp4'); upstream.on('message', (packet, info) => { queries++; const response = Buffer.from(packet); response.writeUInt16BE(0x8180, 2); upstream.send(response, info.port, info.address); });
  await new Promise(resolve => upstream.bind(0, '127.0.0.1', resolve));
  const data = path.join(root, 'data'); fs.mkdirSync(data);
  const file = name => path.join(data, name);
  for (const name of ['block', 'allow', 'rewrite', 'subscriptions', 'allow-subscriptions', 'query.log']) fs.writeFileSync(file(name), name === 'block' ? 'filtered.test\n' : '');
  fs.writeFileSync(file('clients.json'), '[]'); fs.writeFileSync(file('stats.json'), '{}');
  fs.writeFileSync(file('password'), `scrypt$protocol-access$${crypto.scryptSync(password, 'protocol-access', 64).toString('base64url')}\n`);
  const config = {
    domain: 'localhost', http: { host: '127.0.0.1', port: httpPort }, udp: { host: '127.0.0.1', port: corePort },
    upstreams: [`udp://127.0.0.1:${upstream.address().port}`], fallbackUpstreams: [], bootstrapDns: [], timeoutMs: 500,
    dns: { refuseAny: true, privateReverseEnabled: false, resolveClients: false, rateLimit: 0 },
    cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 60, optimistic: false }, ecs: { enabled: false },
    filter: { enabled: true, blockMode: 'nxdomain', blockedServices: [], safeSearch: { enabled: false } },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] }, queryLog: { enabled: false }, statistics: { enabled: false },
    service: { dohPath: '/dns-query', dohEnabled: true, panelPath: '/admin/', plainDnsEnabled: true, plainDnsHost: '127.0.0.1', plainDnsPort: plainPort, doqEnabled: false, dohSyncCommand: '' },
    rules: { blockFile: file('block'), allowFile: file('allow'), rewriteFile: file('rewrite'), subscriptionFile: file('subscriptions'), allowSubscriptionFile: file('allow-subscriptions'), downloadDir: file('subscriptions.d'), allowDownloadDir: file('allow-subscriptions.d'), autoUpdateEnabled: false, autoUpdateOnStartup: false, autoUpdateOnChange: false },
    clients: { file: file('clients.json') }, admin: { username: 'test', passwordFile: file('password'), sessionTtlSeconds: 600, trustProxy: false }, logFile: file('query.log'), statsFile: file('stats.json')
  };
  fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify(config));
}
async function launch() {
  output = ''; child = spawn(process.execPath, ['server.js'], { cwd: appDir, env: { ...process.env, CLEANDNS_CONFIG: path.join(root, 'config.json'), CLEANDNS_AUTH_MODE: 'local' }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
  const until = Date.now() + 8000;
  while (!output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`)) { if (child.exitCode !== null || Date.now() > until) throw new Error('Fixture startup failed: ' + output); await new Promise(r => setTimeout(r, 25)); }
  const r = await fetch(baseUrl() + '/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'test', password }) });
  assert.equal(r.status, 200); cookie = r.headers.get('set-cookie').split(';')[0];
}
async function stop() {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM'); await Promise.race([new Promise(r => child.once('exit', r)), new Promise(r => setTimeout(r, 2000))]);
  if (child.exitCode === null) child.kill();
}
