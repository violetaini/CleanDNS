import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { compileDnsRewrites, parseDnsRewriteLine, resolveDnsRewrite } from '../dns-rewrite.js';
import { decodeDnsResponse } from '../dns-response.js';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = path.resolve(os.tmpdir());
const tempDir = fs.mkdtempSync(path.join(tempRoot, 'cleandns-rewrite-'));

try {
  testCompiler();
  await testRuntime();
  console.log('dns rewrite tests passed');
} finally {
  const resolved = path.resolve(tempDir);
  if (resolved.startsWith(tempRoot + path.sep) && path.basename(resolved).startsWith('cleandns-rewrite-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

function testCompiler() {
  assert.equal(parseDnsRewriteLine('bad.example A not-an-ip'), null);
  assert.equal(parseDnsRewriteLine('alias.example CNAME target.example')?.value, 'target.example');
  assert.equal(parseDnsRewriteLine('# disabled alias.example CNAME target.example')?.enabled, false);

  const compiled = compileDnsRewrites([
    'multi.example A 192.0.2.10',
    'multi.example A 192.0.2.11',
    'multi.example AAAA 2001:db8::10',
    'alias.example CNAME target.example',
    '*.wild.example A 198.51.100.20',
    'exact.wild.example A 198.51.100.21',
    'keep.example A A',
    '# disabled disabled.example A 192.0.2.99'
  ]);

  assert.equal(compiled.entries.length, 7);
  assert.deepEqual(resolveDnsRewrite(compiled, 'multi.example', 1).values, ['192.0.2.10', '192.0.2.11']);
  assert.deepEqual(resolveDnsRewrite(compiled, 'multi.example', 28).values, ['2001:db8::10']);
  assert.equal(resolveDnsRewrite(compiled, 'multi.example', 16).kind, 'nodata');
  assert.deepEqual(resolveDnsRewrite(compiled, 'alias.example', 1), {
    matched: true,
    kind: 'cname',
    entries: [compiled.entries[3]],
    value: 'target.example',
    qtype: 5
  });
  assert.deepEqual(resolveDnsRewrite(compiled, 'child.wild.example', 1).values, ['198.51.100.20']);
  assert.deepEqual(resolveDnsRewrite(compiled, 'exact.wild.example', 1).values, ['198.51.100.21']);
  assert.equal(resolveDnsRewrite(compiled, 'keep.example', 1).kind, 'passthrough');
  assert.equal(resolveDnsRewrite(compiled, 'keep.example', 28).kind, 'nodata');
  assert.equal(resolveDnsRewrite(compiled, 'disabled.example', 1).matched, false);

  const loop = compileDnsRewrites([
    'one.loop.example CNAME two.loop.example',
    'two.loop.example CNAME one.loop.example'
  ]);
  assert.equal(resolveDnsRewrite(loop, 'one.loop.example', 1).loop, true);
  assert.equal(resolveDnsRewrite(loop, 'one.loop.example', 1).kind, 'nodata');

  const wildcardTarget = compileDnsRewrites(['*.self.example CNAME target.self.example']);
  assert.equal(resolveDnsRewrite(wildcardTarget, 'child.self.example', 1).kind, 'cname');
}

async function testRuntime() {
  const dataDir = path.join(tempDir, 'data');
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(path.join(rulesDir, 'subscriptions.d'), { recursive: true });
  fs.mkdirSync(path.join(rulesDir, 'allow-subscriptions.d'), { recursive: true });

  const upstream = dgram.createSocket('udp4');
  const observed = [];
  upstream.on('message', (packet, info) => {
    observed.push(parseQuestion(packet));
    upstream.send(buildUpstreamResponse(packet), info.port, info.address);
  });
  await bindUdp(upstream, 0);

  const httpPort = await unusedTcpPort();
  const udpPort = await unusedUdpPort();
  const files = {
    block: path.join(rulesDir, 'blocklist.txt'),
    allow: path.join(rulesDir, 'allowlist.txt'),
    rewrite: path.join(rulesDir, 'rewrites.txt'),
    subscriptions: path.join(rulesDir, 'subscriptions.txt'),
    allowSubscriptions: path.join(rulesDir, 'allow-subscriptions.txt'),
    clients: path.join(dataDir, 'clients.json'),
    password: path.join(dataDir, 'admin-password'),
    log: path.join(dataDir, 'query.log'),
    stats: path.join(dataDir, 'stats.json')
  };
  [files.block, files.allow, files.subscriptions, files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.rewrite, [
    'multi.example A 192.0.2.10',
    'multi.example A 192.0.2.11',
    'multi.example AAAA 2001:db8::10',
    'alias.example CNAME target.example',
    '*.wild.example A 198.51.100.20',
    'exact.wild.example A 198.51.100.21',
    'keep.example A A'
  ].join('\n') + '\n');
  fs.writeFileSync(files.clients, '[]\n');
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const config = buildConfig({ dataDir, rulesDir, files, httpPort, udpPort, upstreamPort: upstream.address().port });
  const configPath = path.join(tempDir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  const server = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: { ...process.env, CLEANDNS_CONFIG: configPath },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  server.stdout.on('data', (chunk) => { output += chunk; });
  server.stderr.on('data', (chunk) => { output += chunk; });

  try {
    await waitFor(() => output.includes(`cleandns udp listening on 127.0.0.1:${udpPort}`), 8000, () => output);

    const cookie = await addRewriteThroughApi(httpPort, 'api-alias.example CNAME api-target.example');

    const multi = decodeDnsResponse(await queryUdp(udpPort, buildQuery('multi.example', 1, 0x1101)));
    assert.equal(multi.answerCount, 2);
    assert.deepEqual(multi.answers.map((answer) => answer.value), ['192.0.2.10', '192.0.2.11']);

    const ipv6 = decodeDnsResponse(await queryUdp(udpPort, buildQuery('multi.example', 28, 0x1102)));
    assert.equal(ipv6.answers[0].value, '2001:db8:0:0:0:0:0:10');

    const cname = decodeDnsResponse(await queryDoh(httpPort, buildQuery('alias.example', 1, 0x1103)));
    assert.deepEqual(cname.answers[0], { name: 'alias.example', type: 'CNAME', ttl: 120, value: 'target.example' });
    const apiCname = decodeDnsResponse(await queryDoh(httpPort, buildQuery('api-alias.example', 1, 0x1109)));
    assert.equal(apiCname.answers[0].value, 'api-target.example');

    const wildcard = decodeDnsResponse(await queryUdp(udpPort, buildQuery('child.wild.example', 1, 0x1104)));
    assert.equal(wildcard.answers[0].value, '198.51.100.20');
    const exact = decodeDnsResponse(await queryUdp(udpPort, buildQuery('exact.wild.example', 1, 0x1105)));
    assert.equal(exact.answers[0].value, '198.51.100.21');

    const noData = decodeDnsResponse(await queryUdp(udpPort, buildQuery('multi.example', 16, 0x1106)));
    assert.equal(noData.status, 'NOERROR');
    assert.equal(noData.answerCount, 0);

    const keep = decodeDnsResponse(await queryUdp(udpPort, buildQuery('keep.example', 1, 0x1107)));
    assert.equal(keep.answers[0].value, '203.0.113.53');
    const keepOther = decodeDnsResponse(await queryUdp(udpPort, buildQuery('keep.example', 28, 0x1108)));
    assert.equal(keepOther.answerCount, 0);

    const initialSettings = await getJson(httpPort, '/api/settings', cookie);
    assert.equal(initialSettings.rewritesEnabled, true);

    const disabled = await setRewritesEnabled(httpPort, cookie, false);
    assert.equal(disabled.settings.rewritesEnabled, false);
    const disabledRewrite = decodeDnsResponse(await queryUdp(udpPort, buildQuery('alias.example', 1, 0x1110)));
    assert.deepEqual(disabledRewrite.answers.map((answer) => answer.value), ['203.0.113.53']);
    assert.equal((await checkRewrite(httpPort, cookie, 'alias.example')).status, 'not_filtered');

    const enabled = await setRewritesEnabled(httpPort, cookie, true);
    assert.equal(enabled.settings.rewritesEnabled, true);
    const enabledRewrite = decodeDnsResponse(await queryUdp(udpPort, buildQuery('alias.example', 1, 0x1111)));
    assert.equal(enabledRewrite.answers[0].value, 'target.example');
    assert.equal((await checkRewrite(httpPort, cookie, 'alias.example')).status, 'rewritten');

    assert.deepEqual(observed.map(({ name, type }) => ({ name, type })), [
      { name: 'keep.example', type: 1 },
      { name: 'alias.example', type: 1 }
    ]);
  } finally {
    await stopChild(server);
    await new Promise((resolve) => upstream.close(resolve));
  }
}

async function addRewriteThroughApi(port, line) {
  const login = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(login.status, 200);
  const cookie = String(login.headers.get('set-cookie') || '').split(';')[0];
  assert.match(cookie, /^cleandns_session=/);

  const currentResponse = await fetch(`http://127.0.0.1:${port}/api/rules`, { headers: { cookie } });
  assert.equal(currentResponse.status, 200);
  const current = await currentResponse.json();
  const rewrite = String(current.rewrite || '').trimEnd() + '\n' + line + '\n';
  const update = await fetch(`http://127.0.0.1:${port}/api/rules`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ rewrite })
  });
  assert.equal(update.status, 200);
  const updated = await update.json();
  assert.equal(updated.status.rules.rewrite, 8);
  return cookie;
}

async function getJson(port, pathname, cookie) {
  const response = await fetch(`http://127.0.0.1:${port}${pathname}`, { headers: { cookie } });
  assert.equal(response.status, 200);
  return response.json();
}

async function setRewritesEnabled(port, cookie, enabled) {
  const response = await fetch(`http://127.0.0.1:${port}/api/settings`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ rewritesEnabled: enabled })
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function checkRewrite(port, cookie, name) {
  const response = await fetch(`http://127.0.0.1:${port}/api/filter/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name, type: 'A', clientIp: '127.0.0.1' })
  });
  assert.equal(response.status, 200);
  return response.json();
}

function buildConfig({ dataDir, rulesDir, files, httpPort, udpPort, upstreamPort }) {
  return {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [`udp://127.0.0.1:${upstreamPort}`],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 1000,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 300, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: true, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: false, retentionHours: 24, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: { dohPath: '/dns-query', dohEnabled: true, panelPath: '/admin/', plainDnsEnabled: false, doqEnabled: false, doqPort: 8853, dohSyncCommand: '', doqSyncCommand: '' },
    rules: {
      blockFile: files.block,
      allowFile: files.allow,
      rewriteFile: files.rewrite,
      subscriptionFile: files.subscriptions,
      downloadDir: path.join(rulesDir, 'subscriptions.d'),
      allowSubscriptionFile: files.allowSubscriptions,
      allowDownloadDir: path.join(rulesDir, 'allow-subscriptions.d'),
      autoUpdateEnabled: false,
      autoUpdateOnStartup: false,
      autoUpdateOnChange: false
    },
    clients: { file: files.clients },
    admin: { username: 'test', passwordFile: files.password, sessionTtlSeconds: 600, trustProxy: false },
    dhcp: { runtimeSupported: false },
    logFile: files.log,
    statsFile: files.stats
  };
}

function buildQuery(name, type, id) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, encodeName(name), u16(type), u16(1)]);
}

function buildUpstreamResponse(query) {
  const question = parseQuestion(query);
  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(question.type === 1 ? 1 : 0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  const answer = question.type === 1
    ? Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 53])
    : Buffer.alloc(0);
  return Buffer.concat([header, query.subarray(12, question.questionEnd), answer]);
}

function parseQuestion(packet) {
  const name = readName(packet, 12);
  return { name: name.name, type: packet.readUInt16BE(name.offset), questionEnd: name.offset + 4 };
}

function readName(packet, offset) {
  const labels = [];
  let cursor = offset;
  while (cursor < packet.length) {
    const length = packet[cursor];
    if (length === 0) return { name: labels.join('.'), offset: cursor + 1 };
    cursor += 1;
    labels.push(packet.subarray(cursor, cursor + length).toString('ascii'));
    cursor += length;
  }
  throw new Error('invalid dns name');
}

function encodeName(name) {
  return Buffer.concat([
    ...name.split('.').map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')])),
    Buffer.from([0])
  ]);
}

function queryUdp(port, packet) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => finish(new Error('dns query timeout')), 3000);
    const finish = (error, response) => {
      clearTimeout(timer);
      socket.close();
      if (error) reject(error); else resolve(response);
    };
    socket.once('error', finish);
    socket.once('message', (response) => finish(null, response));
    socket.send(packet, port, '127.0.0.1', (error) => { if (error) finish(error); });
  });
}

async function queryDoh(port, packet) {
  const response = await fetch(`http://127.0.0.1:${port}/dns-query`, {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
    body: packet
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'application/dns-message');
  return Buffer.from(await response.arrayBuffer());
}

async function unusedTcpPort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

async function unusedUdpPort() {
  const socket = dgram.createSocket('udp4');
  await bindUdp(socket, 0);
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

function bindUdp(socket, port) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, '127.0.0.1', resolve);
  });
}

function hashPassword(value) {
  const salt = 'cleandns-rewrite';
  return `scrypt$${salt}$${crypto.scryptSync(value, salt, 64).toString('base64url')}`;
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
}

async function waitFor(check, timeoutMs, output = () => '') {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`wait timeout\n${output()}`);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2000))
  ]);
  if (child.exitCode === null) child.kill();
}
