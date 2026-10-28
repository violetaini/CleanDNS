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
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-refuse-any-'));
let server;
let upstream;

try {
  const scenario = await startScenario();
  server = scenario.server;
  upstream = scenario.upstream;
  const apiBase = `http://127.0.0.1:${scenario.httpPort}/api`;
  const anyQuery = buildQuery('refuse-any.test', 255, 0x6101);

  const udpRefused = await queryUdp(scenario.udpPort, anyQuery);
  assert.equal(responseCode(udpRefused), 5);
  assert.equal(scenario.upstreamQueries.length, 0);

  const dohResponse = await fetch(`http://127.0.0.1:${scenario.httpPort}/dns-query`, {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
    body: buildQuery('refuse-any-doh.test', 255, 0x6102)
  });
  assert.equal(dohResponse.status, 200);
  assert.match(String(dohResponse.headers.get('content-type') || ''), /^application\/dns-message/);
  assert.equal(responseCode(Buffer.from(await dohResponse.arrayBuffer())), 5);
  assert.equal(scenario.upstreamQueries.length, 0);

  const login = await fetch(`${apiBase}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(login.status, 200);
  const cookie = String(login.headers.get('set-cookie') || '').split(';')[0];
  const headers = { cookie, 'content-type': 'application/json' };

  const settings = await (await fetch(`${apiBase}/settings`, { headers })).json();
  assert.equal(settings.dnsRefuseAny, true);
  const recent = await (await fetch(`${apiBase}/recent?offset=0&limit=10`, { headers })).json();
  assert.equal(recent.recent.length, 2);
  assert.ok(recent.recent.every((item) => item.action === 'refused'));
  assert.ok(recent.recent.every((item) => item.rule === 'dns:refuse-any'));
  assert.ok(recent.recent.every((item) => item.source === 'dns-settings'));

  const disable = await fetch(`${apiBase}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ dnsRefuseAny: false })
  });
  assert.equal(disable.status, 200);
  assert.equal((await disable.json()).settings.dnsRefuseAny, false);

  const udpAllowed = await queryUdp(scenario.udpPort, buildQuery('allow-any.test', 255, 0x6103));
  assert.equal(responseCode(udpAllowed), 0);
  assert.equal(scenario.upstreamQueries.length, 1);
  assert.equal(scenario.upstreamQueries[0].qtype, 255);

  const enable = await fetch(`${apiBase}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ dnsRefuseAny: true })
  });
  assert.equal(enable.status, 200);
  assert.equal((await enable.json()).settings.dnsRefuseAny, true);

  const testRefused = await fetch(`${apiBase}/test`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'api-any.test', type: 'ANY', clientIp: '192.0.2.25' })
  });
  assert.equal(testRefused.status, 200);
  assert.equal((await testRefused.json()).status, 'REFUSED');
  assert.equal(scenario.upstreamQueries.length, 1);

  const normalA = await queryUdp(scenario.udpPort, buildQuery('normal-a.test', 1, 0x6104));
  assert.equal(responseCode(normalA), 0);
  assert.equal(scenario.upstreamQueries.length, 2);
  assert.equal(scenario.upstreamQueries[1].qtype, 1);

  console.log('refuse ANY tests passed');
} finally {
  await stopChild(server);
  if (upstream) await new Promise((resolve) => upstream.close(resolve));
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-refuse-any-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

async function startScenario() {
  const dataDir = path.join(root, 'data');
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(path.join(rulesDir, 'subscriptions.d'), { recursive: true });
  fs.mkdirSync(path.join(rulesDir, 'allow-subscriptions.d'), { recursive: true });

  const upstreamSocket = dgram.createSocket('udp4');
  const upstreamQueries = [];
  upstreamSocket.on('message', (packet, info) => {
    const question = parseDnsQuestion(packet);
    if (question) upstreamQueries.push(question);
    const response = buildNoErrorResponse(packet, question);
    if (response) upstreamSocket.send(response, info.port, info.address);
  });
  await bindUdp(upstreamSocket, 0);

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
  [files.block, files.allow, files.rewrite, files.subscriptions, files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.clients, '[]\n');
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const config = {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [`udp://127.0.0.1:${upstreamSocket.address().port}`],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 1000,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, refuseAny: true, resolveClients: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: true, retentionHours: 24, ignoredEnabled: false, ignored: [] },
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
    logFile: files.log,
    statsFile: files.stats
  };
  const configPath = path.join(root, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  const child = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: { ...process.env, CLEANDNS_CONFIG: configPath },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 8000, () => output);
  return { server: child, upstream: upstreamSocket, upstreamQueries, httpPort, udpPort };
}

function buildQuery(name, type, id) {
  const labels = name.split('.').map((label) => {
    const value = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([value.length]), value]);
  });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const suffix = Buffer.alloc(5);
  suffix.writeUInt16BE(type, 1);
  suffix.writeUInt16BE(1, 3);
  return Buffer.concat([header, ...labels, suffix]);
}

function parseDnsQuestion(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 17) return null;
  const labels = [];
  let offset = 12;
  while (offset < packet.length && packet[offset]) {
    const length = packet[offset];
    offset += 1;
    if (offset + length > packet.length) return null;
    labels.push(packet.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }
  const questionEnd = offset + 5;
  if (questionEnd > packet.length) return null;
  return { qname: labels.join('.'), qtype: packet.readUInt16BE(offset + 1), questionEnd };
}

function buildNoErrorResponse(packet, question) {
  if (!question) return null;
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, packet.subarray(12, question.questionEnd)]);
}

function responseCode(packet) {
  return Buffer.isBuffer(packet) && packet.length >= 4 ? packet.readUInt16BE(2) & 0x0f : -1;
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
  const salt = 'cleandns-refuse-any';
  return `scrypt$${salt}$${crypto.scryptSync(value, salt, 64).toString('base64url')}`;
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
