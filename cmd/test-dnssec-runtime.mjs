import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dnssecRequestState, enableDnssecRequest } from '../dnssec.js';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cleandns-dnssec-runtime-'));

try {
  await runForcedDnssecScenario();
  await runClientDnssecAndCacheScenario();
  console.log('dnssec runtime tests passed');
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

async function runForcedDnssecScenario() {
  const scenario = await startScenario('forced', true);
  try {
    const response = await queryUdp(scenario.udpPort, buildQuery('forced.example', 1, 0x1101));
    await waitFor(() => scenario.observed.length === 1, 3000);
    assert.deepEqual(scenario.observed[0], { ad: true, do: true });
    assert.equal(Boolean(response.readUInt16BE(2) & 0x0020), true);
  } finally {
    await scenario.close();
  }
}

async function runClientDnssecAndCacheScenario() {
  const scenario = await startScenario('client', false);
  try {
    const plain = buildQuery('cache-profile.example', 1, 0x2201);
    const clientDnssec = Buffer.from(enableDnssecRequest(buildQuery('cache-profile.example', 1, 0x2202)));
    clientDnssec.writeUInt16BE(clientDnssec.readUInt16BE(2) & ~0x0020, 2);

    await queryUdp(scenario.udpPort, plain);
    await queryUdp(scenario.udpPort, clientDnssec);
    await waitFor(() => scenario.observed.length === 2, 3000);
    assert.deepEqual(scenario.observed, [
      { ad: false, do: false },
      { ad: true, do: true }
    ]);

    await queryUdp(scenario.udpPort, Buffer.from(plain));
    await queryUdp(scenario.udpPort, Buffer.from(clientDnssec));
    await new Promise((resolve) => setTimeout(resolve, 120));
    assert.equal(scenario.observed.length, 2, 'plain and DNSSEC cache profiles must remain isolated and reusable');
  } finally {
    await scenario.close();
  }
}

async function startScenario(name, dnssecEnabled) {
  const root = path.join(tempRoot, name);
  const dataDir = path.join(root, 'data');
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(path.join(rulesDir, 'subscriptions.d'), { recursive: true });
  fs.mkdirSync(path.join(rulesDir, 'allow-subscriptions.d'), { recursive: true });

  const upstream = dgram.createSocket('udp4');
  const observed = [];
  upstream.on('message', (packet, info) => {
    observed.push(dnssecRequestState(packet));
    const response = Buffer.from(packet);
    response.writeUInt16BE(0x81a0, 2);
    upstream.send(response, info.port, info.address);
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
  [files.block, files.allow, files.rewrite, files.subscriptions, files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.clients, '[]\n');
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const config = {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [`udp://127.0.0.1:${upstream.address().port}`],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 1000,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled, disableIpv6: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 30, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: false, retentionHours: 24, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: { dohPath: '/dns-query', dohEnabled: false, panelPath: '/admin/', plainDnsEnabled: false, doqEnabled: false, doqPort: 8853, dohSyncCommand: '', doqSyncCommand: '' },
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

  const server = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: { ...process.env, CLEANDNS_CONFIG: configPath },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  server.stdout.on('data', (chunk) => { output += chunk; });
  server.stderr.on('data', (chunk) => { output += chunk; });
  await waitFor(() => output.includes(`cleandns udp listening on 127.0.0.1:${udpPort}`), 8000, () => output);

  return {
    udpPort,
    observed,
    close: async () => {
      await stopChild(server);
      await new Promise((resolve) => upstream.close(resolve));
    }
  };
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
  const salt = 'cleandns-dnssec-runtime';
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
