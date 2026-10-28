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
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-dashboard-period-'));
let server;

try {
  const scenario = await startScenario();
  server = scenario.server;
  const base = `http://127.0.0.1:${scenario.httpPort}/api`;
  const login = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(login.status, 200);
  const headers = { cookie: String(login.headers.get('set-cookie') || '').split(';')[0] };

  const status = async (period = '') => {
    const suffix = period === '' ? '' : `?period=${encodeURIComponent(period)}`;
    const response = await fetch(`${base}/status${suffix}`, { headers });
    assert.equal(response.status, 200);
    return response.json();
  };

  const full = await status();
  assert.equal(full.statistics.retentionHours, 168);
  assert.equal(full.statistics.periodHours, 168);
  assert.deepEqual(full.statistics.periodOptions, [24, 168]);
  assert.equal(full.stats.total, 108);
  assert.equal(full.dashboard.topQueriedDomains[0].name, 'old.example');
  assert.equal(full.dashboard.upstreams[0].responses, 108);

  const oneHour = await status(1);
  assert.equal(oneHour.statistics.periodHours, 1);
  assert.equal(oneHour.stats.total, 3);
  assert.equal(oneHour.stats.avgProcessingMs, 4);
  assert.deepEqual(oneHour.dashboard.topQueriedDomains, [{ name: 'current.example', count: 3 }]);
  assert.equal(oneHour.dashboard.upstreams[0].responses, 3);
  assert.equal(oneHour.dashboard.upstreams[0].avgMs, 4);
  assert.equal(oneHour.statistics.series.dnsQueries.length, 1);

  const day = await status(24);
  assert.equal(day.statistics.periodHours, 24);
  assert.equal(day.stats.total, 8);
  assert.equal(day.stats.blockedFiltering, 2);
  assert.equal(day.stats.avgProcessingMs, 7.75);
  assert.deepEqual(day.dashboard.topQueriedDomains, [
    { name: 'recent.example', count: 5 },
    { name: 'current.example', count: 3 }
  ]);
  assert.equal(day.dashboard.upstreams[0].responses, 8);
  assert.equal(day.dashboard.upstreams[0].avgMs, 8);
  assert.equal(day.statistics.series.dnsQueries.reduce((sum, value) => sum + value, 0), 8);

  const clamped = await status(999);
  assert.equal(clamped.statistics.periodHours, 168);
  assert.equal(clamped.stats.total, 108);

  console.log('dashboard period tests passed');
} finally {
  await stopChild(server);
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-dashboard-period-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

async function startScenario() {
  const dataDir = path.join(root, 'data');
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(path.join(rulesDir, 'subscriptions.d'), { recursive: true });
  fs.mkdirSync(path.join(rulesDir, 'allow-subscriptions.d'), { recursive: true });
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
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const currentHour = Math.floor(Date.now() / 3_600_000) * 3_600_000;
  const upstream = 'udp://1.1.1.1:53';
  const snapshot = (total, blocked, processingTimeMs, domain, client, upstreamResponses) => ({
    total,
    allowed: total - blocked,
    blocked,
    blockedFiltering: blocked,
    processingTimeMs,
    processingCount: total,
    rankingCount: total,
    byDomain: { [domain]: total },
    byBlockedDomain: blocked ? { [domain]: blocked } : {},
    byClient: { [client]: total },
    upstreams: { [upstream]: { responses: upstreamResponses, errors: 0, totalMs: processingTimeMs } }
  });
  fs.writeFileSync(files.stats, JSON.stringify({
    version: 2,
    buckets: [
      { start: currentHour - 30 * 3_600_000, stats: snapshot(100, 20, 1000, 'old.example', 'old-client', 100) },
      { start: currentHour - 2 * 3_600_000, stats: snapshot(5, 2, 50, 'recent.example', 'recent-client', 5) },
      { start: currentHour, stats: snapshot(3, 0, 12, 'current.example', 'current-client', 3) }
    ]
  }, null, 2) + '\n');

  const config = {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [upstream],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 500,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, resolveClients: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: false, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 168, anonymizeClientIp: false },
    statistics: { enabled: true, retentionHours: 168, ignoredEnabled: false, ignored: [] },
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
  return { server: child, httpPort };
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
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

function hashPassword(value) {
  const salt = 'cleandns-dashboard-period';
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
