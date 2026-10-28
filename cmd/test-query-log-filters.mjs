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
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-query-log-filters-'));
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
  const cookie = String(login.headers.get('set-cookie') || '').split(';')[0];
  const headers = { cookie };

  const query = async (params = {}) => {
    const search = new URLSearchParams({ offset: '0', limit: '100', ...params });
    const response = await fetch(`${base}/recent?${search}`, { headers });
    assert.equal(response.status, 200);
    return response.json();
  };

  const all = await query();
  assert.equal(all.total, 11);
  assert.equal(all.unfilteredTotal, 11);

  const expectedStatuses = { processed: 2, allowed: 1, blocked: 3, rewritten: 2, error: 3 };
  for (const [status, count] of Object.entries(expectedStatuses)) {
    const result = await query({ status });
    assert.equal(result.total, count, `status=${status}`);
    assert.equal(result.filters.status, status);
  }

  const expectedReasons = { block: 2, 'block-service': 1, cache: 1, refused: 1, 'rate-limit': 1 };
  for (const [reason, count] of Object.entries(expectedReasons)) {
    const result = await query({ reason });
    assert.equal(result.total, count, `reason=${reason}`);
    assert.equal(result.filters.reason, reason);
  }

  const combined = await query({ status: 'blocked', reason: 'block-service' });
  assert.equal(combined.total, 1);
  assert.equal(combined.recent[0].qname, 'service.example');

  const incompatible = await query({ status: 'allowed', reason: 'block-service' });
  assert.equal(incompatible.total, 0);

  const legacy = await query({ response_status: 'block-service' });
  assert.equal(legacy.total, 1);
  assert.equal(legacy.filters.reason, 'block-service');
  assert.equal(legacy.filters.response_status, 'block-service');

  const searched = await query({ search: 'allowlisted' });
  assert.equal(searched.total, 1);
  assert.equal(searched.recent[0].qname, 'allowlisted.example');

  const cursorQuery = async (cursor = '') => {
    const search = new URLSearchParams({ cursor, limit: '4' });
    const response = await fetch(`${base}/recent?${search}`, { headers });
    assert.equal(response.status, 200);
    return response.json();
  };
  const cursorFirst = await cursorQuery();
  assert.equal(cursorFirst.totalExact, false);
  assert.equal(cursorFirst.recent.length, 4);
  assert.ok(cursorFirst.nextCursor);
  fs.appendFileSync(scenario.files.log, JSON.stringify(row(new Date(Date.now() + 1000).toISOString(), 'after-page.example', 'allow')) + '\n');
  const cursorSecond = await cursorQuery(cursorFirst.nextCursor);
  assert.equal(cursorSecond.recent.length, 4);
  assert.equal(cursorSecond.recent.some((item) => item.qname === 'after-page.example'), false);
  assert.equal(
    cursorSecond.recent.some((item) => cursorFirst.recent.some((first) => first.id === item.id)),
    false,
    'cursor pagination should not duplicate an earlier page after a new record arrives'
  );

  const disallowed = await postJson(`${base}/access/client`, cookie, { action: 'disallow', client: '127.0.0.1' });
  assert.deepEqual(disallowed.access.blockedClients, ['127.0.0.1']);
  assert.deepEqual(disallowed.settings.accessBlockedClients, ['127.0.0.1']);
  const repeated = await postJson(`${base}/access/client`, cookie, { action: 'disallow', client: '127.0.0.1' });
  assert.deepEqual(repeated.access.blockedClients, ['127.0.0.1']);

  const badClient = await fetch(`${base}/access/client`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ action: 'disallow', client: '127.0.0.0/24' })
  });
  assert.equal(badClient.status, 400);

  const allowed = await postJson(`${base}/access/client`, cookie, { action: 'allow', client: '127.0.0.1' });
  assert.deepEqual(allowed.access.blockedClients, []);

  console.log('query log filter tests passed');
} finally {
  await stopChild(server);
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-query-log-filters-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

async function postJson(url, cookie, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(body)
  });
  assert.equal(response.status, 200);
  return response.json();
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
  [files.block, files.allow, files.rewrite, files.subscriptions, files.allowSubscriptions].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.clients, '[]\n');
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const time = new Date().toISOString();
  const rows = [
    row(time, 'processed.example', 'allow'),
    row(time, 'allowlisted.example', 'allow', { rule: '@@||allowlisted.example^' }),
    row(time, 'cached.example', 'allow', { cached: true, source: 'cache' }),
    row(time, 'blocked.example', 'block', { rule: '||blocked.example^', source: 'filter' }),
    row(time, 'service.example', 'block-service', { rule: 'service:social', source: 'filter' }),
    row(time, 'cname.example', 'block-cname', { rule: '||target.example^', source: 'upstream' }),
    row(time, 'rewrite.example', 'rewrite', { rule: 'rewrite.example -> 192.0.2.1', source: 'rewrite' }),
    row(time, 'safe-search.example', 'safe-search', { rule: 'safe-search:google', source: 'safe-search' }),
    row(time, 'refused.example', 'refused', { rule: 'access:blocked', source: 'access' }),
    row(time, 'limited.example', 'rate-limit', { rule: 'dns:rate-limit:127.0.0.1', source: 'dns-settings' }),
    row(time, 'error.example', 'error', { rule: 'upstream timeout', source: 'error' })
  ];
  fs.writeFileSync(files.log, rows.map((item) => JSON.stringify(item)).join('\n') + '\n');

  const config = {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: ['1.1.1.1'],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 500,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, resolveClients: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: false, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
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
  return { server: child, httpPort, files };
}

function row(time, qname, action, extra = {}) {
  return {
    time,
    qname,
    qtype: 'A',
    client: '127.0.0.1',
    protocol: 'udp',
    action,
    rule: '',
    cached: false,
    ecs: '',
    source: 'upstream',
    elapsedMs: 2,
    responseCode: 0,
    responseStatus: 'NOERROR',
    ...extra
  };
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
  const salt = 'cleandns-query-log-filters';
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
