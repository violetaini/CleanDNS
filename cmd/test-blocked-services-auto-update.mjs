import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempBase = path.resolve(os.tmpdir());
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-blocked-services-update-'));
let service;
let catalogSource;

try {
  const scenario = await startScenario();
  service = scenario.service;
  catalogSource = scenario.catalogSource;
  const apiBase = `http://127.0.0.1:${scenario.httpPort}/api`;
  const login = await fetch(`${apiBase}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(login.status, 200);
  const cookie = String(login.headers.get('set-cookie') || '').split(';')[0];
  const headers = { cookie };

  const before = await getJson(`${apiBase}/blocked-services`, headers);
  assert.deepEqual(before.enabled, ['kept-service']);
  assert.deepEqual(before.catalog.map((item) => item.id), ['kept-service']);
  assert.equal(before.autoUpdate.enabled, false);

  const updated = await postJson(`${apiBase}/blocked-services/update`, headers, {});
  assert.equal(updated.ok, true);
  assert.deepEqual(updated.blockedServices.enabled, ['kept-service']);
  assert.deepEqual(updated.blockedServices.catalog.map((item) => item.id), ['kept-service', 'new-service']);
  assert.equal(updated.autoUpdate.lastError, '');
  assert.equal(updated.autoUpdate.lastSummary.enabledRetained, 1);
  assert.ok(updated.autoUpdate.lastSummary.servicesAfter >= 2);
  assert.equal(JSON.parse(fs.readFileSync(scenario.catalogFile, 'utf8')).services.length, 2);

  const automatic = await postJson(`${apiBase}/blocked-services/auto-update`, headers, {
    enabled: true,
    intervalHours: 168
  });
  assert.equal(automatic.autoUpdate.enabled, true);
  assert.equal(automatic.autoUpdate.intervalHours, 168);
  assert.ok(automatic.autoUpdate.nextRunAt);

  console.log('blocked services auto update tests passed');
} finally {
  await stopChild(service);
  await closeServer(catalogSource);
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-blocked-services-update-')) {
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
  const catalogFile = path.join(dataDir, 'blocked-services.json');
  fs.writeFileSync(catalogFile, JSON.stringify({
    source: 'fixture',
    sourceProject: 'Fixture catalog',
    generatedAt: '2026-08-20T00:00:00.000Z',
    groups: [{ id: 'social_network', name: 'Social Network' }],
    services: [serviceEntry('kept-service', 'Kept service', 'kept.example')]
  }, null, 2) + '\n');
  const catalogSource = await startCatalogSource();
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
    filter: { enabled: true, blockedServices: ['kept-service'], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: false, retentionHours: 24, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: { dohPath: '/dns-query', dohEnabled: false, panelPath: '/admin/', plainDnsEnabled: false, doqEnabled: false, doqPort: 8853, dohSyncCommand: '' },
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
      autoUpdateOnChange: false,
      blockedServicesAutoUpdateEnabled: false,
      blockedServicesAutoUpdateOnStartup: false,
      blockedServicesAutoUpdateIntervalHours: 168
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
    env: {
      ...process.env,
      CLEANDNS_CONFIG: configPath,
      CLEANDNS_BLOCKED_SERVICES_CATALOG_FILE: catalogFile,
      BLOCKED_SERVICES_SOURCE: catalogSource.url
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 8_000, () => output);
  return { service: child, catalogSource, catalogFile, httpPort };
}

function serviceEntry(id, name, domain) {
  return {
    id,
    name,
    group: 'social_network',
    groupName: 'Social Network',
    domains: [domain],
    rules: [`||${domain}^`]
  };
}

async function startCatalogSource() {
  const body = JSON.stringify({
    services: [
      serviceEntry('kept-service', 'Kept service', 'kept.example'),
      serviceEntry('new-service', 'New service', 'new.example')
    ]
  });
  const server = http.createServer((request, response) => {
    if (request.url !== '/services.json') {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(body);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}/services.json` };
}

async function getJson(url, headers) {
  const response = await fetch(url, { headers });
  assert.equal(response.status, 200);
  return response.json();
}

async function postJson(url, headers, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
  assert.equal(response.status, 200);
  return response.json();
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
  const salt = 'cleandns-blocked-services-update';
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

async function closeServer(source) {
  if (!source?.server) return;
  await new Promise((resolve) => source.server.close(resolve));
}
