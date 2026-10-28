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
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cleandns-profile-theme-'));

try {
  const httpPort = await unusedTcpPort();
  const udpPort = await unusedUdpPort();
  const configPath = createConfig(root, httpPort, udpPort);

  let server = await startServer(configPath, httpPort);
  try {
    const unauthorized = await request(httpPort, '/api/profile');
    assert.equal(unauthorized.status, 401);

    const login = await request(httpPort, '/api/login', {
      method: 'POST',
      body: { username: 'theme-test', password: 'test-password' }
    });
    assert.equal(login.status, 200);
    assert.deepEqual(login.data.profile, { name: 'theme-test', language: 'zh-CN', theme: 'auto' });
    const cookie = String(login.setCookie || '').split(';')[0];
    assert.match(cookie, /^cleandns_session=/);

    const session = await request(httpPort, '/api/session', { cookie });
    assert.equal(session.data.authenticated, true);
    assert.equal(session.data.profile.theme, 'auto');

    const saved = await request(httpPort, '/api/profile', { method: 'PUT', cookie, body: { theme: 'dark' } });
    assert.equal(saved.status, 200);
    assert.deepEqual(saved.data, { name: 'theme-test', language: 'zh-CN', theme: 'dark' });

    const invalid = await request(httpPort, '/api/profile', { method: 'PUT', cookie, body: { theme: 'sepia' } });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.data.error, 'bad_profile_theme');

    const persisted = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.deepEqual(persisted.admin.profile, { language: 'zh-CN', theme: 'dark' });
  } finally {
    await stopChild(server.child);
  }

  server = await startServer(configPath, httpPort);
  try {
    const login = await request(httpPort, '/api/login', {
      method: 'POST',
      body: { username: 'theme-test', password: 'test-password' }
    });
    assert.equal(login.data.profile.theme, 'dark');
  } finally {
    await stopChild(server.child);
  }

  console.log('profile theme tests passed');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

function createConfig(base, httpPort, udpPort) {
  const dataDir = path.join(base, 'data');
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(rulesDir, { recursive: true });
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
    upstreams: ['udp://127.0.0.1:9'],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 500,
    upstreamMode: 'sequential',
    dns: {},
    cache: { enabled: false, maxEntries: 100, minTtl: 1, maxTtl: 30, staleTtl: 0 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: false, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
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
    admin: { username: 'theme-test', passwordFile: files.password, sessionTtlSeconds: 600, trustProxy: false },
    logFile: files.log,
    statsFile: files.stats
  };
  const configPath = path.join(base, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  return configPath;
}

async function startServer(configPath, httpPort) {
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
  return { child, output: () => output };
}

async function request(port, pathname, options = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${pathname}`, {
    method: options.method || 'GET',
    headers: {
      ...(options.body ? { 'content-type': 'application/json' } : {}),
      ...(options.cookie ? { cookie: options.cookie } : {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const text = await response.text();
  return {
    status: response.status,
    data: text ? JSON.parse(text) : {},
    setCookie: response.headers.get('set-cookie') || ''
  };
}

function hashPassword(value) {
  const salt = 'cleandns-profile-theme';
  return `scrypt$${salt}$${crypto.scryptSync(value, salt, 64).toString('base64url')}`;
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
