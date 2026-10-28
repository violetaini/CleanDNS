import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = path.resolve(os.tmpdir());
const tempDir = fs.mkdtempSync(path.join(tempRoot, 'cleandns-audit-stage-'));
const dataDir = path.join(tempDir, 'data');
const username = 'audit-user';
const password = 'audit-pass';
let server;
let auditUpstream;

try {
  fs.mkdirSync(dataDir, { recursive: true });
  const catalogFile = path.join(dataDir, 'blocked-services.json');
  fs.copyFileSync(path.join(appDir, 'data', 'blocked-services.json'), catalogFile);
  const httpPort = await unusedTcpPort();
  const udpPort = await unusedUdpPort();
  auditUpstream = await startAuditDnsServer();
  const tls = createAuditTlsFixture(tempDir);
  const config = buildConfig(httpPort, udpPort, auditUpstream.port, tls);
  const configPath = path.join(tempDir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  fs.writeFileSync(config.admin.passwordFile, hashPassword(password) + '\n');
  fs.writeFileSync(config.clients.file, JSON.stringify([
    {
      id: 'audit-home-network',
      name: '家庭网络',
      identifiers: ['192.0.2.44', '192.0.2.0/24'],
      note: '家庭出口',
      tags: ['家庭', '国内出口'],
      useGlobalSettings: true,
      useGlobalBlockedServices: true,
      upstreams: []
    },
    {
      id: 'audit-custom-device',
      name: '测试设备',
      identifiers: ['198.51.100.20'],
      note: '自定义 DNS 策略',
      tags: ['测试'],
      useGlobalSettings: false,
      filteringEnabled: true,
      safeBrowsingEnabled: true,
      safeSearch: { enabled: true, google: true, youtube: true },
      useGlobalBlockedServices: false,
      blockedServices: ['youtube', 'tiktok'],
      disableEcs: true,
      upstreams: [`udp://127.0.0.1:${auditUpstream.port}`],
      upstreamsCacheEnabled: true,
      upstreamsCacheSize: 1048576
    }
  ], null, 2) + '\n');
  fs.writeFileSync(config.rules.blockFile, [
    '192.0.2.60 hosts-check.audit hosts-alias.audit # audit hosts rule',
    '203.0.113.54'
  ].join('\n') + '\n');
  fs.writeFileSync(config.rules.allowFile, '');
  fs.writeFileSync(config.rules.rewriteFile, [
    'ipv4.rewrite.test A 192.0.2.10',
    'ipv6.rewrite.test AAAA 2001:db8::10',
    'alias.rewrite.test CNAME target.rewrite.test',
    '*.wild.rewrite.test A 198.51.100.20'
  ].join('\n') + '\n');
  fs.writeFileSync(config.rules.subscriptionFile, '');
  fs.writeFileSync(config.rules.allowSubscriptionFile, '');
  fs.writeFileSync(config.logFile, '');
  fs.writeFileSync(config.statsFile, '{}\n');
  const runtimeHostsFile = path.join(dataDir, 'hosts');
  const runtimeArpFile = path.join(dataDir, 'arp');
  fs.writeFileSync(runtimeHostsFile, '127.0.0.1 audit-node.local audit-node\n');
  fs.writeFileSync(runtimeArpFile, 'IP address       HW type     Flags       HW address            Mask     Device\n192.168.50.21    0x1         0x2         aa:bb:cc:dd:ee:21     *        eth0\n');

  server = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: {
      ...process.env,
      CLEANDNS_CONFIG: configPath,
      CLEANDNS_BLOCKED_SERVICES_CATALOG_FILE: catalogFile,
      CLEANDNS_RUNTIME_CLIENT_HOSTS_FILE: runtimeHostsFile,
      CLEANDNS_RUNTIME_CLIENT_ARP_FILE: runtimeArpFile,
      CLEANDNS_RUNTIME_CLIENT_SOURCE_REFRESH_MS: '1000'
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let serverOutput = '';
  server.stdout.on('data', (chunk) => { serverOutput += chunk; });
  server.stderr.on('data', (chunk) => { serverOutput += chunk; });
  await waitFor(
    () => serverOutput.includes(`cleandns http listening on 127.0.0.1:${httpPort}`),
    10_000,
    () => serverOutput
  );
  await queryAuditDns(udpPort, buildAuditDnsQuery('runtime-client.audit', 0x5201));
  await queryAuditDns(udpPort, buildAuditDnsQuery('runtime-client.audit', 0x5202));
  await queryAuditDns(udpPort, buildAuditDnsQuery('response-filter.audit', 0x5203));

  const audit = spawn(process.execPath, ['cmd/audit-panel.mjs'], {
    cwd: appDir,
    env: {
      ...process.env,
      CLEANDNS_AUDIT_URL: `http://127.0.0.1:${httpPort}/admin/`,
      CLEANDNS_AUDIT_USERNAME: username,
      CLEANDNS_AUDIT_PASSWORD: password,
      CLEANDNS_AUDIT_DIRECT_API: '1',
      CLEANDNS_AUDIT_ALLOW_INSECURE_COOKIE: '1',
      CLEANDNS_AUDIT_THEME_WRITE: '1',
      CLEANDNS_AUDIT_RESPONSE_FILTER: '1',
      CLEANDNS_AUDIT_OUTPUT: process.env.CLEANDNS_AUDIT_OUTPUT || 'audit-screens-local'
    },
    stdio: 'inherit',
    windowsHide: true
  });
  const exitCode = await new Promise((resolve) => audit.once('exit', resolve));
  if (exitCode !== 0) throw new Error(`panel audit exited with code ${exitCode}`);
} finally {
  await stopChild(server);
  await auditUpstream?.close();
  const resolvedTemp = path.resolve(tempDir);
  if (resolvedTemp.startsWith(tempRoot + path.sep) && path.basename(resolvedTemp).startsWith('cleandns-audit-stage-')) {
    fs.rmSync(resolvedTemp, { recursive: true, force: true });
  }
}

function buildConfig(httpPort, udpPort, upstreamPort, tls) {
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(path.join(rulesDir, 'subscriptions.d'), { recursive: true });
  fs.mkdirSync(path.join(rulesDir, 'allow-subscriptions.d'), { recursive: true });
  return {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [
      '# Audit domain routing',
      `udp://127.0.0.1:${upstreamPort}`,
      `[/example.com/]udp://127.0.0.1:${upstreamPort}`,
      `[/*.example.com/]udp://127.0.0.1:${upstreamPort}`,
      '[/www.example.com/]#',
      `[//]udp://127.0.0.1:${upstreamPort}`
    ],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 500,
    upstreamMode: 'sequential',
    dns: { disableIpv6: false, refuseAny: true, resolveClients: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: {
      enabled: true,
      maxEntries: 100,
      minTtl: 1,
      maxTtl: 60,
      staleTtl: 0,
      optimistic: false,
      optimisticAnswerTtl: 30,
      optimisticMaxAge: 43200
    },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: true, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: true },
    statistics: { enabled: true, retentionHours: 168, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: {
      dohPath: '/dns-query',
      dohEnabled: true,
      panelPath: '/admin/',
      dohPublicBaseUrl: 'https://localhost',
      panelPublicUrl: `http://127.0.0.1:${httpPort}/admin/`,
      plainDnsEnabled: false,
      doqEnabled: false,
      doqEndpoint: 'localhost',
      doqPort: 8853,
      doqTlsCertFile: tls.certFile,
      doqTlsKeyFile: tls.keyFile,
      dohSyncCommand: '',
      doqSyncCommand: ''
    },
    rules: {
      blockFile: path.join(rulesDir, 'blocklist.txt'),
      allowFile: path.join(rulesDir, 'allowlist.txt'),
      rewriteFile: path.join(rulesDir, 'rewrites.txt'),
      subscriptionFile: path.join(rulesDir, 'subscriptions.txt'),
      downloadDir: path.join(rulesDir, 'subscriptions.d'),
      allowSubscriptionFile: path.join(rulesDir, 'allow-subscriptions.txt'),
      allowDownloadDir: path.join(rulesDir, 'allow-subscriptions.d'),
      autoUpdateEnabled: false,
      autoUpdateOnStartup: false,
      autoUpdateOnChange: false,
      blockedServicesAutoUpdateEnabled: false,
      blockedServicesAutoUpdateOnStartup: false,
      blockedServicesAutoUpdateIntervalHours: 168
    },
    clients: { file: path.join(dataDir, 'clients.json') },
    admin: {
      username,
      passwordFile: path.join(dataDir, 'admin-password'),
      sessionTtlSeconds: 600,
      trustProxy: false
    },
    logFile: path.join(dataDir, 'query.log'),
    statsFile: path.join(dataDir, 'stats.json')
  };
}

function createAuditTlsFixture(root) {
  const certFile = path.join(root, 'fullchain.pem');
  const keyFile = path.join(root, 'privkey.pem');
  const openssl = findOpenSsl();
  const result = spawnSync(openssl, [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '90',
    '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', keyFile,
    '-out', certFile
  ], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, MSYS2_ARG_CONV_EXCL: '*' }
  });
  if (result.status !== 0) throw new Error(`openssl failed: ${result.stderr || result.stdout}`);
  return { certFile, keyFile };
}

function findOpenSsl() {
  const candidates = process.platform === 'win32'
    ? [process.env.OPENSSL_BIN, 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe', 'openssl.exe']
    : [process.env.OPENSSL_BIN, '/usr/bin/openssl', '/usr/local/bin/openssl', 'openssl'];
  for (const candidate of candidates.filter(Boolean)) {
    const result = spawnSync(candidate, ['version'], { encoding: 'utf8', windowsHide: true });
    if (!result.error && result.status === 0) return candidate;
  }
  throw new Error('openssl is required for local panel audit');
}

function hashPassword(value) {
  const salt = 'cleandns-audit-stage';
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

async function startAuditDnsServer() {
  const socket = dgram.createSocket('udp4');
  socket.on('message', (packet, info) => {
    const response = buildAuditDnsResponse(packet);
    if (response) socket.send(response, info.port, info.address);
  });
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  return {
    port: socket.address().port,
    close: () => new Promise((resolve) => socket.close(resolve))
  };
}

function buildAuditDnsResponse(packet) {
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
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  const lastOctet = labels.join('.') === 'response-filter.audit' ? 54 : 53;
  const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, lastOctet]);
  return Buffer.concat([header, packet.subarray(12, questionEnd), answer]);
}

function buildAuditDnsQuery(name, id) {
  const labels = name.split('.').map((label) => {
    const value = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([value.length]), value]);
  });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const suffix = Buffer.from([0, 0, 1, 0, 1]);
  return Buffer.concat([header, ...labels, suffix]);
}

function queryAuditDns(port, packet) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => finish(new Error('audit dns query timeout')), 3000);
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

async function waitFor(check, timeoutMs, output) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`local audit server start timeout\n${output()}`);
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
