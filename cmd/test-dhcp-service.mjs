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
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-dhcp-service-'));
let server;
let client;

try {
  const scenario = await startScenario();
  server = scenario.server;
  client = await createClient();
  const base = `http://127.0.0.1:${scenario.httpPort}/api`;
  const login = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(login.status, 200);
  const headers = {
    cookie: String(login.headers.get('set-cookie') || '').split(';')[0],
    'content-type': 'application/json'
  };

  const before = await getJson(`${base}/dhcp/status`, headers);
  assert.equal(before.supported, true);
  assert.equal(before.running, false);
  assert.equal(before.validation.ready, false);

  const invalidCheck = await postJson(`${base}/dhcp/check`, headers, {
    config: { dnsServers: ['not-an-ip'] }
  });
  assert.ok(invalidCheck.validation.errors.some((entry) => entry.code === 'dns_server_invalid'));
  const invalidSave = await postError(`${base}/settings`, headers, { dhcpDnsServers: ['not-an-ip'] });
  assert.equal(invalidSave.error, 'dns_server_invalid');

  const enabled = await postJson(`${base}/settings`, headers, {
    dhcpEnabled: true,
    dhcpInterfaceName: 'lan0',
    dhcpGateway: '192.168.50.1',
    dhcpSubnetMask: '255.255.255.0',
    dhcpRangeStart: '192.168.50.100',
    dhcpRangeEnd: '192.168.50.102',
    dhcpLeaseMinutes: 60,
    dhcpDnsServers: ['192.168.50.53', '1.1.1.1']
  });
  assert.equal(enabled.ok, true);
  assert.equal(enabled.status.dhcp.running, true, JSON.stringify(enabled.status.dhcp));
  assert.equal(enabled.status.dhcp.serverAddress, '192.168.50.2');
  assert.equal(enabled.status.dhcp.port, scenario.dhcpPort);

  const dynamicMac = '00:11:22:33:44:55';
  const offer = await sendAndReceive(client, scenario.dhcpPort, buildRequest({ type: 1, xid: 0x01020304, mac: dynamicMac, hostname: 'phone.lan' }));
  assert.equal(offer.type, 2);
  assert.match(offer.yiaddr, /^192\.168\.50\.10[0-2]$/);
  assert.equal(offer.serverIdentifier, '192.168.50.2');
  assert.deepEqual(offer.dnsServers, ['192.168.50.53', '1.1.1.1']);
  const ack = await sendAndReceive(client, scenario.dhcpPort, buildRequest({
    type: 3,
    xid: 0x01020305,
    mac: dynamicMac,
    requestedIp: offer.yiaddr,
    serverIdentifier: '192.168.50.2',
    hostname: 'phone.lan'
  }));
  assert.equal(ack.type, 5);
  assert.equal(ack.yiaddr, offer.yiaddr);

  const afterLease = await getJson(`${base}/dhcp/status`, headers);
  assert.equal(afterLease.running, true);
  assert.equal(afterLease.leases.length, 1);
  assert.equal(afterLease.leases[0].ip, offer.yiaddr);

  const staticResult = await postJson(`${base}/dhcp/static-leases`, headers, {
    action: 'add',
    lease: { mac: '00:11:22:33:44:66', ip: '192.168.50.20', hostname: 'printer.lan' }
  });
  assert.equal(staticResult.ok, true);
  assert.equal(staticResult.dhcp.running, true);
  assert.equal(staticResult.dhcp.leases.length, 1, 'dynamic leases must survive a static lease change');
  const staticOffer = await sendAndReceive(client, scenario.dhcpPort, buildRequest({ type: 1, xid: 0x01020306, mac: '00:11:22:33:44:66' }));
  assert.equal(staticOffer.type, 2);
  assert.equal(staticOffer.yiaddr, '192.168.50.20');

  const disabled = await postJson(`${base}/settings`, headers, { dhcpEnabled: false });
  assert.equal(disabled.ok, true);
  assert.equal(disabled.status.dhcp.running, false);
  assert.equal(disabled.settings.dhcpEnabled, false);
  assert.ok(fs.existsSync(scenario.leaseFile));

  console.log('dhcp service integration tests passed');
} finally {
  await closeClient(client);
  await stopChild(server);
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-dhcp-service-')) {
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
  const dhcpPort = await unusedUdpPort();
  const files = {
    block: path.join(rulesDir, 'blocklist.txt'),
    allow: path.join(rulesDir, 'allowlist.txt'),
    rewrite: path.join(rulesDir, 'rewrites.txt'),
    subscriptions: path.join(rulesDir, 'subscriptions.txt'),
    allowSubscriptions: path.join(rulesDir, 'allow-subscriptions.txt'),
    clients: path.join(dataDir, 'clients.json'),
    password: path.join(dataDir, 'admin-password'),
    log: path.join(dataDir, 'query.log'),
    stats: path.join(dataDir, 'stats.json'),
    lease: path.join(dataDir, 'dhcp-leases.json')
  };
  [files.block, files.allow, files.rewrite, files.subscriptions, files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
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
    filter: { enabled: true, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: false, retentionHours: 24, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    dhcp: { enabled: false, interfaceName: '', gateway: '', subnetMask: '', rangeStart: '', rangeEnd: '', leaseMinutes: 60, staticLeases: [] },
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
      blockedServicesAutoUpdateOnStartup: false
    },
    clients: { file: files.clients },
    admin: { username: 'test', passwordFile: files.password, sessionTtlSeconds: 600, trustProxy: false },
    logFile: files.log,
    statsFile: files.stats
  };
  const configPath = path.join(root, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  const interfaces = {
    lan0: [{ address: '192.168.50.2', netmask: '255.255.255.0', family: 'IPv4', mac: '02:00:00:00:00:01', internal: false, cidr: '192.168.50.2/24' }]
  };
  const child = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      CLEANDNS_CONFIG: configPath,
      CLEANDNS_ENABLE_DHCP_RUNTIME: '1',
      CLEANDNS_DHCP_PORT: String(dhcpPort),
      CLEANDNS_DHCP_LEASE_FILE: files.lease,
      CLEANDNS_DHCP_INTERFACES_JSON: JSON.stringify(interfaces),
      CLEANDNS_DHCP_TEST_BIND_ADDRESS: '127.0.0.1'
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += String(chunk); });
  child.stderr.on('data', (chunk) => { output += String(chunk); });
  await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 8_000, () => output);
  return { server: child, httpPort, dhcpPort, leaseFile: files.lease };
}

async function getJson(url, headers) {
  const response = await fetch(url, { headers });
  assert.equal(response.status, 200);
  return response.json();
}

async function postJson(url, headers, body) {
  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const payload = await response.json();
  assert.equal(response.status, 200, JSON.stringify(payload));
  return payload;
}

async function postError(url, headers, body) {
  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const payload = await response.json();
  assert.equal(response.status, 400, JSON.stringify(payload));
  return payload;
}

function buildRequest({ type, xid, mac, requestedIp = '', serverIdentifier = '', hostname = '' }) {
  const packet = Buffer.alloc(240);
  packet[0] = 1;
  packet[1] = 1;
  packet[2] = 6;
  packet.writeUInt32BE(xid >>> 0, 4);
  Buffer.from(mac.split(':').map((part) => Number.parseInt(part, 16))).copy(packet, 28);
  Buffer.from([99, 130, 83, 99]).copy(packet, 236);
  const options = [dhcpOption(53, Buffer.from([type]))];
  if (requestedIp) options.push(dhcpOption(50, ipv4Buffer(requestedIp)));
  if (serverIdentifier) options.push(dhcpOption(54, ipv4Buffer(serverIdentifier)));
  if (hostname) options.push(dhcpOption(12, Buffer.from(hostname, 'ascii')));
  return Buffer.concat([packet, ...options, Buffer.from([255])]);
}

function sendAndReceive(socket, port, packet) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('dhcp response timeout')), 2_000);
    const finish = (error, response) => {
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
      if (error) reject(error); else resolve(parseResponse(response));
    };
    const onMessage = (response) => finish(null, response);
    const onError = (error) => finish(error);
    socket.once('message', onMessage);
    socket.once('error', onError);
    socket.send(packet, port, '127.0.0.1', (error) => {
      if (error) finish(error);
    });
  });
}

function parseResponse(packet) {
  const options = new Map();
  for (let offset = 240; offset < packet.length;) {
    const code = packet[offset++];
    if (code === 255) break;
    if (code === 0) continue;
    const length = packet[offset++];
    options.set(code, packet.subarray(offset, offset + length));
    offset += length;
  }
  return {
    type: options.get(53)?.[0] || 0,
    yiaddr: ipv4FromBuffer(packet.subarray(16, 20)),
    serverIdentifier: ipv4FromBuffer(options.get(54)),
    dnsServers: ipv4ListFromBuffer(options.get(6))
  };
}

async function createClient() {
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  return socket;
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

function dhcpOption(code, value) {
  return Buffer.concat([Buffer.from([code, value.length]), value]);
}

function ipv4Buffer(value) {
  return Buffer.from(value.split('.').map(Number));
}

function ipv4FromBuffer(value) {
  return Buffer.isBuffer(value) && value.length === 4 ? [...value].join('.') : '';
}

function ipv4ListFromBuffer(value) {
  if (!Buffer.isBuffer(value) || value.length % 4 !== 0) return [];
  const servers = [];
  for (let offset = 0; offset < value.length; offset += 4) servers.push(ipv4FromBuffer(value.subarray(offset, offset + 4)));
  return servers;
}

function hashPassword(value) {
  const salt = 'cleandns-dhcp-service';
  return `scrypt$${salt}$${crypto.scryptSync(value, salt, 64).toString('base64url')}`;
}

function waitFor(check, timeoutMs, output = () => '') {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const timer = setInterval(() => {
      if (check()) {
        clearInterval(timer);
        resolve();
      } else if (Date.now() >= deadline) {
        clearInterval(timer);
        reject(new Error(`wait timeout\n${output()}`));
      }
    }, 25);
  });
}

function closeClient(socket) {
  return new Promise((resolve) => {
    if (!socket) return resolve();
    try {
      socket.close(resolve);
    } catch {
      resolve();
    }
  });
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2_000))
  ]);
  if (child.exitCode === null) child.kill();
}
