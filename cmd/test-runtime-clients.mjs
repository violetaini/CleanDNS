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
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-runtime-clients-'));
let server;
let upstream;
let whois;

try {
  const scenario = await startScenario();
  server = scenario.server;
  upstream = scenario.upstream;
  whois = scenario.whois;
  const base = `http://127.0.0.1:${scenario.httpPort}/api`;

  assert.equal((await fetch(`${base}/clients`)).status, 401);
  const login = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(login.status, 200);
  const cookie = String(login.headers.get('set-cookie') || '').split(';')[0];
  const headers = { cookie, 'content-type': 'application/json' };

  await queryUdp(scenario.udpPort, buildQuery('runtime-client.test', 1, 0x4101));
  await queryUdp(scenario.udpPort, buildQuery('runtime-client.test', 1, 0x4102));

  const recentResponse = await fetch(`${base}/recent?offset=0&limit=10`, { headers });
  assert.equal(recentResponse.status, 200);
  const recent = await recentResponse.json();
  assert.equal(recent.recent.length, 2);
  assert.equal(recent.recent[0].client, '127.0.0.0/24');

  const clientsResponse = await fetch(`${base}/clients`, { headers });
  assert.equal(clientsResponse.status, 200);
  const clientData = await clientsResponse.json();
  assert.equal(clientData.clients.length, 0);
  assert.equal(clientData.runtimeClients.length, 3);
  const queryClient = clientData.runtimeClients.find((item) => item.address === '127.0.0.1');
  const hostsClient = clientData.runtimeClients.find((item) => item.address === '192.168.50.20');
  const arpClient = clientData.runtimeClients.find((item) => item.address === '192.168.50.21');
  assert.deepEqual(queryClient, {
    address: '127.0.0.1',
    name: '',
    note: '',
    tags: [],
    clientId: '',
    known: false,
    source: 'dns-query',
    hosts: null,
    arp: null,
    dhcp: null,
    requests: 2,
    blocked: 0,
    cached: 1,
    protocols: ['udp'],
    types: ['A'],
    firstSeenAt: queryClient.firstSeenAt,
    lastSeenAt: queryClient.lastSeenAt,
    queryLogAnonymized: true,
    reverseDns: {
      enabled: false,
      status: 'disabled',
      hostname: '',
      checkedAt: '',
      nextLookupAt: '',
      resolver: '',
      scope: '',
      error: ''
    },
    whois: {
      enabled: true,
      status: 'not-applicable',
      info: null,
      checkedAt: '',
      nextLookupAt: '',
      server: '',
      error: ''
    }
  });
  assert.ok(Date.parse(queryClient.firstSeenAt));
  assert.ok(Date.parse(queryClient.lastSeenAt));
  assert.deepEqual(hostsClient.hosts, { hostname: 'media-box', aliases: ['media-box', 'media'] });
  assert.equal(hostsClient.source, 'hosts');
  assert.equal(hostsClient.name, 'media-box');
  assert.equal(hostsClient.requests, 0);
  assert.deepEqual(arpClient.arp, { mac: 'aa:bb:cc:dd:ee:21', device: 'eth0' });
  assert.equal(arpClient.source, 'arp');
  assert.equal(arpClient.name, '');
  assert.equal(arpClient.requests, 0);

  const enableClientLookup = await fetch(`${base}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ clientReverseDnsEnabled: true })
  });
  assert.equal(enableClientLookup.status, 200);
  const unavailableClient = await waitForRuntimeClient(base, headers, (item) => item.reverseDns?.status === 'unavailable');
  assert.equal(unavailableClient.source, 'dns-query');
  assert.equal(unavailableClient.name, '');
  assert.equal(unavailableClient.reverseDns.scope, 'private');
  assert.equal(scenario.upstreamQueries.filter((item) => item.qtype === 12).length, 0);

  const enablePrivateLookup = await fetch(`${base}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      privateReverseEnabled: true,
      privateReverseUpstreams: [`udp://127.0.0.1:${scenario.upstream.address().port}`]
    })
  });
  assert.equal(enablePrivateLookup.status, 200);
  const resolvedClient = await waitForRuntimeClient(base, headers, (item) => item.source === 'rdns');
  assert.equal(resolvedClient.name, 'loopback.runtime.test');
  assert.equal(resolvedClient.reverseDns.status, 'resolved');
  assert.equal(resolvedClient.reverseDns.scope, 'private');
  assert.match(resolvedClient.reverseDns.resolver, /^udp:\/\/127\.0\.0\.1:/);
  assert.equal(scenario.upstreamQueries.filter((item) => item.qtype === 12).length, 1);

  const saveClient = await fetch(`${base}/clients`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ clients: [{ name: 'Loopback client', identifiers: ['127.0.0.1'], tags: ['runtime'] }] })
  });
  assert.equal(saveClient.status, 200);
  const saved = await saveClient.json();
  const savedClient = saved.runtimeClients.find((item) => item.address === '127.0.0.1');
  assert.equal(saved.clients.length, 1);
  assert.equal(savedClient.known, true);
  assert.equal(savedClient.name, 'Loopback client');
  assert.equal(savedClient.source, 'persistent');
  assert.equal(saved.status.clients.runtimeCount, 3);
  assert.equal(saved.status.clients.runtimeSources.hosts.count, 1);
  assert.equal(saved.status.clients.runtimeSources.arp.count, 1);

  const disableClientLookup = await fetch(`${base}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ clientReverseDnsEnabled: false })
  });
  assert.equal(disableClientLookup.status, 200);
  await queryUdp(scenario.udpPort, buildProxyV2UdpPacket(
    buildQuery('runtime-whois.test', 1, 0x4104),
    '8.8.8.8',
    53000,
    '127.0.0.1',
    scenario.udpPort
  ));
  const whoisClient = await waitForRuntimeClient(base, headers, (item) => item.address === '8.8.8.8' && item.whois?.status === 'resolved');
  assert.equal(whoisClient.source, 'whois');
  assert.deepEqual(whoisClient.whois.info, {
    orgname: 'CleanDNS Integration Network',
    city: 'Shanghai',
    country: 'CN'
  });
  assert.equal(whois.queries.length, 1);
  const recentWhois = await (await fetch(`${base}/recent?offset=0&limit=10`, { headers })).json();
  const whoisLog = recentWhois.recent.find((row) => row.qname === 'runtime-whois.test');
  assert.equal(whoisLog.client, '8.8.8.0/24');
  assert.equal(whoisLog.clientSource, 'whois');
  assert.deepEqual(whoisLog.clientWhois, whoisClient.whois.info);

  const disableLog = await fetch(`${base}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ queryLogEnabled: false })
  });
  assert.equal(disableLog.status, 200);
  await queryUdp(scenario.udpPort, buildQuery('runtime-without-log.test', 1, 0x4103));

  const afterDisable = await (await fetch(`${base}/clients`, { headers })).json();
  const afterDisableClient = afterDisable.runtimeClients.find((item) => item.address === '127.0.0.1');
  assert.equal(afterDisableClient.requests, 3);
  assert.equal(afterDisableClient.known, true);
  const recentAfterDisable = await (await fetch(`${base}/recent?offset=0&limit=10`, { headers })).json();
  assert.equal(recentAfterDisable.recent.length, 3);
  assert.ok(recentAfterDisable.recent.every((row) => row.qname !== 'runtime-without-log.test'));

  const disableSources = await fetch(`${base}/settings`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ clientWhoisEnabled: false, clientHostsEnabled: false, clientArpEnabled: false, clientDhcpEnabled: false })
  });
  assert.equal(disableSources.status, 200);
  const sourceSettings = await disableSources.json();
  assert.equal(sourceSettings.settings.clientWhoisEnabled, false);
  assert.equal(sourceSettings.settings.clientHostsEnabled, false);
  assert.equal(sourceSettings.settings.clientArpEnabled, false);
  assert.equal(sourceSettings.settings.clientDhcpEnabled, false);
  const sourceDisabledClients = await (await fetch(`${base}/clients`, { headers })).json();
  assert.deepEqual(sourceDisabledClients.runtimeClients.map((item) => item.address).sort(), ['127.0.0.1', '8.8.8.8']);
  assert.equal(sourceDisabledClients.runtimeClients.find((item) => item.address === '127.0.0.1').whois.status, 'managed');
  assert.equal(sourceDisabledClients.runtimeClients.find((item) => item.address === '8.8.8.8').whois.status, 'disabled');

  console.log('runtime client tests passed');
} finally {
  await stopChild(server);
  if (upstream) await new Promise((resolve) => upstream.close(resolve));
  if (whois) await whois.close();
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-runtime-clients-')) {
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
    const response = buildDnsResponse(packet);
    if (response) upstreamSocket.send(response, info.port, info.address);
  });
  await bindUdp(upstreamSocket, 0);
  const whois = await startWhoisServer();

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
    stats: path.join(dataDir, 'stats.json'),
    hosts: path.join(dataDir, 'hosts'),
    arp: path.join(dataDir, 'arp')
  };
  [files.block, files.allow, files.rewrite, files.subscriptions, files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.clients, '[]\n');
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');
  fs.writeFileSync(files.hosts, '192.168.50.20 media-box media\n');
  fs.writeFileSync(files.arp, 'IP address       HW type     Flags       HW address            Mask     Device\n192.168.50.21    0x1         0x2         aa:bb:cc:dd:ee:21     *        eth0\n');

  const config = {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [`udp://127.0.0.1:${upstreamSocket.address().port}`],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 1000,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, resolveClients: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: true },
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
    env: {
      ...process.env,
      CLEANDNS_CONFIG: configPath,
      CLEANDNS_RUNTIME_CLIENT_HOSTS_FILE: files.hosts,
      CLEANDNS_RUNTIME_CLIENT_ARP_FILE: files.arp,
      CLEANDNS_RUNTIME_CLIENT_SOURCE_REFRESH_MS: '1000',
      CLEANDNS_RUNTIME_CLIENT_WHOIS_SERVER: `127.0.0.1:${whois.port}`,
      CLEANDNS_RUNTIME_CLIENT_WHOIS_ALLOW_PRIVATE_SERVER: '1',
      CLEANDNS_RUNTIME_CLIENT_WHOIS_TIMEOUT_MS: '500'
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  await waitFor(() => output.includes(`cleandns udp listening on 127.0.0.1:${udpPort}`), 8000, () => output);
  return { server: child, upstream: upstreamSocket, upstreamQueries, whois, httpPort, udpPort };
}

function buildProxyV2UdpPacket(packet, sourceIp, sourcePort, destinationIp, destinationPort) {
  const signature = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
  const header = Buffer.alloc(28);
  signature.copy(header, 0);
  header[12] = 0x21;
  header[13] = 0x12;
  header.writeUInt16BE(12, 14);
  Buffer.from(sourceIp.split('.').map(Number)).copy(header, 16);
  Buffer.from(destinationIp.split('.').map(Number)).copy(header, 20);
  header.writeUInt16BE(sourcePort, 24);
  header.writeUInt16BE(destinationPort, 26);
  return Buffer.concat([header, packet]);
}

async function startWhoisServer() {
  const queries = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (!data.includes('\n')) return;
      queries.push(data.trim());
      socket.end('OrgName: CleanDNS Integration Network\r\nCity: Shanghai\r\nCountry: CN\r\n');
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    queries,
    close: () => new Promise((resolve) => {
      for (const socket of sockets) socket.destroy();
      server.close(resolve);
    })
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

function buildDnsResponse(packet) {
  const question = parseDnsQuestion(packet);
  if (!question) return null;
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);
  let answer;
  if (question.qtype === 12) {
    const value = encodeDnsName('loopback.runtime.test');
    const record = Buffer.alloc(12);
    record.writeUInt16BE(0xc00c, 0);
    record.writeUInt16BE(12, 2);
    record.writeUInt16BE(1, 4);
    record.writeUInt32BE(300, 6);
    record.writeUInt16BE(value.length, 10);
    answer = Buffer.concat([record, value]);
  } else {
    answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 53]);
  }
  return Buffer.concat([header, packet.subarray(12, question.questionEnd), answer]);
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

function encodeDnsName(name) {
  return Buffer.concat([
    ...name.split('.').map((label) => {
      const value = Buffer.from(label, 'ascii');
      return Buffer.concat([Buffer.from([value.length]), value]);
    }),
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
  const salt = 'cleandns-runtime-clients';
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

async function waitForRuntimeClient(base, headers, predicate) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const response = await fetch(`${base}/clients`, { headers });
    assert.equal(response.status, 200);
    const body = await response.json();
    const item = body.runtimeClients?.find(predicate);
    if (item && predicate(item)) return item;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('runtime client reverse DNS timeout');
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
