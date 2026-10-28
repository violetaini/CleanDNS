import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeDnsResponse } from '../dns-response.js';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempBase = path.resolve(os.tmpdir());
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-response-filtering-'));
let server;
let upstream;

try {
  const scenario = await startScenario();
  server = scenario.server;
  upstream = scenario.upstream;
  const cookie = await login(scenario);

  await expectBlocked(scenario, 'cname-block.test', 1);
  await expectBlocked(scenario, 'cname-hosts.test', 1);
  await expectAllowed(scenario, 'cname-allowed-target.test', 1, ['CNAME:allowed-target.test']);
  await expectBlocked(scenario, 'cname-important.test', 1);
  await expectAllowed(scenario, 'cname-excluded.test', 1, ['CNAME:cname-excluded-target.test']);
  await expectAllowed(scenario, 'allow-origin.test', 1, ['CNAME:blocked-target.test']);

  await expectBlocked(scenario, 'a-plain.test', 1);
  await expectBlocked(scenario, 'a-anchor.test', 1);
  await expectAllowed(scenario, 'a-excluded.test', 1, ['A:203.0.113.10']);
  await expectAllowed(scenario, 'a-allowed.test', 1, ['A:203.0.113.12']);
  await expectBlocked(scenario, 'a-important.test', 1);
  await expectBlocked(scenario, 'aaaa-plain.test', 28);
  await expectAllowed(scenario, 'aaaa-excluded.test', 28, ['AAAA:2001:db8:0:0:0:0:0:10']);

  await expectBlocked(scenario, 'https-ipv4.test', 65);
  await expectBlocked(scenario, 'https-excluded-a.test', 65);
  await expectBlocked(scenario, 'svcb-ipv6.test', 64);
  await expectAllowed(scenario, 'pass.test', 1, ['A:198.51.100.1']);
  await expectDohBlocked(scenario, 'doh-block.test', 1);

  const clientResult = await postJson(scenario, '/api/test', cookie, {
    name: 'client-off.test',
    type: 'A',
    clientIp: '127.0.0.2'
  });
  assert.deepEqual(clientResult.answers?.map(answerKey), ['A:203.0.113.8']);

  const disabledResponseCheck = await postJson(scenario, '/api/settings', cookie, { cnameCheck: false });
  assert.equal(disabledResponseCheck.settings?.cnameCheck, false);
  await expectAllowed(scenario, 'toggle.test', 1, ['A:203.0.113.8']);
  const enabledResponseCheck = await postJson(scenario, '/api/settings', cookie, { cnameCheck: true });
  assert.equal(enabledResponseCheck.settings?.cnameCheck, true);
  await expectBlocked(scenario, 'toggle.test', 1);

  const disabledProtection = await postJson(scenario, '/api/settings', cookie, { filterEnabled: false });
  assert.equal(disabledProtection.settings?.filterEnabled, false);
  await expectAllowed(scenario, 'protection-off.test', 1, ['A:203.0.113.8']);
  const enabledProtection = await postJson(scenario, '/api/settings', cookie, { filterEnabled: true });
  assert.equal(enabledProtection.settings?.filterEnabled, true);

  const beforeConcurrent = scenario.upstreamQueries.length;
  const [firstConcurrent, secondConcurrent] = await Promise.all([
    queryUdp(scenario.udpPort, buildQuery('concurrent.test', 1, 0x7a01)),
    queryUdp(scenario.udpPort, buildQuery('concurrent.test', 1, 0x7a02))
  ]);
  assert.equal(decodeDnsResponse(firstConcurrent).rcode, 3);
  assert.equal(decodeDnsResponse(secondConcurrent).rcode, 3);
  assert.equal(scenario.upstreamQueries.length, beforeConcurrent + 1, 'in-flight response must be shared and filtered for both callers');

  const hostsLog = await recentRow(scenario, cookie, 'cname-hosts.test');
  assert.equal(hostsLog.action, 'block-cname');
  assert.equal(hostsLog.source, 'filter-hosts');
  assert.equal(hostsLog.responseMatchType, 'CNAME');
  assert.equal(hostsLog.responseMatchValue, 'hosts-target.test');
  assert.equal(hostsLog.rule, '0.0.0.0 hosts-target.test');
  assert.deepEqual(hostsLog.matchedRules, ['0.0.0.0 hosts-target.test']);
  assert.deepEqual(hostsLog.originalAnswers?.map(answerKey), ['CNAME:hosts-target.test']);
  assert.equal(hostsLog.responseStatus, 'NXDOMAIN');

  const addressLog = await recentRow(scenario, cookie, 'a-plain.test');
  assert.equal(addressLog.source, 'filter');
  assert.equal(addressLog.responseMatchType, 'A');
  assert.equal(addressLog.responseMatchValue, '203.0.113.8');
  assert.deepEqual(addressLog.originalAnswers?.map(answerKey), ['A:203.0.113.8']);

  const hintLog = await recentRow(scenario, cookie, 'https-ipv4.test');
  assert.equal(hintLog.responseMatchType, 'HTTPS ipv4hint');
  assert.equal(hintLog.responseMatchValue, '203.0.113.8');

  const searched = await getJson(scenario, '/api/recent?search=203.0.113.8&limit=100', cookie);
  assert.ok(searched.recent.some((row) => row.qname === 'a-plain.test'));
  assert.ok(searched.recent.some((row) => row.qname === 'https-ipv4.test'));

  const status = await getJson(scenario, '/api/status', cookie);
  assert.ok(status.rules.block >= 11);
  assert.ok(status.stats.blockedFiltering >= 12);

  console.log('response filtering tests passed');
} finally {
  await stopChild(server);
  if (upstream) await new Promise((resolve) => upstream.close(resolve));
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-response-filtering-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

async function expectBlocked(scenario, name, type) {
  const response = await queryUdp(scenario.udpPort, buildQuery(name, type, 0x7100 + scenario.upstreamQueries.length));
  const decoded = decodeDnsResponse(response);
  assert.equal(decoded.rcode, 3, `${name} must be blocked`);
  assert.deepEqual(decoded.answers, [], `${name} blocked response must not leak upstream answers`);
}

async function expectAllowed(scenario, name, type, expectedAnswers) {
  const response = await queryUdp(scenario.udpPort, buildQuery(name, type, 0x7200 + scenario.upstreamQueries.length));
  const decoded = decodeDnsResponse(response);
  assert.equal(decoded.rcode, 0, `${name} must be allowed`);
  assert.deepEqual(decoded.answers.map(answerKey), expectedAnswers, `${name} answers`);
}

async function expectDohBlocked(scenario, name, type) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}/dns-query`, {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
    body: buildQuery(name, type, 0x7300 + scenario.upstreamQueries.length)
  });
  assert.equal(response.status, 200);
  assert.match(String(response.headers.get('content-type') || ''), /^application\/dns-message/);
  const decoded = decodeDnsResponse(Buffer.from(await response.arrayBuffer()));
  assert.equal(decoded.rcode, 3);
  assert.deepEqual(decoded.answers, []);
}

function answerKey(answer) {
  return `${answer.type}:${answer.value}`;
}

async function recentRow(scenario, cookie, name) {
  const payload = await getJson(scenario, `/api/recent?search=${encodeURIComponent(name)}&limit=20`, cookie);
  const row = payload.recent.find((item) => item.qname === name);
  assert.ok(row, `missing query log row for ${name}`);
  return row;
}

async function login(scenario) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(response.status, 200);
  return String(response.headers.get('set-cookie') || '').split(';')[0];
}

async function getJson(scenario, pathname, cookie) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}${pathname}`, { headers: { cookie } });
  assert.equal(response.status, 200);
  return response.json();
}

async function postJson(scenario, pathname, cookie, body) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}${pathname}`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  const payload = await response.json();
  assert.equal(response.status, 200, JSON.stringify(payload));
  return payload;
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
    if (!question) return;
    upstreamQueries.push(question);
    const send = () => upstreamSocket.send(buildScenarioResponse(packet, question), info.port, info.address);
    if (question.qname === 'concurrent.test') setTimeout(send, 80);
    else send();
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
  fs.writeFileSync(files.block, [
    '||blocked-target.test^',
    '0.0.0.0 hosts-target.test',
    '||allowed-target.test^',
    '||important-target.test^$important',
    '||cname-excluded-target.test^$dnstype=~CNAME',
    '203.0.113.8',
    '||203.0.113.9^',
    '||203.0.113.10^$dnstype=~A',
    '203.0.113.12',
    '203.0.113.13$important',
    '2001:db8::8',
    '||2001:db8::10^$dnstype=~AAAA'
  ].join('\n') + '\n');
  fs.writeFileSync(files.allow, [
    '||allowed-target.test^',
    '||important-target.test^',
    '||allow-origin.test^',
    '203.0.113.12',
    '203.0.113.13'
  ].join('\n') + '\n');
  [files.rewrite, files.subscriptions, files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.clients, JSON.stringify([{
    name: 'Filtering disabled client',
    identifiers: ['127.0.0.2'],
    useGlobalSettings: false,
    filteringEnabled: false
  }], null, 2) + '\n');
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
    filter: { enabled: true, blockMode: 'nxdomain', cnameCheck: true, blockedServices: [], safeBrowsing: { enabled: false }, parental: { enabled: false }, safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 500, retentionHours: 24, anonymizeClientIp: false },
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
  await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 15_000, () => output);
  return { server: child, upstream: upstreamSocket, upstreamQueries, httpPort, udpPort };
}

function buildScenarioResponse(query, question) {
  const records = responseRecords(question.qname);
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(records.length, 6);
  return Buffer.concat([
    header,
    query.subarray(12, question.questionEnd),
    ...records.map(encodeAnswerRecord)
  ]);
}

function responseRecords(name) {
  const records = {
    'cname-block.test': [{ type: 5, value: 'blocked-target.test' }],
    'cname-hosts.test': [{ type: 5, value: 'hosts-target.test' }],
    'cname-allowed-target.test': [{ type: 5, value: 'allowed-target.test' }],
    'cname-important.test': [{ type: 5, value: 'important-target.test' }],
    'cname-excluded.test': [{ type: 5, value: 'cname-excluded-target.test' }],
    'allow-origin.test': [{ type: 5, value: 'blocked-target.test' }],
    'a-plain.test': [{ type: 1, value: '203.0.113.8' }],
    'a-anchor.test': [{ type: 1, value: '203.0.113.9' }],
    'a-excluded.test': [{ type: 1, value: '203.0.113.10' }],
    'a-allowed.test': [{ type: 1, value: '203.0.113.12' }],
    'a-important.test': [{ type: 1, value: '203.0.113.13' }],
    'aaaa-plain.test': [{ type: 28, value: '2001:db8::8' }],
    'aaaa-excluded.test': [{ type: 28, value: '2001:db8::10' }],
    'https-ipv4.test': [{ type: 65, ipv4Hints: ['203.0.113.8'] }],
    'https-excluded-a.test': [{ type: 65, ipv4Hints: ['203.0.113.10'] }],
    'svcb-ipv6.test': [{ type: 64, ipv6Hints: ['2001:db8::8'] }],
    'pass.test': [{ type: 1, value: '198.51.100.1' }],
    'doh-block.test': [{ type: 1, value: '203.0.113.8' }],
    'client-off.test': [{ type: 1, value: '203.0.113.8' }],
    'toggle.test': [{ type: 1, value: '203.0.113.8' }],
    'protection-off.test': [{ type: 1, value: '203.0.113.8' }],
    'concurrent.test': [{ type: 1, value: '203.0.113.8' }]
  };
  return records[name] || [];
}

function encodeAnswerRecord(record) {
  let rdata;
  if (record.type === 1) rdata = ipv4Bytes(record.value);
  else if (record.type === 28) rdata = ipv6Bytes(record.value);
  else if (record.type === 5) rdata = encodeName(record.value);
  else if (record.type === 64 || record.type === 65) rdata = encodeServiceBinding(record);
  else throw new Error(`unsupported test record ${record.type}`);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0xc00c, 0);
  header.writeUInt16BE(record.type, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt32BE(60, 6);
  header.writeUInt16BE(rdata.length, 10);
  return Buffer.concat([header, rdata]);
}

function encodeServiceBinding(record) {
  const params = [];
  if (record.ipv4Hints?.length) {
    params.push(encodeServiceParam(4, Buffer.concat(record.ipv4Hints.map(ipv4Bytes))));
  }
  if (record.ipv6Hints?.length) {
    params.push(encodeServiceParam(6, Buffer.concat(record.ipv6Hints.map(ipv6Bytes))));
  }
  return Buffer.concat([u16(1), Buffer.from([0]), ...params]);
}

function encodeServiceParam(key, value) {
  return Buffer.concat([u16(key), u16(value.length), value]);
}

function buildQuery(name, type, id) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, encodeName(name), u16(type), u16(1)]);
}

function encodeName(name) {
  return Buffer.concat([
    ...String(name).split('.').map((label) => {
      const value = Buffer.from(label, 'ascii');
      return Buffer.concat([Buffer.from([value.length]), value]);
    }),
    Buffer.from([0])
  ]);
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

function ipv4Bytes(value) {
  return Buffer.from(String(value).split('.').map((part) => Number(part)));
}

function ipv6Bytes(value) {
  const [leftText, rightText = ''] = String(value).toLowerCase().split('::');
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  const result = Buffer.alloc(16);
  groups.forEach((group, index) => result.writeUInt16BE(Number.parseInt(group || '0', 16), index * 2));
  return result;
}

function u16(value) {
  const result = Buffer.alloc(2);
  result.writeUInt16BE(value);
  return result;
}

function queryUdp(port, packet) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => finish(new Error('dns query timeout')), 3000);
    const finish = (error, response) => {
      clearTimeout(timer);
      socket.close();
      if (error) reject(error);
      else resolve(response);
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
  const salt = 'cleandns-response-filtering';
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
