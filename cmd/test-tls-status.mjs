import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildDohMobileConfig, inspectTlsConfiguration } from '../tls-status.js';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempBase = path.resolve(os.tmpdir());
const tempDir = fs.mkdtempSync(path.join(tempBase, 'cleandns-tls-'));

try {
  const openssl = findOpenSsl();
  const certFile = path.join(tempDir, 'fullchain.pem');
  const keyFile = path.join(tempDir, 'privkey.pem');
  const wrongKeyFile = path.join(tempDir, 'wrong-key.pem');

  runOpenSsl(openssl, [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '90',
    '-subj', '/CN=dnspro.test',
    '-addext', 'subjectAltName=DNS:dnspro.test,DNS:*.dnspro.test',
    '-keyout', keyFile,
    '-out', certFile
  ]);
  runOpenSsl(openssl, ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', wrongKeyFile]);

  const config = {
    domain: 'dnspro.test',
    service: {
      dohEnabled: false,
      doqEnabled: true,
      dohPublicBaseUrl: 'https://dnspro.test',
      doqEndpoint: 'dnspro.test',
      doqTlsCertFile: certFile,
      doqTlsKeyFile: keyFile
    }
  };
  const valid = inspectTlsConfiguration(config);
  assert.equal(valid.status, 'valid');
  assert.equal(valid.validCert, true);
  assert.equal(valid.validKey, true);
  assert.equal(valid.validPair, true);
  assert.equal(valid.validChain, true);
  assert.equal(valid.validTime, true);
  assert.equal(valid.validHost, true);
  assert.equal(valid.chainCertificates, 1);
  assert.match(valid.keyType, /^RSA 2048$/);
  assert.ok(valid.dnsNames.includes('dnspro.test'));
  assert.ok(valid.dnsNames.includes('*.dnspro.test'));
  assert.equal(valid.hostMatches[0].host, 'dnspro.test');
  assert.ok(valid.daysRemaining > 30);
  assert.equal(valid.certificateFile.exists, true);
  assert.equal(valid.privateKeyFile.exists, true);

  const wrongKey = inspectTlsConfiguration({
    ...config,
    service: { ...config.service, doqTlsKeyFile: wrongKeyFile }
  });
  assert.equal(wrongKey.validPair, false);
  assert.equal(wrongKey.status, 'invalid');
  assert.ok(wrongKey.issues.some((issue) => issue.code === 'certificate_key_mismatch'));

  const wrongHost = inspectTlsConfiguration({ ...config, domain: 'other.test', service: { ...config.service, dohPublicBaseUrl: '', doqEndpoint: '' } });
  assert.equal(wrongHost.validHost, false);
  assert.ok(wrongHost.issues.some((issue) => issue.code === 'certificate_host_mismatch'));

  const expired = inspectTlsConfiguration(config, { now: new Date(new Date(valid.notAfter).getTime() + 86_400_000) });
  assert.equal(expired.validTime, false);
  assert.equal(expired.status, 'invalid');

  const missing = inspectTlsConfiguration({
    domain: 'dnspro.test',
    service: { doqTlsCertFile: path.join(tempDir, 'missing-cert.pem'), doqTlsKeyFile: path.join(tempDir, 'missing-key.pem') }
  });
  assert.equal(missing.validCert, false);
  assert.equal(missing.validKey, false);
  assert.ok(missing.issues.some((issue) => issue.code === 'certificate_missing'));
  assert.ok(missing.issues.some((issue) => issue.code === 'private_key_missing'));

  const profile = buildDohMobileConfig({
    serverUrl: 'https://dnspro.test/secret/dns-query?client=ios&mode=secure',
    displayName: 'CleanDNS'
  });
  const profileAgain = buildDohMobileConfig({
    serverUrl: 'https://dnspro.test/secret/dns-query?client=ios&mode=secure',
    displayName: 'CleanDNS'
  });
  assert.equal(profile, profileAgain);
  assert.match(profile, /com\.apple\.dnsSettings\.managed/);
  assert.match(profile, /https:\/\/dnspro\.test\/secret\/dns-query\?client=ios&amp;mode=secure/);
  assert.match(profile, /<string>HTTPS<\/string>/);
  assert.equal((profile.match(/<key>PayloadUUID<\/key>/g) || []).length, 2);
  assert.throws(() => buildDohMobileConfig({ serverUrl: 'http://dnspro.test/dns-query' }), /bad_doh_profile_url/);

  await testServerApi({ certFile, keyFile });

  console.log('tls status tests passed');
} finally {
  const resolved = path.resolve(tempDir);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-tls-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

function findOpenSsl() {
  const candidates = process.platform === 'win32'
    ? [
        process.env.OPENSSL_BIN,
        'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
        'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
        'openssl.exe'
      ]
    : [process.env.OPENSSL_BIN, '/usr/bin/openssl', '/usr/local/bin/openssl', 'openssl'];
  for (const candidate of candidates.filter(Boolean)) {
    const result = spawnSync(candidate, ['version'], { encoding: 'utf8', windowsHide: true });
    if (!result.error && result.status === 0) return candidate;
  }
  throw new Error('openssl is required for tls status tests');
}

function runOpenSsl(executable, args) {
  const result = spawnSync(executable, args, {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, MSYS2_ARG_CONV_EXCL: '*' }
  });
  if (result.status !== 0) throw new Error(`openssl failed: ${result.stderr || result.stdout}`);
}

async function testServerApi({ certFile, keyFile }) {
  const root = path.join(tempDir, 'server');
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
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const config = {
    domain: 'dnspro.test',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: ['127.0.0.1:9'],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 100,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: false, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false } },
    queryLog: { enabled: false, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: false, retentionHours: 24, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: {
      dohPath: '/secret/dns-query',
      dohEnabled: true,
      dohPublicBaseUrl: 'https://dnspro.test',
      panelPath: '/admin/',
      panelPublicUrl: `http://127.0.0.1:${httpPort}/admin/`,
      plainDnsEnabled: false,
      doqEnabled: true,
      doqEndpoint: 'edge.dnspro.test',
      doqPort: 853,
      doqTlsCertFile: certFile,
      doqTlsKeyFile: keyFile,
      dohSyncCommand: '',
      doqSyncCommand: ''
    },
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
    dhcp: { runtimeSupported: false },
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
  try {
    await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 8000, () => output);
    const base = `http://127.0.0.1:${httpPort}/api`;
    const unauthorized = await fetch(`${base}/tls/status`);
    assert.equal(unauthorized.status, 401);
    assert.equal((await fetch(`${base}/protocols/defaults`)).status, 401);
    assert.equal((await fetch(`${base}/protocols/reset`, { method: 'POST' })).status, 401);
    assert.equal((await fetch(`${base}/tls/config`, { method: 'POST' })).status, 401);

    const login = await fetch(`${base}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'test', password: 'test-password' })
    });
    assert.equal(login.status, 200);
    const cookie = String(login.headers.get('set-cookie') || '').split(';')[0];

    const statusResponse = await fetch(`${base}/tls/status`, { headers: { cookie } });
    assert.equal(statusResponse.status, 200);
    const status = await statusResponse.json();
    assert.equal(status.status, 'valid');
    assert.equal(status.validPair, true);
    assert.equal(status.certificatePath, certFile);
    assert.equal(Object.hasOwn(status, 'privateKey'), false);

    const validation = await fetch(`${base}/tls/validate`, { method: 'POST', headers: { cookie } });
    assert.equal(validation.status, 200);
    assert.equal((await validation.json()).validHost, true);

    const relativePathValidation = await fetch(`${base}/tls/validate`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ certificatePath: 'relative/fullchain.pem', privateKeyPath: keyFile })
    });
    assert.equal(relativePathValidation.status, 400);
    assert.equal((await relativePathValidation.json()).error, 'bad_tls_certificate_path');

    const missingPathValidation = await fetch(`${base}/tls/validate`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ certificatePath: path.join(tempDir, 'missing.pem'), privateKeyPath: keyFile })
    });
    assert.equal(missingPathValidation.status, 200);
    assert.equal((await missingPathValidation.json()).status, 'invalid');

    const saveTls = await fetch(`${base}/tls/config`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ certificatePath: certFile, privateKeyPath: keyFile })
    });
    assert.equal(saveTls.status, 200);
    const savedTls = await saveTls.json();
    assert.equal(savedTls.tls.status, 'valid');
    assert.equal(savedTls.settings.tlsCertificatePath, certFile);
    assert.equal(savedTls.settings.tlsPrivateKeyPath, keyFile);

    const invalidTlsSave = await fetch(`${base}/tls/config`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ certificatePath: path.join(tempDir, 'missing.pem'), privateKeyPath: keyFile })
    });
    assert.equal(invalidTlsSave.status, 400);
    const invalidTlsBody = await invalidTlsSave.json();
    assert.equal(invalidTlsBody.error, 'tls_configuration_invalid');
    assert.equal(invalidTlsBody.tls.status, 'invalid');

    const defaultsResponse = await fetch(`${base}/protocols/defaults`, { headers: { cookie } });
    assert.equal(defaultsResponse.status, 200);
    const defaults = await defaultsResponse.json();
    assert.deepEqual(defaults.defaults.plainDns, { enabled: false, host: '0.0.0.0', port: 53 });
    assert.equal(defaults.defaults.doh.enabled, true);
    assert.equal(defaults.defaults.doh.path, '/secret/dns-query');
    assert.deepEqual(defaults.defaults.doq, { enabled: true, host: 'dnspro.test', port: 853 });
    assert.equal(defaults.preserved.certificatePath, certFile);
    assert.equal(defaults.preserved.privateKeyPath, keyFile);

    const resetResponse = await fetch(`${base}/protocols/reset`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: '{}'
    });
    assert.equal(resetResponse.status, 200);
    const reset = await resetResponse.json();
    assert.equal(reset.settings.dohEnabled, true);
    assert.equal(reset.settings.plainDnsEnabled, false);
    assert.equal(reset.settings.doqEnabled, true);
    assert.equal(reset.settings.doqEndpoint, 'dnspro.test');
    assert.equal(reset.settings.doqPort, 853);
    assert.equal(reset.settings.dohPath, '/secret/dns-query');
    assert.equal(reset.settings.tlsCertificatePath, certFile);
    assert.equal(reset.settings.tlsPrivateKeyPath, keyFile);

    const persisted = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.equal(persisted.service.dohPath, '/secret/dns-query');
    assert.equal(persisted.service.doqTlsCertFile, certFile);
    assert.equal(persisted.service.doqTlsKeyFile, keyFile);

    const mobileConfig = await fetch(`${base}/apple/doh.mobileconfig`, { headers: { cookie } });
    assert.equal(mobileConfig.status, 200);
    assert.match(String(mobileConfig.headers.get('content-type')), /^application\/x-apple-aspen-config/);
    assert.match(String(mobileConfig.headers.get('content-disposition')), /CleanDNS-DoH\.mobileconfig/);
    assert.match(await mobileConfig.text(), /https:\/\/dnspro\.test\/secret\/dns-query/);
  } finally {
    await stopChild(server);
  }
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
  const salt = 'cleandns-tls-status';
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
