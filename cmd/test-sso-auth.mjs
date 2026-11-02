import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { createSsoAuth } from '../sso-auth.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cleandns-sso-'));
const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const credential = crypto.randomBytes(32).toString('hex');
let revoked = false, maliciousRedirect = false, child;
const agent = http.createServer(async (req, res) => {
  assert.equal(req.headers.authorization, 'Bearer ' + credential);
  const parts = []; for await (const part of req) parts.push(part);
  const body = JSON.parse(Buffer.concat(parts)), operation = req.url.split('/').at(-1);
  const reply = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
  if (operation === 'start') return reply(200, { location: maliciousRedirect ? 'https://untrusted.invalid/' : 'https://sso.example.com/oauth/authorize?state=test', cookies: ['__Host-flow=test; Path=/; Secure; HttpOnly; SameSite=Lax'] });
  if (operation === 'callback') return reply(body.query === '?code=valid&state=test' ? 200 : 401, { location: '/admin/', cookies: ['auth=valid; Path=/; Secure; HttpOnly'] });
  if (String(body.cookie).includes('auth=denied')) return reply(403, { error: 'not permitted' });
  if (revoked || !String(body.cookie).includes('auth=valid')) return reply(401, { error: 'login required' });
  if (!['GET', 'HEAD', 'OPTIONS'].includes(body.method) && (body.origin !== 'https://dns.example.com' || body.csrf !== 'valid-csrf')) return reply(403, { error: 'csrf' });
  if (operation === 'logout') return reply(200, { redirect_to: 'https://sso.example.com/oauth/logout', cookies: ['auth=; Max-Age=0; Path=/; Secure; HttpOnly'] });
  reply(200, { ok: true, subject: 'usr_owner', username: 'owner', displayName: 'Owner', csrfToken: 'valid-csrf', accountUrl: 'https://sso.example.com/portal' });
});
const upstream = dgram.createSocket('udp4');
upstream.on('message', (packet, remote) => { const response = Buffer.from(packet); response.writeUInt16BE(0x8180, 2); upstream.send(response, remote.port, remote.address); });
try {
  await new Promise(resolve => agent.listen(0, '127.0.0.1', resolve));
  await new Promise(resolve => upstream.bind(0, '127.0.0.1', resolve));
  const port = await unusedPort();
  const cfg = { origin: 'https://dns.example.com', issuer: 'https://sso.example.com', agentURL: `http://127.0.0.1:${agent.address().port}/cleandns`, key: credential, panelPath: '/admin/', apiBase: '/rpc', allowedOrigins: ['https://dns.example.com:8443'] };
  assert.equal(createSsoAuth({ env: {} }).enabled, false);
  assert.throws(() => createSsoAuth({ env: { CLEANDNS_AUTH_MODE: 'sso' }, configuration: { ...cfg, agentURL: 'http://untrusted.invalid/cleandns' } }), /loopback/);
  assert.throws(() => createSsoAuth({ env: { CLEANDNS_AUTH_MODE: 'sso' }, configuration: { ...cfg, allowedOrigins: ['https://other.example.com'] } }), /origin/);
  const authFile = path.join(root, 'sso.json'); fs.writeFileSync(authFile, JSON.stringify(cfg));
  const rules = path.join(root, 'rules'); fs.mkdirSync(rules);
  const files = Object.fromEntries(['block', 'allow', 'rewrite', 'subscriptions', 'allowSubscriptions', 'clients', 'password', 'log', 'stats'].map(n => [n, path.join(root, n)]));
  for (const [name, file] of Object.entries(files)) fs.writeFileSync(file, name === 'clients' ? '[]' : name === 'stats' ? '{}' : '');
  fs.writeFileSync(files.password, 'scrypt$test$' + crypto.scryptSync('old-password', 'test', 64).toString('base64url'));
  const config = { domain: 'dns.example.com', http: { host: '127.0.0.1', port }, udp: { host: '127.0.0.1', port: 0 }, upstreams: [`udp://127.0.0.1:${upstream.address().port}`], fallbackUpstreams: [], bootstrapDns: [], timeoutMs: 500, filter: { enabled: false }, cache: { enabled: false }, queryLog: { enabled: false }, statistics: { enabled: false }, service: { dohEnabled: true, dohPath: '/dns-query', doqEnabled: false, plainDnsEnabled: false }, rules: { blockFile: files.block, allowFile: files.allow, rewriteFile: files.rewrite, subscriptionFile: files.subscriptions, allowSubscriptionFile: files.allowSubscriptions, downloadDir: rules, allowDownloadDir: rules, autoUpdateEnabled: false, autoUpdateOnStartup: false, autoUpdateOnChange: false }, clients: { file: files.clients }, admin: { username: 'owner', passwordFile: files.password }, logFile: files.log, statsFile: files.stats };
  const configFile = path.join(root, 'config.json'); fs.writeFileSync(configFile, JSON.stringify(config));
  child = spawn(process.execPath, ['server.js'], { cwd: appDir, env: { ...process.env, CLEANDNS_CONFIG: configFile, CLEANDNS_AUTH_MODE: 'sso', CLEANDNS_SSO_CONFIG_FILE: authFile }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let output = ''; child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
  for (let n = 0; !output.includes('cleandns http listening') && n < 160; n++) { assert.equal(child.exitCode, null, output); await new Promise(r => setTimeout(r, 50)); }
  assert.match(output, /cleandns http listening/, output);
  const request = (url, options = {}) => fetch(`http://127.0.0.1:${port}${url}`, { redirect: 'manual', ...options });
  let response = await request('/admin/'); assert.equal(response.status, 302); assert.equal(response.headers.get('location'), 'https://dns.example.com/rpc/sso/start');
  response = await request('/api/session'); assert.deepEqual(await response.json(), { authenticated: false, authMode: 'sso', loginUrl: 'https://dns.example.com/rpc/sso/start' });
  response = await request('/api/login', { method: 'POST', body: JSON.stringify({ username: 'owner', password: 'old-password' }) }); assert.equal(response.status, 403);
  response = await request('/api/profile', { headers: { cookie: 'cleandns_session=old' } }); assert.equal(response.status, 401);
  response = await request('/api/sso/start'); assert.equal(response.status, 302); assert.match(response.headers.get('set-cookie'), /Secure; HttpOnly/);
  maliciousRedirect = true; response = await request('/api/sso/start'); assert.equal(response.status, 503); assert.equal(response.headers.get('location'), null); maliciousRedirect = false;
  response = await request('/api/sso/callback?code=invalid'); assert.equal(response.status, 401);
  response = await request('/api/sso/callback?code=valid&state=test'); assert.equal(response.status, 302); assert.equal(response.headers.get('location'), 'https://dns.example.com/admin/');
  response = await request('/admin/', { headers: { cookie: 'auth=denied' } }); assert.equal(response.status, 403);
  response = await request('/admin/', { headers: { cookie: 'auth=valid' } }); assert.equal(response.status, 200); const panelHtml = await response.text(); assert.match(panelHtml, /data-auth-mode="sso"/); assert.match(panelHtml, /data-auth-api-base="\/rpc"/);
  response = await request('/api/session', { headers: { cookie: 'auth=valid' } }); const session = await response.json(); assert.equal(session.authenticated, true); assert.equal(session.username, 'owner'); assert.equal(session.csrfToken, 'valid-csrf');
  for (const headers of [{ cookie: 'auth=valid', origin: 'https://untrusted.invalid', 'x-csrf-token': 'valid-csrf' }, { cookie: 'auth=valid', origin: cfg.origin }]) {
    response = await request('/api/profile', { method: 'PUT', headers, body: JSON.stringify({ theme: 'dark' }) }); assert.equal(response.status, 403);
  }
  response = await request('/api/profile', { method: 'PUT', headers: { cookie: 'auth=valid', origin: 'https://dns.example.com:8443', 'x-csrf-token': 'valid-csrf' }, body: JSON.stringify({ theme: 'dark' }) }); assert.equal(response.status, 200);
  const wire = Buffer.concat([Buffer.from('521601000001000000000000', 'hex'), Buffer.from('\x07example\x03com\0', 'binary'), Buffer.from('00010001', 'hex')]);
  for (const method of ['GET', 'POST']) {
    response = await request('/dns-query' + (method === 'GET' ? '?dns=' + wire.toString('base64url') : ''), { method, ...(method === 'POST' ? { body: wire, headers: { 'Content-Type': 'application/dns-message' } } : {}) });
    assert.equal(response.status, 200); assert.match(response.headers.get('content-type'), /application\/dns-message/); assert.deepEqual(Buffer.from(await response.arrayBuffer()).subarray(0, 2), wire.subarray(0, 2));
  }
  response = await request('/api/logout', { method: 'POST', headers: { cookie: 'auth=valid', origin: cfg.origin, 'x-csrf-token': 'valid-csrf' } }); assert.equal(response.status, 200); assert.equal((await response.json()).redirectTo, 'https://sso.example.com/oauth/logout');
  revoked = true; response = await request('/api/profile', { headers: { cookie: 'auth=valid' } }); assert.equal(response.status, 401);
  agent.closeAllConnections(); await new Promise(resolve => agent.close(resolve));
  response = await request('/api/session', { headers: { cookie: 'auth=valid' } }); assert.equal(response.status, 503);
  await verifyLogoutRefreshRace();
  console.log('SSO authentication, fail-closed access, CSRF, logout/refresh races, and anonymous DoH passed.');
} finally {
  if (child && child.exitCode === null) { child.kill('SIGTERM'); await new Promise(resolve => child.once('exit', resolve)); }
  agent.closeAllConnections(); agent.close(); upstream.close();
  fs.rmSync(root, { recursive: true, force: true });
}
async function unusedPort() { const server = net.createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }

async function verifyLogoutRefreshRace() {
  const html = fs.readFileSync(path.join(appDir, 'panel.html'), 'utf8');
  const api = html.match(/    async function api\(path[\s\S]+?(?=    const THEME_PREFERENCES)/)?.[0];
  const logout = html.match(/    async function logout\(\)[\s\S]+?(?=    async function refreshAll)/)?.[0];
  assert.ok(api && logout);
  for (const succeeds of [true, false]) {
    const requests = [], redirects = [], notices = [], button = { disabled: false };
    const context = vm.createContext({ authMode: 'sso', csrfToken: 'valid-csrf', signingOut: false, ssoLoginUrl: 'https://dns.example.com/api/sso/start', apiTarget: value => value,
      fetch: url => new Promise(resolve => requests.push({ url, resolve })), window: { location: { assign: url => redirects.push(url) } }, $: () => button,
      showNotice: (...args) => notices.push(args), setAuthView() {}, setAccountMenu() {} });
    new vm.Script(api + '\n' + logout).runInContext(context);
    const leaving = context.logout();
    assert.equal(button.disabled, true);
    const refresh = context.api('/api/profile').catch(() => {});
    const respond = (url, status, body) => requests.find(r => r.url === url).resolve({ status, ok: status < 400, text: async () => JSON.stringify(body) });
    respond('/api/profile', 401, { error: 'sso_required', authMode: 'sso' }); await refresh;
    assert.deepEqual(redirects, [], 'background refresh interrupted logout');
    respond('/api/logout', succeeds ? 200 : 503, succeeds ? { redirectTo: 'https://sso.example.com/oauth/logout' } : { error: 'identity_unavailable' }); await leaving;
    if (succeeds) assert.deepEqual(redirects, ['https://sso.example.com/oauth/logout']);
    else { assert.equal(button.disabled, false); assert.equal(notices.length, 1); assert.deepEqual(redirects, []); }
  }
}
