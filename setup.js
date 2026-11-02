import http from 'node:http';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { normalizeUpstreamAddress } from './upstream.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const scrypt = promisify(crypto.scrypt);
function integer(value, min, max, code) { if (!Number.isInteger(value) || value < min || value > max) throw new Error(code); return value; }
function address(value) { if (typeof value !== 'string' || !net.isIP(value)) throw new Error('invalid_listen_address'); return value; }
export function setupCandidate(body, setupPort) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('invalid_settings');
  const settings = {
    httpHost: address(body.httpHost), httpPort: integer(body.httpPort, 1, 65535, 'invalid_http_port'),
    corePort: integer(body.corePort ?? 8053, 1, 65535, 'invalid_core_port'),
    plainEnabled: body.plainEnabled === true, plainHost: address(body.plainHost || '127.0.0.1'),
    plainPort: integer(body.plainPort ?? 53, 1, 65535, 'invalid_dns_port')
  };
  if (settings.httpPort === setupPort) throw new Error('setup_port_reserved');
  if (typeof body.upstreams !== 'string' || body.upstreams.length > 8000) throw new Error('invalid_upstreams');
  settings.upstreams = body.upstreams.split(/\r?\n/).map(v => v.trim()).filter(v => v && !v.startsWith('#'));
  if (!settings.upstreams.length || settings.upstreams.length > 16) throw new Error('invalid_upstreams');
  settings.upstreams = [...new Set(settings.upstreams.map(normalizeUpstreamAddress))];
  return settings;
}
export async function checkSetupPorts(settings) {
  const sockets = [];
  const bind = async (kind, host, port, field) => {
    const socket = kind === 'tcp' ? net.createServer() : dgram.createSocket(net.isIP(host) === 6 ? 'udp6' : 'udp4');
    try {
      await new Promise((resolve, reject) => { socket.once('error', reject); kind === 'tcp' ? socket.listen({ host, port, exclusive: true }, resolve) : socket.bind({ address: host, port, exclusive: true }, resolve); });
      sockets.push(socket);
    } catch (err) { try { socket.close(); } catch {} throw new Error(`${field}:${err.code === 'EACCES' ? 'permission_denied' : err.code === 'EADDRINUSE' ? 'port_in_use' : 'bind_failed'}`); }
  };
  try {
    await bind('tcp', settings.httpHost, settings.httpPort, 'http');
    await bind('udp', '127.0.0.1', settings.corePort, 'core');
    if (settings.plainEnabled) { await bind('tcp', settings.plainHost, settings.plainPort, 'dns_tcp'); await bind('udp', settings.plainHost, settings.plainPort, 'dns_udp'); }
  } finally { await Promise.all(sockets.map(socket => new Promise(resolve => socket.close(resolve)))); }
}
async function readBody(req) {
  const chunks = []; let bytes = 0;
  for await (const chunk of req) { bytes += chunk.length; if (bytes > 16384) throw new Error('request_too_large'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('invalid_json'); }
}
function send(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
  res.end(JSON.stringify(value));
}
export async function startSetup({ configPath, dataDir, host = '127.0.0.1', port = 3000, tokenFile, onComplete = async () => {} }) {
  address(host); integer(port, 0, 65535, 'invalid_setup_port');
  configPath = path.resolve(configPath); dataDir = path.resolve(dataDir);
  if (fs.existsSync(configPath)) throw new Error('already_configured');
  let token = crypto.randomBytes(32).toString('hex'), busy = false, completed = false, closing = false;
  if (tokenFile) {
    fs.mkdirSync(path.dirname(tokenFile), { recursive: true, mode: 0o700 });
    if (fs.existsSync(tokenFile)) {
      const stat = fs.lstatSync(tokenFile); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('unsafe_token_file');
      token = fs.readFileSync(tokenFile, 'utf8').trim(); if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('invalid_token_file');
      fs.chmodSync(tokenFile, 0o600);
    } else fs.writeFileSync(tokenFile, token + '\n', { mode: 0o600, flag: 'wx' });
  }
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && ['/', '/setup', '/setup/'].includes(url.pathname)) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" });
        return res.end(fs.readFileSync(path.join(root, 'setup.html')));
      }
      if (req.method === 'GET' && url.pathname === '/assets/avatar.webp') { res.writeHead(200, { 'content-type': 'image/webp', 'cache-control': 'public, max-age=3600' }); return res.end(fs.readFileSync(path.join(root, 'assets/avatar.webp'))); }
      if (!['/api/setup/status', '/api/setup/check', '/api/setup/apply'].includes(url.pathname)) return send(res, 404, { error: 'not_found' });
      const provided = String(req.headers['x-setup-token'] || '');
      if (!/^[a-f0-9]{64}$/.test(provided) || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(token))) return send(res, 401, { error: 'invalid_setup_token' });
      if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}` && req.headers.origin !== `https://${req.headers.host}`) return send(res, 403, { error: 'invalid_origin' });
      if (completed || fs.existsSync(configPath)) return send(res, 409, { error: 'already_configured' });
      if (req.method === 'GET' && url.pathname === '/api/setup/status') {
        const interfaces = Object.entries(os.networkInterfaces()).flatMap(([name, entries]) => entries.filter(item => !item.internal).map(item => ({ name, address: item.address, family: item.family })));
        return send(res, 200, { interfaces, defaults: { httpHost: '127.0.0.1', httpPort: 8055, corePort: 8053, plainEnabled: true, plainHost: '127.0.0.1', plainPort: 53, upstreams: '223.5.5.5\n1.1.1.1' } });
      }
      if (req.method !== 'POST' || !String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, { error: 'json_required' });
      if (busy) return send(res, 409, { error: 'setup_busy' });
      busy = true;
      let passwordPath, tempConfig;
      try {
        const body = await readBody(req), settings = setupCandidate(body, server.address().port);
        await checkSetupPorts(settings);
        if (url.pathname === '/api/setup/check') return send(res, 200, { ok: true });
        if (typeof body.username !== 'string' || !/^[a-zA-Z0-9_.@-]{1,64}$/.test(body.username)) throw new Error('invalid_username');
        if (typeof body.password !== 'string' || body.password.length < 12 || body.password.length > 256) throw new Error('password_length');
        if (body.password !== body.confirmPassword) throw new Error('password_mismatch');
        const config = JSON.parse(fs.readFileSync(path.join(root, 'config.example.json'), 'utf8'));
        fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 }); fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
        const id = crypto.randomBytes(8).toString('hex'), salt = crypto.randomBytes(16).toString('base64url');
        const hash = (await scrypt(body.password, salt, 64)).toString('base64url');
        const passwordTarget = path.join(dataDir, 'admin-password-' + id);
        fs.writeFileSync(passwordTarget, `scrypt$${salt}$${hash}\n`, { mode: 0o600, flag: 'wx' }); passwordPath = passwordTarget;
        config.http = { host: settings.httpHost, port: settings.httpPort }; config.udp = { host: '127.0.0.1', port: settings.corePort };
        config.upstreams = settings.upstreams; config.bootstrapDns = ['223.5.5.5', '1.1.1.1'];
        config.admin.username = body.username; config.admin.passwordFile = passwordPath;
        config.service.plainDnsEnabled = settings.plainEnabled; config.service.plainDnsHost = settings.plainHost; config.service.plainDnsPort = settings.plainPort;
        config.service.doqEnabled = false; config.service.dohEnabled = true;
        config.queryLog.enabled = body.queryLogEnabled === true;
        config.rules.autoUpdateOnStartup = false; config.rules.blockedServicesAutoUpdateOnStartup = false;
        for (const key of ['blockFile','allowFile','rewriteFile','subscriptionFile','allowSubscriptionFile','downloadDir','allowDownloadDir']) config.rules[key] = path.join(dataDir, path.basename(config.rules[key]));
        config.clients.file = path.join(dataDir, 'clients.json'); config.logFile = path.join(dataDir, 'query.log'); config.statsFile = path.join(dataDir, 'stats.json');
        const configTarget = configPath + '.setup-' + id;
        fs.writeFileSync(configTarget, JSON.stringify(config, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); tempConfig = configTarget;
        fs.linkSync(tempConfig, configPath); fs.unlinkSync(tempConfig); tempConfig = null;
        completed = true; passwordPath = null;
        if (tokenFile) { try { fs.unlinkSync(tokenFile); } catch {} }
        send(res, 200, { ok: true, httpPort: settings.httpPort, panelPath: '/admin/', dnsHost: settings.plainHost, dnsPort: settings.plainPort, plainEnabled: settings.plainEnabled });
        setTimeout(() => { server.close(); onComplete().catch(() => { console.error('CleanDNS failed to start; inspect the configuration and restart the service.'); process.exitCode = 1; }); }, 200).unref();
      } finally { busy = false; if (tempConfig) fs.unlinkSync(tempConfig); if (passwordPath) fs.unlinkSync(passwordPath); }
    } catch (error) { if (!res.headersSent) send(res, error.message === 'request_too_large' ? 413 : 400, { error: /^[a-z_]+(?::[a-z_]+)?$/.test(error.message) ? error.message : error.code === 'EEXIST' ? 'already_configured' : 'setup_failed' }); }
  });
  server.headersTimeout = 10000; server.requestTimeout = 15000; server.timeout = 15000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return { host, port: server.address().port, token, server, close: async () => { if (closing) return; closing = true; await new Promise(resolve => server.close(resolve)); } };
}
