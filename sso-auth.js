import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';

const failure = (status, message) => Object.assign(new Error(message), { status });
const loopback = value => ['127.0.0.1', '::1'].includes(String(value || '').replace(/^::ffff:/, ''));

export function createSsoAuth({ env = process.env, configuration, timeoutMs = 12000 } = {}) {
  const mode = env.CLEANDNS_AUTH_MODE || 'local';
  if (!['local', 'sso'].includes(mode)) throw new Error('Invalid authentication mode');
  if (mode === 'local') return { enabled: false };
  const cfg = configuration || JSON.parse(fs.readFileSync(env.CLEANDNS_SSO_CONFIG_FILE || '/etc/cleandns-sso.json', 'utf8'));
  const origin = new URL(cfg.origin), issuer = new URL(cfg.issuer), agent = new URL(cfg.agentURL);
  if ([origin, issuer].some(u => u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash)) throw new Error('Fixed HTTPS origins required');
  if (agent.protocol !== 'http:' || !loopback(agent.hostname.replace(/^\[|\]$/g, '')) || agent.username || agent.password || !/^\/[a-z0-9-]+$/.test(agent.pathname) || agent.search || agent.hash) throw new Error('Fixed loopback identity agent required');
  if (typeof cfg.key !== 'string' || cfg.key.length < 32 || /[\r\n]/.test(cfg.key)) throw new Error('Identity agent credential required');
  for (const p of [cfg.panelPath, cfg.apiBase]) if (typeof p !== 'string' || !/^\/[a-zA-Z0-9._~/-]+$/.test(p) || p.startsWith('//') || p.includes('..')) throw new Error('Invalid public application path');
  const apiBase = cfg.apiBase.replace(/\/$/, '');
  const loginUrl = origin.origin + apiBase + '/sso/start';
  const allowedOrigins = new Set([origin.origin, ...(cfg.allowedOrigins || [])]);
  for (const value of allowedOrigins) {
    const u = new URL(value);
    if (u.origin !== value || u.protocol !== 'https:' || u.hostname !== origin.hostname) throw new Error('Invalid application origin');
  }

  function context(req) {
    const peer = String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
    if (!loopback(peer)) throw failure(403, 'identity_proxy_required');
    const ip = req.headers['x-real-ip'] || peer;
    if (typeof ip !== 'string' || !net.isIP(ip)) throw failure(400, 'invalid_client_address');
    const method = req.method.toUpperCase(), unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    const requestOrigin = req.headers.origin || '';
    if (unsafe && !allowedOrigins.has(requestOrigin)) throw failure(403, 'invalid_request_origin');
    return { ip, cookie: req.headers.cookie || '', method, origin: unsafe ? origin.origin : '', csrf: req.headers['x-csrf-token'] || '' };
  }

  function rpc(operation, body) {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(body);
      if (Buffer.byteLength(data) > 16384) return reject(failure(400, 'invalid_authentication_request'));
      const url = new URL(agent.href); url.pathname += '/' + operation;
      const req = http.request(url, { method: 'POST', headers: { Authorization: 'Bearer ' + cfg.key, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, response => {
        const chunks = []; let length = 0;
        response.on('data', chunk => { length += chunk.length; if (length > 65536) response.destroy(); else chunks.push(chunk); });
        response.on('error', () => reject(failure(503, 'identity_unavailable')));
        response.on('end', () => {
          let value; try { value = JSON.parse(Buffer.concat(chunks)); } catch { return reject(failure(503, 'identity_unavailable')); }
          if (response.statusCode !== 200) return reject(failure([400, 401, 403, 405, 429].includes(response.statusCode) ? response.statusCode : 503, response.statusCode === 401 ? 'sso_required' : 'identity_request_rejected'));
          resolve(value);
        });
      });
      const timer = setTimeout(() => req.destroy(), timeoutMs);
      req.on('close', () => clearTimeout(timer));
      req.on('error', () => reject(failure(503, 'identity_unavailable')));
      req.end(data);
    });
  }

  async function authorize(req) {
    const identity = await rpc('validate', context(req));
    if (identity.ok !== true || typeof identity.subject !== 'string' || typeof identity.csrfToken !== 'string') throw failure(503, 'invalid_identity_response');
    req.ssoIdentity = identity;
    return identity;
  }
  function redirect(res, location, cookies = []) {
    const u = new URL(location, origin);
    if (![origin.origin, issuer.origin].includes(u.origin) || u.username || u.password || /[\r\n]/.test(location)) throw failure(503, 'invalid_identity_redirect');
    if (!Array.isArray(cookies) || cookies.some(c => typeof c !== 'string' || /[\r\n]/.test(c))) throw failure(503, 'invalid_identity_cookie');
    res.writeHead(302, { Location: u.href, 'Cache-Control': 'no-store', ...(cookies.length ? { 'Set-Cookie': cookies } : {}) }); res.end();
  }
  function json(res, status, body, cookies) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...(cookies?.length ? { 'Set-Cookie': cookies } : {}) }); res.end(JSON.stringify(body));
  }
  function reject(res, error) { json(res, error.status || 503, { error: error.status ? error.message : 'identity_unavailable', authMode: 'sso', loginUrl }); }

  async function handleApi(req, res, url, profile) {
    const path = url.pathname;
    try {
      if (path === '/api/login') { json(res, 403, { error: 'sso_required', authMode: 'sso', loginUrl }); return true; }
      if (['/api/sso/start', '/api/sso/callback'].includes(path)) {
        if (req.method !== 'GET') throw failure(405, 'method_not_allowed');
        if (path === '/api/sso/callback' && url.searchParams.get('loggedout') === '1') {
          try { await authorize(req); redirect(res, cfg.panelPath); }
          catch (error) {
            if (error.status !== 401) throw error;
            const html = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CleanDNS · 已退出</title><body style="font-family:Times New Roman,STKaiti,KaiTi,serif;max-width:32rem;margin:18vh auto;padding:24px"><h1>已退出统一登录</h1><a href="' + loginUrl + '">重新登录 CleanDNS</a></body></html>';
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" }); res.end(html);
          }
          return true;
        }
        const result = await rpc(path.endsWith('/start') ? 'start' : 'callback', { ...context(req), query: url.search });
        redirect(res, result.location, result.cookies); return true;
      }
      if (path === '/api/logout') {
        if (req.method !== 'POST') throw failure(405, 'method_not_allowed');
        const result = await rpc('logout', context(req));
        const location = new URL(result.redirect_to);
        if (location.origin !== issuer.origin) throw failure(503, 'invalid_identity_redirect');
        json(res, 200, { ok: true, redirectTo: location.href, authMode: 'sso' }, result.cookies); return true;
      }
      const identity = await authorize(req);
      if (path === '/api/session' && req.method === 'GET') {
        json(res, 200, { authenticated: true, username: identity.username, profile: { ...profile(), name: identity.displayName || identity.username }, authMode: 'sso', csrfToken: identity.csrfToken, accountUrl: identity.accountUrl }); return true;
      }
      return false;
    } catch (error) {
      if (path === '/api/session' && req.method === 'GET' && error.status === 401) json(res, 200, { authenticated: false, authMode: 'sso', loginUrl });
      else reject(res, error);
      return true;
    }
  }
  async function panel(req, res) {
    try { await authorize(req); return true; }
    catch (error) { if (error.status === 401) redirect(res, loginUrl); else reject(res, error); return false; }
  }
  return { enabled: true, loginUrl, apiBase, panel, handleApi, authorize };
}
