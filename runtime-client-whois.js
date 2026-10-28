import dns from 'node:dns';
import net from 'node:net';

const DEFAULT_SERVER = 'whois.arin.net';
const DEFAULT_PORT = 43;
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000;
const DEFAULT_MAX_CACHE_ENTRIES = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_FIELD_LENGTH = 250;
const DEFAULT_CONCURRENCY = 4;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export class RuntimeWhoisResolver {
  constructor(options = {}) {
    this.server = parseWhoisEndpoint(options.server || DEFAULT_SERVER, options.port || DEFAULT_PORT);
    this.timeoutMs = boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, 100, 60_000);
    this.cacheTtlMs = boundedInteger(options.cacheTtlMs, DEFAULT_CACHE_TTL_MS, 1000, 7 * 24 * 60 * 60 * 1000);
    this.maxCacheEntries = boundedInteger(options.maxCacheEntries, DEFAULT_MAX_CACHE_ENTRIES, 1, 100_000);
    this.maxResponseBytes = boundedInteger(options.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, 1024, 1024 * 1024);
    this.maxRedirects = boundedInteger(options.maxRedirects, DEFAULT_MAX_REDIRECTS, 1, 10);
    this.maxFieldLength = boundedInteger(options.maxFieldLength, DEFAULT_MAX_FIELD_LENGTH, 16, 2048);
    this.concurrency = boundedInteger(options.concurrency, DEFAULT_CONCURRENCY, 1, 32);
    this.allowPrivateServer = options.allowPrivateServer === true;
    this.lookupHost = options.lookupHost || dns.promises.lookup.bind(dns.promises);
    this.createConnection = options.createConnection || ((value) => net.createConnection(value));
    this.now = options.now || Date.now;
    this.cache = new Map();
    this.pending = new Map();
    this.queue = [];
    this.sockets = new Set();
    this.running = 0;
    this.closed = false;
  }

  lookup(value) {
    const address = normalizeAddress(value);
    if (!address) return Promise.resolve(this.result(address, 'error', null, 'bad_whois_address'));
    if (!isPublicWhoisAddress(address)) return Promise.resolve(this.result(address, 'not-applicable'));
    if (this.closed) return Promise.resolve(this.result(address, 'error', null, 'whois_resolver_closed'));

    const cached = this.cache.get(address);
    if (cached && cached.expiresAt > this.now()) {
      this.cache.delete(address);
      this.cache.set(address, cached);
      return Promise.resolve(cloneResult(cached.result, true));
    }
    if (cached) this.cache.delete(address);
    if (this.pending.has(address)) return this.pending.get(address);

    const promise = new Promise((resolve) => {
      this.queue.push({ address, resolve });
      this.pump();
    }).finally(() => {
      if (this.pending.get(address) === promise) this.pending.delete(address);
    });
    this.pending.set(address, promise);
    return promise;
  }

  status() {
    return {
      server: formatWhoisEndpoint(this.server),
      cacheEntries: this.cache.size,
      pending: this.pending.size,
      queued: this.queue.length,
      running: this.running,
      concurrency: this.concurrency,
      closed: this.closed
    };
  }

  clear() {
    this.cache.clear();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    const queued = this.queue.splice(0);
    for (const job of queued) job.resolve(this.result(job.address, 'error', null, 'whois_resolver_closed'));
    for (const socket of this.sockets) socket.destroy(new Error('whois_resolver_closed'));
    this.sockets.clear();
  }

  pump() {
    while (!this.closed && this.running < this.concurrency && this.queue.length) {
      const job = this.queue.shift();
      this.running += 1;
      this.resolveAddress(job.address)
        .then(job.resolve)
        .finally(() => {
          this.running -= 1;
          this.pump();
        });
    }
  }

  async resolveAddress(address) {
    let result;
    try {
      const lookup = await this.queryAll(address);
      const info = normalizeWhoisInfo(lookup.info, this.maxFieldLength);
      result = this.result(address, Object.keys(info).length ? 'resolved' : 'not-found', info, '', lookup.server);
    } catch (error) {
      result = this.result(address, 'error', null, normalizeWhoisError(error));
    }
    this.cache.set(address, { result, expiresAt: this.now() + this.cacheTtlMs });
    while (this.cache.size > this.maxCacheEntries) this.cache.delete(this.cache.keys().next().value);
    return cloneResult(result, false);
  }

  result(address, status, info = null, error = '', server = '') {
    const checkedAt = this.now();
    return {
      address,
      status,
      info: info && Object.keys(info).length ? { ...info } : null,
      error: String(error || ''),
      server: String(server || ''),
      checkedAt: new Date(checkedAt).toISOString(),
      nextLookupAt: new Date(checkedAt + this.cacheTtlMs).toISOString(),
      cached: false
    };
  }

  async queryAll(address) {
    let endpoint = this.server;
    const visited = new Set();
    for (let redirect = 0; redirect < this.maxRedirects; redirect += 1) {
      const key = formatWhoisEndpoint(endpoint).toLowerCase();
      if (visited.has(key)) throw new Error('whois_redirect_loop');
      visited.add(key);
      const data = await this.queryServer(address, endpoint, redirect === 0 && endpoint.host.toLowerCase() === DEFAULT_SERVER);
      const info = parseWhoisResponse(data, this.maxFieldLength);
      if (!info.whois) return { info, server: key };
      endpoint = parseWhoisEndpoint(info.whois, DEFAULT_PORT);
    }
    throw new Error('whois_redirect_limit');
  }

  async queryServer(address, endpoint, arinQuery) {
    const target = await this.resolveEndpoint(endpoint);
    return new Promise((resolve, reject) => {
      let settled = false;
      let size = 0;
      const chunks = [];
      const socket = this.createConnection({ host: target.address, port: endpoint.port, family: target.family });
      this.sockets.add(socket);
      const finish = (error, value = '') => {
        if (settled) return;
        settled = true;
        this.sockets.delete(socket);
        socket.destroy();
        if (error) reject(error); else resolve(value);
      };
      socket.setTimeout(this.timeoutMs, () => finish(new Error('whois_timeout')));
      socket.once('error', (error) => finish(error));
      socket.on('data', (chunk) => {
        const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += value.length;
        if (size > this.maxResponseBytes) {
          finish(new Error('whois_response_too_large'));
          return;
        }
        chunks.push(value);
      });
      socket.once('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
      socket.once('connect', () => {
        socket.write(`${arinQuery ? 'n + ' : ''}${address}\r\n`, (error) => {
          if (error) finish(error);
        });
      });
    });
  }

  async resolveEndpoint(endpoint) {
    if (net.isIP(endpoint.host)) {
      if (!this.allowPrivateServer && !isPublicWhoisAddress(endpoint.host)) throw new Error('whois_server_not_public');
      return { address: endpoint.host, family: net.isIP(endpoint.host) };
    }
    let records;
    try {
      records = await this.lookupHost(endpoint.host, { all: true, verbatim: true });
    } catch {
      throw new Error('whois_server_lookup_failed');
    }
    const values = (Array.isArray(records) ? records : [records]).filter((record) => (
      record && net.isIP(record.address) && (this.allowPrivateServer || isPublicWhoisAddress(record.address))
    ));
    if (!values.length) throw new Error('whois_server_not_public');
    return values[0];
  }
}

export function parseWhoisResponse(value, maxFieldLength = DEFAULT_MAX_FIELD_LENGTH) {
  const result = {};
  let preferredOrg = '';
  for (const rawLine of String(value || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('%')) continue;
    const separator = line.indexOf(':');
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    let data = line.slice(separator + 1).trim();
    if (!data) continue;
    if (key === 'orgname' || key === 'org-name' || key === 'organization') {
      preferredOrg = trimField(data, maxFieldLength);
      result.orgname = preferredOrg;
    } else if (key === 'descr' || key === 'netname') {
      if (!preferredOrg && !result.orgname) result.orgname = trimField(data, maxFieldLength);
    } else if (key === 'city' || key === 'country') {
      result[key] = trimField(data, maxFieldLength);
    } else if (key === 'whois' || key === 'refer') {
      result.whois = trimField(data, maxFieldLength);
    } else if (key === 'referralserver') {
      data = data.replace(/^whois:\/\//i, '');
      result.whois = trimField(data, maxFieldLength);
    }
  }
  return result;
}

export function normalizeWhoisInfo(value, maxFieldLength = DEFAULT_MAX_FIELD_LENGTH) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const result = {};
  for (const key of ['orgname', 'city', 'country']) {
    const data = trimField(source[key], maxFieldLength);
    if (data) result[key] = data;
  }
  return result;
}

export function isPublicWhoisAddress(value) {
  const address = normalizeAddress(value);
  const family = net.isIP(address);
  if (family === 4) {
    const bytes = address.split('.').map(Number);
    const [a, b, c] = bytes;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (family !== 6) return false;
  if (address.startsWith('::ffff:') && net.isIP(address.slice(7)) === 4) return isPublicWhoisAddress(address.slice(7));
  const bytes = ipv6Bytes(address);
  if (!bytes) return false;
  if (bytes.every((byte) => byte === 0)) return false;
  if (bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1) return false;
  if ((bytes[0] & 0xfe) === 0xfc || (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) || bytes[0] === 0xff) return false;
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) return false;
  if (bytes[0] === 0x01 && bytes[1] === 0x00 && bytes.slice(2, 8).every((byte) => byte === 0)) return false;
  return true;
}

function parseWhoisEndpoint(value, fallbackPort) {
  let raw = String(value || '').trim().replace(/^whois:\/\//i, '');
  raw = raw.split(/[/?#\s]/, 1)[0];
  if (!raw) throw new Error('bad_whois_server');
  let host = raw;
  let port = Number(fallbackPort) || DEFAULT_PORT;
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end < 1) throw new Error('bad_whois_server');
    host = raw.slice(1, end);
    if (raw.slice(end + 1)) {
      if (!/^:\d+$/.test(raw.slice(end + 1))) throw new Error('bad_whois_server');
      port = Number(raw.slice(end + 2));
    }
  } else if (!net.isIP(raw) && raw.split(':').length === 2 && /:\d+$/.test(raw)) {
    const split = raw.lastIndexOf(':');
    host = raw.slice(0, split);
    port = Number(raw.slice(split + 1));
  }
  host = host.trim().replace(/\.+$/, '').toLowerCase();
  if ((!net.isIP(host) && !HOSTNAME.test(host)) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('bad_whois_server');
  }
  return { host, port };
}

function formatWhoisEndpoint(value) {
  const host = net.isIP(value.host) === 6 ? `[${value.host}]` : value.host;
  return `${host}:${value.port}`;
}

function normalizeAddress(value) {
  let address = String(value || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (address.startsWith('::ffff:') && net.isIP(address.slice(7)) === 4) address = address.slice(7);
  if (net.isIP(address) === 4) return address.split('.').map((part) => String(Number(part))).join('.');
  return net.isIP(address) === 6 ? address : '';
}

function trimField(value, maxLength) {
  const text = String(value || '').trim().replace(/[\u0000-\u001f\u007f]+/g, ' ');
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 3))}...`;
}

function cloneResult(value, cached) {
  return { ...value, info: value.info ? { ...value.info } : null, cached };
}

function normalizeWhoisError(error) {
  const message = String(error?.message || error || 'whois_query_failed').toLowerCase();
  if (message.includes('timeout')) return 'whois_timeout';
  if (message.includes('response_too_large')) return 'whois_response_too_large';
  if (message.includes('redirect')) return message.includes('loop') ? 'whois_redirect_loop' : 'whois_redirect_limit';
  if (message.includes('not_public')) return 'whois_server_not_public';
  if (message.includes('lookup')) return 'whois_server_lookup_failed';
  if (message.includes('closed')) return 'whois_resolver_closed';
  return 'whois_query_failed';
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value);
  return Number.isInteger(number) && number >= min && number <= max ? number : fallback;
}

function ipv6Bytes(value) {
  let address = String(value || '').toLowerCase().split('%')[0];
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const expandIpv4 = (parts) => {
    if (!parts.length || net.isIP(parts[parts.length - 1]) !== 4) return parts;
    const bytes = parts.pop().split('.').map(Number);
    parts.push(((bytes[0] << 8) | bytes[1]).toString(16), ((bytes[2] << 8) | bytes[3]).toString(16));
    return parts;
  };
  expandIpv4(left);
  expandIpv4(right);
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return null;
  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) => bytes.writeUInt16BE(Number.parseInt(group, 16), index * 2));
  return bytes;
}
