import dgram from 'node:dgram';
import dns from 'node:dns';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { closeDoqUpstreamBridge, queryDoqUpstream } from './doq-upstream.js';

const MAX_DNS_MESSAGE_SIZE = 65535;
const DEFAULT_PORTS = Object.freeze({
  udp: 53,
  tcp: 53,
  tls: 853,
  quic: 853,
  https: 443
});

export function normalizeUpstreamAddress(value) {
  let raw = String(value || '').trim();
  if (!raw || /\s/.test(raw)) throw new Error('bad_upstream');
  if (net.isIP(raw)) return raw;
  const bracketedIpv6 = raw.match(/^\[([^\]]+)\]$/);
  if (bracketedIpv6 && net.isIP(bracketedIpv6[1]) === 6) return bracketedIpv6[1];

  if (/^doh:\/\//i.test(raw)) raw = raw.replace(/^doh:/i, 'https:');
  if (/^dot:\/\//i.test(raw)) raw = raw.replace(/^dot:/i, 'tls:');
  if (/^doq:\/\//i.test(raw)) raw = raw.replace(/^doq:/i, 'quic:');

  if (!raw.includes('://')) return normalizePlainUpstream(raw);

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('bad_upstream');
  }
  if (parsed.username || parsed.password || parsed.hash) throw new Error('bad_upstream');

  const protocol = parsed.protocol.slice(0, -1).toLowerCase();
  if (!Object.hasOwn(DEFAULT_PORTS, protocol)) throw new Error('unsupported_upstream_protocol');
  const host = normalizeUpstreamHost(parsed.hostname);
  const port = normalizeUpstreamPort(parsed.port, DEFAULT_PORTS[protocol]);

  if (protocol === 'https') {
    if (!parsed.pathname || parsed.pathname === '/') throw new Error('bad_doh_path');
    parsed.protocol = 'https:';
    parsed.hostname = formatUrlHostname(host);
    parsed.port = parsed.port || '';
    return parsed.toString();
  }

  if ((parsed.pathname && parsed.pathname !== '/') || parsed.search) throw new Error('bad_upstream');
  const explicitPort = Boolean(parsed.port);
  return `${protocol}://${formatHost(host)}${explicitPort ? `:${port}` : ''}`;
}

export function parseUpstreamAddress(value) {
  const normalized = normalizeUpstreamAddress(value);
  if (!normalized.includes('://')) {
    return { value: normalized, protocol: 'udp', host: normalized, port: DEFAULT_PORTS.udp };
  }

  const parsed = new URL(normalized);
  const protocol = parsed.protocol.slice(0, -1);
  const host = stripIpv6Brackets(parsed.hostname);
  const port = normalizeUpstreamPort(parsed.port, DEFAULT_PORTS[protocol]);
  return {
    value: normalized,
    protocol,
    host,
    port,
    url: protocol === 'https' ? normalized : ''
  };
}

export function upstreamProtocol(value) {
  return parseUpstreamAddress(value).protocol;
}

export function closeUpstreamTransports() {
  closeDoqUpstreamBridge();
}

export async function queryDnsUpstream(value, packet, timeoutMs, options = {}) {
  if (!Buffer.isBuffer(packet) || packet.length < 12 || packet.length > MAX_DNS_MESSAGE_SIZE) {
    throw new Error('bad_dns_query');
  }
  const target = parseUpstreamAddress(value);
  const timeout = normalizeTimeout(timeoutMs);
  let response;
  if (target.protocol === 'udp') {
    const started = Date.now();
    const udpTarget = options.lookup && !net.isIP(target.host)
      ? { ...target, host: await lookupOne(options.lookup, target.host, timeout) }
      : target;
    const udpTimeout = Math.max(1, timeout - (Date.now() - started));
    response = await queryUdp(udpTarget, packet, udpTimeout);
    response = validateDnsResponse(response);
    if ((response[2] & 0x02) !== 0) {
      const remaining = Math.max(1, timeout - (Date.now() - started));
      response = await queryTcp({ ...target, host: udpTarget.host, protocol: 'tcp' }, packet, remaining, false);
    }
  } else if (target.protocol === 'tcp') {
    response = await queryTcp(target, packet, timeout, false, options.lookup);
  } else if (target.protocol === 'tls') {
    response = await queryTcp(target, packet, timeout, true, options.lookup);
  } else if (target.protocol === 'https') {
    response = await queryDoh(target, packet, timeout, options.lookup);
  } else if (target.protocol === 'quic') {
    const started = Date.now();
    const resolvedHost = net.isIP(target.host)
      ? target.host
      : await lookupOne(options.lookup || dns.lookup, target.host, timeout);
    const remaining = Math.max(1, timeout - (Date.now() - started));
    const queryDoq = options.queryDoq || queryDoqUpstream;
    response = await queryDoq({
      address: `${formatHost(resolvedHost)}:${target.port}`,
      serverName: target.host,
      timeoutMs: remaining,
      packet
    });
  } else {
    throw new Error('unsupported_upstream_protocol');
  }
  return validateDnsResponse(response);
}

function normalizePlainUpstream(raw) {
  let parsed;
  try {
    const candidate = net.isIP(raw) === 6 ? `udp://[${raw}]` : `udp://${raw}`;
    parsed = new URL(candidate);
  } catch {
    throw new Error('bad_upstream');
  }
  if (parsed.username || parsed.password || parsed.hash || parsed.search || (parsed.pathname && parsed.pathname !== '/')) {
    throw new Error('bad_upstream');
  }
  const host = normalizeUpstreamHost(parsed.hostname);
  if (!parsed.port) return host;
  const port = normalizeUpstreamPort(parsed.port, DEFAULT_PORTS.udp);
  return `udp://${formatHost(host)}:${port}`;
}

function normalizeUpstreamHost(value) {
  const host = stripIpv6Brackets(String(value || '').trim()).toLowerCase().replace(/\.$/, '');
  if (net.isIP(host)) return host;
  if (host === 'localhost') return host;
  if (host.length > 253 || !host.includes('.')) throw new Error('bad_upstream_host');
  const labels = host.split('.');
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error('bad_upstream_host');
  }
  return host;
}

function normalizeUpstreamPort(value, fallback) {
  if (value === '' || value === null || typeof value === 'undefined') return fallback;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad_upstream_port');
  return port;
}

function normalizeTimeout(value) {
  const timeout = Number(value);
  if (!Number.isFinite(timeout) || timeout < 1) throw new Error('bad_timeout');
  return Math.min(30000, Math.floor(timeout));
}

function stripIpv6Brackets(value) {
  return String(value || '').replace(/^\[|\]$/g, '');
}

function formatHost(host) {
  return net.isIP(host) === 6 ? `[${host}]` : host;
}

function formatUrlHostname(host) {
  return net.isIP(host) === 6 ? `[${host}]` : host;
}

function queryUdp(target, packet, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIP(target.host) === 6 ? 'udp6' : 'udp4');
    let settled = false;
    const finish = (error, response) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // The timeout may fire before the datagram socket finishes binding.
      }
      if (error) reject(error);
      else resolve(response);
    };
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    socket.once('error', (error) => finish(error));
    socket.once('message', (message) => finish(null, message));
    socket.connect(target.port, target.host, () => {
      socket.send(packet, (error) => {
        if (error) finish(error);
      });
    });
  });
}

function queryTcp(target, packet, timeoutMs, encrypted, lookup) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let expectedLength = -1;
    let received = Buffer.alloc(0);
    const readyEvent = encrypted ? 'secureConnect' : 'connect';
    const options = encrypted
      ? {
          host: target.host,
          port: target.port,
          servername: net.isIP(target.host) ? undefined : target.host,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
          lookup,
          checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(target.host, certificate)
        }
      : { host: target.host, port: target.port, lookup };
    const socket = encrypted ? tls.connect(options) : net.connect(options);
    const finish = (error, response) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(response);
    };
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    socket.once('error', (error) => finish(error));
    socket.once('end', () => finish(new Error('upstream_closed')));
    socket.once('close', () => finish(new Error('upstream_closed')));
    socket.once(readyEvent, () => {
      socket.setNoDelay(true);
      const frame = Buffer.alloc(packet.length + 2);
      frame.writeUInt16BE(packet.length, 0);
      packet.copy(frame, 2);
      socket.write(frame);
    });
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length >= 2 && expectedLength < 0) {
        expectedLength = received.readUInt16BE(0);
        if (expectedLength < 12 || expectedLength > MAX_DNS_MESSAGE_SIZE) {
          return finish(new Error('bad_dns_response'));
        }
      }
      if (expectedLength >= 0 && received.length >= expectedLength + 2) {
        finish(null, received.subarray(2, expectedLength + 2));
      }
    });
  });
}

async function queryDoh(target, packet, timeoutMs, lookup) {
  if (lookup) return queryDohWithLookup(target, packet, timeoutMs, lookup);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(target.url, {
      method: 'POST',
      headers: {
        accept: 'application/dns-message',
        'content-type': 'application/dns-message'
      },
      body: packet,
      redirect: 'error',
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`doh_http_${response.status}`);
    const contentType = String(response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/dns-message') throw new Error('bad_doh_content_type');
    return Buffer.from(await response.arrayBuffer());
  } catch (error) {
    if (controller.signal.aborted) throw new Error('timeout');
    if (error?.message === 'fetch failed' && error?.cause?.code) throw new Error(error.cause.code);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function queryDohWithLookup(target, packet, timeoutMs, lookup) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let received = 0;
    const chunks = [];
    const request = https.request(target.url, {
      method: 'POST',
      headers: {
        accept: 'application/dns-message',
        'content-type': 'application/dns-message',
        'content-length': packet.length
      },
      lookup,
      minVersion: 'TLSv1.2'
    }, (response) => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        return finish(new Error(`doh_http_${response.statusCode}`));
      }
      const contentType = String(response.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      if (contentType !== 'application/dns-message') {
        response.resume();
        return finish(new Error('bad_doh_content_type'));
      }
      response.on('data', (chunk) => {
        received += chunk.length;
        if (received > MAX_DNS_MESSAGE_SIZE) return finish(new Error('bad_dns_response'));
        chunks.push(chunk);
      });
      response.once('end', () => finish(null, Buffer.concat(chunks)));
      response.once('error', (error) => finish(error));
    });
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    const finish = (error, response) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.destroy();
      if (error) reject(error);
      else resolve(response);
    };
    request.once('error', (error) => finish(error));
    request.end(packet);
  });
}

function lookupOne(lookup, hostname, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, address) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) return reject(error);
      if (!net.isIP(address)) return reject(new Error('bad_bootstrap_response'));
      resolve(address);
    };
    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs);
    try {
      lookup(hostname, { family: 0, all: false, verbatim: true }, finish);
    } catch (error) {
      finish(error);
    }
  });
}

function validateDnsResponse(response) {
  if (!Buffer.isBuffer(response) || response.length < 12 || response.length > MAX_DNS_MESSAGE_SIZE) {
    throw new Error('bad_dns_response');
  }
  return response;
}
