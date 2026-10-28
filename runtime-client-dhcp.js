import net from 'node:net';
import { normalizeDhcpMac } from './dhcp-config.js';

const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const MAX_LEASE_ROWS = 65_536;

export function resolveRuntimeClientDhcpLease(address, options = {}) {
  const ip = normalizeIpv4(address);
  if (!ip) return null;

  const now = normalizeNow(options.now);
  const dynamic = findDynamicLease(ip, options.dynamicLeases, now);
  if (dynamic) return dynamic;
  return findStaticLease(ip, options.staticLeases);
}

function findDynamicLease(address, rows, now) {
  for (const item of leaseRows(rows)) {
    const lease = normalizeLease(item, 'dynamic');
    if (!lease || lease.ip !== address || Date.parse(lease.expiresAt) <= now) continue;
    return lease;
  }
  return null;
}

function findStaticLease(address, rows) {
  for (const item of leaseRows(rows)) {
    const lease = normalizeLease(item, 'static');
    if (lease?.ip === address) return lease;
  }
  return null;
}

function leaseRows(value) {
  return Array.isArray(value) ? value.slice(0, MAX_LEASE_ROWS) : [];
}

function normalizeLease(value, kind) {
  const source = value && typeof value === 'object' ? value : {};
  const mac = normalizeDhcpMac(source.mac);
  const ip = normalizeIpv4(source.ip);
  if (!mac || !ip) return null;

  const lease = {
    kind,
    mac,
    ip,
    hostname: normalizeHostname(source.hostname)
  };
  if (kind === 'dynamic') {
    const expiresAt = normalizeTimestamp(source.expiresAt);
    if (!expiresAt) return null;
    lease.expiresAt = expiresAt;
  }
  return lease;
}

function normalizeIpv4(value) {
  const address = String(value || '').trim();
  return net.isIP(address) === 4 ? address : '';
}

function normalizeHostname(value) {
  const hostname = String(value || '').trim().replace(/\.+$/, '').slice(0, 253);
  if (!hostname) return '';
  return hostname.split('.').every((label) => HOST_LABEL_PATTERN.test(label)) ? hostname : '';
}

function normalizeTimestamp(value) {
  const timestamp = Date.parse(String(value || ''));
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : '';
}

function normalizeNow(value) {
  if (value instanceof Date) return value.getTime();
  const timestamp = Number(value);
  return Number.isFinite(timestamp) ? timestamp : Date.now();
}
