import { HOUR_MS } from './retention.js';

export function dashboardWindowBounds(retentionHours, now = Date.now()) {
  const hours = normalizeRetentionHours(retentionHours);
  const end = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  const start = end - hours * HOUR_MS;
  return {
    retentionHours: hours,
    start,
    end,
    startedAt: new Date(start).toISOString(),
    endedAt: new Date(end).toISOString()
  };
}

export function selectDashboardRows(rows, options = {}) {
  if (options.enabled === false) return [];
  const bounds = dashboardWindowBounds(options.retentionHours, options.now);
  const requestedStart = Number(options.start);
  const start = Number.isFinite(requestedStart) ? Math.max(bounds.start, requestedStart) : bounds.start;
  const ignoredDomains = options.ignoredEnabled === true
    ? normalizeDomains(options.ignoredDomains)
    : [];
  const ignoredClientIds = new Set((options.ignoredClientIds || []).map(String));

  return (rows || []).filter((row) => {
    const timestamp = Date.parse(row?.time || '');
    if (!Number.isFinite(timestamp) || timestamp < start || timestamp > bounds.end) return false;
    if (ignoredDomains.length && matchesIgnoredDomain(row?.qname, ignoredDomains)) return false;
    if (row?.clientPolicy?.ignoreStatistics === true) return false;
    if (row?.clientId && ignoredClientIds.has(String(row.clientId))) return false;
    return true;
  });
}

function normalizeRetentionHours(value) {
  const hours = Math.floor(Number(value));
  return Number.isFinite(hours) && hours > 0 ? hours : 24;
}

function normalizeDomains(values) {
  return [...new Set((values || []).map(normalizeDomain).filter(Boolean))];
}

function normalizeDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}

function matchesIgnoredDomain(value, domains) {
  const host = normalizeDomain(value);
  return Boolean(host) && domains.some((domain) => host === domain || host.endsWith('.' + domain));
}
