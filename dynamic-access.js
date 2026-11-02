import net from 'node:net';
import { domainToASCII } from 'node:url';
import { Resolver } from 'node:dns/promises';

export function normalizeAllowedDomains(value = []) {
  if (!Array.isArray(value) && typeof value !== 'string') throw new Error('bad_allowed_domains');
  const lines = Array.isArray(value) ? value : value.split(/[\r\n,]+/);
  if (lines.length > 256) throw new Error('too_many_allowed_domains');
  const domains = new Set();
  for (const line of lines) {
    if (typeof line !== 'string') throw new Error('bad_allowed_domain');
    const raw = line.trim();
    if (!raw || raw.startsWith('#')) continue;
    if (/[\s/:@?#*\\\[\]]/.test(raw)) throw new Error('bad_allowed_domain');
    const host = domainToASCII(raw.replace(/\.$/, '').toLowerCase());
    if (!host || net.isIP(host) || host.length > 253 || !host.includes('.') || !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('bad_allowed_domain');
    domains.add(host);
  }
  if (domains.size > 64) throw new Error('too_many_allowed_domains');
  return [...domains];
}

export function normalizeDynamicRefresh(value = 0) {
  if ((typeof value !== 'number' && typeof value !== 'string') || value === '') throw new Error('bad_dynamic_refresh');
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || (seconds !== 0 && (seconds < 10 || seconds > 86400))) throw new Error('bad_dynamic_refresh');
  return seconds;
}

// No disk cache: a restart must resolve names again before allowing their IPs.
export class DynamicAccess {
  constructor({ lookup, now = Date.now, timers = true } = {}) {
    this.lookupOverride = lookup; this.now = now; this.timers = timers;
    this.entries = new Map(); this.refreshSeconds = 0; this.closed = false; this.manualAt = -Infinity;
  }
  configure(access, servers = []) {
    if (this.closed) return;
    const signature = JSON.stringify(servers);
    if (!this.lookupOverride && signature !== this.serverSignature) {
      this.resolver?.cancel(); this.entries.clear();
      this.resolver = new Resolver({ timeout: 2000, tries: 1 });
      this.resolver.setServers(servers.length ? servers : ['1.1.1.1', '223.5.5.5']);
      this.serverSignature = signature;
    }
    this.refreshSeconds = access.dynamicRefreshSeconds || 0;
    const groups = [access, ...Object.values(access.protocols || {}).filter(policy => policy.mode === 'custom')];
    const hosts = new Set(groups.flatMap(policy => policy.allowedDomains || []));
    for (const host of this.entries.keys()) if (!hosts.has(host)) this.entries.delete(host);
    for (const host of hosts) {
      if (!this.entries.has(host)) this.entries.set(host, { host, families: [4, 6].map(family => ({ family, addresses: [], nextAt: 0, validUntil: 0, staleUntil: 0, checkedAt: 0, error: '', ttl: null })) });
      else for (const record of this.entries.get(host).families) {
        if (record.checkedAt && !record.error) record.nextAt = Math.min(record.nextAt, record.checkedAt + this.interval(record.ttl) * 1000);
      }
    }
    this.schedule();
  }
  interval(ttl) { return this.refreshSeconds || Math.max(10, Math.min(3600, Number.isFinite(ttl) ? ttl : 60)); }
  addresses(hosts) {
    const now = this.now();
    return [...new Set(hosts.flatMap(host => this.entries.get(host)?.families.flatMap(record => now < record.staleUntil ? record.addresses : []) || []))];
  }
  snapshot() {
    const now = this.now();
    return { automatic: !this.refreshSeconds, refreshSeconds: this.refreshSeconds, minSeconds: 10, maxAutoSeconds: 3600, staleGraceSeconds: 300,
      domains: [...this.entries.values()].map(entry => ({ host: entry.host, checking: Boolean(entry.checking), families: entry.families.map(record => ({
        family: record.family, addresses: now < record.staleUntil ? [...record.addresses] : [], ttl: record.ttl,
        checkedAt: record.checkedAt || null, nextCheckAt: record.nextAt || null, expiresAt: record.staleUntil || null,
        state: !record.checkedAt ? 'pending' : record.addresses.length && now >= record.staleUntil ? 'expired' : record.error ? (record.addresses.length && now < record.staleUntil ? 'stale' : 'error') : 'ok', error: record.error
      })) })) };
  }
  requestRefresh() {
    if (this.now() - this.manualAt < 10000) return false;
    this.manualAt = this.now();
    for (const entry of this.entries.values()) for (const record of entry.families) record.nextAt = 0;
    this.schedule();
    return true;
  }
  schedule() {
    clearTimeout(this.timer);
    if (!this.timers || this.closed || !this.entries.size || this.running) return;
    const next = Math.min(...[...this.entries.values()].flatMap(entry => entry.families.map(record => record.nextAt)));
    this.timer = setTimeout(() => { this.refresh().catch(() => {}); }, Math.max(0, next - this.now()));
    this.timer.unref?.();
  }
  async refresh() {
    if (this.running) return this.running;
    if (this.closed) return;
    const due = [...this.entries.values()].filter(entry => entry.families.some(record => record.nextAt <= this.now()));
    let index = 0;
    const run = async () => { while (index < due.length && !this.closed) await this.resolveEntry(due[index++]); };
    this.running = Promise.all(Array.from({ length: Math.min(4, due.length) }, run));
    try { await this.running; } finally { this.running = null; this.schedule(); }
  }
  async resolveEntry(entry) {
    entry.checking = true;
    const resolver = this.resolver;
    await Promise.all(entry.families.filter(record => record.nextAt <= this.now()).map(async record => {
      let result, error = '';
      try { result = await (this.lookupOverride ? this.lookupOverride(entry.host, record.family) : resolver[record.family === 4 ? 'resolve4' : 'resolve6'](entry.host, { ttl: true })); }
      catch (err) { error = /^[A-Z_]+$/.test(err.code || '') ? err.code : 'LOOKUP_FAILED'; }
      if (this.closed || this.entries.get(entry.host) !== entry) return;
      const now = this.now(); record.checkedAt = now;
      if (!error) {
        const records = Array.isArray(result) ? result.filter(item => net.isIP(item.address) === record.family) : [];
        if (records.length > 128) error = 'TOO_MANY_ADDRESSES';
        else {
          const ttl = Math.min(...records.map(item => Math.max(0, Number(item.ttl) || 0)));
          record.ttl = records.length ? ttl : null;
          record.addresses = [...new Set(records.map(item => item.address))];
          record.validUntil = now + this.interval(record.ttl) * 1000;
          record.staleUntil = record.validUntil + 300000;
          record.nextAt = record.validUntil;
        }
      }
      if (error) {
        // A negative answer withdraws that family's old addresses immediately.
        if (['ENODATA', 'ENOTFOUND'].includes(error)) { record.addresses = []; record.staleUntil = 0; record.ttl = null; }
        record.nextAt = now + 30000;
      }
      record.error = error;
    }));
    entry.checking = false;
  }
  close() { this.closed = true; clearTimeout(this.timer); this.resolver?.cancel(); this.entries.clear(); }
}
