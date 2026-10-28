import crypto from 'node:crypto';
import { decodeDnsResponse } from './dns-response.js';

const HASH_PREFIX_BYTES = 2;
const MAX_CACHE_ENTRIES = 4096;

const COMMON_TWO_LABEL_SUFFIXES = new Set(`
ac.jp ac.nz ac.uk asn.au co.id co.il co.in co.jp co.kr co.nz co.th co.uk
com.ar com.au com.br com.cn com.hk com.mx com.my com.sg com.tr com.tw
edu.au edu.cn edu.hk edu.sg gov.au gov.cn gov.uk id.au net.au net.cn net.nz
org.au org.cn org.nz org.uk
`.trim().split(/\s+/));

export const DOMAIN_PROTECTION_SERVICES = Object.freeze({
  safeBrowsing: Object.freeze({
    id: 'safeBrowsing',
    suffix: 'sb.dns.adguard.com',
    upstream: 'https://family.adguard-dns.com/dns-query',
    rule: 'safe-browsing:adguard-malware-shavar'
  }),
  parental: Object.freeze({
    id: 'parental',
    suffix: 'pc.dns.adguard.com',
    upstream: 'https://family.adguard-dns.com/dns-query',
    rule: 'parental:category-blacklisted'
  })
});

export class DomainProtectionChecker {
  constructor({ query, now = () => Date.now(), maxCacheEntries = MAX_CACHE_ENTRIES } = {}) {
    if (typeof query !== 'function') throw new TypeError('domain protection query function is required');
    this.query = query;
    this.now = now;
    this.maxCacheEntries = Math.max(16, Number(maxCacheEntries) || MAX_CACHE_ENTRIES);
    this.cache = new Map();
    this.pending = new Map();
    this.runtime = Object.fromEntries(Object.keys(DOMAIN_PROTECTION_SERVICES).map((id) => [id, emptyRuntime()]));
  }

  async check(domain, settings = {}) {
    const services = ['safeBrowsing', 'parental']
      .filter((id) => settings[id]?.enabled === true)
      .map((id) => ({ ...DOMAIN_PROTECTION_SERVICES[id], ...settings[id], id }));
    if (!services.length) return null;

    const results = await Promise.all(services.map((service) => this.checkService(domain, service)));
    return results.find((result) => result?.blocked) || null;
  }

  async checkService(domain, service) {
    const normalized = normalizeProtectionDomain(domain);
    if (!normalized) return null;
    const key = `${service.id}:${normalized}`;
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > this.now()) {
      this.runtime[service.id].cacheHits += 1;
      return cached.result;
    }
    if (cached) this.cache.delete(key);
    if (this.pending.has(key)) return this.pending.get(key);

    const task = this.queryAndMatch(normalized, service)
      .then((result) => {
        const ttlMinutes = clampNumber(service.cacheTtlMinutes, 1, 1440, 30);
        this.cache.set(key, { result, expiresAt: this.now() + ttlMinutes * 60_000 });
        this.trimCache();
        return result;
      })
      .catch((error) => {
        const runtime = this.runtime[service.id];
        runtime.failures += 1;
        runtime.lastError = error?.message || String(error || 'domain_protection_failed');
        runtime.lastErrorAt = new Date(this.now()).toISOString();
        return null;
      })
      .finally(() => this.pending.delete(key));
    this.pending.set(key, task);
    return task;
  }

  async queryAndMatch(domain, service) {
    const hashes = protectionDomainHashes(domain);
    if (!hashes.length) return null;
    const question = protectionHashQuestion(hashes, service.suffix);
    const runtime = this.runtime[service.id];
    runtime.queries += 1;
    const response = await this.query(service, question);
    const received = protectionResponseHashes(response);
    const matchedHash = hashes.find((hash) => received.has(hash));
    runtime.lastSuccessAt = new Date(this.now()).toISOString();
    runtime.lastError = '';
    runtime.lastErrorAt = '';
    if (!matchedHash) return null;
    runtime.blocked += 1;
    return { blocked: true, service: service.id, rule: service.rule, matchedHash };
  }

  clear() {
    this.cache.clear();
    this.pending.clear();
  }

  status() {
    return {
      cacheEntries: this.cache.size,
      pending: this.pending.size,
      services: Object.fromEntries(Object.entries(this.runtime).map(([id, value]) => [id, { ...value }]))
    };
  }

  trimCache() {
    while (this.cache.size > this.maxCacheEntries) this.cache.delete(this.cache.keys().next().value);
  }
}

export function protectionDomainCandidates(domain) {
  const normalized = normalizeProtectionDomain(domain);
  if (!normalized) return [];
  const labels = normalized.split('.');
  if (labels.length < 2) return [];
  const suffixLabels = COMMON_TWO_LABEL_SUFFIXES.has(labels.slice(-2).join('.')) ? 2 : 1;
  const registrableIndex = labels.length - suffixLabels - 1;
  if (registrableIndex < 0) return [];
  const start = Math.max(0, registrableIndex - 3);
  const result = [];
  for (let index = start; index <= registrableIndex; index += 1) result.push(labels.slice(index).join('.'));
  return result;
}

export function protectionDomainHashes(domain) {
  return protectionDomainCandidates(domain).map((candidate) => crypto.createHash('sha256').update(candidate).digest('hex'));
}

export function protectionHashQuestion(hashes, suffix) {
  const normalizedSuffix = normalizeProtectionDomain(suffix);
  if (!normalizedSuffix) throw new Error('bad_domain_protection_suffix');
  const prefixes = (hashes || [])
    .map((hash) => String(hash || '').toLowerCase())
    .filter((hash) => /^[0-9a-f]{64}$/.test(hash))
    .map((hash) => hash.slice(0, HASH_PREFIX_BYTES * 2));
  if (!prefixes.length) throw new Error('bad_domain_protection_hashes');
  return `${prefixes.join('.')}.${normalizedSuffix}`;
}

export function protectionResponseHashes(packet) {
  const hashes = new Set();
  const decoded = decodeDnsResponse(packet, { maxAnswers: 64 });
  for (const answer of decoded.answers || []) {
    if (answer.type !== 'TXT') continue;
    for (const value of String(answer.value || '').split(/\s+/)) {
      const normalized = value.toLowerCase();
      if (/^[0-9a-f]{64}$/.test(normalized)) hashes.add(normalized);
    }
  }
  return hashes;
}

function normalizeProtectionDomain(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!normalized || normalized.length > 253 || !normalized.includes('.')) return '';
  const labels = normalized.split('.');
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9_-]+$/.test(label))) return '';
  return normalized;
}

function clampNumber(value, min, max, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function emptyRuntime() {
  return { queries: 0, cacheHits: 0, blocked: 0, failures: 0, lastSuccessAt: '', lastErrorAt: '', lastError: '' };
}
