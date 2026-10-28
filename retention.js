export const HOUR_MS = 60 * 60 * 1000;

const STAT_KEYS = ['total', 'allowed', 'blocked', 'blockedFiltering', 'rewritten', 'safeBrowsing', 'parental', 'safeSearch', 'cached', 'upstream', 'errors', 'processingTimeMs', 'processingCount', 'rankingCount'];
const SERIES_KEYS = ['total', 'allowed', 'blocked', 'blockedFiltering', 'rewritten', 'safeBrowsing', 'parental', 'safeSearch', 'cached', 'upstream', 'errors', 'processingTimeMs', 'processingCount'];
const STORED_RANK_MAP_LIMIT = 512;
const AGGREGATE_RANK_MAP_LIMIT = 4096;

export function emptyStatsSnapshot() {
  return {
    total: 0,
    allowed: 0,
    blocked: 0,
    blockedFiltering: 0,
    rewritten: 0,
    safeBrowsing: 0,
    parental: 0,
    safeSearch: 0,
    cached: 0,
    upstream: 0,
    errors: 0,
    processingTimeMs: 0,
    processingCount: 0,
    rankingCount: 0,
    byType: {},
    byRule: {},
    byDomain: {},
    byBlockedDomain: {},
    byClient: {},
    upstreams: {}
  };
}

export function normalizeStatsSnapshot(value = {}) {
  const source = value && typeof value === 'object' ? value : {};
  const snapshot = emptyStatsSnapshot();
  for (const key of STAT_KEYS) snapshot[key] = nonNegativeNumber(source[key]);
  if (!Object.prototype.hasOwnProperty.call(source, 'blockedFiltering')) snapshot.blockedFiltering = snapshot.blocked;
  snapshot.byType = normalizeNumberMap(source.byType);
  snapshot.byRule = normalizeNumberMap(source.byRule);
  snapshot.byDomain = normalizeNumberMap(source.byDomain, STORED_RANK_MAP_LIMIT);
  snapshot.byBlockedDomain = normalizeNumberMap(source.byBlockedDomain, STORED_RANK_MAP_LIMIT);
  snapshot.byClient = normalizeNumberMap(source.byClient, STORED_RANK_MAP_LIMIT);
  snapshot.upstreams = normalizeUpstreamMap(source.upstreams);
  return snapshot;
}

export function loadStatsBuckets(value, now = Date.now()) {
  const source = value && typeof value === 'object' ? value : {};
  if (source.version === 2 && Array.isArray(source.buckets)) {
    return source.buckets
      .map(normalizeBucket)
      .filter(Boolean)
      .sort((a, b) => a.start - b.start);
  }

  const legacy = normalizeStatsSnapshot(source);
  if (!statsSnapshotHasData(legacy)) return [];
  return [{ start: statsBucketStart(now), stats: legacy }];
}

export function statsBucketStart(now = Date.now()) {
  return Math.floor(Number(now) / HOUR_MS) * HOUR_MS;
}

export function ensureStatsBucket(buckets, now = Date.now()) {
  const start = statsBucketStart(now);
  let bucket = buckets.find((item) => item.start === start);
  if (!bucket) {
    bucket = { start, stats: emptyStatsSnapshot() };
    buckets.push(bucket);
    buckets.sort((a, b) => a.start - b.start);
  }
  return bucket.stats;
}

export function pruneStatsBuckets(buckets, retentionHours, now = Date.now()) {
  const hours = normalizeRetentionHours(retentionHours);
  const latestHour = statsBucketStart(now);
  const cutoff = latestHour - (hours - 1) * HOUR_MS;
  return (buckets || []).filter((bucket) => bucket.start >= cutoff && bucket.start <= latestHour);
}

export function aggregateStatsBuckets(buckets) {
  const aggregate = emptyStatsSnapshot();
  for (const bucket of buckets || []) mergeStatsSnapshot(aggregate, bucket.stats);
  trimNumberMap(aggregate.byDomain, AGGREGATE_RANK_MAP_LIMIT);
  trimNumberMap(aggregate.byBlockedDomain, AGGREGATE_RANK_MAP_LIMIT);
  trimNumberMap(aggregate.byClient, AGGREGATE_RANK_MAP_LIMIT);
  return aggregate;
}

export function buildStatsSeries(buckets, retentionHours, now = Date.now()) {
  const hours = normalizeRetentionHours(retentionHours);
  const timeUnits = hours > 7 * 24 ? 'days' : 'hours';
  const stepHours = timeUnits === 'days' ? 24 : 1;
  const pointCount = Math.max(1, Math.ceil(hours / stepHours));
  const latestHour = statsBucketStart(now);
  const firstHour = latestHour - (hours - 1) * HOUR_MS;
  const starts = Array.from({ length: pointCount }, (_, index) => firstHour + index * stepHours * HOUR_MS);
  const result = {
    timeUnits,
    starts,
    dnsQueries: Array(pointCount).fill(0),
    allowed: Array(pointCount).fill(0),
    blocked: Array(pointCount).fill(0),
    blockedFiltering: Array(pointCount).fill(0),
    rewritten: Array(pointCount).fill(0),
    safeBrowsing: Array(pointCount).fill(0),
    parental: Array(pointCount).fill(0),
    safeSearch: Array(pointCount).fill(0),
    cached: Array(pointCount).fill(0),
    upstream: Array(pointCount).fill(0),
    errors: Array(pointCount).fill(0),
    processingTimeMs: Array(pointCount).fill(0),
    processingCount: Array(pointCount).fill(0)
  };

  for (const bucket of buckets || []) {
    const start = statsBucketStart(bucket?.start);
    if (!Number.isFinite(start) || start < firstHour || start > latestHour) continue;
    const index = Math.floor((start - firstHour) / (stepHours * HOUR_MS));
    if (index < 0 || index >= pointCount) continue;
    const snapshot = bucket?.stats && typeof bucket.stats === 'object' ? bucket.stats : {};
    for (const key of SERIES_KEYS) {
      const targetKey = key === 'total' ? 'dnsQueries' : key;
      result[targetKey][index] += nonNegativeNumber(snapshot[key]);
    }
  }

  return result;
}

export function pruneTimedRows(rows, retentionHours, maxEntries, now = Date.now()) {
  const cutoff = Number(now) - Number(retentionHours) * HOUR_MS;
  const limit = Math.max(1, Math.floor(Number(maxEntries) || 1));
  return (rows || [])
    .filter((row) => {
      const timestamp = Date.parse(row?.time || '');
      return Number.isFinite(timestamp) && timestamp >= cutoff;
    })
    .slice(0, limit);
}

function normalizeBucket(value) {
  const start = Number(value?.start);
  if (!Number.isFinite(start) || start < 0) return null;
  return { start: statsBucketStart(start), stats: normalizeStatsSnapshot(value?.stats) };
}

function mergeStatsSnapshot(target, sourceValue) {
  const source = normalizeStatsSnapshot(sourceValue);
  for (const key of STAT_KEYS) target[key] += source[key];
  mergeNumberMap(target.byType, source.byType);
  mergeNumberMap(target.byRule, source.byRule);
  mergeNumberMap(target.byDomain, source.byDomain);
  mergeNumberMap(target.byBlockedDomain, source.byBlockedDomain);
  mergeNumberMap(target.byClient, source.byClient);
  for (const [name, item] of Object.entries(source.upstreams)) {
    const current = target.upstreams[name] || { responses: 0, errors: 0, totalMs: 0 };
    current.responses += item.responses;
    current.errors += item.errors;
    current.totalMs += item.totalMs;
    target.upstreams[name] = current;
  }
}

function normalizeNumberMap(value, limit = Number.POSITIVE_INFINITY) {
  const result = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return result;
  const entries = [];
  for (const [key, count] of Object.entries(value)) {
    const normalized = nonNegativeNumber(count);
    if (key && normalized) entries.push([key, normalized]);
  }
  entries.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  for (const [key, count] of entries.slice(0, limit)) result[key] = count;
  return result;
}

function normalizeUpstreamMap(value) {
  const result = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return result;
  for (const [name, item] of Object.entries(value)) {
    if (!name || !item || typeof item !== 'object') continue;
    const normalized = {
      responses: nonNegativeNumber(item.responses),
      errors: nonNegativeNumber(item.errors),
      totalMs: nonNegativeNumber(item.totalMs)
    };
    if (normalized.responses || normalized.errors || normalized.totalMs) result[name] = normalized;
  }
  return result;
}

function mergeNumberMap(target, source) {
  for (const [key, value] of Object.entries(source)) target[key] = (target[key] || 0) + value;
}

function trimNumberMap(target, limit) {
  const entries = Object.entries(target);
  if (entries.length <= limit) return;
  entries.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  for (const [key] of entries.slice(limit)) delete target[key];
}

function statsSnapshotHasData(snapshot) {
  return STAT_KEYS.some((key) => snapshot[key] > 0) ||
    Object.keys(snapshot.byType).length > 0 ||
    Object.keys(snapshot.byRule).length > 0 ||
    Object.keys(snapshot.byDomain).length > 0 ||
    Object.keys(snapshot.byBlockedDomain).length > 0 ||
    Object.keys(snapshot.byClient).length > 0 ||
    Object.keys(snapshot.upstreams).length > 0;
}

function nonNegativeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function normalizeRetentionHours(value) {
  const hours = Math.floor(Number(value));
  return Number.isFinite(hours) && hours > 0 ? hours : 24;
}
