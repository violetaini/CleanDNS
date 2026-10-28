import assert from 'node:assert/strict';
import {
  HOUR_MS,
  aggregateStatsBuckets,
  ensureStatsBucket,
  loadStatsBuckets,
  pruneStatsBuckets,
  pruneTimedRows
} from '../retention.js';

const now = Date.UTC(2026, 6, 10, 12, 30);
const legacy = loadStatsBuckets({
  total: 12,
  blocked: 3,
  byType: { A: 9 },
  upstreams: { '8.8.8.8': { responses: 8, errors: 1, totalMs: 80 } }
}, now);
assert.equal(legacy.length, 1);
assert.equal(aggregateStatsBuckets(legacy).total, 12);
assert.equal(aggregateStatsBuckets(legacy).blockedFiltering, 3);

const buckets = [
  { start: now - 30 * HOUR_MS, stats: { total: 100, blocked: 20 } },
  { start: now - 2 * HOUR_MS, stats: { total: 10, blocked: 2, byRule: { ads: 2 } } },
  { start: now - HOUR_MS, stats: { total: 5, upstreams: { '8.8.8.8': { responses: 4, errors: 1, totalMs: 40 } } } }
];
const retained = pruneStatsBuckets(loadStatsBuckets({ version: 2, buckets }, now), 24, now);
const aggregate = aggregateStatsBuckets(retained);
assert.equal(retained.length, 2);
assert.equal(aggregate.total, 15);
assert.equal(aggregate.blocked, 2);
assert.equal(aggregate.blockedFiltering, 2);
assert.deepEqual(aggregate.byRule, { ads: 2 });
assert.deepEqual(aggregate.upstreams['8.8.8.8'], { responses: 4, errors: 1, totalMs: 40 });

const current = ensureStatsBucket(retained, now);
current.total += 1;
assert.equal(aggregateStatsBuckets(retained).total, 16);

const rows = [
  { time: new Date(now - HOUR_MS).toISOString(), qname: 'new.example' },
  { time: new Date(now - 8 * HOUR_MS).toISOString(), qname: 'old.example' },
  { time: 'invalid', qname: 'invalid.example' }
];
assert.deepEqual(pruneTimedRows(rows, 6, 100, now).map((row) => row.qname), ['new.example']);
assert.equal(pruneTimedRows(rows, 24, 1, now).length, 1);

console.log('retention tests passed');
