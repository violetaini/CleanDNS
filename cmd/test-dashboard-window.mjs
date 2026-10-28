import assert from 'node:assert/strict';
import { HOUR_MS } from '../retention.js';
import { dashboardWindowBounds, selectDashboardRows } from '../dashboard-window.js';

const now = Date.UTC(2026, 6, 13, 8, 0, 0);
const rows = [
  { time: new Date(now - HOUR_MS).toISOString(), qname: 'keep.example', clientId: 'keep' },
  { time: new Date(now - 2 * HOUR_MS).toISOString(), qname: 'metrics.example', clientId: 'keep' },
  { time: new Date(now - 3 * HOUR_MS).toISOString(), qname: 'sub.metrics.example', clientId: 'keep' },
  { time: new Date(now - 4 * HOUR_MS).toISOString(), qname: 'client.example', clientId: 'ignored-client' },
  { time: new Date(now - 5 * HOUR_MS).toISOString(), qname: 'policy.example', clientPolicy: { ignoreStatistics: true } },
  { time: new Date(now - 25 * HOUR_MS).toISOString(), qname: 'old.example' },
  { time: new Date(now + HOUR_MS).toISOString(), qname: 'future.example' },
  { time: 'invalid', qname: 'invalid.example' }
];

const bounds = dashboardWindowBounds(24, now);
assert.equal(bounds.retentionHours, 24);
assert.equal(bounds.start, now - 24 * HOUR_MS);
assert.equal(bounds.end, now);

const selected = selectDashboardRows(rows, {
  retentionHours: 24,
  now,
  enabled: true,
  ignoredEnabled: true,
  ignoredDomains: ['metrics.example'],
  ignoredClientIds: ['ignored-client']
});
assert.deepEqual(selected.map((row) => row.qname), ['keep.example']);

assert.equal(selectDashboardRows(rows, { retentionHours: 24, now, enabled: false }).length, 0);
assert.deepEqual(
  selectDashboardRows(rows, { retentionHours: 24, now }).map((row) => row.qname),
  ['keep.example', 'metrics.example', 'sub.metrics.example', 'client.example']
);
assert.deepEqual(
  selectDashboardRows(rows, { retentionHours: 24, now, start: now - 90 * 60 * 1000 }).map((row) => row.qname),
  ['keep.example']
);
assert.equal(dashboardWindowBounds('bad', now).retentionHours, 24);

console.log('dashboard window tests passed');
