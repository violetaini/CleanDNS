import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { QueryLogStore } from '../query-log-store.js';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cleandns-query-log-store-'));
const file = path.join(root, 'query.log');
let now = Date.parse('2026-08-20T00:00:00.000Z');
const store = new QueryLogStore({
  logFile: file,
  retentionHours: 24,
  maxMemoryEntries: 3,
  maxScanEntries: 100,
  now: () => now
});

try {
  await store.append(row('2026-08-19T23:50:00.000Z', 'one.example', 'one'));
  await store.append(row('2026-08-19T23:51:00.000Z', 'two.example', 'two'));
  await store.append(row('2026-08-19T23:52:00.000Z', 'three.example', 'three'));
  await store.append(row('2026-08-19T23:53:00.000Z', 'four.example', 'four'));
  await store.append(row('2026-08-19T23:54:00.000Z', 'five.example', 'five'));

  assert.deepEqual(store.loadRecent(3).map((item) => item.id), ['five', 'four', 'three']);
  const first = await store.readPage({ limit: 2 });
  assert.deepEqual(first.rows.map((item) => item.id), ['five', 'four']);
  assert.ok(first.nextCursor);
  assert.equal(first.hasMore, true);

  await store.append(row('2026-08-20T00:01:00.000Z', 'new.example', 'new'));
  const second = await store.readPage({ limit: 2, cursor: first.nextCursor });
  assert.deepEqual(second.rows.map((item) => item.id), ['three', 'two']);
  assert.equal(second.rows.some((item) => item.id === 'new'), false);

  fs.appendFileSync(file, JSON.stringify({ time: '2026-08-19T23:49:00.000Z', qname: 'legacy.example', qtype: 'A' }) + '\n');
  const legacy = await store.readPage({ limit: 20 });
  assert.ok(legacy.rows.some((item) => String(item.id).startsWith('legacy:')));

  now = Date.parse('2026-08-21T00:00:00.000Z');
  await store.rotateIfDue({ force: true, now });
  assert.equal(fs.existsSync(`${file}.1`), true);
  assert.equal(fs.readFileSync(file, 'utf8'), '');
  const retained = await store.readPage({ limit: 20, now });
  assert.deepEqual(retained.rows.map((item) => item.id), ['new']);

  now = Date.parse('2026-08-22T01:00:00.000Z');
  await store.rotateIfDue({ force: true, now });
  assert.equal(fs.existsSync(`${file}.1`), false, 'expired archive should be removed even when no active rows exist');

  await store.clear();
  assert.equal(fs.readFileSync(file, 'utf8'), '');
  assert.equal(fs.existsSync(`${file}.1`), false);
  console.log('query log store tests passed');
} finally {
  const resolved = path.resolve(root);
  const temp = path.resolve(os.tmpdir());
  if (resolved.startsWith(temp + path.sep) && path.basename(resolved).startsWith('cleandns-query-log-store-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

function row(time, qname, id) {
  return {
    id,
    time,
    qname,
    qtype: 'A',
    client: '192.0.2.1',
    protocol: 'udp',
    action: 'allow'
  };
}
