import assert from 'node:assert/strict';
import {
  normalizeUpstreamConfiguration,
  selectUpstreamConfiguration,
  upstreamConfigurationEntries,
  upstreamConfigurationSummary
} from '../upstream-config.js';

const configuration = normalizeUpstreamConfiguration([
  '# routing policy',
  '1.1.1.1',
  '1.1.1.1',
  '[/example.com/example.net/]8.8.8.8 9.9.9.9',
  '[/*.example.com/]4.4.4.4',
  '[/www.example.com/]#',
  '[//]127.0.0.1',
  '[/com/]2.2.2.2'
], { requireDefaults: true });

assert.deepEqual(configuration, [
  '# routing policy',
  '1.1.1.1',
  '[/example.com/example.net/]8.8.8.8 9.9.9.9',
  '[/*.example.com/]4.4.4.4',
  '[/www.example.com/]#',
  '[//]127.0.0.1',
  '[/com/]2.2.2.2'
]);
assert.deepEqual(selectUpstreamConfiguration(configuration, 'outside.test', 'A').upstreams, ['1.1.1.1']);
assert.deepEqual(selectUpstreamConfiguration(configuration, 'example.com', 'A').upstreams, ['8.8.8.8', '9.9.9.9']);
assert.deepEqual(selectUpstreamConfiguration(configuration, 'a.example.com', 'A').upstreams, ['4.4.4.4']);
assert.deepEqual(selectUpstreamConfiguration(configuration, 'www.example.com', 'A').upstreams, ['1.1.1.1']);
assert.deepEqual(selectUpstreamConfiguration(configuration, 'router', 'A').upstreams, ['127.0.0.1']);
assert.deepEqual(selectUpstreamConfiguration(configuration, 'com', 'A').upstreams, ['2.2.2.2']);
assert.equal(selectUpstreamConfiguration(configuration, 'child.example.com', 'DS').route, '[/example.com/example.net/]');
assert.deepEqual(upstreamConfigurationSummary(configuration), { defaults: 1, routes: 5, comments: 1, targets: 6 });

const entries = upstreamConfigurationEntries(configuration);
assert.equal(entries.length, 6);
assert.deepEqual(entries.find((entry) => entry.upstream === '1.1.1.1')?.routes, ['default']);
assert.deepEqual(entries.find((entry) => entry.upstream === '8.8.8.8')?.routes, ['[/example.com/example.net/]']);

const overlay = normalizeUpstreamConfiguration(['[/internal.test/]192.0.2.53']);
assert.equal(selectUpstreamConfiguration(overlay, 'outside.test', 'A'), null);
assert.deepEqual(
  selectUpstreamConfiguration(['[/internal.test/]#'], 'internal.test', 'A', { fallbackDefaults: ['192.0.2.1'] }).upstreams,
  ['192.0.2.1']
);

assert.throws(
  () => normalizeUpstreamConfiguration(['[/only-route.test/]1.1.1.1'], { requireDefaults: true }),
  /no_upstreams/
);
assert.throws(() => normalizeUpstreamConfiguration(['1.1.1.1', '[/bad.*.test/]8.8.8.8']), /bad_upstream/);
assert.throws(() => normalizeUpstreamConfiguration(['1.1.1.1', '[/example.test/]# 8.8.8.8']), /bad_upstream/);

const bulkConfiguration = normalizeUpstreamConfiguration([
  '192.0.2.1',
  ...Array.from({ length: 10_000 }, (_, index) => `[/route-${index}.bulk.test/]192.0.2.53`)
], { requireDefaults: true });
assert.deepEqual(upstreamConfigurationSummary(bulkConfiguration), { defaults: 1, routes: 10_000, comments: 0, targets: 2 });
assert.equal(selectUpstreamConfiguration(bulkConfiguration, 'host.route-9999.bulk.test', 'A').route, '[/route-9999.bulk.test/]');
const lookupStarted = performance.now();
for (let index = 0; index < 5_000; index += 1) {
  assert.equal(selectUpstreamConfiguration(bulkConfiguration, `host.route-${index % 10_000}.bulk.test`, 'A').upstreams[0], '192.0.2.53');
}
assert.ok(performance.now() - lookupStarted < 2_000, 'indexed upstream routing lookup is unexpectedly slow');

console.log('upstream configuration tests passed');
