import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { decodeDnsResponse } from '../dns-response.js';
import { protectionDomainHashes } from '../domain-protection.js';

const appDir = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/(?:[A-Za-z]:)/, (value) => value.slice(1))), '..');
const expectedAddress = '203.0.113.42';

await testGlobalFallback();
await testBootstrapLookup();
await testDomainSpecificUpstreamRouting();
await testLayeredUpstreamRouting();
await testClientUpstreamDoesNotLeakToFallback();
await testClientUpstreamCachePolicy();
await testClientOptimisticCache();
await testOptimisticCacheAndTtlAging();
await testOptimisticRefreshCannotRepopulateClearedCache();
await testGlobalCacheToggle();
await testDashboardWindowAndReset();
await testDashboardRankingsWithoutQueryLog();
await testBlockedResponseSettings();
await testDnsRateLimit();
await testDnsRateLimitWhitelist();
await testDomainProtection();
await testClientDomainProtectionOverride();
console.log('upstream policy tests passed');

async function testGlobalFallback() {
  const fallback = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const deadPort = await unusedUdpPort();
  try {
    const result = await withCleanDns({
      upstreams: [`udp://127.0.0.1:${deadPort}`],
      fallbackUpstreams: [`udp://127.0.0.1:${fallback.port}`],
      timeoutMs: 120
    }, async ({ baseUrl, cookie }) => {
      const response = await dohQuery(baseUrl, 'fallback.example');
      assert.equal(firstIpv4Answer(response), expectedAddress);
      const row = await recentQuery(baseUrl, cookie, 'fallback.example');
      assert.equal(row.upstreamMode, 'fallback');
      assert.equal(row.upstream, `udp://127.0.0.1:${fallback.port}`);
      assert.equal(row.responseCode, 0);
      assert.equal(row.responseStatus, 'NOERROR');
      assert.equal(row.answerCount, 1);
      assert.deepEqual(row.answers, [{ name: 'fallback.example', type: 'A', ttl: 60, value: expectedAddress }]);
    });
    assert.equal(result.exitCode, 0);
  } finally {
    await fallback.close();
  }
}

async function testBootstrapLookup() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const bootstrap = await startDnsServer((packet) => {
    const question = parseQuestion(packet);
    return question.name === 'resolver.test' && question.type === 1
      ? buildAnswer(packet, '127.0.0.1')
      : buildAnswer(packet, '');
  });
  try {
    const result = await withCleanDns({
      upstreams: [`udp://resolver.test:${upstream.port}`],
      bootstrapDns: [`udp://127.0.0.1:${bootstrap.port}`]
    }, async ({ baseUrl, cookie }) => {
      const response = await dohQuery(baseUrl, 'bootstrap.example');
      assert.equal(firstIpv4Answer(response), expectedAddress);
      const row = await recentQuery(baseUrl, cookie, 'bootstrap.example');
      assert.equal(row.upstreamMode, 'sequential');
      assert.equal(row.upstream, `udp://resolver.test:${upstream.port}`);
    });
    assert.equal(result.exitCode, 0);
    assert.ok(bootstrap.queries.some((item) => item.name === 'resolver.test' && item.type === 1));
  } finally {
    await Promise.all([upstream.close(), bootstrap.close()]);
  }
}

async function testDomainSpecificUpstreamRouting() {
  const addresses = {
    default: '203.0.113.10',
    normal: '203.0.113.11',
    wildcard: '203.0.113.12',
    unqualified: '203.0.113.13',
    parent: '203.0.113.14'
  };
  const servers = Object.fromEntries(await Promise.all(Object.entries(addresses).map(async ([name, address]) => [
    name,
    await startDnsServer((packet) => buildAnswer(packet, address))
  ])));
  const upstreams = [
    '# Domain routing test',
    `udp://127.0.0.1:${servers.default.port}`,
    `[/example.test/]udp://127.0.0.1:${servers.normal.port}`,
    `[/*.example.test/]udp://127.0.0.1:${servers.wildcard.port}`,
    '[/www.example.test/]#',
    `[//]udp://127.0.0.1:${servers.unqualified.port}`,
    `[/parent.test/]udp://127.0.0.1:${servers.parent.port}`
  ];
  try {
    await withCleanDns({ upstreams }, async ({ baseUrl, cookie }) => {
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'other.test')), addresses.default);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'example.test')), addresses.normal);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'api.example.test')), addresses.wildcard);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'www.example.test')), addresses.default);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'router')), addresses.unqualified);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'child.parent.test', 'DS')), addresses.parent);

      const wildcardRow = await recentQuery(baseUrl, cookie, 'api.example.test');
      assert.equal(wildcardRow.upstreamRoute, '[/*.example.test/]');
      assert.equal(wildcardRow.upstreamMode, 'sequential');
      const dsRow = await recentQuery(baseUrl, cookie, 'child.parent.test');
      assert.equal(dsRow.qtype, 'DS');
      assert.equal(dsRow.upstreamRoute, '[/parent.test/]');

      const settingsResponse = await fetch(baseUrl + '/api/settings', { headers: { cookie } });
      assert.equal(settingsResponse.status, 200);
      const settings = await settingsResponse.json();
      assert.deepEqual(settings.upstreamConfiguration, { defaults: 1, routes: 5, comments: 1, targets: 5 });
      assert.ok(settings.upstreams.includes('# Domain routing test'));

      const saveResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ upstreams })
      });
      assert.equal(saveResponse.status, 200);
      const saved = await saveResponse.json();
      assert.ok(saved.settings.upstreams.includes('# Domain routing test'));

      const privateReverseUpstreams = [`[/168.192.in-addr.arpa/]udp://127.0.0.1:${servers.default.port}`];
      const testResponse = await fetch(baseUrl + '/api/test-upstreams', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ upstreams, privateReverseUpstreams, name: 'api.example.test', type: 'A', timeoutMs: 500 })
      });
      assert.equal(testResponse.status, 200);
      const tested = await testResponse.json();
      assert.equal(tested.selectedRoute, '[/*.example.test/]');
      assert.deepEqual(tested.selectedUpstreams, [`udp://127.0.0.1:${servers.wildcard.port}`]);
      assert.deepEqual(tested.configuration, { defaults: 1, routes: 5, comments: 1, targets: 5 });
      assert.deepEqual(tested.privateReverseConfiguration, { defaults: 0, routes: 1, comments: 0, targets: 1 });
      assert.equal(tested.results.filter((row) => row.role === 'primary').length, 5);
      assert.ok(tested.results.some((row) => row.route === '[/*.example.test/]' && row.ok));
      assert.ok(tested.results.some((row) => row.role === 'private-reverse' && row.route === '[/168.192.in-addr.arpa/]' && row.ok));
    });
  } finally {
    await Promise.all(Object.values(servers).map((server) => server.close()));
  }
}

async function testLayeredUpstreamRouting() {
  const global = await startDnsServer((packet) => buildAnswer(packet, '198.51.100.10'));
  const client = await startDnsServer((packet) => buildAnswer(packet, '198.51.100.11'));
  const privateReverse = await startDnsServer((packet) => buildAnswer(packet, '198.51.100.12'));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${global.port}`],
      dns: {
        privateReverseEnabled: true,
        privateReverseUpstreams: [`[/168.192.in-addr.arpa/]udp://127.0.0.1:${privateReverse.port}`]
      },
      clients: [{
        id: 'client-route-overlay',
        name: 'Client route overlay',
        identifiers: ['127.0.0.1'],
        upstreams: [
          `[/client.test/]udp://127.0.0.1:${client.port}`,
          '[/default.client.test/]#'
        ]
      }]
    }, async ({ baseUrl, cookie }) => {
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client.test')), '198.51.100.11');
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'other.test')), '198.51.100.10');
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'default.client.test')), '198.51.100.10');
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, '1.0.168.192.in-addr.arpa', 'PTR')), '198.51.100.12');

      const clientRow = await recentQuery(baseUrl, cookie, 'client.test');
      assert.equal(clientRow.upstreamMode, 'client');
      assert.equal(clientRow.upstreamRoute, '[/client.test/]');
      const globalRow = await recentQuery(baseUrl, cookie, 'other.test');
      assert.equal(globalRow.upstreamMode, 'sequential');
      assert.equal(globalRow.upstreamRoute, '默认上游');
      const defaultRow = await recentQuery(baseUrl, cookie, 'default.client.test');
      assert.equal(defaultRow.upstreamMode, 'client');
      assert.equal(defaultRow.upstreamRoute, '[/default.client.test/]');
      const privateRow = await recentQuery(baseUrl, cookie, '1.0.168.192.in-addr.arpa');
      assert.equal(privateRow.upstreamMode, 'private-reverse');
      assert.equal(privateRow.upstreamRoute, '[/168.192.in-addr.arpa/]');
    });
  } finally {
    await Promise.all([global.close(), client.close(), privateReverse.close()]);
  }
}

async function testClientUpstreamDoesNotLeakToFallback() {
  const fallback = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const deadPort = await unusedUdpPort();
  try {
    const result = await withCleanDns({
      upstreams: [`udp://127.0.0.1:${fallback.port}`],
      fallbackUpstreams: [`udp://127.0.0.1:${fallback.port}`],
      timeoutMs: 120,
      clients: [{
        id: 'client-test',
        name: 'Policy test',
        identifiers: ['127.0.0.1'],
        upstreams: [`udp://127.0.0.1:${deadPort}`]
      }]
    }, async ({ baseUrl }) => {
      const response = await dohQuery(baseUrl, 'client-policy.example');
      assert.equal(response[3] & 0x0f, 2);
    });
    assert.equal(result.exitCode, 0);
    assert.equal(fallback.queries.length, 0);
  } finally {
    await fallback.close();
  }
}

async function testClientUpstreamCachePolicy() {
  const customAddress = '198.51.100.77';
  const globalUpstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const clientUpstream = await startDnsServer((packet) => buildAnswer(packet, customAddress));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${globalUpstream.port}`],
      cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0 },
      clients: [{
        id: 'client-cache-test',
        name: 'Client cache test',
        identifiers: ['127.0.0.1'],
        upstreams: [`udp://127.0.0.1:${clientUpstream.port}`]
      }]
    }, async ({ baseUrl, cookie, tempDir }) => {
      const clientsResponse = await fetch(baseUrl + '/api/clients', { headers: { cookie } });
      assert.equal(clientsResponse.status, 200);
      let client = (await clientsResponse.json()).clients[0];
      assert.equal(client.upstreamsCacheEnabled, false);
      assert.equal(client.upstreamsCacheSize, 0);

      const saveClient = async (patch) => {
        const response = await fetch(baseUrl + '/api/clients', {
          method: 'POST',
          headers: { cookie, 'content-type': 'application/json' },
          body: JSON.stringify({ clients: [{ ...client, ...patch }] })
        });
        assert.equal(response.status, 200);
        const body = await response.json();
        client = body.clients[0];
        return body;
      };

      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client-no-cache.example')), customAddress);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client-no-cache.example')), customAddress);
      assert.equal(clientUpstream.queries.length, 2);
      assert.equal(globalUpstream.queries.length, 0);

      await saveClient({ upstreamsCacheEnabled: true, upstreamsCacheSize: 1024 * 1024 });
      assert.equal(client.upstreamsCacheEnabled, true);
      assert.equal(client.upstreamsCacheSize, 1024 * 1024);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client-cache.example')), customAddress);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client-cache.example')), customAddress);
      assert.equal(clientUpstream.queries.length, 3);

      const cachedRow = await recentQuery(baseUrl, cookie, 'client-cache.example');
      assert.equal(cachedRow.cached, true);
      assert.equal(cachedRow.source, 'client-cache');
      assert.equal(cachedRow.clientPolicy.upstreamsCacheEnabled, true);
      assert.equal(cachedRow.clientPolicy.upstreamsCacheSize, 1024 * 1024);
      assert.equal(cachedRow.clientPolicy.upstreamsCacheActive, true);
      const enabledStatus = await statusPayload(baseUrl, cookie);
      assert.equal(enabledStatus.cache.globalEntries, 0);
      assert.equal(enabledStatus.cache.clientCaches, 1);
      assert.equal(enabledStatus.cache.clientEntries, 1);
      assert.equal(enabledStatus.cache.totalEntries, 1);
      assert.equal(enabledStatus.clients.customUpstreamCaches, 1);

      const disableGlobalResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ cacheEnabled: false })
      });
      assert.equal(disableGlobalResponse.status, 200);
      assert.equal((await disableGlobalResponse.json()).settings.cacheEnabled, false);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client-cache-independent.example')), customAddress);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'client-cache-independent.example')), customAddress);
      assert.equal(clientUpstream.queries.length, 4);
      const independentStatus = await statusPayload(baseUrl, cookie);
      assert.equal(independentStatus.cache.enabled, false);
      assert.equal(independentStatus.cache.globalEntries, 0);
      assert.equal(independentStatus.cache.clientEntries, 1);

      const clearResponse = await fetch(baseUrl + '/api/cache/clear', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '{}'
      });
      assert.equal(clearResponse.status, 200);
      const cleared = await clearResponse.json();
      assert.equal(cleared.removedByScope.globalEntries, 0);
      assert.equal(cleared.removedByScope.clientEntries, 1);
      assert.equal(cleared.status.cache.clientEntries, 0);
      await dohQuery(baseUrl, 'client-cache-independent.example');
      assert.equal(clientUpstream.queries.length, 5);

      await saveClient({ upstreamsCacheEnabled: true, upstreamsCacheSize: 0 });
      await dohQuery(baseUrl, 'client-zero-cache.example');
      await dohQuery(baseUrl, 'client-zero-cache.example');
      assert.equal(clientUpstream.queries.length, 7);
      const zeroStatus = await statusPayload(baseUrl, cookie);
      assert.equal(zeroStatus.cache.clientCaches, 0);
      assert.equal(zeroStatus.cache.clientEntries, 0);
      assert.equal(zeroStatus.clients.customUpstreamCaches, 0);

      await saveClient({ upstreams: [], upstreamsCacheEnabled: true, upstreamsCacheSize: 1024 * 1024 });
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'global-cache-disabled.example')), expectedAddress);
      assert.equal(firstIpv4Answer(await dohQuery(baseUrl, 'global-cache-disabled.example')), expectedAddress);
      assert.equal(globalUpstream.queries.length, 2);
      assert.equal(clientUpstream.queries.length, 7);
      const globalStatus = await statusPayload(baseUrl, cookie);
      assert.equal(globalStatus.cache.clientCaches, 0);
      assert.equal(globalStatus.cache.clientEntries, 0);
      assert.equal(globalStatus.clients.customUpstreamCaches, 0);

      const persistedClients = JSON.parse(fs.readFileSync(path.join(tempDir, 'data', 'clients.json'), 'utf8'));
      assert.equal(persistedClients[0].upstreamsCacheEnabled, true);
      assert.equal(persistedClients[0].upstreamsCacheSize, 1024 * 1024);
      assert.deepEqual(persistedClients[0].upstreams, []);
    });
  } finally {
    await Promise.all([globalUpstream.close(), clientUpstream.close()]);
  }
}

async function testOptimisticCacheAndTtlAging() {
  const refreshedAddress = '203.0.113.43';
  let upstreamResponses = 0;
  const upstream = await startDnsServer((packet) => {
    upstreamResponses += 1;
    return buildAnswer(packet, upstreamResponses === 1 ? expectedAddress : refreshedAddress, 30);
  });
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      cache: {
        enabled: true,
        maxEntries: 100,
        minTtl: 1,
        maxTtl: 2,
        staleTtl: 0,
        optimistic: true,
        optimisticAnswerTtl: 9,
        optimisticMaxAge: 30
      }
    }, async ({ baseUrl, cookie, tempDir }) => {
      const settingsResponse = await fetch(baseUrl + '/api/settings', { headers: { cookie } });
      assert.equal(settingsResponse.status, 200);
      const settings = await settingsResponse.json();
      assert.equal(settings.cacheOptimistic, true);
      assert.equal(settings.cacheOptimisticAnswerTtl, 9);
      assert.equal(settings.cacheOptimisticMaxAge, 30);

      const first = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-cache.example'));
      assert.equal(first.answers[0].value, expectedAddress);
      assert.equal(first.answers[0].ttl, 2);
      assert.equal(upstream.queries.length, 1);

      await sleep(1250);
      const aged = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-cache.example'));
      assert.equal(aged.answers[0].value, expectedAddress);
      assert.equal(aged.answers[0].ttl, 1);
      assert.equal(upstream.queries.length, 1);
      const agedRow = await recentQuery(baseUrl, cookie, 'optimistic-cache.example');
      assert.equal(agedRow.cached, true);
      assert.equal(agedRow.source, 'cache');

      await sleep(1250);
      const optimistic = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-cache.example'));
      assert.equal(optimistic.answers[0].value, expectedAddress);
      assert.equal(optimistic.answers[0].ttl, 9);
      const optimisticRow = await recentQuery(baseUrl, cookie, 'optimistic-cache.example');
      assert.equal(optimisticRow.cached, true);
      assert.equal(optimisticRow.source, 'optimistic-cache');

      await waitFor(() => upstream.queries.length === 2, 2000, () => `queries=${upstream.queries.length}`);
      await sleep(50);
      const refreshed = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-cache.example'));
      assert.equal(refreshed.answers[0].value, refreshedAddress);
      assert.equal(refreshed.answers[0].ttl, 2);
      assert.equal(upstream.queries.length, 2);

      const status = await statusPayload(baseUrl, cookie);
      assert.equal(status.cache.optimistic, true);
      assert.equal(status.cache.optimisticAnswerTtl, 9);
      assert.equal(status.cache.optimisticMaxAge, 30);
      assert.equal(status.cache.optimisticRefreshes, 0);

      const updateResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({
          cacheOptimistic: false,
          cacheOptimisticAnswerTtl: 11,
          cacheOptimisticMaxAge: 45
        })
      });
      assert.equal(updateResponse.status, 200);
      const updated = await updateResponse.json();
      assert.equal(updated.settings.cacheOptimistic, false);
      assert.equal(updated.settings.cacheOptimisticAnswerTtl, 11);
      assert.equal(updated.settings.cacheOptimisticMaxAge, 45);
      assert.equal(updated.status.cache.entries, 0);

      const persisted = JSON.parse(fs.readFileSync(path.join(tempDir, 'config.json'), 'utf8'));
      assert.equal(persisted.cache.optimistic, false);
      assert.equal(persisted.cache.optimisticAnswerTtl, 11);
      assert.equal(persisted.cache.optimisticMaxAge, 45);
    });
  } finally {
    await upstream.close();
  }
}

async function testClientOptimisticCache() {
  const refreshedAddress = '198.51.100.78';
  let upstreamResponses = 0;
  const globalUpstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const clientUpstream = await startDnsServer((packet) => {
    upstreamResponses += 1;
    return buildAnswer(packet, upstreamResponses === 1 ? '198.51.100.77' : refreshedAddress, 30);
  });
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${globalUpstream.port}`],
      cache: {
        enabled: false,
        maxEntries: 100,
        minTtl: 1,
        maxTtl: 1,
        staleTtl: 0,
        optimistic: true,
        optimisticAnswerTtl: 8,
        optimisticMaxAge: 30
      },
      clients: [{
        id: 'client-optimistic-cache',
        name: 'Client optimistic cache',
        identifiers: ['127.0.0.1'],
        upstreams: [`udp://127.0.0.1:${clientUpstream.port}`],
        upstreamsCacheEnabled: true,
        upstreamsCacheSize: 1024 * 1024
      }]
    }, async ({ baseUrl, cookie }) => {
      const first = decodeDnsResponse(await dohQuery(baseUrl, 'client-optimistic.example'));
      assert.equal(first.answers[0].value, '198.51.100.77');
      assert.equal(first.answers[0].ttl, 1);
      assert.equal(clientUpstream.queries.length, 1);

      await sleep(1250);
      const optimistic = decodeDnsResponse(await dohQuery(baseUrl, 'client-optimistic.example'));
      assert.equal(optimistic.answers[0].value, '198.51.100.77');
      assert.equal(optimistic.answers[0].ttl, 8);
      const row = await recentQuery(baseUrl, cookie, 'client-optimistic.example');
      assert.equal(row.cached, true);
      assert.equal(row.source, 'optimistic-client-cache');

      await waitFor(() => clientUpstream.queries.length === 2, 2000, () => `queries=${clientUpstream.queries.length}`);
      await sleep(50);
      const refreshed = decodeDnsResponse(await dohQuery(baseUrl, 'client-optimistic.example'));
      assert.equal(refreshed.answers[0].value, refreshedAddress);
      assert.equal(refreshed.answers[0].ttl, 1);
      assert.equal(globalUpstream.queries.length, 0);

      const status = await statusPayload(baseUrl, cookie);
      assert.equal(status.cache.enabled, false);
      assert.equal(status.cache.clientEntries, 1);
      assert.equal(status.clients.customUpstreamCaches, 1);
    });
  } finally {
    await Promise.all([globalUpstream.close(), clientUpstream.close()]);
  }
}

async function testOptimisticRefreshCannotRepopulateClearedCache() {
  let responseCount = 0;
  const upstream = await startDnsServer(async (packet) => {
    responseCount += 1;
    if (responseCount === 2) await sleep(250);
    return buildAnswer(packet, responseCount === 1 ? expectedAddress : '203.0.113.44', 30);
  });
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      cache: {
        enabled: true,
        maxEntries: 100,
        minTtl: 1,
        maxTtl: 1,
        staleTtl: 0,
        optimistic: true,
        optimisticAnswerTtl: 7,
        optimisticMaxAge: 30
      }
    }, async ({ baseUrl, cookie }) => {
      const first = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-clear.example'));
      assert.equal(first.answers[0].value, expectedAddress);
      await sleep(1250);

      const stale = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-clear.example'));
      assert.equal(stale.answers[0].value, expectedAddress);
      assert.equal(stale.answers[0].ttl, 7);
      await waitFor(() => upstream.queries.length === 2, 500, () => `queries=${upstream.queries.length}`);

      const clearResponse = await fetch(baseUrl + '/api/cache/clear', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '{}'
      });
      assert.equal(clearResponse.status, 200);
      await sleep(350);
      const clearedStatus = await statusPayload(baseUrl, cookie);
      assert.equal(clearedStatus.cache.entries, 0);
      assert.equal(clearedStatus.cache.totalEntries, 0);
      assert.equal(clearedStatus.cache.optimisticRefreshes, 0);

      const afterClear = decodeDnsResponse(await dohQuery(baseUrl, 'optimistic-clear.example'));
      assert.equal(afterClear.answers[0].value, '203.0.113.44');
      assert.equal(upstream.queries.length, 3);
    });
  } finally {
    await upstream.close();
  }
}

async function testGlobalCacheToggle() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      cache: { enabled: true, maxEntries: 123, minTtl: 1, maxTtl: 60, staleTtl: 15 }
    }, async ({ baseUrl, cookie, tempDir }) => {
      const initialSettingsResponse = await fetch(baseUrl + '/api/settings', { headers: { cookie } });
      assert.equal(initialSettingsResponse.status, 200);
      const initialSettings = await initialSettingsResponse.json();
      assert.equal(initialSettings.cacheEnabled, true);
      assert.equal(initialSettings.cacheMaxEntries, 123);
      assert.equal(initialSettings.cacheOptimistic, false);
      assert.equal(initialSettings.cacheOptimisticAnswerTtl, 30);
      assert.equal(initialSettings.cacheOptimisticMaxAge, 43200);

      await dohQuery(baseUrl, 'cache-enabled.example');
      await dohQuery(baseUrl, 'cache-enabled.example');
      assert.equal(upstream.queries.length, 1);
      const enabledStatus = await statusPayload(baseUrl, cookie);
      assert.equal(enabledStatus.cache.enabled, true);
      assert.equal(enabledStatus.cache.entries, 1);

      const disableResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ cacheEnabled: false })
      });
      assert.equal(disableResponse.status, 200);
      const disabled = await disableResponse.json();
      assert.equal(disabled.settings.cacheEnabled, false);
      assert.equal(disabled.settings.cacheMaxEntries, 123);
      assert.equal(disabled.status.cache.enabled, false);
      assert.equal(disabled.status.cache.entries, 0);

      await dohQuery(baseUrl, 'cache-disabled.example');
      await dohQuery(baseUrl, 'cache-disabled.example');
      assert.equal(upstream.queries.length, 3);
      const disabledStatus = await statusPayload(baseUrl, cookie);
      assert.equal(disabledStatus.cache.enabled, false);
      assert.equal(disabledStatus.cache.entries, 0);

      const enableResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ cacheEnabled: true })
      });
      assert.equal(enableResponse.status, 200);
      const reenabled = await enableResponse.json();
      assert.equal(reenabled.settings.cacheEnabled, true);
      assert.equal(reenabled.settings.cacheMaxEntries, 123);

      await dohQuery(baseUrl, 'cache-reenabled.example');
      await dohQuery(baseUrl, 'cache-reenabled.example');
      assert.equal(upstream.queries.length, 4);
      const reenabledStatus = await statusPayload(baseUrl, cookie);
      assert.equal(reenabledStatus.cache.enabled, true);
      assert.equal(reenabledStatus.cache.entries, 1);

      const persisted = JSON.parse(fs.readFileSync(path.join(tempDir, 'config.json'), 'utf8'));
      assert.equal(persisted.cache.enabled, true);
      assert.equal(persisted.cache.maxEntries, 123);
      assert.equal(persisted.cache.staleTtl, 15);
      assert.equal(persisted.cache.optimistic, false);
      assert.equal(persisted.cache.optimisticAnswerTtl, 30);
      assert.equal(persisted.cache.optimisticMaxAge, 43200);
    });
  } finally {
    await upstream.close();
  }
}

async function testDashboardWindowAndReset() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const now = Date.now();
  const bucketStart = Math.floor(now / (60 * 60 * 1000)) * 60 * 60 * 1000;
  const queryLogRows = [
    { time: new Date(now - 48 * 60 * 60 * 1000).toISOString(), qname: 'old.example', qtype: 'A', client: '127.0.0.1', action: 'allow', protocol: 'test', cached: false },
    { time: new Date(now).toISOString(), qname: 'current.example', qtype: 'A', client: '127.0.0.1', action: 'allow', protocol: 'test', cached: false }
  ];
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      queryLog: { enabled: true, maxEntries: 100, retentionHours: 2160, anonymizeClientIp: false },
      statistics: { enabled: true, retentionHours: 24, ignoredEnabled: false, ignored: [] },
      queryLogRows,
      statsData: { version: 2, buckets: [{ start: bucketStart, stats: { total: 1, allowed: 1, upstream: 1 } }] }
    }, async ({ baseUrl, cookie, tempDir }) => {
      const initial = await statusPayload(baseUrl, cookie);
      assert.equal(initial.stats.total, 1);
      assert.equal(initial.stats.rankingCount, 1);
      assert.equal(initial.dashboard.window, 1);
      assert.equal(initial.dashboard.retentionHours, 24);
      assert.deepEqual(initial.dashboard.topQueriedDomains.map((item) => item.name), ['current.example']);
      assert.deepEqual(initial.dashboard.topClients, [{ name: '127.0.0.1', count: 1 }]);
      assert.equal(initial.dashboard.rankingSource, 'statistics');
      const backfilled = JSON.parse(fs.readFileSync(path.join(tempDir, 'data', 'stats.json'), 'utf8'));
      assert.equal(backfilled.buckets[0].stats.rankingCount, 1);
      assert.deepEqual(backfilled.buckets[0].stats.byDomain, { 'current.example': 1 });

      const clearedResponse = await fetch(baseUrl + '/api/stats/clear', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '{}'
      });
      assert.equal(clearedResponse.status, 200);
      const cleared = await clearedResponse.json();
      assert.equal(cleared.status.stats.total, 0);
      assert.equal(cleared.status.stats.processingCount, 0);
      assert.equal(cleared.status.stats.rankingCount, 0);
      assert.equal(cleared.status.stats.avgProcessingMs, 0);
      assert.equal(cleared.status.statistics.series.timeUnits, 'hours');
      assert.equal(cleared.status.statistics.series.starts.length, 24);
      assert.equal(cleared.status.statistics.series.dnsQueries.reduce((sum, value) => sum + value, 0), 0);
      assert.equal(cleared.status.dashboard.window, 0);
      assert.equal(cleared.status.dashboard.coverage, 'complete');
      const persisted = JSON.parse(fs.readFileSync(path.join(tempDir, 'data', 'stats.json'), 'utf8'));
      assert.ok(Number(persisted.resetAt) >= now);

      await dohQuery(baseUrl, 'after-reset.example');
      const afterReset = await statusPayload(baseUrl, cookie);
      assert.equal(afterReset.stats.total, 1);
      assert.equal(afterReset.stats.processingCount, 1);
      assert.equal(afterReset.stats.rankingCount, 1);
      assert.ok(afterReset.stats.processingTimeMs >= 0);
      assert.ok(afterReset.stats.avgProcessingMs >= 0);
      assert.equal(afterReset.statistics.series.dnsQueries.reduce((sum, value) => sum + value, 0), 1);
      assert.equal(afterReset.statistics.series.processingCount.reduce((sum, value) => sum + value, 0), 1);
      assert.equal(afterReset.dashboard.window, 1);
      assert.deepEqual(afterReset.dashboard.topQueriedDomains.map((item) => item.name), ['after-reset.example']);
      assert.deepEqual(afterReset.dashboard.topClients, [{ name: '127.0.0.1', count: 1 }]);
      const row = await recentQuery(baseUrl, cookie, 'after-reset.example');
      assert.equal(row.responseStatus, 'NOERROR');
      assert.equal(row.answerCount, 1);
      assert.equal(row.answers[0].value, expectedAddress);
    });
  } finally {
    await upstream.close();
  }
}

async function testDashboardRankingsWithoutQueryLog() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      queryLog: { enabled: false, maxEntries: 100, retentionHours: 1, anonymizeClientIp: true },
      statistics: { enabled: true, retentionHours: 24, ignoredEnabled: true, ignored: ['ignored.example'] },
      filter: { enabled: true },
      blockRules: '||rank-blocked.example^\n',
      clients: [{ id: 'rank-client', name: 'Rank client', identifiers: ['127.0.0.1'] }]
    }, async ({ baseUrl, cookie }) => {
      for (let index = 0; index < 3; index += 1) await dohQuery(baseUrl, 'rank-one.example');
      await dohQuery(baseUrl, 'rank-two.example');
      for (let index = 0; index < 2; index += 1) await dohQuery(baseUrl, 'rank-blocked.example');
      await dohQuery(baseUrl, 'ignored.example');

      const status = await statusPayload(baseUrl, cookie);
      assert.equal(status.stats.total, 6);
      assert.equal(status.stats.rankingCount, 6);
      assert.equal(status.dashboard.window, 6);
      assert.equal(status.dashboard.coverage, 'complete');
      assert.deepEqual(status.dashboard.topQueriedDomains, [
        { name: 'rank-one.example', count: 3 },
        { name: 'rank-blocked.example', count: 2 },
        { name: 'rank-two.example', count: 1 }
      ]);
      assert.deepEqual(status.dashboard.topBlockedDomains, [{ name: 'rank-blocked.example', count: 2 }]);
      assert.deepEqual(status.dashboard.topClients, [{ name: 'Rank client', count: 6 }]);
      assert.equal(Object.prototype.hasOwnProperty.call(status.stats, 'byDomain'), false);

      const recentResponse = await fetch(baseUrl + '/api/recent', { headers: { cookie } });
      assert.equal(recentResponse.status, 200);
      const recent = await recentResponse.json();
      assert.deepEqual(recent.recent, []);
    });
  } finally {
    await upstream.close();
  }
}

async function testBlockedResponseSettings() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      filter: { enabled: true, blockMode: 'custom' },
      blockRules: '||blocked.example^\n192.0.2.44 hosts.blocked.example\n'
    }, async ({ baseUrl, cookie }) => {
      const savedResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({
          blockMode: 'custom',
          dnsBlockingIpv4: '203.0.113.9',
          dnsBlockingIpv6: '2001:db8::9',
          dnsBlockedResponseTtl: 321
        })
      });
      assert.equal(savedResponse.status, 200);
      const saved = await savedResponse.json();
      assert.equal(saved.settings.dnsBlockingIpv4, '203.0.113.9');
      assert.equal(saved.settings.dnsBlockingIpv6, '2001:db8::9');
      assert.equal(saved.settings.dnsBlockedResponseTtl, 321);
      assert.equal(saved.settings.blockMode, 'custom');

      const ipv4 = decodeDnsResponse(await dohQuery(baseUrl, 'custom.blocked.example', 'A'));
      assert.equal(ipv4.status, 'NOERROR');
      assert.deepEqual(ipv4.answers[0], { name: 'custom.blocked.example', type: 'A', ttl: 321, value: '203.0.113.9' });

      const ipv6 = decodeDnsResponse(await dohQuery(baseUrl, 'custom-v6.blocked.example', 'AAAA'));
      assert.equal(ipv6.status, 'NOERROR');
      assert.equal(ipv6.answers[0].type, 'AAAA');
      assert.equal(ipv6.answers[0].ttl, 321);
      assert.equal(ipv6.answers[0].value, '2001:db8:0:0:0:0:0:9');

      const setMode = async (blockMode) => {
        const response = await fetch(baseUrl + '/api/settings', {
          method: 'POST',
          headers: { cookie, 'content-type': 'application/json' },
          body: JSON.stringify({ blockMode })
        });
        assert.equal(response.status, 200, `save block mode ${blockMode}`);
        return response.json();
      };

      assert.equal((await setMode('null_ip')).settings.blockMode, 'null');
      const nullIpv4 = decodeDnsResponse(await dohQuery(baseUrl, 'null.blocked.example', 'A'));
      assert.deepEqual(nullIpv4.answers[0], { name: 'null.blocked.example', type: 'A', ttl: 321, value: '0.0.0.0' });
      const nullIpv6 = decodeDnsResponse(await dohQuery(baseUrl, 'null-v6.blocked.example', 'AAAA'));
      assert.equal(nullIpv6.answers[0].value, '0:0:0:0:0:0:0:0');

      assert.equal((await setMode('default')).settings.blockMode, 'default');
      const defaultRule = decodeDnsResponse(await dohQuery(baseUrl, 'default.blocked.example', 'A'));
      assert.equal(defaultRule.answers[0].value, '0.0.0.0');
      const defaultHosts = decodeDnsResponse(await dohQuery(baseUrl, 'hosts.blocked.example', 'A'));
      assert.deepEqual(defaultHosts.answers[0], { name: 'hosts.blocked.example', type: 'A', ttl: 321, value: '192.0.2.44' });

      assert.equal((await setMode('refused')).settings.blockMode, 'refused');
      const refused = decodeDnsResponse(await dohQuery(baseUrl, 'refused.blocked.example', 'A'));
      assert.equal(refused.status, 'REFUSED');
      assert.deepEqual(refused.answers, []);

      assert.equal((await setMode('nxdomain')).settings.blockMode, 'nxdomain');
      const nxdomain = decodeDnsResponse(await dohQuery(baseUrl, 'nxdomain.blocked.example', 'A'));
      assert.equal(nxdomain.status, 'NXDOMAIN');
      assert.deepEqual(nxdomain.answers, []);

      assert.equal((await setMode('nodata')).settings.blockMode, 'nodata');
      const nodata = decodeDnsResponse(await dohQuery(baseUrl, 'nodata.blocked.example', 'A'));
      assert.equal(nodata.status, 'NOERROR');
      assert.deepEqual(nodata.answers, []);

      assert.equal((await setMode('custom_ip')).settings.blockMode, 'custom');
      const customAlias = decodeDnsResponse(await dohQuery(baseUrl, 'custom-alias.blocked.example', 'A'));
      assert.equal(customAlias.answers[0].value, '203.0.113.9');

      const invalidResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ dnsBlockingIpv4: 'not-an-ip' })
      });
      assert.equal(invalidResponse.status, 400);
      assert.equal((await invalidResponse.json()).error, 'bad_dns_blocking_ipv4');

      const invalidModeResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ blockMode: 'redirect' })
      });
      assert.equal(invalidModeResponse.status, 400);
      assert.equal((await invalidModeResponse.json()).error, 'bad_block_mode');
    });
  } finally {
    await upstream.close();
  }
}

async function testDnsRateLimit() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      dns: { rateLimit: 2, rateLimitSubnetIpv4: 32, rateLimitSubnetIpv6: 128, rateLimitWhitelist: [] }
    }, async ({ baseUrl, cookie }) => {
      assert.equal(decodeDnsResponse(await dohQuery(baseUrl, 'rate-one.example')).status, 'NOERROR');
      assert.equal(decodeDnsResponse(await dohQuery(baseUrl, 'rate-two.example')).status, 'NOERROR');
      assert.equal(decodeDnsResponse(await dohQuery(baseUrl, 'rate-three.example')).status, 'REFUSED');
      assert.equal(upstream.queries.length, 2);

      const row = await recentQuery(baseUrl, cookie, 'rate-three.example');
      assert.equal(row.action, 'rate-limit');
      assert.equal(row.responseStatus, 'REFUSED');
      assert.match(row.rule, /^dns:rate-limit:v4:127\.0\.0\.1\/32$/);

      await new Promise((resolve) => setTimeout(resolve, 550));
      assert.equal(decodeDnsResponse(await dohQuery(baseUrl, 'rate-recovered.example')).status, 'NOERROR');
      assert.equal(upstream.queries.length, 3);
    });
  } finally {
    await upstream.close();
  }
}

async function testDnsRateLimitWhitelist() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      dns: { rateLimit: 1, rateLimitWhitelist: ['127.0.0.1'] }
    }, async ({ baseUrl }) => {
      for (const name of ['white-one.example', 'white-two.example', 'white-three.example']) {
        assert.equal(decodeDnsResponse(await dohQuery(baseUrl, name)).status, 'NOERROR');
      }
      assert.equal(upstream.queries.length, 3);
    });
  } finally {
    await upstream.close();
  }
}

async function testDomainProtection() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const threatDomain = 'malware.example';
  const adultDomain = 'adult.example';
  const threatHash = protectionDomainHashes(threatDomain).at(-1);
  const adultHash = protectionDomainHashes(adultDomain).at(-1);
  const protection = await startDnsServer((packet) => {
    const question = parseQuestion(packet);
    if (question.name.endsWith('.sb.dns.adguard.com')) return buildTxtAnswer(packet, [threatHash]);
    if (question.name.endsWith('.pc.dns.adguard.com')) return buildTxtAnswer(packet, [adultHash]);
    return buildTxtAnswer(packet, []);
  });
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      statistics: { enabled: true, retentionHours: 24, ignoredEnabled: false, ignored: [] },
      filter: {
        enabled: true,
        blockMode: 'null',
        safeBrowsing: {
          enabled: true,
          upstream: `udp://127.0.0.1:${protection.port}`,
          suffix: 'sb.dns.adguard.com',
          cacheTtlMinutes: 30
        },
        parental: {
          enabled: false,
          upstream: `udp://127.0.0.1:${protection.port}`,
          suffix: 'pc.dns.adguard.com',
          cacheTtlMinutes: 30
        }
      }
    }, async ({ baseUrl, cookie }) => {
      const blocked = decodeDnsResponse(await dohQuery(baseUrl, threatDomain));
      assert.equal(blocked.answers[0].value, '0.0.0.0');
      const threatRow = await recentQuery(baseUrl, cookie, threatDomain);
      assert.equal(threatRow.action, 'block-safebrowsing');
      assert.equal(threatRow.source, 'safe-browsing');
      assert.equal(threatRow.rule, 'safe-browsing:adguard-malware-shavar');
      assert.equal(upstream.queries.length, 0);

      await dohQuery(baseUrl, threatDomain);
      assert.equal(protection.queries.filter((item) => item.name.endsWith('.sb.dns.adguard.com')).length, 1);

      const settingsResponse = await fetch(baseUrl + '/api/settings', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ safeBrowsingEnabled: false, parentalEnabled: true })
      });
      assert.equal(settingsResponse.status, 200);
      const saved = await settingsResponse.json();
      assert.equal(saved.settings.safeBrowsingEnabled, false);
      assert.equal(saved.settings.parentalEnabled, true);

      const adult = decodeDnsResponse(await dohQuery(baseUrl, adultDomain));
      assert.equal(adult.answers[0].value, '0.0.0.0');
      const adultRow = await recentQuery(baseUrl, cookie, adultDomain);
      assert.equal(adultRow.action, 'block-parental');
      assert.equal(adultRow.source, 'parental');
      assert.equal(adultRow.rule, 'parental:category-blacklisted');

      const allowed = decodeDnsResponse(await dohQuery(baseUrl, 'allowed.example'));
      assert.equal(allowed.answers[0].value, expectedAddress);
      const status = await statusPayload(baseUrl, cookie);
      assert.equal(status.stats.safeBrowsing, 2);
      assert.equal(status.stats.parental, 1);
      assert.equal(status.stats.blocked, 3);
      assert.equal(status.stats.blockedFiltering, 0);
      assert.equal(status.domainProtection.services.safeBrowsing.blocked, 1);
      assert.equal(status.domainProtection.services.parental.blocked, 1);
    });
  } finally {
    await Promise.all([upstream.close(), protection.close()]);
  }
}

async function testClientDomainProtectionOverride() {
  const upstream = await startDnsServer((packet) => buildAnswer(packet, expectedAddress));
  const threatDomain = 'client-threat.example';
  const threatHash = protectionDomainHashes(threatDomain).at(-1);
  const protection = await startDnsServer((packet) => buildTxtAnswer(packet, [threatHash]));
  try {
    await withCleanDns({
      upstreams: [`udp://127.0.0.1:${upstream.port}`],
      filter: {
        enabled: true,
        safeBrowsing: {
          enabled: true,
          upstream: `udp://127.0.0.1:${protection.port}`,
          suffix: 'sb.dns.adguard.com'
        }
      },
      clients: [{
        id: 'client-domain-protection',
        name: 'Domain protection override',
        identifiers: ['127.0.0.1'],
        useGlobalSettings: false,
        filteringEnabled: true,
        safeBrowsingEnabled: false,
        parentalEnabled: false,
        safeSearch: { enabled: false }
      }]
    }, async ({ baseUrl, cookie }) => {
      const response = decodeDnsResponse(await dohQuery(baseUrl, threatDomain));
      assert.equal(response.answers[0].value, expectedAddress);
      assert.equal(protection.queries.length, 0);
      const row = await recentQuery(baseUrl, cookie, threatDomain);
      assert.equal(row.action, 'allow');
      assert.equal(row.clientPolicy.safeBrowsingEnabled, false);
      assert.equal(row.clientPolicy.parentalEnabled, false);
    });
  } finally {
    await Promise.all([upstream.close(), protection.close()]);
  }
}

async function withCleanDns(overrides, run) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cleandns-policy-'));
  const dataDir = path.join(tempDir, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const httpPort = await unusedTcpPort();
  const udpPort = await unusedUdpPort();
  const password = 'policy-test-password';
  const passwordFile = path.join(dataDir, 'admin-password');
  fs.writeFileSync(passwordFile, hashPassword(password) + '\n');
  fs.writeFileSync(path.join(dataDir, 'clients.json'), JSON.stringify(overrides.clients || []) + '\n');
  if (overrides.queryLogRows) {
    fs.writeFileSync(path.join(dataDir, 'query.log'), overrides.queryLogRows.map((row) => JSON.stringify(row)).join('\n') + '\n');
  }
  if (overrides.statsData) {
    fs.writeFileSync(path.join(dataDir, 'stats.json'), JSON.stringify(overrides.statsData, null, 2) + '\n');
  }
  if (overrides.blockRules) fs.writeFileSync(path.join(dataDir, 'blocklist.txt'), String(overrides.blockRules));
  const config = baseConfig(tempDir, httpPort, udpPort, passwordFile, overrides);
  const configPath = path.join(tempDir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  const child = spawn(process.execPath, ['server.js'], {
    cwd: appDir,
    env: { ...process.env, CLEANDNS_CONFIG: configPath },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  try {
    await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 5000, () => output);
    const baseUrl = `http://127.0.0.1:${httpPort}`;
    const cookie = await login(baseUrl, password);
    await run({ baseUrl, cookie, tempDir });
    return { exitCode: 0, output };
  } finally {
    await stopChild(child);
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function baseConfig(tempDir, httpPort, udpPort, passwordFile, overrides) {
  const dataDir = path.join(tempDir, 'data');
  return {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: overrides.upstreams,
    fallbackUpstreams: overrides.fallbackUpstreams || [],
    bootstrapDns: overrides.bootstrapDns || [],
    timeoutMs: overrides.timeoutMs || 500,
    upstreamMode: 'sequential',
    dns: { disableIpv6: false, privateReverseEnabled: false, privateReverseUpstreams: [], ...(overrides.dns || {}) },
    cache: { enabled: true, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, ...(overrides.cache || {}) },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: false, blockedServices: [], safeSearch: { enabled: false }, ...(overrides.filter || {}) },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 2160, anonymizeClientIp: false, ...(overrides.queryLog || {}) },
    statistics: { enabled: false, retentionHours: 24, ignoredEnabled: false, ignored: [], ...(overrides.statistics || {}) },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: {
      dohPath: '/dns-query',
      dohEnabled: true,
      panelPath: '/admin/',
      dohPublicBaseUrl: 'https://localhost',
      panelPublicUrl: 'https://localhost/admin/',
      plainDnsEnabled: false,
      doqEnabled: false,
      doqEndpoint: 'localhost',
      doqPort: 8853,
      dohSyncCommand: '',
      doqSyncCommand: ''
    },
    rules: {
      blockFile: path.join(dataDir, 'blocklist.txt'),
      allowFile: path.join(dataDir, 'allowlist.txt'),
      rewriteFile: path.join(dataDir, 'rewrites.txt'),
      subscriptionFile: path.join(dataDir, 'subscriptions.txt'),
      downloadDir: path.join(dataDir, 'subscriptions.d'),
      allowSubscriptionFile: path.join(dataDir, 'allow-subscriptions.txt'),
      allowDownloadDir: path.join(dataDir, 'allow-subscriptions.d'),
      autoUpdateEnabled: false,
      autoUpdateOnStartup: false,
      autoUpdateOnChange: false
    },
    clients: { file: path.join(dataDir, 'clients.json') },
    admin: { username: 'policy-test', passwordFile, sessionTtlSeconds: 60, trustProxy: false },
    logFile: path.join(dataDir, 'query.log'),
    statsFile: path.join(dataDir, 'stats.json')
  };
}

async function startDnsServer(answer) {
  const socket = dgram.createSocket('udp4');
  const queries = [];
  socket.on('message', (packet, info) => {
    queries.push(parseQuestion(packet));
    Promise.resolve(answer(packet)).then((response) => {
      if (response) socket.send(response, info.port, info.address);
    }).catch(() => {});
  });
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  return {
    port: socket.address().port,
    queries,
    close: () => new Promise((resolve) => socket.close(resolve))
  };
}

async function login(baseUrl, password) {
  const response = await fetch(baseUrl + '/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'policy-test', password })
  });
  assert.equal(response.status, 200);
  return String(response.headers.get('set-cookie') || '').split(';')[0];
}

async function recentQuery(baseUrl, cookie, name) {
  const response = await fetch(baseUrl + '/api/recent', { headers: { cookie } });
  assert.equal(response.status, 200);
  const body = await response.json();
  const row = (body.recent || []).find((item) => item.qname === name);
  assert.ok(row, `missing query log row for ${name}`);
  return row;
}

async function statusPayload(baseUrl, cookie) {
  const response = await fetch(baseUrl + '/api/status', { headers: { cookie } });
  assert.equal(response.status, 200);
  return response.json();
}

async function dohQuery(baseUrl, name, type = 'A') {
  const response = await fetch(baseUrl + '/dns-query', {
    method: 'POST',
    headers: {
      accept: 'application/dns-message',
      'content-type': 'application/dns-message'
    },
    body: buildQuery(name, type)
  });
  assert.equal(response.status, 200);
  assert.equal(String(response.headers.get('content-type')).split(';')[0], 'application/dns-message');
  return Buffer.from(await response.arrayBuffer());
}

function buildQuery(name, type = 'A') {
  const labels = name.split('.').flatMap((label) => [label.length, ...Buffer.from(label, 'ascii')]);
  const qtype = { A: 1, PTR: 12, AAAA: 28, DS: 43 }[String(type || 'A').toUpperCase()] || 1;
  return Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, ...labels, 0, (qtype >> 8) & 0xff, qtype & 0xff, 0, 1]);
}

function parseQuestion(packet) {
  const labels = [];
  let offset = 12;
  while (offset < packet.length && packet[offset]) {
    const length = packet[offset++];
    labels.push(packet.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }
  offset += 1;
  return { name: labels.join('.').toLowerCase(), type: packet.readUInt16BE(offset), end: offset + 4 };
}

function buildAnswer(packet, address, ttl = 60) {
  const question = parseQuestion(packet);
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(address ? 1 : 0, 6);
  if (!address) return Buffer.concat([header, packet.subarray(12, question.end)]);
  const octets = address.split('.').map(Number);
  const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, (ttl >>> 24) & 0xff, (ttl >>> 16) & 0xff, (ttl >>> 8) & 0xff, ttl & 0xff, 0, 4, ...octets]);
  return Buffer.concat([header, packet.subarray(12, question.end), answer]);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildTxtAnswer(packet, values) {
  const question = parseQuestion(packet);
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(values.length, 6);
  const answers = values.map((value) => {
    const text = Buffer.from(value, 'ascii');
    const record = Buffer.alloc(13);
    record.writeUInt16BE(0xc00c, 0);
    record.writeUInt16BE(16, 2);
    record.writeUInt16BE(1, 4);
    record.writeUInt32BE(60, 6);
    record.writeUInt16BE(text.length + 1, 10);
    record[12] = text.length;
    return Buffer.concat([record, text]);
  });
  return Buffer.concat([header, packet.subarray(12, question.end), ...answers]);
}

function firstIpv4Answer(packet) {
  return packet.readUInt16BE(6) ? [...packet.subarray(-4)].join('.') : '';
}

function hashPassword(password) {
  const salt = 'cleandns-policy-test';
  return `scrypt$${salt}$${crypto.scryptSync(password, salt, 64).toString('base64url')}`;
}

async function unusedUdpPort() {
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

async function unusedTcpPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(check, timeoutMs, output) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`server start timeout\n${output()}`);
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2000))
  ]);
  if (child.exitCode === null) child.kill();
}
