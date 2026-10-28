import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeDnsResponse } from '../dns-response.js';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempBase = path.resolve(os.tmpdir());
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-filter-modifiers-'));
let server;
let upstream;

try {
  const scenario = await startScenario();
  server = scenario.server;
  upstream = scenario.upstream;
  const cookie = await login(scenario);
  const clientPayload = await getJson(scenario, '/api/clients', cookie);
  assert.equal(clientPayload.clients?.[0]?.name, "Family, Lab|One's PC");
  assert.deepEqual(clientPayload.clients?.[0]?.identifiers, ['127.0.0.1']);

  const checkStatusBefore = await getJson(scenario, '/api/status', cookie);
  const checkLogBefore = await getJson(scenario, '/api/recent?limit=1', cookie);
  const checkUpstreamBefore = scenario.upstreamQueries.length;
  const blockedCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'type-only.test', type: 'AAAA', clientIp: '127.0.0.1' });
  assert.equal(blockedCheck.status, 'blocked');
  assert.equal(blockedCheck.reason, 'block');
  assert.equal(blockedCheck.rules?.[0]?.text, '||type-only.test^$dnstype=AAAA');
  const notFilteredCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'type-only.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(notFilteredCheck.status, 'not_filtered');
  const clientCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'client-name.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(clientCheck.status, 'blocked');
  assert.equal(clientCheck.client?.name, "Family, Lab|One's PC");
  const rewriteCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'rewrite-multi.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(rewriteCheck.status, 'rewritten');
  assert.equal(rewriteCheck.reason, 'filter_rewrite');
  assert.deepEqual(rewriteCheck.rewrite?.values, ['192.0.2.20', '192.0.2.21']);
  assert.equal(rewriteCheck.rules?.length, 2);
  const dedicatedCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'check-dedicated.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(dedicatedCheck.status, 'rewritten');
  assert.equal(dedicatedCheck.source, 'rewrite');
  assert.deepEqual(dedicatedCheck.rewrite?.values, ['192.0.2.50']);
  const serviceCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'openai.com', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(serviceCheck.status, 'blocked');
  assert.equal(serviceCheck.reason, 'blocked_service');
  assert.equal(serviceCheck.service?.id, 'chatgpt');
  const arbitraryTypeCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'unmatched.test', type: 'CAA', clientIp: '127.0.0.1' });
  assert.equal(arbitraryTypeCheck.status, 'not_filtered');
  assert.equal(arbitraryTypeCheck.qtype, 'CAA');
  const plainExactCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'plain-exact.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(plainExactCheck.status, 'blocked');
  const plainChildCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'child.plain-exact.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(plainChildCheck.status, 'not_filtered');
  const hostsCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'www.google-host.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(hostsCheck.status, 'blocked');
  assert.equal(hostsCheck.reason, 'hosts_rule');
  assert.equal(hostsCheck.source, 'filter-hosts');
  assert.deepEqual(hostsCheck.rewrite?.values, ['216.239.38.120']);
  assert.equal(hostsCheck.rules?.[0]?.text, '216.239.38.120 google-host.test www.google-host.test');
  const hostsWrongFamilyCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'ipv6-host.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(hostsWrongFamilyCheck.status, 'blocked');
  assert.equal(hostsWrongFamilyCheck.rewrite?.kind, 'nodata');
  assert.deepEqual(hostsWrongFamilyCheck.rewrite?.values, []);
  const checkStatusAfter = await getJson(scenario, '/api/status', cookie);
  const checkLogAfter = await getJson(scenario, '/api/recent?limit=1', cookie);
  assert.equal(checkStatusAfter.stats.total, checkStatusBefore.stats.total);
  assert.equal(checkLogAfter.total, checkLogBefore.total);
  assert.equal(scenario.upstreamQueries.length, checkUpstreamBefore);

  await expectUdp(scenario, 'bulk129999.large.test', 1, 3, false);
  await expectUdp(scenario, 'type-only.test', 1, 0, true);
  await expectUdp(scenario, 'type-only.test', 28, 3, false);
  await expectUdp(scenario, 'type-exclude.test', 1, 3, false);
  await expectUdp(scenario, 'type-exclude.test', 28, 0, true);
  await expectUdp(scenario, 'duplicate-type.test', 1, 3, false);
  await expectUdp(scenario, 'duplicate-type.test', 28, 3, false);

  await expectUdp(scenario, 'important.test', 1, 0, true);
  await expectUdp(scenario, 'blocked.important.test', 1, 3, false);
  await expectUdp(scenario, 'important-exception.test', 1, 0, true);

  await expectUdp(scenario, 'evil.deny.test', 1, 3, false);
  await expectUdp(scenario, 'safe.deny.test', 1, 0, true);
  await expectUdp(scenario, 'child.safe.deny.test', 1, 0, true);

  await expectUdp(scenario, 'unsupported-client.test', 1, 0, true);

  await expectRewrite(scenario, 'rewrite-a.test', 1, { answers: ['A:192.0.2.10'] });
  await expectRewrite(scenario, 'rewrite-aaaa.test', 28, { answers: ['AAAA:2001:db8:0:0:0:0:0:10'] });
  await expectRewrite(scenario, 'rewrite-cname.test', 1, { answers: ['CNAME:target.rewrite.test'] });
  await expectRewrite(scenario, 'rewrite-cname-latest.test', 1, { answers: ['CNAME:second.rewrite.test'] });
  await expectRewrite(scenario, 'rewrite-txt.test', 16, { answers: ['TXT:hello,world'] });
  await expectRewrite(scenario, '4.3.2.1.in-addr.arpa', 12, { answers: ['PTR:ptr.rewrite.test'] });
  await expectRewrite(scenario, 'rewrite-mx.test', 15, { answers: ['MX:10 mail.rewrite.test'] });
  await expectRewrite(scenario, '_service._tcp.rewrite-srv.test', 33, { answers: ['SRV:5 10 443 target.rewrite.test'] });
  await expectRewrite(scenario, 'rewrite-caa.test', 257, { answers: ['CAA:0 issue letsencrypt.org'] });
  await expectRewrite(scenario, 'rewrite-refused.test', 1, { code: 5, answers: [] });
  await expectRewrite(scenario, 'rewrite-nxdomain.test', 1, { code: 3, answers: [] });
  await expectRewrite(scenario, 'rewrite-nodata.test', 16, { code: 0, answers: [] });
  await expectRewrite(scenario, 'rewrite-multi.test', 1, { answers: ['A:192.0.2.20', 'A:192.0.2.21'] });
  await expectRewrite(scenario, 'rewrite-disable-one.test', 1, { answers: ['A:192.0.2.31'] });
  await expectRewrite(scenario, 'rewrite-disable-all.test', 1, { answers: [], forwarded: true });
  const clientApiResult = await postJson(scenario, '/api/test', cookie, {
    name: 'rewrite-client.test',
    type: 'A',
    clientIp: '127.0.0.1'
  });
  const clientApiLog = await getJson(scenario, '/api/recent?search=rewrite-client.test&limit=5', cookie);
  assert.deepEqual(
    clientApiResult.answers?.map((answer) => `${answer.type}:${answer.value}`),
    ['A:192.0.2.40'],
    JSON.stringify({ result: clientApiResult, log: clientApiLog.recent })
  );
  await expectRewrite(scenario, 'rewrite-client.test', 1, { answers: ['A:192.0.2.40'] });
  await expectRewrite(scenario, 'rewrite-client-miss.test', 1, { answers: [], forwarded: true });
  await expectRewrite(scenario, 'rewrite-tag.test', 1, { answers: ['A:192.0.2.42'] });
  await expectRewrite(scenario, 'rewrite-type.test', 28, { answers: ['AAAA:2001:db8:0:0:0:0:0:43'] });
  await expectRewrite(scenario, 'rewrite-type.test', 1, { answers: [], forwarded: true });
  await expectRewrite(scenario, 'rewrite-allow.test', 1, { answers: [], forwarded: true });
  await expectRewrite(scenario, 'rewrite-important.test', 1, { answers: ['A:192.0.2.45'] });
  await expectRewrite(scenario, 'rewrite-important-allow.test', 1, { answers: [], forwarded: true });
  await expectRewrite(scenario, 'rewrite-important-exception.test', 1, { answers: ['A:192.0.2.47'] });
  await expectRewrite(scenario, 'rewrite-badfilter.test', 1, { answers: [], forwarded: true });

  await expectUdp(scenario, 'badfilter-disabled.test', 1, 0, true);
  await expectUdp(scenario, 'badfilter-important.test', 1, 0, true);
  await expectUdp(scenario, 'badfilter-exception.test', 1, 3, false);
  await expectUdp(scenario, 'badfilter-type.test', 1, 3, false);
  await expectUdp(scenario, 'badfilter-type.test', 28, 0, true);

  await expectUdp(scenario, 'test123.wild.test', 1, 3, false);
  await expectUdp(scenario, 'test.wild.test', 1, 3, false);
  await expectUdp(scenario, 'other.wild.test', 1, 0, true);
  await expectUdp(scenario, 'child.subwild.test', 1, 3, false);
  await expectUdp(scenario, 'deep.child.subwild.test', 1, 3, false);
  await expectUdp(scenario, 'subwild.test', 1, 0, true);
  await expectUdp(scenario, 'notsubwild.test', 1, 0, true);
  await expectUdp(scenario, 'type123.wildtype.test', 1, 0, true);
  await expectUdp(scenario, 'type123.wildtype.test', 28, 3, false);
  await expectUdp(scenario, 'foo123bar.midwild.test', 1, 3, false);
  await expectUdp(scenario, 'foo123.midwild.test', 1, 0, true);

  await expectUdp(scenario, 'plain-exact.test', 1, 3, false);
  await expectUdp(scenario, 'child.plain-exact.test', 1, 0, true);
  await expectUdp(scenario, 'plain-allowed.test', 1, 0, true);
  await expectUdp(scenario, 'child.plain-allowed.test', 1, 3, false);
  await expectUdp(scenario, 'hosts-allowed.test', 1, 0, true);
  await expectUdp(scenario, 'child.hosts-allowed.test', 1, 3, false);
  await expectUdp(scenario, 'singlehost', 1, 3, false);
  await expectUdp(scenario, 'onemoreexamsite.com', 1, 3, false);
  await expectUdp(scenario, 'regexgeneric-value.test', 1, 3, false);
  await expectUdp(scenario, 'safe.regexgeneric.test', 1, 0, true);
  await expectUdp(scenario, 'start-anchor.test', 1, 3, false);
  await expectUdp(scenario, 'xstart-anchor.test', 1, 0, true);
  await expectUdp(scenario, 'prefix-end-anchor.test', 1, 3, false);
  await expectUdp(scenario, 'prefix-end-anchor.test.evil', 1, 0, true);
  await expectUdp(scenario, 'both-anchor.test', 1, 3, false);
  await expectUdp(scenario, 'child.both-anchor.test', 1, 0, true);
  await expectUdp(scenario, 'anchor-match.boundary.test', 1, 3, false);
  await expectUdp(scenario, 'anchor-match.boundary.test.evil', 1, 0, true);
  await expectUdp(scenario, 'aaaaaaaaaaaaaaaaaaaaab.unsafe', 1, 0, true);

  await expectUdp(scenario, 'google-host.test', 1, 3, false);
  const defaultModeResponse = await postJson(scenario, '/api/settings', cookie, { blockMode: 'default' });
  assert.equal(defaultModeResponse.settings?.blockMode, 'default');
  await expectRewrite(scenario, 'google-host.test', 1, { answers: ['A:216.239.38.120'], ttl: 60 });
  await expectRewrite(scenario, 'www.google-host.test', 1, { answers: ['A:216.239.38.120'] });
  await expectRewrite(scenario, 'child.google-host.test', 1, { answers: [], forwarded: true });
  await expectRewrite(scenario, 'ipv6-host.test', 28, { answers: ['AAAA:0:0:0:0:0:0:0:1'] });
  await expectRewrite(scenario, 'ipv6-host.test', 1, { answers: ['A:0.0.0.0'] });
  await expectRewrite(scenario, 'multi-host.test', 1, { answers: ['A:0.0.0.1', 'A:0.0.0.2'] });
  await expectRewrite(scenario, 'multi-host.test', 28, { answers: ['AAAA:0:0:0:0:0:0:0:1'] });
  await expectRewrite(scenario, 'blocked-host.test', 1, { answers: ['A:0.0.0.0'] });
  await expectRewrite(scenario, 'arbitrary-host.test', 1, { answers: ['A:198.51.100.25'] });
  const nxdomainModeResponse = await postJson(scenario, '/api/settings', cookie, { blockMode: 'nxdomain' });
  assert.equal(nxdomainModeResponse.settings?.blockMode, 'nxdomain');

  await expectUdp(scenario, 'client-name.test', 1, 3, false);
  await expectUdp(scenario, 'client-ip.test', 1, 3, false);
  await expectUdp(scenario, 'client-cidr.test', 1, 3, false);
  await expectUdp(scenario, 'client-unmatched.test', 1, 0, true);
  await expectUdp(scenario, 'client-excluded.test', 1, 0, true);
  await expectUdp(scenario, 'client-combined.test', 1, 0, true);
  await expectUdp(scenario, 'client-combined.test', 28, 3, false);
  await expectUdp(scenario, 'client-tag.test', 1, 3, false);
  await expectUdp(scenario, 'client-tag-excluded.test', 1, 0, true);
  await expectUdp(scenario, 'client-tag-mixed.test', 1, 3, false);

  await expectDoh(scenario, 'type-only.test', 28, 3, false);
  await expectDoh(scenario, 'type-only.test', 1, 0, true);
  await expectDohRewrite(scenario, 'rewrite-a.test', 1, ['A:192.0.2.10']);

  const status = await getJson(scenario, '/api/status', cookie);
  assert.ok(status.rules.hosts >= 8);
  assert.ok(status.rules.filterRewrite >= 20);
  assert.ok(status.rules.filterRewriteException >= 3);
  assert.equal(status.rules.rewrite, status.rules.dedicatedRewrite + status.rules.filterRewrite);
  assert.ok(status.stats.rewritten >= 20);
  const recent = await getJson(scenario, '/api/recent?search=rewrite-multi.test&limit=10', cookie);
  const rewriteLog = recent.recent.find((row) => row.qname === 'rewrite-multi.test');
  assert.equal(rewriteLog?.action, 'rewrite');
  assert.equal(rewriteLog?.source, 'filter-rewrite');
  assert.deepEqual(rewriteLog?.matchedRules, [
    '||rewrite-multi.test^$dnsrewrite=192.0.2.20',
    '||rewrite-multi.test^$dnsrewrite=192.0.2.21'
  ]);

  const settingsResponse = await fetch(`http://127.0.0.1:${scenario.httpPort}/api/settings`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({ filterEnabled: false })
  });
  assert.equal(settingsResponse.status, 200);
  const disabledBlockCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'type-exclude.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(disabledBlockCheck.status, 'not_filtered');
  assert.equal(disabledBlockCheck.reason, 'protection_disabled');
  const disabledRewriteCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'rewrite-a.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(disabledRewriteCheck.status, 'rewritten');
  const disabledHostsCheck = await postJson(scenario, '/api/filter/check', cookie, { name: 'google-host.test', type: 'A', clientIp: '127.0.0.1' });
  assert.equal(disabledHostsCheck.status, 'not_filtered');
  assert.equal(disabledHostsCheck.reason, 'protection_disabled');
  await expectRewrite(scenario, 'rewrite-a.test', 1, { answers: ['A:192.0.2.10'] });
  await expectUdp(scenario, 'google-host.test', 1, 0, true);
  await expectUdp(scenario, 'blocked.important.test', 1, 0, true);

  console.log('filter modifier tests passed');
} finally {
  await stopChild(server);
  if (upstream) await new Promise((resolve) => upstream.close(resolve));
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-filter-modifiers-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

async function expectUdp(scenario, name, type, expectedCode, forwarded) {
  const before = scenario.upstreamQueries.length;
  const response = await queryUdp(scenario.udpPort, buildQuery(name, type, 0x7100 + before));
  assert.equal(responseCode(response), expectedCode, `${name} type ${type}`);
  assert.equal(scenario.upstreamQueries.length, before + (forwarded ? 1 : 0), `${name} forwarding`);
}

async function expectRewrite(scenario, name, type, expected = {}) {
  const before = scenario.upstreamQueries.length;
  const response = await queryUdp(scenario.udpPort, buildQuery(name, type, 0x7300 + before));
  const decoded = decodeDnsResponse(response);
  assert.equal(decoded.rcode, expected.code ?? 0, `${name} type ${type} rcode`);
  assert.deepEqual(
    decoded.answers.map((answer) => `${answer.type}:${answer.value}`),
    expected.answers || [],
    `${name} type ${type} answers`
  );
  if (Number.isInteger(expected.ttl)) {
    assert.ok(decoded.answers.every((answer) => answer.ttl === expected.ttl), `${name} type ${type} ttl`);
  }
  assert.equal(scenario.upstreamQueries.length, before + (expected.forwarded ? 1 : 0), `${name} forwarding`);
}

async function expectDoh(scenario, name, type, expectedCode, forwarded) {
  const before = scenario.upstreamQueries.length;
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}/dns-query`, {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
    body: buildQuery(name, type, 0x7200 + before)
  });
  assert.equal(response.status, 200);
  assert.match(String(response.headers.get('content-type') || ''), /^application\/dns-message/);
  assert.equal(responseCode(Buffer.from(await response.arrayBuffer())), expectedCode, `${name} DoH type ${type}`);
  assert.equal(scenario.upstreamQueries.length, before + (forwarded ? 1 : 0), `${name} DoH forwarding`);
}

async function expectDohRewrite(scenario, name, type, answers) {
  const before = scenario.upstreamQueries.length;
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}/dns-query`, {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
    body: buildQuery(name, type, 0x7400 + before)
  });
  assert.equal(response.status, 200);
  const decoded = decodeDnsResponse(Buffer.from(await response.arrayBuffer()));
  assert.equal(decoded.rcode, 0);
  assert.deepEqual(decoded.answers.map((answer) => `${answer.type}:${answer.value}`), answers);
  assert.equal(scenario.upstreamQueries.length, before, `${name} DoH forwarding`);
}

async function login(scenario) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'test', password: 'test-password' })
  });
  assert.equal(response.status, 200);
  return String(response.headers.get('set-cookie') || '').split(';')[0];
}

async function getJson(scenario, pathname, cookie) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}${pathname}`, { headers: { cookie } });
  assert.equal(response.status, 200);
  return response.json();
}

async function postJson(scenario, pathname, cookie, body) {
  const response = await fetch(`http://127.0.0.1:${scenario.httpPort}${pathname}`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function startScenario() {
  const dataDir = path.join(root, 'data');
  const rulesDir = path.join(dataDir, 'rules');
  fs.mkdirSync(path.join(rulesDir, 'subscriptions.d'), { recursive: true });
  fs.mkdirSync(path.join(rulesDir, 'allow-subscriptions.d'), { recursive: true });

  const upstreamSocket = dgram.createSocket('udp4');
  const upstreamQueries = [];
  upstreamSocket.on('message', (packet, info) => {
    const question = parseDnsQuestion(packet);
    if (question) upstreamQueries.push(question);
    const response = buildNoErrorResponse(packet, question);
    if (response) upstreamSocket.send(response, info.port, info.address);
  });
  await bindUdp(upstreamSocket, 0);

  const httpPort = await unusedTcpPort();
  const udpPort = await unusedUdpPort();
  const files = {
    block: path.join(rulesDir, 'blocklist.txt'),
    allow: path.join(rulesDir, 'allowlist.txt'),
    rewrite: path.join(rulesDir, 'rewrites.txt'),
    subscriptions: path.join(rulesDir, 'subscriptions.txt'),
    allowSubscriptions: path.join(rulesDir, 'allow-subscriptions.txt'),
    clients: path.join(dataDir, 'clients.json'),
    password: path.join(dataDir, 'admin-password'),
    log: path.join(dataDir, 'query.log'),
    stats: path.join(dataDir, 'stats.json')
  };
  fs.writeFileSync(files.block, [
    '||type-only.test^$dnstype=AAAA',
    '||type-exclude.test^$dnstype=~AAAA',
    '||duplicate-type.test^$dnstype=A',
    '||duplicate-type.test^$dnstype=AAAA',
    '@@||important.test^',
    '||blocked.important.test^$important',
    '||important-exception.test^$important',
    '@@||important-exception.test^$important',
    '||deny.test^$denyallow=safe.deny.test|other.deny.test',
    '||unsupported-client.test^$client=family',
    '||rewrite-a.test^$dnsrewrite=192.0.2.10',
    '||rewrite-aaaa.test^$dnsrewrite=2001:db8::10',
    '||rewrite-cname.test^$dnsrewrite=target.rewrite.test',
    '||rewrite-cname-latest.test^$dnsrewrite=first.rewrite.test',
    '||rewrite-cname-latest.test^$dnsrewrite=second.rewrite.test',
    '||rewrite-txt.test^$dnsrewrite=NOERROR;TXT;hello\\,world',
    '||4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;ptr.rewrite.test.',
    '||rewrite-mx.test^$dnsrewrite=NOERROR;MX;10 mail.rewrite.test.',
    '||_service._tcp.rewrite-srv.test^$dnsrewrite=NOERROR;SRV;5 10 443 target.rewrite.test.',
    '||rewrite-caa.test^$dnsrewrite=NOERROR;CAA;0 issue letsencrypt.org',
    '||rewrite-refused.test^$dnsrewrite=REFUSED',
    '||rewrite-nxdomain.test^$dnsrewrite=NXDOMAIN;;',
    '||rewrite-nodata.test^$dnsrewrite=NOERROR;;',
    '||rewrite-multi.test^$dnsrewrite=192.0.2.20',
    '||rewrite-multi.test^$dnsrewrite=192.0.2.21',
    '||rewrite-disable-one.test^$dnsrewrite=192.0.2.30',
    '||rewrite-disable-one.test^$dnsrewrite=192.0.2.31',
    '@@||rewrite-disable-one.test^$dnsrewrite=NOERROR;A;192.0.2.30',
    '||rewrite-disable-all.test^$dnsrewrite=192.0.2.32',
    '@@||rewrite-disable-all.test^$dnsrewrite',
    "||rewrite-client.test^$client='Family\\, Lab\\|One\\'s PC',dnsrewrite=192.0.2.40",
    '||rewrite-client-miss.test^$client=192.0.2.0/24,dnsrewrite=192.0.2.41',
    '||rewrite-tag.test^$ctag=device_laptop,dnsrewrite=192.0.2.42',
    '||rewrite-type.test^$dnstype=AAAA,dnsrewrite=2001:db8::43',
    '@@||rewrite-allow.test^',
    '||rewrite-allow.test^$dnsrewrite=192.0.2.44',
    '@@||rewrite-important.test^',
    '||rewrite-important.test^$important,dnsrewrite=192.0.2.45',
    '@@||rewrite-important-allow.test^$important',
    '||rewrite-important-allow.test^$important,dnsrewrite=192.0.2.46',
    '||rewrite-important-exception.test^$important,dnsrewrite=192.0.2.47',
    '@@||rewrite-important-exception.test^$dnsrewrite=192.0.2.47',
    '||rewrite-badfilter.test^$dnsrewrite=192.0.2.48',
    '||rewrite-badfilter.test^$badfilter,dnsrewrite=192.0.2.48',
    '||badfilter-disabled.test^',
    '||badfilter-disabled.test^$badfilter',
    '||badfilter-important.test^$important',
    '||badfilter-important.test^$badfilter,important',
    '||badfilter-exception.test^',
    '@@||badfilter-exception.test^',
    '@@||badfilter-exception.test^$badfilter',
    '||badfilter-type.test^$dnstype=A',
    '||badfilter-type.test^$dnstype=AAAA,badfilter',
    'test*.wild.test^',
    '||*.subwild.test^',
    'type*.wildtype.test^$dnstype=AAAA',
    'foo*bar.midwild.test^',
    'plain-exact.test',
    '||plain-allowed.test^',
    '||hosts-allowed.test^',
    '||singlehost^',
    'exam*.com',
    '/regexgeneric.*/',
    '@@||safe.regexgeneric.test^',
    '|start-anchor',
    'end-anchor.test|',
    '|both-anchor.test|',
    'anchor*.boundary.test^',
    '/(a+)+\\.unsafe/',
    '216.239.38.120 google-host.test www.google-host.test # enforce a fixed result',
    '::1 ipv6-host.test',
    '0.0.0.1 multi-host.test',
    '0.0.0.2 multi-host.test',
    '::1 multi-host.test',
    '0.0.0.0 blocked-host.test',
    '198.51.100.25 arbitrary-host.test',
    "||client-name.test^$client='Family\\, Lab\\|One\\'s PC'",
    '||client-ip.test^$client=127.0.0.1',
    '||client-cidr.test^$client=127.0.0.0/8',
    '||client-unmatched.test^$client=192.0.2.0/24',
    "||client-excluded.test^$client=~'Family\\, Lab\\|One\\'s PC'",
    "||client-combined.test^$client='Family\\, Lab\\|One\\'s PC',dnstype=AAAA",
    '||client-tag.test^$ctag=device_laptop|device_phone',
    '||client-tag-excluded.test^$ctag=~device_laptop',
    '||client-tag-mixed.test^$ctag=~device_phone|user_child'
  ].join('\n') + '\n');
  fs.writeFileSync(files.allow, [
    'plain-allowed.test',
    '198.51.100.10 hosts-allowed.test alias-hosts-allowed.test # exact allow aliases'
  ].join('\n') + '\n');
  [files.allowSubscriptions, files.log].forEach((file) => fs.writeFileSync(file, ''));
  fs.writeFileSync(files.rewrite, 'check-dedicated.test A 192.0.2.50\n');
  const bulkUrl = 'https://filters.test/large-corpus.txt';
  const bulkFile = path.join(rulesDir, 'subscriptions.d', crypto.createHash('sha256').update(bulkUrl).digest('hex').slice(0, 16) + '.txt');
  fs.writeFileSync(files.subscriptions, bulkUrl + '\n');
  fs.writeFileSync(bulkFile, Array.from({ length: 130_000 }, (_, index) => `||bulk${index}.large.test^`).join('\n') + '\n');
  fs.writeFileSync(files.clients, JSON.stringify([{
    name: "Family, Lab|One's PC",
    identifiers: ['127.0.0.1'],
    tags: ['device_laptop', 'user_child']
  }], null, 2) + '\n');
  fs.writeFileSync(files.stats, '{}\n');
  fs.writeFileSync(files.password, hashPassword('test-password') + '\n');

  const config = {
    domain: 'localhost',
    http: { host: '127.0.0.1', port: httpPort },
    udp: { host: '127.0.0.1', port: udpPort },
    upstreams: [`udp://127.0.0.1:${upstreamSocket.address().port}`],
    fallbackUpstreams: [],
    bootstrapDns: [],
    timeoutMs: 1000,
    upstreamMode: 'sequential',
    dns: { dnssecEnabled: false, disableIpv6: false, refuseAny: true, resolveClients: false, privateReverseEnabled: false, privateReverseUpstreams: [] },
    cache: { enabled: false, maxEntries: 100, minTtl: 1, maxTtl: 60, staleTtl: 0, optimistic: false, optimisticAnswerTtl: 30, optimisticMaxAge: 60 },
    ecs: { enabled: false, ipv4Prefix: 24, ipv6Prefix: 56, defaultIpv4: '' },
    filter: { enabled: true, blockMode: 'nxdomain', blockedServices: ['chatgpt'], safeBrowsing: { enabled: false }, parental: { enabled: false }, safeSearch: { enabled: false } },
    queryLog: { enabled: true, maxEntries: 100, retentionHours: 24, anonymizeClientIp: false },
    statistics: { enabled: true, retentionHours: 24, ignoredEnabled: false, ignored: [] },
    access: { allowedClients: [], blockedClients: [], blockedHosts: [] },
    service: { dohPath: '/dns-query', dohEnabled: true, panelPath: '/admin/', plainDnsEnabled: false, doqEnabled: false, doqPort: 8853, dohSyncCommand: '', doqSyncCommand: '' },
    rules: {
      blockFile: files.block,
      allowFile: files.allow,
      rewriteFile: files.rewrite,
      subscriptionFile: files.subscriptions,
      downloadDir: path.join(rulesDir, 'subscriptions.d'),
      allowSubscriptionFile: files.allowSubscriptions,
      allowDownloadDir: path.join(rulesDir, 'allow-subscriptions.d'),
      autoUpdateEnabled: false,
      autoUpdateOnStartup: false,
      autoUpdateOnChange: false
    },
    clients: { file: files.clients },
    admin: { username: 'test', passwordFile: files.password, sessionTtlSeconds: 600, trustProxy: false },
    logFile: files.log,
    statsFile: files.stats
  };
  const configPath = path.join(root, 'config.json');
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
  await waitFor(() => output.includes(`cleandns http listening on 127.0.0.1:${httpPort}`), 30_000, () => output);
  return { server: child, upstream: upstreamSocket, upstreamQueries, httpPort, udpPort };
}

function buildQuery(name, type, id) {
  const labels = name.split('.').map((label) => {
    const value = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([value.length]), value]);
  });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const suffix = Buffer.alloc(5);
  suffix.writeUInt16BE(type, 1);
  suffix.writeUInt16BE(1, 3);
  return Buffer.concat([header, ...labels, suffix]);
}

function parseDnsQuestion(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 17) return null;
  const labels = [];
  let offset = 12;
  while (offset < packet.length && packet[offset]) {
    const length = packet[offset];
    offset += 1;
    if (offset + length > packet.length) return null;
    labels.push(packet.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }
  const questionEnd = offset + 5;
  if (questionEnd > packet.length) return null;
  return { qname: labels.join('.'), qtype: packet.readUInt16BE(offset + 1), questionEnd };
}

function buildNoErrorResponse(packet, question) {
  if (!question) return null;
  const header = Buffer.alloc(12);
  packet.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, packet.subarray(12, question.questionEnd)]);
}

function responseCode(packet) {
  return Buffer.isBuffer(packet) && packet.length >= 4 ? packet.readUInt16BE(2) & 0x0f : -1;
}

function queryUdp(port, packet) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => finish(new Error('dns query timeout')), 3000);
    const finish = (error, response) => {
      clearTimeout(timer);
      socket.close();
      if (error) reject(error); else resolve(response);
    };
    socket.once('error', finish);
    socket.once('message', (response) => finish(null, response));
    socket.send(packet, port, '127.0.0.1', (error) => { if (error) finish(error); });
  });
}

async function unusedTcpPort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

async function unusedUdpPort() {
  const socket = dgram.createSocket('udp4');
  await bindUdp(socket, 0);
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

function bindUdp(socket, port) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(port, '127.0.0.1', resolve);
  });
}

function hashPassword(value) {
  const salt = 'cleandns-filter-modifiers';
  return `scrypt$${salt}$${crypto.scryptSync(value, salt, 64).toString('base64url')}`;
}

async function waitFor(check, timeoutMs, output = () => '') {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`wait timeout\n${output()}`);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2000))
  ]);
  if (child.exitCode === null) child.kill();
}
