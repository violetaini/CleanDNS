import assert from 'node:assert/strict';
import {
  DOMAIN_PROTECTION_SERVICES,
  DomainProtectionChecker,
  protectionDomainCandidates,
  protectionDomainHashes,
  protectionHashQuestion,
  protectionResponseHashes
} from '../domain-protection.js';

assert.deepEqual(protectionDomainCandidates('a.b.example.com'), [
  'a.b.example.com',
  'b.example.com',
  'example.com'
]);
assert.deepEqual(protectionDomainCandidates('www.example.co.uk'), ['www.example.co.uk', 'example.co.uk']);
assert.deepEqual(protectionDomainCandidates('localhost'), []);

const blockedDomain = 'www.example.com';
const blockedHash = protectionDomainHashes(blockedDomain).at(-1);
const question = protectionHashQuestion(protectionDomainHashes(blockedDomain), 'sb.dns.adguard.com.');
assert.ok(question.endsWith('.sb.dns.adguard.com'));
assert.ok(question.split('.')[0].length === 4);

const txtResponse = buildTxtResponse(question, [blockedHash]);
assert.deepEqual([...protectionResponseHashes(txtResponse)], [blockedHash]);

let now = Date.parse('2026-07-13T00:00:00Z');
const calls = [];
const checker = new DomainProtectionChecker({
  now: () => now,
  query: async (service, name) => {
    calls.push({ service: service.id, name });
    return service.id === 'parental' ? buildTxtResponse(name, [blockedHash]) : buildTxtResponse(name, []);
  }
});
const settings = {
  safeBrowsing: { ...DOMAIN_PROTECTION_SERVICES.safeBrowsing, enabled: true, cacheTtlMinutes: 30 },
  parental: { ...DOMAIN_PROTECTION_SERVICES.parental, enabled: true, cacheTtlMinutes: 30 }
};
const blocked = await checker.check(blockedDomain, settings);
assert.equal(blocked.service, 'parental');
assert.equal(blocked.rule, DOMAIN_PROTECTION_SERVICES.parental.rule);
assert.equal(calls.length, 2);

const cached = await checker.check(blockedDomain, settings);
assert.equal(cached.service, 'parental');
assert.equal(calls.length, 2);
assert.equal(checker.status().services.safeBrowsing.cacheHits, 1);
assert.equal(checker.status().services.parental.cacheHits, 1);

now += 31 * 60_000;
await checker.check(blockedDomain, settings);
assert.equal(calls.length, 4);

const failing = new DomainProtectionChecker({ query: async () => { throw new Error('offline'); } });
assert.equal(await failing.check(blockedDomain, { safeBrowsing: settings.safeBrowsing }), null);
assert.equal(failing.status().services.safeBrowsing.failures, 1);
assert.equal(failing.status().services.safeBrowsing.lastError, 'offline');

checker.clear();
assert.equal(checker.status().cacheEntries, 0);
console.log('domain protection tests passed');

function buildTxtResponse(name, values) {
  const question = encodeName(name);
  const answers = values.map((value) => {
    const text = Buffer.from(value, 'ascii');
    return Buffer.concat([
      Buffer.from([0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, text.length + 1, text.length]),
      text
    ]);
  });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  return Buffer.concat([header, question, Buffer.from([0x00, 0x10, 0x00, 0x01]), ...answers]);
}

function encodeName(name) {
  return Buffer.concat(String(name).split('.').map((label) => {
    const text = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([text.length]), text]);
  }).concat(Buffer.from([0])));
}
