import crypto from 'node:crypto';
import { queryDnsUpstream } from '../upstream.js';

const upstreams = process.argv.slice(2);
if (!upstreams.length) {
  console.error('usage: node cmd/smoke-upstreams.mjs <upstream> [...]');
  process.exit(2);
}

const query = buildQuery('example.com');
let failed = false;
for (const upstream of upstreams) {
  const started = Date.now();
  try {
    const response = await queryDnsUpstream(upstream, query, 8000);
    console.log(JSON.stringify({
      upstream,
      ok: true,
      elapsedMs: Date.now() - started,
      rcode: response[3] & 0x0f,
      answers: response.readUInt16BE(6),
      bytes: response.length
    }));
  } catch (error) {
    failed = true;
    console.log(JSON.stringify({
      upstream,
      ok: false,
      elapsedMs: Date.now() - started,
      error: error.message || String(error)
    }));
  }
}

if (failed) process.exitCode = 1;

function buildQuery(name) {
  const labels = name.split('.').flatMap((label) => [label.length, ...Buffer.from(label, 'ascii')]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(crypto.randomInt(0, 65536), 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, Buffer.from([...labels, 0, 0, 1, 0, 1])]);
}
