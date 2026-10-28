import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { DoqUpstreamBridge } from '../doq-upstream.js';

const children = [];
const requests = [];
const bridge = new DoqUpstreamBridge({
  command: 'test-cleandns-dns',
  spawnProcess(command, args, options) {
    assert.equal(command, 'test-cleandns-dns');
    assert.deepEqual(args, ['-mode', 'upstream-stdio']);
    assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
    const child = createFakeChild(requests);
    children.push(child);
    return child;
  }
});

try {
  const firstPacket = dnsPacket(0x1234);
  const secondPacket = dnsPacket(0x5678);
  const [first, second] = await Promise.all([
    bridge.query({ address: '127.0.0.1:853', serverName: 'dns.example', timeoutMs: 1000, packet: firstPacket }),
    bridge.query({ address: '[2001:db8::53]:853', serverName: 'dns.example', timeoutMs: 1000, packet: secondPacket })
  ]);
  assert.deepEqual(first, firstPacket);
  assert.deepEqual(second, secondPacket);
  assert.equal(children.length, 1);
  assert.deepEqual(requests.map((item) => item.address), ['127.0.0.1:853', '[2001:db8::53]:853']);
  assert.deepEqual(requests.map((item) => Buffer.from(item.packet, 'base64')), [firstPacket, secondPacket]);

  children[0].failNext = 'tls: certificate verification failed';
  await assert.rejects(
    bridge.query({ address: '127.0.0.1:853', serverName: 'bad.example', timeoutMs: 1000, packet: firstPacket }),
    /certificate verification failed/
  );

  children[0].stdout.write('{not-json}\n');
  await new Promise((resolve) => setImmediate(resolve));
  const restarted = await bridge.query({ address: '127.0.0.1:853', serverName: 'dns.example', timeoutMs: 1000, packet: firstPacket });
  assert.deepEqual(restarted, firstPacket);
  assert.equal(children.length, 2);

  bridge.close();
  await assert.rejects(
    bridge.query({ address: '127.0.0.1:853', serverName: 'dns.example', timeoutMs: 1000, packet: firstPacket }),
    /doq_helper_closed/
  );

  const missingBridge = new DoqUpstreamBridge({
    spawnProcess() {
      const error = new Error('spawn missing-helper ENOENT');
      error.code = 'ENOENT';
      throw error;
    }
  });
  await assert.rejects(
    missingBridge.query({ address: '127.0.0.1:853', serverName: 'dns.example', timeoutMs: 1000, packet: firstPacket }),
    /doq_helper_unavailable/
  );
  missingBridge.close();
  console.log('DoQ upstream bridge tests passed');
} finally {
  bridge.close();
}

function createFakeChild(requestLog) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.buffer = '';
  child.failNext = '';
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      child.buffer += chunk.toString('utf8');
      for (;;) {
        const newline = child.buffer.indexOf('\n');
        if (newline < 0) break;
        const request = JSON.parse(child.buffer.slice(0, newline));
        child.buffer = child.buffer.slice(newline + 1);
        requestLog.push(request);
        const response = child.failNext
          ? { id: request.id, ok: false, error: child.failNext }
          : { id: request.id, ok: true, packet: request.packet };
        child.failNext = '';
        setImmediate(() => child.stdout.write(`${JSON.stringify(response)}\n`));
      }
      callback();
    }
  });
  child.kill = () => {
    child.killed = true;
    return true;
  };
  return child;
}

function dnsPacket(id) {
  return Buffer.from([
    id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01
  ]);
}
