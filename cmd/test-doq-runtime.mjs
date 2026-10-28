import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { ManagedDoqRuntime } from '../doq-runtime.js';

const children = [];
const runtime = new ManagedDoqRuntime({
  command: '/test/cleandns-dns',
  configPath: '/test/config.json',
  restartDelayMs: 5,
  startTimeoutMs: 250,
  stopTimeoutMs: 100,
  spawnProcess(command, args, options) {
    assert.equal(command, '/test/cleandns-dns');
    assert.deepEqual(args, ['-config', '/test/config.json', '-listen', '0.0.0.0']);
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
    const child = createChild(7300 + children.length);
    children.push(child);
    queueMicrotask(() => child.stderr.write('cleandns-dns doq listening on 0.0.0.0:853\n'));
    return child;
  }
});

const running = await runtime.sync({ enabled: true });
assert.equal(running.running, true);
assert.equal(running.unit, 'cleandns.service');
assert.equal(running.manager, 'cleandns-main-process');
assert.equal(running.pid, 7300);
assert.equal(running.parentPid, process.pid);
assert.equal(children.length, 1);

children[0].emitExit(1);
await waitFor(() => children.length === 2 && runtime.snapshot().running === true);
assert.equal(runtime.snapshot().pid, 7301);

const disabled = await runtime.sync({ enabled: false });
assert.equal(disabled.running, false);
assert.equal(disabled.activeState, 'disabled');
assert.equal(children[1].killed, true);

const failing = new ManagedDoqRuntime({
  command: '/test/missing',
  configPath: '/test/config.json',
  startTimeoutMs: 100,
  spawnProcess() {
    const child = createChild(7400);
    queueMicrotask(() => child.emitExit(1, null, 'bind: address already in use'));
    return child;
  }
});
await assert.rejects(failing.sync({ enabled: true }), /bind: address already in use/);
assert.equal(failing.snapshot().running, false);
assert.equal(failing.snapshot().activeState, 'failed');
await failing.close();

const retryChildren = [];
const retrying = new ManagedDoqRuntime({
  command: '/test/retry',
  configPath: '/test/config.json',
  restartDelayMs: 5,
  startTimeoutMs: 100,
  spawnProcess() {
    const child = createChild(7500 + retryChildren.length);
    retryChildren.push(child);
    if (retryChildren.length === 1) queueMicrotask(() => child.emitExit(1, null, 'bind: address already in use'));
    else queueMicrotask(() => child.stderr.write('cleandns-dns doq listening on 0.0.0.0:853\n'));
    return child;
  }
});
await assert.rejects(retrying.sync({ enabled: true }), /bind: address already in use/);
await waitFor(() => retryChildren.length === 2 && retrying.snapshot().running === true);
assert.equal(retrying.snapshot().pid, 7501);
await retrying.close();
await runtime.close();

console.log('Managed DoQ runtime tests passed');

function createChild(pid) {
  const child = new EventEmitter();
  child.pid = pid;
  child.killed = false;
  child.exitCode = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => {
    child.killed = true;
    queueMicrotask(() => child.emitExit(0, 'SIGTERM'));
    return true;
  };
  child.emitExit = (code, signal, detail = '') => {
    if (detail) child.stderr.write(detail);
    child.exitCode = code;
    child.emit('exit', code, signal);
  };
  return child;
}

async function waitFor(predicate, timeoutMs = 500) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error('wait_timeout');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
