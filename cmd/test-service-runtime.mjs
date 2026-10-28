import assert from 'node:assert/strict';
import { parseSystemdServiceStatus, probeSystemdService } from '../service-runtime.js';

const active = parseSystemdServiceStatus([
  'LoadState=loaded',
  'ActiveState=active',
  'SubState=running',
  'MainPID=4321',
  'Result=success'
].join('\n'), 'cleandns.service');
assert.deepEqual(active, {
  unit: 'cleandns.service',
  running: true,
  verified: true,
  loadState: 'loaded',
  activeState: 'active',
  subState: 'running',
  pid: 4321,
  result: 'success',
  error: ''
});

const failed = parseSystemdServiceStatus([
  'LoadState=loaded',
  'ActiveState=failed',
  'SubState=failed',
  'MainPID=0',
  'Result=exit-code'
].join('\n'));
assert.equal(failed.running, false);
assert.equal(failed.verified, true);
assert.equal(failed.error, 'failed/failed/exit-code');

const missing = parseSystemdServiceStatus([
  'LoadState=not-found',
  'ActiveState=inactive',
  'SubState=dead',
  'MainPID=0',
  'Result=success'
].join('\n'));
assert.equal(missing.running, false);
assert.equal(missing.verified, true);
assert.equal(missing.error, 'service_not_found');

const probed = await probeSystemdService('cleandns.service', {
  run: async (command, args, timeoutMs) => {
    assert.equal(command, 'systemctl');
    assert.equal(args[0], 'show');
    assert.equal(args[1], 'cleandns.service');
    assert.equal(timeoutMs, 900);
    return {
      code: 0,
      stdout: 'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=77\nResult=success\n',
      stderr: ''
    };
  },
  timeoutMs: 900
});
assert.equal(probed.running, true);
assert.equal(probed.pid, 77);

const unavailable = await probeSystemdService('cleandns.service', {
  run: async () => ({ code: -1, stdout: '', stderr: '', error: new Error('spawn ENOENT') })
});
assert.equal(unavailable.running, false);
assert.equal(unavailable.verified, false);
assert.equal(unavailable.error, 'spawn ENOENT');

console.log('service runtime tests passed');
