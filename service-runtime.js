import { spawn } from 'node:child_process';

const RUNNING_SUBSTATES = new Set(['running', 'listening', 'exited']);

export function parseSystemdServiceStatus(output, unit = '') {
  const fields = {};
  for (const line of String(output || '').split(/\r?\n/)) {
    const index = line.indexOf('=');
    if (index <= 0) continue;
    fields[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }

  const loadState = fields.LoadState || 'unknown';
  const activeState = fields.ActiveState || 'unknown';
  const subState = fields.SubState || 'unknown';
  const pid = Number.parseInt(fields.MainPID || '0', 10) || 0;
  const result = fields.Result || '';
  const found = loadState !== 'not-found';
  const verified = Boolean(fields.ActiveState) && loadState !== 'unknown';
  const running = found && activeState === 'active' && RUNNING_SUBSTATES.has(subState) && pid > 0;
  const error = running
    ? ''
    : !found
      ? 'service_not_found'
      : verified
        ? [activeState, subState, result && result !== 'success' ? result : ''].filter(Boolean).join('/')
        : 'service_status_unavailable';

  return {
    unit,
    running,
    verified,
    loadState,
    activeState,
    subState,
    pid,
    result,
    error
  };
}

export async function probeSystemdService(unit, options = {}) {
  const run = options.run || runCommand;
  const command = options.command || 'systemctl';
  const timeoutMs = Math.max(100, Number(options.timeoutMs) || 1500);
  try {
    const execution = await run(command, [
      'show',
      unit,
      '--property=LoadState',
      '--property=ActiveState',
      '--property=SubState',
      '--property=MainPID',
      '--property=Result',
      '--no-pager'
    ], timeoutMs);
    const status = parseSystemdServiceStatus(execution.stdout, unit);
    if (execution.error && !status.verified) {
      return { ...status, error: execution.error.message || 'service_status_unavailable' };
    }
    if (execution.code !== 0 && !status.verified) {
      return { ...status, error: String(execution.stderr || `systemctl_exit_${execution.code}`).trim() };
    }
    return status;
  } catch (error) {
    return {
      unit,
      running: false,
      verified: false,
      loadState: 'unknown',
      activeState: 'unknown',
      subState: 'unknown',
      pid: 0,
      result: '',
      error: error?.message || 'service_status_unavailable'
    };
  }
}

function runCommand(command, args, timeoutMs) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timer = null;
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, ...result });
    };
    child.stdout.on('data', (chunk) => { stdout += chunk.toString().slice(0, 16_384); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString().slice(0, 16_384); });
    child.on('error', (error) => finish({ code: -1, error }));
    child.on('close', (code, signal) => finish({ code: Number(code ?? -1), signal }));
    timer = setTimeout(() => {
      child.kill();
      finish({ code: -1, signal: 'SIGTERM', error: new Error('service_status_timeout') });
    }, timeoutMs);
    timer.unref?.();
  });
}
