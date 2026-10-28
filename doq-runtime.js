import { spawn } from 'node:child_process';

const READY_LINE = /\bdoq listening on\b/i;

export class ManagedDoqRuntime {
  constructor(options = {}) {
    this.command = String(options.command || process.env.CLEANDNS_DOQ_RUNTIME_COMMAND || '/opt/cleandns/bin/cleandns-dns').trim();
    this.spawnProcess = options.spawnProcess || spawn;
    this.now = options.now || (() => new Date());
    this.onStatus = typeof options.onStatus === 'function' ? options.onStatus : null;
    this.startTimeoutMs = Math.max(500, Number(options.startTimeoutMs) || 6000);
    this.stopTimeoutMs = Math.max(250, Number(options.stopTimeoutMs) || 4000);
    this.restartDelayMs = Math.max(100, Number(options.restartDelayMs) || 1500);
    this.child = null;
    this.operation = Promise.resolve();
    this.restartTimer = null;
    this.desired = {
      enabled: false,
      configPath: String(options.configPath || '/opt/cleandns/config.json').trim(),
      listen: String(options.listen || '0.0.0.0').trim()
    };
    this.status = this.createStatus({
      activeState: 'inactive',
      subState: 'dead',
      error: 'doq_runtime_not_started'
    });
  }

  snapshot() {
    return { ...this.status };
  }

  sync(options = {}) {
    const desired = normalizeDesired(options, this.desired);
    this.desired = desired;
    this.clearRestartTimer();
    return this.enqueue(() => this.applyDesired(desired));
  }

  close() {
    this.desired = { ...this.desired, enabled: false };
    this.clearRestartTimer();
    return this.enqueue(async () => {
      await this.stopCurrent();
      this.setStatus(this.createStatus({ activeState: 'inactive', subState: 'dead' }));
      return this.snapshot();
    });
  }

  enqueue(operation) {
    const next = this.operation.catch(() => {}).then(operation);
    this.operation = next.catch(() => {});
    return next;
  }

  async applyDesired(desired) {
    if (!desired.enabled) {
      await this.stopCurrent();
      this.setStatus(this.createStatus({ activeState: 'disabled', subState: 'disabled' }));
      return this.snapshot();
    }

    await this.stopCurrent();
    return this.start(desired);
  }

  start(desired) {
    return new Promise((resolve, reject) => {
      let child = null;
      let settled = false;
      let stderr = '';
      let timer = null;

      const finishStartFailure = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (this.child === child) this.child = null;
        const message = normalizeRuntimeError(error);
        this.setStatus(this.createStatus({
          activeState: 'failed',
          subState: 'failed',
          result: 'exit-code',
          error: message
        }));
        try {
          child?.kill('SIGTERM');
        } catch {
          // The child may have already exited.
        }
        if (this.desired.enabled) this.scheduleRestart();
        reject(new Error(message));
      };

      const finishReady = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.setStatus(this.createStatus({
          running: true,
          activeState: 'active',
          subState: 'running',
          pid: Number(child?.pid || 0),
          error: ''
        }));
        resolve(this.snapshot());
      };

      try {
        child = this.spawnProcess(this.command, ['-config', desired.configPath, '-listen', desired.listen], {
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true
        });
      } catch (error) {
        finishStartFailure(error);
        return;
      }

      if (!child) {
        finishStartFailure(new Error('doq_runtime_unavailable'));
        return;
      }

      this.child = child;
      this.setStatus(this.createStatus({
        activeState: 'activating',
        subState: 'start',
        pid: Number(child.pid || 0),
        error: ''
      }));

      const consumeStderr = (chunk) => {
        stderr = `${stderr}${Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk)}`.slice(-16_384);
        if (READY_LINE.test(stderr)) finishReady();
      };
      child.stdout?.on('data', () => {});
      child.stderr?.on('data', consumeStderr);
      child.once?.('error', finishStartFailure);
      child.once?.('exit', (code, signal) => {
        if (!settled) {
          const detail = String(stderr || '').trim();
          finishStartFailure(new Error(detail || exitReason(code, signal)));
          return;
        }
        this.handleUnexpectedExit(child, code, signal, stderr);
      });

      timer = setTimeout(() => finishStartFailure(new Error('doq_runtime_start_timeout')), this.startTimeoutMs);
      timer.unref?.();
    });
  }

  async stopCurrent() {
    const child = this.child;
    if (!child) return;
    this.child = null;
    await stopChild(child, this.stopTimeoutMs);
  }

  handleUnexpectedExit(child, code, signal, stderr) {
    if (this.child !== child) return;
    this.child = null;
    const detail = String(stderr || '').trim();
    this.setStatus(this.createStatus({
      activeState: 'failed',
      subState: 'failed',
      result: 'exit-code',
      error: detail || exitReason(code, signal)
    }));
    if (this.desired.enabled) this.scheduleRestart();
  }

  scheduleRestart() {
    if (this.restartTimer || !this.desired.enabled) return;
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null;
      if (!this.desired.enabled) return;
      this.enqueue(() => this.start(this.desired)).catch(() => {
        if (this.desired.enabled) this.scheduleRestart();
      });
    }, this.restartDelayMs);
    this.restartTimer.unref?.();
  }

  clearRestartTimer() {
    if (!this.restartTimer) return;
    clearTimeout(this.restartTimer);
    this.restartTimer = null;
  }

  createStatus(overrides = {}) {
    return {
      unit: 'cleandns.service',
      manager: 'cleandns-main-process',
      running: false,
      verified: true,
      loadState: 'loaded',
      activeState: 'inactive',
      subState: 'dead',
      pid: 0,
      parentPid: process.pid,
      result: '',
      error: '',
      checkedAt: this.now().toISOString(),
      ...overrides
    };
  }

  setStatus(status) {
    this.status = status;
    this.onStatus?.(this.snapshot());
  }
}

function normalizeDesired(options, fallback) {
  const configPath = String(options.configPath ?? fallback.configPath ?? '').trim();
  const listen = String(options.listen ?? fallback.listen ?? '').trim();
  if (!configPath) throw new Error('bad_doq_config_path');
  if (!listen) throw new Error('bad_doq_listen_address');
  return {
    enabled: options.enabled !== false,
    configPath,
    listen
  };
}

function normalizeRuntimeError(error) {
  if (error?.code === 'ENOENT' || error?.code === 'EACCES') return 'doq_runtime_unavailable';
  const message = String(error?.message || error || 'doq_runtime_start_failed').replace(/[\r\n]+/g, ' ').trim().slice(0, 512);
  return message || 'doq_runtime_start_failed';
}

function exitReason(code, signal) {
  return signal ? `doq_runtime_signal_${signal}` : `doq_runtime_exit_${code ?? 'unknown'}`;
}

function stopChild(child, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };
    child.once?.('exit', finish);
    timer = setTimeout(() => {
      try {
        child.kill?.('SIGKILL');
      } catch {
        // The child may have already exited.
      }
      finish();
    }, timeoutMs);
    timer.unref?.();
    try {
      if (child.exitCode !== undefined && child.exitCode !== null) return finish();
      if (child.killed) return finish();
      child.kill?.('SIGTERM');
    } catch {
      finish();
    }
  });
}
