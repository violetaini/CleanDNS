import { spawn } from 'node:child_process';

const DEFAULT_HELPER = '/opt/cleandns/bin/cleandns-dns';
const MAX_DNS_MESSAGE_SIZE = 65535;
const MAX_STDOUT_BUFFER = 384 * 1024;

export class DoqUpstreamBridge {
  constructor(options = {}) {
    this.command = String(options.command || process.env.CLEANDNS_DOQ_HELPER || DEFAULT_HELPER);
    this.args = Array.isArray(options.args) ? [...options.args] : ['-mode', 'upstream-stdio'];
    this.spawnProcess = options.spawnProcess || spawn;
    this.child = null;
    this.pending = new Map();
    this.sequence = 0;
    this.stdoutBuffer = '';
    this.closed = false;
  }

  query({ address, serverName, timeoutMs, packet }) {
    if (this.closed) return Promise.reject(new Error('doq_helper_closed'));
    if (!Buffer.isBuffer(packet) || packet.length < 12 || packet.length > MAX_DNS_MESSAGE_SIZE) {
      return Promise.reject(new Error('bad_dns_query'));
    }
    const timeout = Number(timeoutMs);
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 30000) {
      return Promise.reject(new Error('bad_timeout'));
    }

    let child;
    try {
      child = this.ensureChild();
    } catch (error) {
      return Promise.reject(normalizeBridgeError(error, 'doq_helper_start_failed'));
    }
    const id = String(++this.sequence);
    const request = JSON.stringify({
      id,
      address: String(address || ''),
      serverName: String(serverName || ''),
      timeoutMs: timeout,
      packet: packet.toString('base64')
    }) + '\n';

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.pending.delete(id)) return;
        reject(new Error('timeout'));
      }, timeout + 500);
      this.pending.set(id, { resolve, reject, timer });
      child.stdin.write(request, (error) => {
        if (error) this.rejectPending(id, normalizeBridgeError(error, 'doq_helper_write_failed'));
      });
    });
  }

  ensureChild() {
    if (this.child && !this.child.killed) return this.child;
    const child = this.spawnProcess(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });
    if (!child?.stdin || !child?.stdout || !child?.stderr) {
      throw new Error('doq_helper_bad_stdio');
    }
    this.child = child;
    this.stdoutBuffer = '';
    child.stdout.on('data', (chunk) => this.consumeStdout(child, chunk));
    child.stdout.on('error', (error) => this.failChild(child, error));
    child.stdin.on('error', (error) => this.failChild(child, error));
    child.stderr.on('data', () => {});
    child.once('error', (error) => this.failChild(child, error));
    child.once('exit', (code, signal) => {
      const reason = signal ? `doq_helper_signal_${signal}` : `doq_helper_exit_${code ?? 'unknown'}`;
      this.failChild(child, new Error(reason), false);
    });
    return child;
  }

  consumeStdout(child, chunk) {
    if (this.child !== child) return;
    this.stdoutBuffer += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
    if (this.stdoutBuffer.length > MAX_STDOUT_BUFFER) {
      this.failChild(child, new Error('doq_helper_protocol_error'));
      return;
    }
    for (;;) {
      const newline = this.stdoutBuffer.indexOf('\n');
      if (newline < 0) return;
      const line = this.stdoutBuffer.slice(0, newline).replace(/\r$/, '');
      this.stdoutBuffer = this.stdoutBuffer.slice(newline + 1);
      if (line) this.consumeResponse(child, line);
    }
  }

  consumeResponse(child, line) {
    let response;
    try {
      response = JSON.parse(line);
    } catch {
      this.failChild(child, new Error('doq_helper_protocol_error'));
      return;
    }
    const id = typeof response?.id === 'string' ? response.id : '';
    if (!id) {
      this.failChild(child, new Error('doq_helper_protocol_error'));
      return;
    }
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    clearTimeout(pending.timer);
    if (response.ok !== true) {
      pending.reject(new Error(normalizeHelperMessage(response.error)));
      return;
    }
    try {
      pending.resolve(decodePacket(response.packet));
    } catch (error) {
      pending.reject(error);
      this.failChild(child, error);
    }
  }

  rejectPending(id, error) {
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    clearTimeout(pending.timer);
    pending.reject(error);
  }

  failChild(child, error, terminate = true) {
    if (this.child !== child) return;
    this.child = null;
    this.stdoutBuffer = '';
    if (terminate) {
      try {
        child.kill();
      } catch {
        // The helper may already have exited.
      }
    }
    const failure = normalizeBridgeError(error, 'doq_helper_failed');
    for (const [id] of this.pending) this.rejectPending(id, failure);
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    const child = this.child;
    this.child = null;
    if (child) {
      try {
        child.stdin.end();
        child.kill();
      } catch {
        // The helper may already have exited.
      }
    }
    const error = new Error('doq_helper_closed');
    for (const [id] of this.pending) this.rejectPending(id, error);
  }
}

let defaultBridge;

export function queryDoqUpstream(request) {
  defaultBridge ||= new DoqUpstreamBridge();
  return defaultBridge.query(request);
}

export function closeDoqUpstreamBridge() {
  defaultBridge?.close();
  defaultBridge = null;
}

function decodePacket(value) {
  const encoded = String(value || '');
  if (!encoded || encoded.length > 90_000 || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error('doq_helper_protocol_error');
  }
  const packet = Buffer.from(encoded, 'base64');
  if (packet.length < 12 || packet.length > MAX_DNS_MESSAGE_SIZE || packet.toString('base64') !== encoded) {
    throw new Error('doq_helper_protocol_error');
  }
  return packet;
}

function normalizeHelperMessage(value) {
  const message = String(value || 'doq_query_failed').replace(/[\r\n]+/g, ' ').trim().slice(0, 512);
  return message || 'doq_query_failed';
}

function normalizeBridgeError(error, fallback) {
  if (error?.code === 'ENOENT' || error?.code === 'EACCES') return new Error('doq_helper_unavailable');
  if (error instanceof Error && error.message) return error;
  return new Error(String(error || fallback));
}
