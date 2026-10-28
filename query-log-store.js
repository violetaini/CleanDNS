import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_QUERY_LOG_SCAN_LIMIT = 50_000;

const READ_CHUNK_BYTES = 64 * 1024;
const MAX_LOG_LINE_BYTES = 256 * 1024;

export class QueryLogStore {
  constructor(options = {}) {
    this.fs = options.fs || fs;
    this.now = options.now || (() => Date.now());
    this.writeChain = Promise.resolve();
    this.lastError = '';
    this.lastRotationCheckAt = 0;
    this.configure(options);
  }

  configure(options = {}) {
    this.logFile = String(options.logFile || '').trim();
    this.retentionHours = normalizeRetentionHours(options.retentionHours);
    this.maxMemoryEntries = normalizePositiveInteger(options.maxMemoryEntries, 1000);
    this.maxScanEntries = normalizePositiveInteger(options.maxScanEntries, DEFAULT_QUERY_LOG_SCAN_LIMIT);
  }

  get archiveFile() {
    return this.logFile ? `${this.logFile}.1` : '';
  }

  status() {
    return {
      diskEnabled: Boolean(this.logFile),
      archivePresent: Boolean(this.archiveFile && this.fs.existsSync(this.archiveFile)),
      lastError: this.lastError
    };
  }

  append(row) {
    if (!this.logFile) return Promise.resolve(false);
    const file = this.logFile;
    const line = `${JSON.stringify(row)}\n`;
    return this.enqueue(async () => {
      await this.fs.promises.mkdir(path.dirname(file), { recursive: true });
      await this.fs.promises.appendFile(file, line, 'utf8');
      return true;
    });
  }

  flush() {
    return this.writeChain;
  }

  clear() {
    if (!this.logFile) return Promise.resolve(false);
    const file = this.logFile;
    const archive = `${file}.1`;
    return this.enqueue(async () => {
      await this.fs.promises.mkdir(path.dirname(file), { recursive: true });
      await this.fs.promises.writeFile(file, '', 'utf8');
      await removeIfPresent(this.fs, archive);
      return true;
    });
  }

  rotateIfDue(options = {}) {
    if (!this.logFile) return Promise.resolve(false);
    const force = options.force === true;
    const now = Number(options.now ?? this.now());
    const checkIntervalMs = Math.max(60_000, Number(options.checkIntervalMs) || 60 * 60 * 1000);
    if (!force && now - this.lastRotationCheckAt < checkIntervalMs) return this.flush().then(() => false, () => false);
    this.lastRotationCheckAt = now;
    const file = this.logFile;
    const archive = `${file}.1`;
    const retentionHours = this.retentionHours;
    return this.enqueue(async () => {
      const cutoff = now - retentionHours * 60 * 60 * 1000;
      const archiveNewest = readNewestTimestamp(this.fs, archive);
      if (archiveNewest && archiveNewest < cutoff) await removeIfPresent(this.fs, archive);
      const oldest = readOldestTimestamp(this.fs, file);
      if (!oldest || oldest + retentionHours * 60 * 60 * 1000 > now) return false;
      try {
        await this.fs.promises.rename(file, archive);
      } catch (error) {
        if (error?.code === 'ENOENT') return false;
        throw error;
      }
      await this.fs.promises.writeFile(file, '', 'utf8');
      return true;
    });
  }

  loadRecent(limit = this.maxMemoryEntries, options = {}) {
    return scanQueryLogFiles({
      fs: this.fs,
      logFile: this.logFile,
      retentionHours: this.retentionHours,
      limit,
      now: Number(options.now ?? this.now()),
      maxScanEntries: options.maxScanEntries || this.maxScanEntries
    }).rows;
  }

  async readPage(options = {}) {
    try {
      await this.flush();
    } catch {
      // The in-memory buffer remains available to callers even when disk
      // persistence has a transient failure.
    }
    return scanQueryLogFiles({
      fs: this.fs,
      logFile: this.logFile,
      retentionHours: this.retentionHours,
      limit: options.limit,
      cursor: options.cursor,
      match: options.match,
      now: Number(options.now ?? this.now()),
      maxScanEntries: options.maxScanEntries || this.maxScanEntries
    });
  }

  enqueue(operation) {
    const pending = this.writeChain.catch(() => {}).then(operation);
    this.writeChain = pending.then(
      (result) => {
        this.lastError = '';
        return result;
      },
      (error) => {
        this.lastError = normalizeError(error);
        throw error;
      }
    );
    return this.writeChain;
  }
}

export function scanQueryLogFiles(options = {}) {
  const fsModule = options.fs || fs;
  const file = String(options.logFile || '').trim();
  const retentionHours = normalizeRetentionHours(options.retentionHours);
  const now = Number(options.now ?? Date.now());
  const cutoff = now - retentionHours * 60 * 60 * 1000;
  const limit = normalizePositiveInteger(options.limit, 100);
  const maxScanEntries = normalizePositiveInteger(options.maxScanEntries, DEFAULT_QUERY_LOG_SCAN_LIMIT);
  const match = typeof options.match === 'function' ? options.match : () => true;
  const requestedCursor = decodeCursor(options.cursor);
  const rows = [];
  let scanned = 0;
  let matched = 0;
  let complete = true;
  let cursorFound = !requestedCursor || requestedCursor.timeOnly;
  let lastScanned = null;
  let extraMatch = false;

  const files = file ? [file, `${file}.1`] : [];
  for (const currentFile of files) {
    const fullyRead = readLinesReverse(fsModule, currentFile, (line, offset) => {
      if (scanned >= maxScanEntries) {
        complete = false;
        return false;
      }
      scanned += 1;
      let source;
      try {
        source = JSON.parse(line);
      } catch {
        return true;
      }
      const timestamp = Date.parse(source?.time || '');
      if (!Number.isFinite(timestamp) || timestamp < cutoff) return true;
      const row = normalizeRow(source, currentFile, offset);
      const marker = { time: row.time, id: row.id };

      if (requestedCursor && !cursorFound) {
        if (requestedCursor.timeOnly) {
          if (timestamp >= requestedCursor.timestamp) return true;
          cursorFound = true;
        } else if (row.time === requestedCursor.time && row.id === requestedCursor.id) {
          cursorFound = true;
          return true;
        } else {
          if (timestamp < requestedCursor.timestamp) cursorFound = true;
          else return true;
        }
      }

      lastScanned = marker;
      if (!match(row)) return true;
      matched += 1;
      if (rows.length < limit) {
        rows.push(row);
        return true;
      }
      extraMatch = true;
      return false;
    });
    if (!fullyRead || extraMatch || !complete) break;
  }

  const hasMore = extraMatch || !complete;
  const lastRow = rows.at(-1);
  const continuation = lastRow
    ? { time: lastRow.time, id: lastRow.id }
    : hasMore ? lastScanned : null;
  return {
    rows,
    nextCursor: hasMore && continuation ? encodeCursor(continuation) : '',
    oldest: lastRow?.time || '',
    hasMore,
    complete,
    cursorExpired: Boolean(requestedCursor && !requestedCursor.timeOnly && !cursorFound && !rows.length),
    scanned,
    matched
  };
}

function readLinesReverse(fsModule, file, visit) {
  if (!file || !fsModule.existsSync(file)) return true;
  let fd;
  try {
    fd = fsModule.openSync(file, 'r');
    const size = fsModule.fstatSync(fd).size;
    let position = size;
    let carry = Buffer.alloc(0);
    while (position > 0) {
      const length = Math.min(READ_CHUNK_BYTES, position);
      position -= length;
      const chunk = Buffer.allocUnsafe(length);
      const bytes = fsModule.readSync(fd, chunk, 0, length, position);
      const data = Buffer.concat([chunk.subarray(0, bytes), carry]);
      let end = data.length;
      for (let index = data.length - 1; index >= 0; index -= 1) {
        if (data[index] !== 0x0a) continue;
        const lineBytes = data.subarray(index + 1, end);
        end = index;
        if (!lineBytes.length) continue;
        if (lineBytes.length > MAX_LOG_LINE_BYTES) continue;
        const line = lineBytes.toString('utf8').replace(/\r$/, '');
        if (!line || visit(line, position + index + 1) !== false) continue;
        return false;
      }
      carry = data.subarray(0, end);
      if (carry.length > MAX_LOG_LINE_BYTES) return false;
    }
    if (carry.length && carry.length <= MAX_LOG_LINE_BYTES) {
      const line = carry.toString('utf8').replace(/\r$/, '');
      if (line && visit(line, 0) === false) return false;
    }
    return true;
  } finally {
    if (fd !== undefined) fsModule.closeSync(fd);
  }
}

function readOldestTimestamp(fsModule, file) {
  if (!file || !fsModule.existsSync(file)) return 0;
  let fd;
  try {
    fd = fsModule.openSync(file, 'r');
    const size = fsModule.fstatSync(fd).size;
    if (!size) return 0;
    const length = Math.min(size, MAX_LOG_LINE_BYTES);
    const buffer = Buffer.allocUnsafe(length);
    const bytes = fsModule.readSync(fd, buffer, 0, length, 0);
    const newline = buffer.subarray(0, bytes).indexOf(0x0a);
    const line = buffer.subarray(0, newline < 0 ? bytes : newline).toString('utf8').replace(/\r$/, '');
    const row = JSON.parse(line);
    const timestamp = Date.parse(row?.time || '');
    return Number.isFinite(timestamp) ? timestamp : 0;
  } catch {
    return 0;
  } finally {
    if (fd !== undefined) fsModule.closeSync(fd);
  }
}

function readNewestTimestamp(fsModule, file) {
  let timestamp = 0;
  readLinesReverse(fsModule, file, (line) => {
    try {
      const row = JSON.parse(line);
      const parsed = Date.parse(row?.time || '');
      if (Number.isFinite(parsed)) timestamp = parsed;
    } catch {
      // Skip malformed rows while finding the latest valid record.
    }
    return false;
  });
  return timestamp;
}

function normalizeRow(source, file, offset) {
  const row = source && typeof source === 'object' ? { ...source } : {};
  const id = String(row.id || '').trim();
  row.id = id || `legacy:${path.basename(file)}:${offset}`;
  return row;
}

function encodeCursor(value) {
  return Buffer.from(JSON.stringify({ time: value.time, id: value.id }), 'utf8').toString('base64url');
}

function decodeCursor(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const timestamp = Date.parse(raw);
  if (Number.isFinite(timestamp)) return { timeOnly: true, timestamp };
  try {
    const decoded = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    const time = String(decoded?.time || '');
    const id = String(decoded?.id || '');
    const parsed = Date.parse(time);
    if (!time || !id || !Number.isFinite(parsed)) return null;
    return { time, id, timestamp: parsed, timeOnly: false };
  } catch {
    return null;
  }
}

function normalizeRetentionHours(value) {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) && number > 0 ? number : 24;
}

function normalizePositiveInteger(value, fallback) {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function normalizeError(error) {
  const message = String(error?.message || error || 'query_log_write_failed').replace(/[\r\n]+/g, ' ').trim().slice(0, 512);
  return message || 'query_log_write_failed';
}

async function removeIfPresent(fsModule, file) {
  try {
    await fsModule.promises.unlink(file);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}
