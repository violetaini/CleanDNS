import fs from 'node:fs';
import path from 'node:path';

const MAX_TEXT_LENGTH = 4096;

export function emptyBlockedServicesAutoUpdateState() {
  return {
    version: 1,
    lastStartedAt: '',
    lastFinishedAt: '',
    lastSuccessfulAt: '',
    lastReason: '',
    lastError: '',
    lastSummary: null,
    nextRunAt: ''
  };
}

export function normalizeBlockedServicesAutoUpdateState(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  return {
    version: 1,
    lastStartedAt: normalizeTimestamp(source.lastStartedAt),
    lastFinishedAt: normalizeTimestamp(source.lastFinishedAt),
    lastSuccessfulAt: normalizeTimestamp(source.lastSuccessfulAt),
    lastReason: normalizeText(source.lastReason, 120),
    lastError: normalizeText(source.lastError, 512),
    lastSummary: normalizeSummary(source.lastSummary),
    nextRunAt: normalizeTimestamp(source.nextRunAt)
  };
}

export function readBlockedServicesAutoUpdateState(filePath) {
  try {
    return normalizeBlockedServicesAutoUpdateState(JSON.parse(fs.readFileSync(filePath, 'utf8')));
  } catch {
    return emptyBlockedServicesAutoUpdateState();
  }
}

export function writeBlockedServicesAutoUpdateState(filePath, patch = {}) {
  const current = readBlockedServicesAutoUpdateState(filePath);
  const next = normalizeBlockedServicesAutoUpdateState({ ...current, ...patch });
  const target = path.resolve(filePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temp = `${target}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(temp, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
  fs.renameSync(temp, target);
  return next;
}

export function blockedServicesAutoUpdateIsDue(state, now = Date.now()) {
  const nextRunAt = Date.parse(String(state?.nextRunAt || ''));
  return !Number.isFinite(nextRunAt) || nextRunAt <= now;
}

function normalizeTimestamp(value) {
  const time = Date.parse(String(value || ''));
  return Number.isFinite(time) ? new Date(time).toISOString() : '';
}

function normalizeText(value, maxLength = MAX_TEXT_LENGTH) {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim().slice(0, maxLength);
}

function normalizeSummary(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const summary = {};
  for (const [key, item] of Object.entries(value)) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key)) continue;
    if (typeof item === 'number' && Number.isFinite(item)) summary[key] = item;
    else if (typeof item === 'boolean') summary[key] = item;
    else if (typeof item === 'string') summary[key] = normalizeText(item);
  }
  return Object.keys(summary).length ? summary : null;
}
