// Source-IP policy selection. Domain filtering and rate limits remain separate.
export const ACCESS_PROTOCOLS = Object.freeze(['plain', 'doh', 'doq']);
const MODES = new Set(['inherit', 'custom', 'unrestricted']);
const FIELDS = new Set(['mode', 'allowedClients', 'blockedClients']);

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateMap(value) {
  if (!object(value) || Object.keys(value).some(key => !ACCESS_PROTOCOLS.includes(key))) throw new Error('bad_protocol_access');
  for (const policy of Object.values(value)) {
    if (!object(policy) || Object.keys(policy).some(key => !FIELDS.has(key))) throw new Error('bad_protocol_access');
  }
}

function clientList(value, normalizeIdentifier) {
  if (value === undefined) return [];
  if (!Array.isArray(value) && typeof value !== 'string') throw new Error('bad_protocol_access_client');
  const lines = Array.isArray(value) ? value : value.split(/[\r\n,]+/);
  if (lines.length > 4096) throw new Error('too_many_protocol_access_clients');
  const result = new Set();
  for (const line of lines) {
    if (typeof line !== 'string') throw new Error('bad_protocol_access_client');
    const raw = line.trim();
    if (!raw || raw.startsWith('#')) continue;
    const parts = raw.split('/');
    if (parts.length > 2 || (parts.length === 2 && !/^\d+$/.test(parts[1]))) throw new Error('bad_protocol_access_client');
    const normalized = normalizeIdentifier(raw);
    if (!normalized) throw new Error('bad_protocol_access_client');
    result.add(normalized);
  }
  return [...result];
}

export function normalizeProtocolAccess(value = {}, normalizeIdentifier) {
  validateMap(value);
  return Object.fromEntries(ACCESS_PROTOCOLS.map(name => {
    const policy = value[name] || {};
    const mode = policy.mode === undefined ? 'inherit' : policy.mode;
    if (!MODES.has(mode)) throw new Error('bad_protocol_access_mode');
    return [name, {
      mode,
      allowedClients: clientList(policy.allowedClients, normalizeIdentifier),
      blockedClients: clientList(policy.blockedClients, normalizeIdentifier)
    }];
  }));
}

export function mergeProtocolAccess(current, patch, normalizeIdentifier) {
  validateMap(patch);
  const merged = { ...current };
  for (const [name, policy] of Object.entries(patch)) merged[name] = { ...current[name], ...policy };
  return normalizeProtocolAccess(merged, normalizeIdentifier);
}

export function selectProtocolAccess(access, transport) {
  const name = ['dns-udp', 'dns-tcp', 'udp', 'tcp'].includes(transport) ? 'plain' : ['doh', 'doq'].includes(transport) ? transport : '';
  const policy = name ? access.protocols?.[name] : null;
  if (policy?.mode === 'custom') return { scope: name, policy };
  if (policy?.mode === 'unrestricted') return { scope: name, policy: { allowedClients: [], blockedClients: [] } };
  return { scope: 'global', policy: access };
}
