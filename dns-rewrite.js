import net from 'node:net';

export const DNS_REWRITE_QTYPE = Object.freeze({
  A: 1,
  CNAME: 5,
  AAAA: 28
});

export function parseDnsRewriteLine(value) {
  const original = String(value || '').trim();
  if (!original) return null;

  let raw = original;
  let enabled = true;
  const disabled = raw.match(/^#\s*disabled:?\s+(.+)$/i);
  if (disabled) {
    enabled = false;
    raw = disabled[1].trim();
  } else if (raw.startsWith('#') || raw.startsWith('!')) {
    return null;
  }

  const parts = raw.split(/\s+/);
  if (parts.length !== 3) return null;
  const domain = normalizeDnsRewriteDomain(parts[0], true);
  const answer = normalizeDnsRewriteAnswer(parts[2], parts[1]);
  if (!domain || !answer) return null;

  return {
    original,
    enabled,
    domain,
    wildcard: domain.startsWith('*.'),
    ...answer
  };
}

export function compileDnsRewrites(lines = []) {
  const entries = lines.map(parseDnsRewriteLine).filter((entry) => entry?.enabled !== false);
  const exact = new Map();
  const wildcardGroups = new Map();

  for (const entry of entries) {
    const target = entry.wildcard ? wildcardGroups : exact;
    if (!target.has(entry.domain)) target.set(entry.domain, []);
    target.get(entry.domain).push(entry);
  }

  const wildcards = [...wildcardGroups.entries()]
    .map(([domain, group]) => ({ domain, suffix: domain.slice(1), entries: group }))
    .sort((left, right) => right.suffix.length - left.suffix.length);

  return { entries, exact, wildcards };
}

export function resolveDnsRewrite(compiled, domain, qtype) {
  const qname = normalizeDnsRewriteDomain(domain, false);
  if (!qname) return { matched: false, kind: 'none', entries: [] };

  const entries = matchingEntries(compiled, qname);
  if (!entries.length) return { matched: false, kind: 'none', entries: [] };

  const cname = entries.find((entry) => entry.type === 'CNAME');
  if (cname) {
    if (cname.value === qname) {
      return { matched: true, kind: 'passthrough', entries: [cname], value: cname.value };
    }
    if (hasCnameLoop(compiled, qname, cname.value)) {
      return { matched: true, kind: 'nodata', entries: [cname], value: cname.value, loop: true };
    }
    return { matched: true, kind: 'cname', entries: [cname], value: cname.value, qtype: DNS_REWRITE_QTYPE.CNAME };
  }

  const type = Number(qtype) === DNS_REWRITE_QTYPE.A
    ? 'A'
    : Number(qtype) === DNS_REWRITE_QTYPE.AAAA
      ? 'AAAA'
      : '';
  if (!type) return { matched: true, kind: 'nodata', entries };

  const matchingType = entries.filter((entry) => entry.type === type);
  const passthrough = matchingType.find((entry) => entry.passthrough === true);
  if (passthrough) {
    return { matched: true, kind: 'passthrough', entries: [passthrough], qtype: passthrough.qtype };
  }

  const answers = matchingType.filter((entry) => entry.passthrough !== true);
  if (answers.length) {
    return {
      matched: true,
      kind: 'address',
      entries: answers,
      qtype: answers[0].qtype,
      values: answers.map((entry) => entry.value)
    };
  }

  return { matched: true, kind: 'nodata', entries };
}

export function normalizeDnsRewriteDomain(value, allowWildcard = true) {
  let raw = String(value || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!raw) return '';
  const wildcard = allowWildcard && raw.startsWith('*.');
  if (wildcard) raw = raw.slice(2);
  if (raw.includes('*') || !isDnsHostname(raw)) return '';
  return wildcard ? `*.${raw}` : raw;
}

export function normalizeDnsRewriteAnswer(value, explicitType = '') {
  const raw = String(value || '').trim();
  const requestedType = String(explicitType || '').trim().toUpperCase();
  if (!raw || (requestedType && !Object.hasOwn(DNS_REWRITE_QTYPE, requestedType))) return null;

  const upper = raw.toUpperCase();
  if ((!requestedType || requestedType === upper) && (upper === 'A' || upper === 'AAAA')) {
    return { type: upper, qtype: DNS_REWRITE_QTYPE[upper], value: upper, passthrough: true };
  }

  const family = net.isIP(raw);
  if (family === 4 && (!requestedType || requestedType === 'A')) {
    return { type: 'A', qtype: DNS_REWRITE_QTYPE.A, value: raw, passthrough: false };
  }
  if (family === 6 && (!requestedType || requestedType === 'AAAA')) {
    return { type: 'AAAA', qtype: DNS_REWRITE_QTYPE.AAAA, value: raw.toLowerCase(), passthrough: false };
  }

  if (!requestedType || requestedType === 'CNAME') {
    const target = normalizeDnsRewriteDomain(raw, false);
    if (target) return { type: 'CNAME', qtype: DNS_REWRITE_QTYPE.CNAME, value: target, passthrough: false };
  }

  return null;
}

function matchingEntries(compiled, qname) {
  const exact = compiled?.exact?.get(qname);
  if (exact?.length) return exact;

  for (const wildcard of compiled?.wildcards || []) {
    if (qname.length > wildcard.suffix.length && qname.endsWith(wildcard.suffix)) {
      return wildcard.entries;
    }
  }
  return [];
}

function hasCnameLoop(compiled, original, target) {
  const visited = new Set([original]);
  let current = target;
  for (let depth = 0; depth < 16; depth += 1) {
    if (visited.has(current)) return true;
    visited.add(current);
    const cname = matchingEntries(compiled, current).find((entry) => entry.type === 'CNAME');
    if (!cname) return false;
    if (cname.value === current) return false;
    current = cname.value;
  }
  return true;
}

function isDnsHostname(value) {
  if (!value || value.length > 253) return false;
  const labels = value.split('.');
  return labels.every((label) => (
    label.length > 0
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  ));
}
