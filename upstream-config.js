import { normalizeUpstreamAddress } from './upstream.js';

const compiledConfigurations = new WeakMap();

export function normalizeUpstreamConfiguration(value, options = {}) {
  const errorCode = options.errorCode || 'bad_upstream';
  const requireDefaults = options.requireDefaults === true;
  const ignoreInvalid = options.ignoreInvalid === true;
  const lines = [];
  const defaults = new Set();

  for (const sourceLine of upstreamSourceLines(value)) {
    const raw = String(sourceLine || '').trim();
    if (!raw) continue;
    if (isCommentLine(raw)) {
      lines.push(raw);
      continue;
    }

    if (raw.startsWith('[/')) {
      try {
        lines.push(parseRouteLine(raw, errorCode).canonical);
      } catch (error) {
        if (!ignoreInvalid) throw error;
      }
      continue;
    }

    for (const item of raw.split(',')) {
      const address = String(item || '').trim();
      if (!address) continue;
      try {
        const normalized = normalizeUpstreamAddress(address);
        if (!defaults.has(normalized)) {
          defaults.add(normalized);
          lines.push(normalized);
        }
      } catch {
        if (!ignoreInvalid) throw new Error(errorCode);
      }
    }
  }

  if (requireDefaults && !defaults.size) throw new Error('no_upstreams');
  return lines;
}

export function compileUpstreamConfiguration(lines) {
  if (Array.isArray(lines) && compiledConfigurations.has(lines)) {
    return compiledConfigurations.get(lines);
  }

  const normalizedLines = Array.isArray(lines)
    ? lines
    : normalizeUpstreamConfiguration(lines);
  const compiled = {
    defaults: [],
    routes: [],
    comments: [],
    lines: normalizedLines,
    normalRoutes: new Map(),
    wildcardRoutes: new Map(),
    unqualifiedRoute: null,
    targets: new Set()
  };

  for (const value of normalizedLines) {
    const raw = String(value || '').trim();
    if (!raw) continue;
    if (isCommentLine(raw)) {
      compiled.comments.push(raw);
      continue;
    }
    if (raw.startsWith('[/')) {
      const route = parseRouteLine(raw, 'bad_upstream');
      route.order = compiled.routes.length;
      compiled.routes.push(route);
      for (const pattern of route.patterns) {
        if (pattern.unqualified) compiled.unqualifiedRoute = route;
        else if (pattern.wildcard) compiled.wildcardRoutes.set(pattern.domain, route);
        else compiled.normalRoutes.set(pattern.domain, route);
      }
      for (const target of route.targets) compiled.targets.add(target);
      continue;
    }
    if (!compiled.defaults.includes(raw)) compiled.defaults.push(raw);
    compiled.targets.add(raw);
  }

  if (Array.isArray(lines)) compiledConfigurations.set(lines, compiled);
  return compiled;
}

export function selectUpstreamConfiguration(lines, qname, qtype, options = {}) {
  const compiled = compileUpstreamConfiguration(lines);
  const question = routingQuestionName(qname, qtype);
  let selected = null;
  let selectedScore = -1;
  const consider = (route, score) => {
    if (!route || score < selectedScore) return;
    selected = route;
    selectedScore = score;
  };
  const labels = question.split('.').filter(Boolean);
  if (labels.length === 1) consider(compiled.unqualifiedRoute, 0);
  for (let index = 0; index < labels.length; index += 1) {
    const domain = labels.slice(index).join('.');
    const specificity = labels.length - index;
    consider(compiled.normalRoutes.get(domain), specificity * 2);
    if (index > 0) consider(compiled.wildcardRoutes.get(domain), specificity * 2 + 1);
  }

  if (selected) {
    const upstreams = selected.useDefault
      ? (compiled.defaults.length ? compiled.defaults : uniqueAddresses(options.fallbackDefaults))
      : selected.targets;
    if (!upstreams.length) return null;
    return {
      upstreams: upstreams.slice(),
      route: selected.display,
      source: 'domain',
      routedQuestion: question,
      usesDefault: selected.useDefault
    };
  }

  if (!compiled.defaults.length) return null;
  return {
    upstreams: compiled.defaults.slice(),
    route: options.defaultRoute || 'default',
    source: 'default',
    routedQuestion: question,
    usesDefault: true
  };
}

export function upstreamConfigurationEntries(lines) {
  const compiled = compileUpstreamConfiguration(lines);
  const entries = new Map();
  const add = (upstream, route) => {
    const current = entries.get(upstream) || { upstream, routes: [] };
    if (!current.routes.includes(route)) current.routes.push(route);
    entries.set(upstream, current);
  };

  for (const upstream of compiled.defaults) add(upstream, 'default');
  for (const route of compiled.routes) {
    if (route.useDefault) continue;
    for (const upstream of route.targets) add(upstream, route.display);
  }
  return [...entries.values()];
}

export function upstreamConfigurationTargets(lines) {
  return [...compileUpstreamConfiguration(lines).targets];
}

export function upstreamConfigurationSummary(lines) {
  const compiled = compileUpstreamConfiguration(lines);
  return {
    defaults: compiled.defaults.length,
    routes: compiled.routes.length,
    comments: compiled.comments.length,
    targets: compiled.targets.size
  };
}

function upstreamSourceLines(value) {
  const source = Array.isArray(value) ? value : [value];
  return source.flatMap((item) => String(item || '').split(/\r?\n/));
}

function isCommentLine(value) {
  return value.startsWith('#') || value.startsWith('!');
}

function parseRouteLine(value, errorCode) {
  const match = value.match(/^\[\/(.*)\/\]\s*(.+)$/);
  if (!match) throw new Error(errorCode);
  const patternValues = match[1] === '' ? [''] : match[1].split('/');
  if (!patternValues.length || patternValues.some((item) => item === '' && patternValues.length > 1)) {
    throw new Error(errorCode);
  }
  const patterns = patternValues.map((item) => normalizeRoutePattern(item, errorCode));
  const targetTokens = match[2].trim().split(/\s+/).filter(Boolean);
  if (!targetTokens.length || (targetTokens.includes('#') && (targetTokens.length !== 1 || targetTokens[0] !== '#'))) {
    throw new Error(errorCode);
  }
  const useDefault = targetTokens[0] === '#';
  let targets = [];
  if (!useDefault) {
    try {
      targets = uniqueAddresses(targetTokens.map(normalizeUpstreamAddress));
    } catch {
      throw new Error(errorCode);
    }
  }
  const patternText = patterns.map((item) => item.canonical).join('/');
  const display = `[/${patternText}/]`;
  return {
    canonical: `${display}${useDefault ? '#' : targets.join(' ')}`,
    display,
    patterns,
    targets,
    useDefault
  };
}

function normalizeRoutePattern(value, errorCode) {
  const raw = String(value || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!raw) return { canonical: '', domain: '', wildcard: false, unqualified: true };
  const wildcard = raw.startsWith('*.');
  const domain = wildcard ? raw.slice(2) : raw;
  if (!domain || domain.includes('*') || domain.length > 253) throw new Error(errorCode);
  const labels = domain.split('.');
  if (labels.some((label) => !/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))) {
    throw new Error(errorCode);
  }
  return {
    canonical: `${wildcard ? '*.' : ''}${domain}`,
    domain,
    wildcard,
    unqualified: false
  };
}

function routingQuestionName(qname, qtype) {
  const normalized = String(qname || '').trim().toLowerCase().replace(/\.+$/, '');
  const isDs = Number(qtype) === 43 || String(qtype || '').toUpperCase() === 'DS';
  if (!isDs) return normalized;
  const labels = normalized.split('.').filter(Boolean);
  return labels.length > 1 ? labels.slice(1).join('.') : '';
}

function uniqueAddresses(value) {
  return [...new Set((value || []).map((item) => String(item || '').trim()).filter(Boolean))];
}
