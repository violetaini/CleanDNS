import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  blockedServicesAutoUpdateIsDue,
  readBlockedServicesAutoUpdateState,
  writeBlockedServicesAutoUpdateState
} from '../blocked-services-auto-update-state.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SOURCE_URL = process.env.BLOCKED_SERVICES_SOURCE || 'https://adguardteam.github.io/HostlistsRegistry/assets/services.json';
const TARGET_PATH = process.env.BLOCKED_SERVICES_TARGET || path.join(__dirname, '..', 'data', 'blocked-services.json');
const AUTOMATIC = process.env.BLOCKED_SERVICES_AUTOMATIC === '1';
const CONFIG_PATH = process.env.CLEANDNS_CONFIG || path.join(__dirname, '..', 'config.json');
const AUTO_UPDATE_STATE_PATH = process.env.BLOCKED_SERVICES_AUTO_UPDATE_STATE || path.join(path.dirname(TARGET_PATH), 'blocked-services-auto-update-state.json');

const GROUP_NAMES = {
  ai: 'AI',
  cdn: 'CDN',
  dating: 'Dating',
  gambling: 'Gambling',
  gaming: 'Gaming',
  hosting: 'Hosting',
  messenger: 'Messenger',
  privacy: 'Privacy',
  shopping: 'Shopping',
  social_network: 'Social Network',
  software: 'Software',
  streaming: 'Streaming'
};

const GROUP_ORDER = Object.keys(GROUP_NAMES);

function normalizeGroupName(value) {
  const name = String(value || '').replace(/\s+/g, ' ').trim();
  return name || 'Other';
}

function normalizeRule(value) {
  const rule = String(value || '').trim();
  if (!rule || rule.length > 400 || /[\u0000-\u001f]/.test(rule)) return '';
  return rule;
}

function domainFromRule(rule) {
  let value = normalizeRule(rule);
  if (!value || value.startsWith('@@') || value.startsWith('!') || (value.startsWith('/') && value.endsWith('/'))) return '';
  value = value.replace(/\$.*$/, '').replace(/\^.*$/, '');
  value = value.replace(/^\|\|?/, '').replace(/^\*/, '');
  return value;
}

function normalizeDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]{2,}$/i.test(domain)) return '';
  if (domain.includes('*') || domain.includes(':') || domain.includes('_')) return '';
  return domain;
}

function normalizeIcon(value) {
  const svg = String(value || '').trim();
  if (!svg || svg.length > 12000) return '';
  if (!/^<svg[\s\S]*<\/svg>$/i.test(svg)) return '';
  if (/(<script|<foreignobject|on[a-z]+\s*=|javascript:)/i.test(svg)) return '';
  return svg;
}

function normalizeService(item) {
  const id = String(item?.id || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(id)) return null;
  const name = String(item?.name || id).replace(/\s+/g, ' ').trim();
  const group = String(item?.group || item?.group_id || '').replace(/\s+/g, '_').trim().toLowerCase();
  const groupName = normalizeGroupName(item?.groupName || GROUP_NAMES[group] || group || 'Other');
  const rules = [...new Set((Array.isArray(item?.rules) ? item.rules : []).map(normalizeRule).filter(Boolean))];
  const domains = [...new Set([
    ...(Array.isArray(item?.domains) ? item.domains : []),
    ...rules.map(domainFromRule)
  ].map(normalizeDomain).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  const iconSvg = normalizeIcon(item?.iconSvg || item?.icon_svg);
  if (!name || (!domains.length && !rules.length)) return null;
  return { id, name, group, groupName, domains, rules, iconSvg };
}

function buildGroups(services) {
  const serviceGroups = new Set(services.map((service) => service.group || 'other'));
  return [
    ...GROUP_ORDER.filter((id) => serviceGroups.has(id)),
    ...[...serviceGroups].filter((id) => !GROUP_ORDER.includes(id)).sort((a, b) => a.localeCompare(b))
  ].map((id) => ({
    id,
    name: normalizeGroupName(GROUP_NAMES[id] || id.replace(/_/g, ' '))
  }));
}

async function main() {
  const automatic = await prepareAutomaticRun();
  if (automatic?.skip) return;
  try {
    const response = await fetch(SOURCE_URL);
    if (!response.ok) {
      throw new Error(`failed to fetch ${SOURCE_URL}: HTTP ${response.status}`);
    }
    const parsed = await response.json();
    const rawServices = Array.isArray(parsed?.blocked_services)
      ? parsed.blocked_services
      : Array.isArray(parsed?.services)
        ? parsed.services
        : Array.isArray(parsed)
          ? parsed
          : [];
    const services = rawServices.map(normalizeService).filter(Boolean);
    if (!services.length) {
      throw new Error('blocked services source did not contain any usable services');
    }
    const output = {
      source: SOURCE_URL,
      sourceProject: 'AdGuardTeam/AdGuardHome blocked services via HostlistsRegistry',
      generatedAt: new Date().toISOString(),
      groups: buildGroups(services),
      services
    };
    await fs.mkdir(path.dirname(TARGET_PATH), { recursive: true });
    const tempPath = `${TARGET_PATH}.tmp-${Date.now()}-${process.pid}`;
    await fs.writeFile(tempPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
    await fs.rename(tempPath, TARGET_PATH);
    const rules = services.reduce((total, service) => total + service.rules.length, 0);
    const icons = services.filter((service) => service.iconSvg).length;
    if (automatic) {
      const finishedAt = new Date().toISOString();
      writeBlockedServicesAutoUpdateState(AUTO_UPDATE_STATE_PATH, {
        lastStartedAt: automatic.startedAt,
        lastFinishedAt: finishedAt,
        lastSuccessfulAt: finishedAt,
        lastReason: 'systemd',
        lastError: '',
        lastSummary: { services: services.length, groups: output.groups.length, icons, rules, generatedAt: output.generatedAt },
        nextRunAt: new Date(Date.now() + automatic.intervalHours * 60 * 60 * 1000).toISOString()
      });
    }
    console.log(`updated ${TARGET_PATH}`);
    console.log(`${services.length} services, ${output.groups.length} groups, ${icons} icons, ${rules} rules`);
  } catch (error) {
    if (automatic) {
      const finishedAt = new Date().toISOString();
      try {
        writeBlockedServicesAutoUpdateState(AUTO_UPDATE_STATE_PATH, {
          lastStartedAt: automatic.startedAt,
          lastFinishedAt: finishedAt,
          lastReason: 'systemd',
          lastError: String(error?.message || error)
        });
      } catch {}
    }
    throw error;
  }
}

async function prepareAutomaticRun() {
  if (!AUTOMATIC) return null;
  let config;
  try {
    config = JSON.parse(await fs.readFile(CONFIG_PATH, 'utf8'));
  } catch (error) {
    throw new Error(`failed to read CleanDNS config: ${error?.message || error}`);
  }
  const rules = config?.rules && typeof config.rules === 'object' ? config.rules : {};
  if (rules.blockedServicesAutoUpdateEnabled === false) {
    console.log('skipped automatic blocked services update: disabled');
    return { skip: true };
  }
  const intervalHours = normalizeIntervalHours(rules.blockedServicesAutoUpdateIntervalHours);
  const state = readBlockedServicesAutoUpdateState(AUTO_UPDATE_STATE_PATH);
  if (!blockedServicesAutoUpdateIsDue(state)) {
    console.log(`skipped automatic blocked services update: next run ${state.nextRunAt}`);
    return { skip: true };
  }
  const startedAt = new Date().toISOString();
  writeBlockedServicesAutoUpdateState(AUTO_UPDATE_STATE_PATH, {
    lastStartedAt: startedAt,
    lastReason: 'systemd',
    lastError: ''
  });
  return { intervalHours, startedAt };
}

function normalizeIntervalHours(value) {
  const hours = Math.floor(Number(value));
  if (!Number.isFinite(hours)) return 168;
  return Math.max(24, Math.min(720, hours));
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
