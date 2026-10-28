import dgram from 'node:dgram';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildCnameResponse,
  buildSafeSearchCnameResponse,
  matchSafeSearch,
  normalizeSafeSearchConfig,
  safeSearchRuleCount
} from './safe-search.js';
import {
  DOMAIN_PROTECTION_SERVICES,
  DomainProtectionChecker
} from './domain-protection.js';
import { closeUpstreamTransports, normalizeUpstreamAddress, parseUpstreamAddress, queryDnsUpstream } from './upstream.js';
import {
  compileUpstreamConfiguration,
  normalizeUpstreamConfiguration,
  selectUpstreamConfiguration,
  upstreamConfigurationEntries,
  upstreamConfigurationSummary,
  upstreamConfigurationTargets
} from './upstream-config.js';
import { parseProxyV2 } from './proxy-protocol.js';
import { dashboardWindowBounds, selectDashboardRows } from './dashboard-window.js';
import { decodeDnsResponse } from './dns-response.js';
import { compileDnsRewrites, resolveDnsRewrite } from './dns-rewrite.js';
import { dnssecCacheProfile, enableDnssecRequest } from './dnssec.js';
import {
  buildDohMobileConfig,
  DEFAULT_TLS_CERT_FILE,
  DEFAULT_TLS_KEY_FILE,
  inspectTlsConfiguration
} from './tls-status.js';
import { ManagedDoqRuntime } from './doq-runtime.js';
import { ManagedDhcpRuntime } from './dhcp-runtime.js';
import {
  aggregateStatsBuckets,
  buildStatsSeries,
  emptyStatsSnapshot,
  ensureStatsBucket,
  loadStatsBuckets,
  pruneStatsBuckets,
  pruneTimedRows,
  statsBucketStart
} from './retention.js';
import { QueryLogStore } from './query-log-store.js';
import {
  readBlockedServicesAutoUpdateState,
  writeBlockedServicesAutoUpdateState
} from './blocked-services-auto-update-state.js';
import {
  collectDhcpInterfaces,
  dhcpInterfaceIpv4ForConfig,
  normalizeDhcpConfig,
  normalizeDhcpMac,
  validateDhcpConfig,
  validateDhcpStaticLease
} from './dhcp-config.js';
import { resolveRuntimeClientDhcpLease } from './runtime-client-dhcp.js';
import { parseHostsFile, parseLinuxArpTable } from './runtime-client-sources.js';
import {
  isPublicWhoisAddress,
  normalizeWhoisInfo,
  RuntimeWhoisResolver
} from './runtime-client-whois.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = process.env.CLEANDNS_CONFIG || path.join(__dirname, 'config.json');
const BASE_DIR = path.dirname(CONFIG_PATH);

const QTYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  SVCB: 64,
  HTTPS: 65,
  CAA: 257,
  ANY: 255
};

const QTYPE_NAME = Object.fromEntries(Object.entries(QTYPE).map(([k, v]) => [v, k]));
const DNS_RULE_QTYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  SIG: 24,
  KEY: 25,
  AAAA: 28,
  LOC: 29,
  SRV: 33,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  DNAME: 39,
  OPT: 41,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  ANY: 255,
  CAA: 257
};
const DNS_RULE_QTYPE_NAME = Object.fromEntries(Object.entries(DNS_RULE_QTYPE).map(([name, code]) => [code, name]));
const RCODE = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  REFUSED: 5
};

const FALLBACK_BLOCKED_SERVICE_CATALOG = [
  { id: 'youtube', name: 'YouTube', domains: ['youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com', 'ytimg.com', 'youtubei.googleapis.com'] },
  { id: 'tiktok', name: 'TikTok', domains: ['tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'byteoversea.com', 'ibytedtos.com'] },
  { id: 'facebook', name: 'Facebook', domains: ['facebook.com', 'fb.com', 'fbcdn.net', 'messenger.com'] },
  { id: 'instagram', name: 'Instagram', domains: ['instagram.com', 'cdninstagram.com'] },
  { id: 'x', name: 'X / Twitter', domains: ['x.com', 'twitter.com', 'twimg.com', 't.co'] },
  { id: 'telegram', name: 'Telegram', domains: ['telegram.org', 't.me', 'telegram.me', 'telegram-cdn.org'] },
  { id: 'discord', name: 'Discord', domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'] },
  { id: 'netflix', name: 'Netflix', domains: ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxso.net', 'nflxext.com'] },
  { id: 'spotify', name: 'Spotify', domains: ['spotify.com', 'scdn.co', 'spotifycdn.com'] },
  { id: 'reddit', name: 'Reddit', domains: ['reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com'] }
];
const BLOCKED_SERVICE_GROUP_NAMES = {
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
const SCHEDULE_DAY_KEYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const BLOCKED_SERVICE_ALIASES = new Map([['x', 'twitter']]);
const BLOCKED_SERVICES_CATALOG_FILE = path.resolve(process.env.CLEANDNS_BLOCKED_SERVICES_CATALOG_FILE || path.join(__dirname, 'data', 'blocked-services.json'));
const BLOCKED_SERVICES_UPDATER_SCRIPT = path.resolve(process.env.CLEANDNS_BLOCKED_SERVICES_UPDATER_SCRIPT || path.join(__dirname, 'cmd', 'update-blocked-services.mjs'));
const BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE = path.resolve(process.env.CLEANDNS_BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE || path.join(BASE_DIR, 'data', 'blocked-services-auto-update-state.json'));
const BLOCKED_SERVICES_UPDATE_TIMEOUT_MS = 60_000;
let BLOCKED_SERVICE_DATA = loadBlockedServiceData();
let BLOCKED_SERVICE_CATALOG = BLOCKED_SERVICE_DATA.catalog;
let BLOCKED_SERVICE_GROUPS = BLOCKED_SERVICE_DATA.groups;
let BLOCKED_SERVICE_IDS = new Set(BLOCKED_SERVICE_CATALOG.map((item) => item.id));
let BLOCKED_SERVICE_MATCHERS = new Map(BLOCKED_SERVICE_CATALOG.map((item) => [item.id, buildBlockedServiceMatcher(item)]));
const BLOCK_MODE_LABELS = {
  'default': '默认（Hosts 规则地址 / Adblock 零地址）',
  refused: '返回 REFUSED',
  'null': '返回空地址 0.0.0.0 / ::',
  custom: '返回自定义 IP',
  nxdomain: '返回 NXDOMAIN',
  nodata: '返回空响应 NODATA'
};
const ADGUARD_PROTECTION_BOOTSTRAP = Object.freeze([
  { address: '94.140.14.15', family: 4 },
  { address: '94.140.14.16', family: 4 },
  { address: '2a10:50c0::bad1:ff', family: 6 },
  { address: '2a10:50c0::bad2:ff', family: 6 }
]);
const AGGREGATE_RANK_MAP_LIMIT = 4096;
const RUNTIME_CLIENT_LIMIT = 1024;
const RUNTIME_CLIENT_RDNS_SUCCESS_MIN_MS = 5 * 60 * 1000;
const RUNTIME_CLIENT_RDNS_SUCCESS_MAX_MS = 24 * 60 * 60 * 1000;
const RUNTIME_CLIENT_RDNS_NEGATIVE_MS = 6 * 60 * 60 * 1000;
const RUNTIME_CLIENT_RDNS_RETRY_MS = 15 * 60 * 1000;
const RUNTIME_CLIENT_WHOIS_CACHE_TTL_MS = normalizeInteger(
  process.env.CLEANDNS_RUNTIME_CLIENT_WHOIS_CACHE_TTL_MS ?? 60 * 60 * 1000,
  60_000,
  7 * 24 * 60 * 60 * 1000,
  'bad_runtime_client_whois_cache_ttl'
);
const RUNTIME_CLIENT_WHOIS_TIMEOUT_MS = normalizeInteger(
  process.env.CLEANDNS_RUNTIME_CLIENT_WHOIS_TIMEOUT_MS ?? 5000,
  100,
  60_000,
  'bad_runtime_client_whois_timeout'
);
const RUNTIME_CLIENT_WHOIS_CONCURRENCY = normalizeInteger(
  process.env.CLEANDNS_RUNTIME_CLIENT_WHOIS_CONCURRENCY ?? 4,
  1,
  32,
  'bad_runtime_client_whois_concurrency'
);
const RUNTIME_CLIENT_SOURCE_LIMIT = 4096;
const DEFAULT_RUNTIME_CLIENT_HOSTS_FILE = process.platform === 'win32'
  ? path.join(process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
  : '/etc/hosts';
const RUNTIME_CLIENT_HOSTS_FILE = process.env.CLEANDNS_RUNTIME_CLIENT_HOSTS_FILE
  ? path.resolve(process.env.CLEANDNS_RUNTIME_CLIENT_HOSTS_FILE)
  : DEFAULT_RUNTIME_CLIENT_HOSTS_FILE;
const RUNTIME_CLIENT_ARP_FILE = process.env.CLEANDNS_RUNTIME_CLIENT_ARP_FILE
  ? path.resolve(process.env.CLEANDNS_RUNTIME_CLIENT_ARP_FILE)
  : (process.platform === 'linux' ? '/proc/net/arp' : '');
const RUNTIME_CLIENT_SOURCE_REFRESH_MS = normalizeInteger(
  process.env.CLEANDNS_RUNTIME_CLIENT_SOURCE_REFRESH_MS ?? 60_000,
  1_000,
  24 * 60 * 60 * 1000,
  'bad_runtime_client_source_refresh'
);
const UINT32_MAX = 0xffffffff;
const DNS_TYPE_OPT = 41;
const DHCP_RUNTIME_SUPPORTED = (process.platform === 'linux' || process.env.CLEANDNS_ENABLE_DHCP_RUNTIME === '1') && process.env.CLEANDNS_DISABLE_DHCP_RUNTIME !== '1';
const DHCP_RUNTIME_PORT = normalizeInteger(process.env.CLEANDNS_DHCP_PORT ?? 67, 1, 65535, 'bad_dhcp_port');
const DHCP_LEASE_FILE = path.resolve(process.env.CLEANDNS_DHCP_LEASE_FILE || path.join(BASE_DIR, 'data', 'dhcp-leases.json'));
const DOQ_RUNTIME_REFRESH_MS = 15_000;
const DOQ_RUNTIME_COMMAND = process.env.CLEANDNS_DOQ_RUNTIME_COMMAND || path.join(__dirname, 'bin', 'cleandns-dns');
const DOQ_RUNTIME_LISTEN = process.env.CLEANDNS_DOQ_RUNTIME_LISTEN || '0.0.0.0';

let config = loadConfig();
config = normalizeConfig(config);
ensureDataFiles();
const queryLogStore = new QueryLogStore(queryLogStoreOptions());
const runtimeWhoisResolver = new RuntimeWhoisResolver({
  server: process.env.CLEANDNS_RUNTIME_CLIENT_WHOIS_SERVER || 'whois.arin.net',
  port: process.env.CLEANDNS_RUNTIME_CLIENT_WHOIS_PORT || 43,
  timeoutMs: RUNTIME_CLIENT_WHOIS_TIMEOUT_MS,
  cacheTtlMs: RUNTIME_CLIENT_WHOIS_CACHE_TTL_MS,
  concurrency: RUNTIME_CLIENT_WHOIS_CONCURRENCY,
  allowPrivateServer: process.env.CLEANDNS_RUNTIME_CLIENT_WHOIS_ALLOW_PRIVATE_SERVER === '1'
});

let rules = loadRules();
const loadedStats = loadStats();
let stats = loadedStats.stats;
let statsBuckets = loadedStats.buckets;
let statsResetAt = loadedStats.resetAt;
let clients = loadClients();
const runtimeClients = new Map();
const runtimeClientReverseLookups = new Map();
let runtimeClientReverseGeneration = 0;
const runtimeClientWhoisLookups = new Map();
let runtimeClientWhoisGeneration = 0;
const runtimeClientSourceCache = {
  hosts: { records: new Map(), refreshedAt: 0, error: '' },
  arp: { records: new Map(), refreshedAt: 0, error: '' }
};
const cache = new Map();
const clientCaches = new Map();
const pending = new Map();
const optimisticRefreshes = new Map();
let cacheGeneration = 0;
const bootstrapLookupCache = new Map();
const bootstrapLookupPending = new Map();
const dnsRateLimitBuckets = new Map();
const domainProtectionChecker = new DomainProtectionChecker({ query: queryDomainProtectionService });
const recentQueries = [];
let startedAt = Date.now();
let adminAuth = ensureAdminAuth();
const sessions = new Map();
const subscriptionAutoUpdateState = {
  running: false,
  queuedTargets: new Set(),
  lastStartedAt: '',
  lastFinishedAt: '',
  lastReason: '',
  lastError: '',
  lastSummary: null,
  nextRunAt: ''
};
let subscriptionAutoUpdateTimer = null;
let subscriptionAutoUpdateStartupTimer = null;
const blockedServicesAutoUpdateState = {
  running: false,
  scheduled: false,
  queued: false,
  lastStartedAt: '',
  lastFinishedAt: '',
  lastSuccessfulAt: '',
  lastReason: '',
  lastError: '',
  lastSummary: null,
  nextRunAt: ''
};
let blockedServicesAutoUpdateTimer = null;
let blockedServicesAutoUpdateStartupTimer = null;
hydrateBlockedServicesAutoUpdateState();
let plainDnsUdpServer = null;
let plainDnsTcpServer = null;
let plainDnsRuntime = {
  enabled: false,
  udp: false,
  tcp: false,
  host: '',
  port: 0,
  error: ''
};
const dhcpRuntime = new ManagedDhcpRuntime({
  leaseFile: DHCP_LEASE_FILE,
  onStatus(status) {
    dhcpRuntimeStatus = status;
  }
});
let dhcpRuntimeStatus = dhcpRuntime.snapshot();
const doqRuntime = new ManagedDoqRuntime({
  command: DOQ_RUNTIME_COMMAND,
  configPath: CONFIG_PATH,
  listen: DOQ_RUNTIME_LISTEN,
  onStatus(status) {
    doqRuntimeStatus = status;
  }
});
let doqRuntimeStatus = doqRuntime.snapshot();

refreshRuntimeClientSources({ force: true });
loadRecentQueries();
backfillDashboardRankings();
startHttpServer();
startUdpServer();
applyPlainDnsRuntime().catch((err) => {
  plainDnsRuntime = {
    enabled: config.service?.plainDnsEnabled === true,
    udp: false,
    tcp: false,
    host: config.service?.plainDnsHost || '',
    port: config.service?.plainDnsPort || 0,
    error: err.message || 'plain_dns_start_failed'
  };
  console.error(`cleandns plain dns disabled: ${plainDnsRuntime.error}`);
});
applyDhcpRuntime().catch((err) => {
  dhcpRuntimeStatus = {
    ...dhcpRuntime.snapshot(),
    enabled: config.dhcp?.enabled === true,
    running: false,
    state: 'error',
    error: err.message || 'dhcp_runtime_start_failed'
  };
  console.error(`cleandns dhcp disabled: ${dhcpRuntimeStatus.error}`);
});
syncDoqService(config.service.doqEnabled !== false, config.service.doqPort).catch((err) => {
  console.error(`cleandns doq disabled: ${err.message || 'doq_runtime_start_failed'}`);
});
refreshDoqRuntimeStatus({ force: true }).catch(() => {});
startSubscriptionAutoUpdater();
startBlockedServicesAutoUpdater();
setInterval(() => saveStats(), 30_000).unref();
setInterval(() => refreshDoqRuntimeStatus({ force: true }).catch(() => {}), DOQ_RUNTIME_REFRESH_MS).unref();
setInterval(() => refreshRuntimeClientSources(), RUNTIME_CLIENT_SOURCE_REFRESH_MS).unref();
setInterval(() => {
  pruneCache();
  pruneClientCaches();
  pruneDnsRateLimitBuckets();
  runRetentionMaintenance();
}, 60_000).unref();

let shuttingDown = false;
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  if (subscriptionAutoUpdateTimer) clearInterval(subscriptionAutoUpdateTimer);
  if (subscriptionAutoUpdateStartupTimer) clearTimeout(subscriptionAutoUpdateStartupTimer);
  if (blockedServicesAutoUpdateTimer) clearInterval(blockedServicesAutoUpdateTimer);
  if (blockedServicesAutoUpdateStartupTimer) clearTimeout(blockedServicesAutoUpdateStartupTimer);
  Promise.allSettled([doqRuntime.close(), dhcpRuntime.close()])
    .finally(() => {
      runtimeWhoisResolver.close();
      closeUpstreamTransports();
      queryLogStore.flush()
        .catch(() => {})
        .finally(() => {
          saveStats();
          process.exit(0);
        });
    });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('SIGUSR1', () => {
  try {
    reloadBlockedServicesCatalogFromDisk('systemd');
    console.info('cleandns blocked services catalog reloaded from disk');
  } catch (error) {
    console.warn(`cleandns blocked services catalog reload failed: ${error.message || error}`);
  }
});

function loadConfig() {
  const text = fs.readFileSync(CONFIG_PATH, 'utf8');
  return JSON.parse(text);
}

function normalizeConfig(input) {
  const next = { ...input };
  next.filter = {
    enabled: true,
    rewritesEnabled: true,
    blockMode: 'null',
    cnameCheck: true,
    blockedServices: [],
    blockedServicesSchedule: {},
    ...(next.filter || {})
  };
  next.filter.enabled = next.filter.enabled !== false;
  next.filter.rewritesEnabled = next.filter.rewritesEnabled !== false;
  next.filter.blockMode = normalizeBlockMode(next.filter.blockMode);
  next.filter.cnameCheck = next.filter.cnameCheck !== false;
  next.filter.blockedServices = normalizeBlockedServices(next.filter.blockedServices);
  next.filter.blockedServicesSchedule = normalizeBlockedServicesSchedule(next.filter.blockedServicesSchedule);
  next.filter.pauseUntil = normalizeProtectionPauseUntil(next.filter.pauseUntil);
  next.filter.safeSearch = normalizeSafeSearchConfig(next.filter.safeSearch);
  next.filter.safeBrowsing = normalizeDomainProtectionService(next.filter.safeBrowsing, 'safeBrowsing');
  next.filter.parental = normalizeDomainProtectionService(next.filter.parental, 'parental');
  next.timeoutMs = normalizeInteger(next.timeoutMs ?? 2500, 100, 30000, 'bad_timeout');
  next.upstreamMode = normalizeUpstreamMode(next.upstreamMode);
  next.dns = normalizeDnsConfig(next.dns);
  next.cache = normalizeCacheConfig(next.cache);
  next.ecs = normalizeEcsConfig(next.ecs);
  next.queryLog = normalizeQueryLogConfig(next.queryLog);
  next.statistics = normalizeStatisticsConfig(next.statistics);
  next.access = normalizeAccessConfig(next.access);
  next.dhcp = normalizeDhcpConfig(next.dhcp);
  if (!DHCP_RUNTIME_SUPPORTED) next.dhcp.enabled = false;
  const rawAdmin = next.admin && typeof next.admin === 'object' ? next.admin : {};
  next.admin = {
    ...rawAdmin,
    profile: normalizeAdminProfile(rawAdmin.profile)
  };
  next.rules = {
    blockFile: path.join(BASE_DIR, 'data/blocklist.txt'),
    allowFile: path.join(BASE_DIR, 'data/allowlist.txt'),
    rewriteFile: path.join(BASE_DIR, 'data/rewrites.txt'),
    subscriptionFile: path.join(BASE_DIR, 'data/subscriptions.txt'),
    downloadDir: path.join(BASE_DIR, 'data/subscriptions.d'),
    allowSubscriptionFile: path.join(BASE_DIR, 'data/allow-subscriptions.txt'),
    allowDownloadDir: path.join(BASE_DIR, 'data/allow-subscriptions.d'),
    autoUpdateEnabled: true,
    autoUpdateIntervalHours: 24,
    autoUpdateOnStartup: true,
    autoUpdateOnChange: true,
    blockedServicesAutoUpdateEnabled: true,
    blockedServicesAutoUpdateIntervalHours: 168,
    blockedServicesAutoUpdateOnStartup: true,
    ...(next.rules || {})
  };
  next.rules.autoUpdateEnabled = next.rules.autoUpdateEnabled !== false;
  next.rules.autoUpdateIntervalHours = normalizeInteger(next.rules.autoUpdateIntervalHours ?? 24, 1, 168, 'bad_rules_auto_update_interval');
  next.rules.autoUpdateOnStartup = next.rules.autoUpdateOnStartup !== false;
  next.rules.autoUpdateOnChange = next.rules.autoUpdateOnChange !== false;
  next.rules.blockedServicesAutoUpdateEnabled = next.rules.blockedServicesAutoUpdateEnabled !== false;
  next.rules.blockedServicesAutoUpdateIntervalHours = normalizeInteger(
    next.rules.blockedServicesAutoUpdateIntervalHours ?? 168,
    24,
    720,
    'bad_blocked_services_auto_update_interval'
  );
  next.rules.blockedServicesAutoUpdateOnStartup = next.rules.blockedServicesAutoUpdateOnStartup !== false;
  const rawClients = next.clients && typeof next.clients === 'object' ? next.clients : {};
  next.clients = {
    file: path.join(BASE_DIR, 'data/clients.json'),
    ...rawClients
  };
  next.clients.runtimeSources = normalizeRuntimeClientSources(rawClients.runtimeSources, next.dns.resolveClients);
  next.dns.resolveClients = next.clients.runtimeSources.rdns;
  const rawService = next.service || {};
  next.service = {
    dohPath: '/dns-query',
    dohEnabled: true,
    panelPath: '/admin/',
    dohPublicBaseUrl: `https://${next.domain}`,
    panelPublicUrl: `https://${next.domain}/admin/`,
    plainDnsEnabled: false,
    plainDnsHost: '0.0.0.0',
    plainDnsPort: 53,
    doqEnabled: true,
    doqEndpoint: next.domain,
    doqPort: 853,
    doqTlsCertFile: DEFAULT_TLS_CERT_FILE,
    doqTlsKeyFile: DEFAULT_TLS_KEY_FILE,
    dohSyncCommand: '/opt/cleandns/bin/apply-nginx-doh-path',
    ...rawService
  };
  next.service.dohPath = normalizeDohPath(next.service.dohPath);
  next.service.dohEnabled = next.service.dohEnabled !== false;
  next.service.panelPath = normalizePanelPath(next.service.panelPath);
  next.service.dohPublicBaseUrl = normalizePublicBaseUrl(next.service.dohPublicBaseUrl);
  next.service.panelPublicUrl = normalizePublicUrl(next.service.panelPublicUrl);
  next.service.plainDnsEnabled = next.service.plainDnsEnabled === true;
  next.service.plainDnsHost = normalizePlainDnsHost(next.service.plainDnsHost);
  next.service.plainDnsPort = normalizePort(next.service.plainDnsPort || 53);
  next.service.doqEnabled = next.service.doqEnabled !== false;
  const legacyDoqPort = parseEndpointPort(rawService.doqEndpoint);
  const configuredDoqPort = Object.prototype.hasOwnProperty.call(rawService, 'doqPort') ? rawService.doqPort : legacyDoqPort || next.service.doqPort;
  next.service.doqPort = normalizePort(configuredDoqPort || 853);
  next.service.doqEndpoint = normalizeDoqEndpoint(next.service.doqEndpoint, next.domain);
  next.service.doqTlsCertFile = normalizeTlsFilePath(next.service.doqTlsCertFile, 'bad_tls_certificate_path');
  next.service.doqTlsKeyFile = normalizeTlsFilePath(next.service.doqTlsKeyFile, 'bad_tls_private_key_path');
  next.service.dohSyncCommand = String(next.service.dohSyncCommand || '').trim();
  next.upstreams = normalizeUpstreams(next.upstreams);
  next.fallbackUpstreams = normalizeOptionalUpstreams(next.fallbackUpstreams, 'bad_fallback_upstream');
  next.bootstrapDns = normalizeBootstrapDns(next.bootstrapDns);
  return next;
}

function loadBlockedServiceData() {
  const catalogPath = BLOCKED_SERVICES_CATALOG_FILE;
  try {
    const parsed = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
    const rawCatalog = Array.isArray(parsed) ? parsed : (parsed?.services || parsed?.blocked_services);
    const catalog = normalizeBlockedServiceCatalog(rawCatalog);
    if (catalog.length) {
      return {
        catalog,
        groups: normalizeBlockedServiceGroups(parsed?.groups, catalog),
        source: String(parsed?.source || '').trim(),
        sourceProject: String(parsed?.sourceProject || 'AdGuardHome blocked services').trim(),
        generatedAt: String(parsed?.generatedAt || '').trim()
      };
    }
  } catch (err) {
    console.warn('blocked services catalog fallback:', err.message || err);
  }
  const catalog = normalizeBlockedServiceCatalog(FALLBACK_BLOCKED_SERVICE_CATALOG);
  return {
    catalog,
    groups: normalizeBlockedServiceGroups([], catalog),
    source: 'embedded-fallback',
    sourceProject: 'CleanDNS fallback blocked services',
    generatedAt: ''
  };
}

function installBlockedServiceData(data) {
  const next = data && Array.isArray(data.catalog) && data.catalog.length
    ? data
    : loadBlockedServiceData();
  BLOCKED_SERVICE_DATA = next;
  BLOCKED_SERVICE_CATALOG = next.catalog;
  BLOCKED_SERVICE_GROUPS = next.groups;
  BLOCKED_SERVICE_IDS = new Set(BLOCKED_SERVICE_CATALOG.map((item) => item.id));
  BLOCKED_SERVICE_MATCHERS = new Map(BLOCKED_SERVICE_CATALOG.map((item) => [item.id, buildBlockedServiceMatcher(item)]));
  return BLOCKED_SERVICE_DATA;
}

function normalizeBlockedServiceCatalog(value) {
  return (Array.isArray(value) ? value : [])
    .map(normalizeBlockedServiceEntry)
    .filter(Boolean);
}

function normalizeBlockedServiceGroups(value, catalog = []) {
  const groups = [];
  const seen = new Set();
  const add = (id, name = '') => {
    const normalizedId = String(id || '').replace(/\s+/g, '_').trim().toLowerCase();
    if (!normalizedId || seen.has(normalizedId)) return;
    seen.add(normalizedId);
    groups.push({
      id: normalizedId,
      name: normalizeBlockedServiceGroupName(name || BLOCKED_SERVICE_GROUP_NAMES[normalizedId] || normalizedId)
    });
  };
  (Array.isArray(value) ? value : []).forEach((item) => add(item?.id, item?.name));
  catalog.forEach((service) => add(service.group || 'other', service.groupName || service.group || 'Other'));
  return groups;
}

function normalizeBlockedServiceGroupName(value) {
  const name = String(value || '').replace(/\s+/g, ' ').trim();
  return name || 'Other';
}

function normalizeBlockedServiceEntry(item) {
  const id = String(item?.id || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(id)) return null;
  const name = String(item?.name || id).replace(/\s+/g, ' ').trim();
  const group = String(item?.group || item?.group_id || '').replace(/\s+/g, '_').trim().toLowerCase();
  const groupName = normalizeBlockedServiceGroupName(item?.groupName || BLOCKED_SERVICE_GROUP_NAMES[group] || group || 'Other');
  const rules = [...new Set((Array.isArray(item?.rules) ? item.rules : [])
    .map(normalizeBlockedServiceRule)
    .filter(Boolean))];
  const rawDomains = [
    ...(Array.isArray(item?.domains) ? item.domains : []),
    ...rules.map(blockedServiceDomainFromRule)
  ];
  const domains = [...new Set(rawDomains
    .map(normalizeBlockedServiceDomain)
    .filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const patterns = [...new Set(rules.map(blockedServicePatternFromRule).filter(Boolean))];
  const iconSvg = normalizeBlockedServiceIcon(item?.iconSvg || item?.icon_svg);
  if (!name || (!domains.length && !patterns.length)) return null;
  return { id, name, group, groupName, domains, rules, patterns, iconSvg };
}

function normalizeBlockedServiceDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/^\*\./, '').replace(/^\.+|\.+$/g, '');
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]{2,}$/i.test(domain)) return '';
  if (domain.includes('*') || domain.includes(':') || domain.includes('_')) return '';
  return domain;
}

function normalizeBlockedServiceRule(value) {
  const rule = String(value || '').trim();
  if (!rule || rule.length > 400 || /[\u0000-\u001f]/.test(rule)) return '';
  return rule;
}

function blockedServiceDomainFromRule(rule) {
  let value = normalizeBlockedServiceRule(rule);
  if (!value || value.startsWith('@@') || value.startsWith('!') || (value.startsWith('/') && value.endsWith('/'))) return '';
  value = value.replace(/\$.*$/, '').replace(/\^.*$/, '');
  value = value.replace(/^\|\|?/, '').replace(/^\*/, '');
  return value;
}

function blockedServicePatternFromRule(rule) {
  let value = normalizeBlockedServiceRule(rule);
  if (!value || value.startsWith('@@') || value.startsWith('!')) return '';
  if (value.startsWith('/') && value.endsWith('/')) {
    const body = value.slice(1, -1);
    if (!body || body.length > 160 || /[\r\n]/.test(body)) return '';
    try {
      new RegExp(body, 'i');
      return body;
    } catch {
      return '';
    }
  }
  value = value.replace(/\$.*$/, '').replace(/\^.*$/, '');
  const domainBoundary = value.startsWith('||');
  const anchorStart = value.startsWith('|') && !domainBoundary;
  value = value.replace(/^\|\|?/, '');
  if (!value.includes('*')) return '';
  if (!/^[a-z0-9*_.-]+$/i.test(value)) return '';
  const wildcard = value.split('*').map(escapeRegex).join('[a-z0-9-]*');
  const source = domainBoundary ? `(^|\\.)${wildcard}$` : anchorStart ? `^${wildcard}$` : `${wildcard}$`;
  try {
    new RegExp(source, 'i');
    return source;
  } catch {
    return '';
  }
}

function normalizeBlockedServiceIcon(value) {
  const svg = String(value || '').trim();
  if (!svg || svg.length > 12000) return '';
  if (!/^<svg[\s\S]*<\/svg>$/i.test(svg)) return '';
  if (/(<script|<foreignobject|on[a-z]+\s*=|javascript:)/i.test(svg)) return '';
  return svg;
}

function escapeRegex(value) {
  return String(value || '').replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

function normalizeBlockedServiceId(value) {
  const id = String(value || '').trim().toLowerCase();
  const aliased = BLOCKED_SERVICE_ALIASES.get(id);
  if (aliased && BLOCKED_SERVICE_IDS.has(aliased)) return aliased;
  return BLOCKED_SERVICE_IDS.has(id) ? id : '';
}

function normalizeBlockedServices(value) {
  const input = Array.isArray(value) ? value : String(value || '').split(/\r?\n|,/);
  return [...new Set(input.map(normalizeBlockedServiceId).filter(Boolean))];
}

function normalizeScheduleTimeZone(value) {
  const raw = String(value || 'Local').trim();
  if (!raw || /^local$/i.test(raw)) return 'Local';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: raw }).format(new Date());
    return raw;
  } catch {
    return 'Local';
  }
}

function normalizeScheduleRange(value) {
  if (!value || typeof value !== 'object') return {};
  const start = Number(value.start);
  const end = Number(value.end);
  const minute = 60 * 1000;
  const day = 24 * 60 * minute;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return {};
  const roundedStart = Math.floor(start / minute) * minute;
  const roundedEnd = Math.floor(end / minute) * minute;
  if (roundedStart < 0 || roundedEnd > day || roundedStart >= roundedEnd) return {};
  return { start: roundedStart, end: roundedEnd };
}

function normalizeBlockedServicesSchedule(value = {}) {
  const source = value && typeof value === 'object' ? value : {};
  const schedule = { time_zone: normalizeScheduleTimeZone(source.time_zone || source.timeZone) };
  for (const day of SCHEDULE_DAY_KEYS) {
    schedule[day] = normalizeScheduleRange(source[day]);
  }
  return schedule;
}

function hasScheduleRange(range) {
  return range && typeof range === 'object' && Number.isFinite(Number(range.start)) && Number.isFinite(Number(range.end)) && Number(range.start) < Number(range.end);
}

function blockedServicesScheduleEnabled(schedule = config.filter.blockedServicesSchedule) {
  return SCHEDULE_DAY_KEYS.some((day) => hasScheduleRange(schedule?.[day]));
}

function scheduleDateParts(date, timeZone) {
  if (!timeZone || timeZone === 'Local') {
    return {
      weekday: date.getDay(),
      hour: date.getHours(),
      minute: date.getMinutes(),
      second: date.getSeconds(),
      millisecond: date.getMilliseconds()
    };
  }
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(date).reduce((acc, part) => {
    if (part.type !== 'literal') acc[part.type] = part.value;
    return acc;
  }, {});
  const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(parts.weekday);
  return {
    weekday: weekday >= 0 ? weekday : date.getDay(),
    hour: Number(parts.hour || 0),
    minute: Number(parts.minute || 0),
    second: Number(parts.second || 0),
    millisecond: date.getMilliseconds()
  };
}

function blockedServicesScheduleStatus(scheduleValue = config.filter.blockedServicesSchedule, now = new Date()) {
  const schedule = normalizeBlockedServicesSchedule(scheduleValue);
  const enabled = blockedServicesScheduleEnabled(schedule);
  if (!enabled) return { enabled: false, paused: false, timeZone: schedule.time_zone, day: '', nowMs: 0, range: null };
  const parts = scheduleDateParts(now, schedule.time_zone);
  const day = SCHEDULE_DAY_KEYS[parts.weekday] || 'sun';
  const nowMs = ((parts.hour * 60 + parts.minute) * 60 + parts.second) * 1000 + parts.millisecond;
  const range = schedule[day] || {};
  const paused = hasScheduleRange(range) && nowMs >= range.start && nowMs < range.end;
  return { enabled, paused, timeZone: schedule.time_zone, day, nowMs, range: hasScheduleRange(range) ? range : null };
}

function buildBlockedServiceMatcher(service) {
  const regexes = (service.patterns || [])
    .map((source) => {
      try {
        return new RegExp(source, 'i');
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  return {
    domains: Array.isArray(service.domains) ? service.domains : [],
    regexes
  };
}

function blockedServiceMatchesDomain(domain, matcher) {
  for (const suffix of matcher?.domains || []) {
    if (domain === suffix || domain.endsWith('.' + suffix)) return true;
  }
  for (const regex of matcher?.regexes || []) {
    if (regex.test(domain)) return true;
  }
  return false;
}

function normalizeBlockMode(value) {
  const mode = String(value || 'null').trim().toLowerCase();
  if (mode === 'null_ip') return 'null';
  if (mode === 'custom_ip') return 'custom';
  if (['default', 'refused', 'null', 'custom', 'nxdomain', 'nodata'].includes(mode)) return mode;
  throw new Error('bad_block_mode');
}

function blockModeLabel(value) {
  const mode = normalizeBlockMode(value);
  return BLOCK_MODE_LABELS[mode] || BLOCK_MODE_LABELS.null;
}

function normalizeProtectionPauseUntil(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.floor(number);
}

function normalizeDomainProtectionService(value, serviceId) {
  const defaults = DOMAIN_PROTECTION_SERVICES[serviceId];
  if (!defaults) throw new Error('bad_domain_protection_service');
  const source = typeof value === 'boolean'
    ? { enabled: value }
    : value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const suffix = String(source.suffix || defaults.suffix).trim().toLowerCase().replace(/\.+$/, '');
  if (!/^(?:[a-z0-9_-]+\.)+[a-z0-9_-]+$/.test(suffix)) throw new Error('bad_domain_protection_suffix');
  return {
    enabled: source.enabled === true,
    upstream: normalizeUpstreamAddress(source.upstream || defaults.upstream),
    suffix,
    timeoutMs: normalizeInteger(source.timeoutMs ?? 3000, 100, 30000, 'bad_domain_protection_timeout'),
    cacheTtlMinutes: normalizeInteger(source.cacheTtlMinutes ?? 30, 1, 1440, 'bad_domain_protection_cache_ttl')
  };
}

function normalizeUpstreamMode(value) {
  const mode = String(value || 'sequential').trim().toLowerCase();
  if (['sequential', 'parallel', 'fastest'].includes(mode)) return mode;
  throw new Error('bad_upstream_mode');
}

function normalizeDnsConfig(value = {}) {
  const dns = {
    dnssecEnabled: false,
    disableIpv6: false,
    refuseAny: true,
    resolveClients: false,
    privateReverseEnabled: false,
    privateReverseUpstreams: [],
    rateLimit: 0,
    rateLimitSubnetIpv4: 24,
    rateLimitSubnetIpv6: 56,
    rateLimitWhitelist: [],
    blockingIpv4: '0.0.0.0',
    blockingIpv6: '::',
    blockedResponseTtl: 60,
    ...(value || {})
  };
  dns.dnssecEnabled = dns.dnssecEnabled === true;
  dns.disableIpv6 = dns.disableIpv6 === true;
  dns.refuseAny = dns.refuseAny !== false;
  dns.resolveClients = dns.resolveClients === true;
  dns.privateReverseEnabled = dns.privateReverseEnabled === true;
  dns.privateReverseUpstreams = normalizeUpstreamConfiguration(dns.privateReverseUpstreams, {
    errorCode: 'bad_private_reverse_upstream'
  });
  dns.rateLimit = normalizeInteger(dns.rateLimit ?? 0, 0, 1000000, 'bad_dns_rate_limit');
  dns.rateLimitSubnetIpv4 = normalizeInteger(dns.rateLimitSubnetIpv4 ?? 24, 0, 32, 'bad_dns_rate_limit_subnet_ipv4');
  dns.rateLimitSubnetIpv6 = normalizeInteger(dns.rateLimitSubnetIpv6 ?? 56, 0, 128, 'bad_dns_rate_limit_subnet_ipv6');
  dns.rateLimitWhitelist = normalizeDnsRateLimitWhitelist(dns.rateLimitWhitelist);
  dns.blockingIpv4 = normalizeDnsBlockingIp(dns.blockingIpv4, 4, '0.0.0.0', 'bad_dns_blocking_ipv4');
  dns.blockingIpv6 = normalizeDnsBlockingIp(dns.blockingIpv6, 6, '::', 'bad_dns_blocking_ipv6');
  dns.blockedResponseTtl = normalizeInteger(dns.blockedResponseTtl ?? 60, 0, 0xffffffff, 'bad_dns_blocked_response_ttl');
  return dns;
}

function normalizeRuntimeClientSources(value, legacyReverseDns = false) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const hasReverseDns = Object.prototype.hasOwnProperty.call(source, 'rdns');
  return {
    whois: source.whois !== false,
    hosts: source.hosts !== false,
    arp: source.arp !== false,
    dhcp: source.dhcp !== false,
    rdns: hasReverseDns ? source.rdns === true : legacyReverseDns === true
  };
}

function normalizeDnsRateLimitWhitelist(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
  const result = [];
  for (const item of items) {
    const raw = String(item || '').trim();
    if (!raw) continue;
    const normalized = normalizeClientIdentifier(raw);
    if (!normalized) throw new Error('bad_dns_rate_limit_whitelist');
    if (!result.includes(normalized)) result.push(normalized);
  }
  return result;
}

function normalizeDnsBlockingIp(value, family, fallback, errorCode) {
  const raw = String(value ?? fallback).trim() || fallback;
  const normalized = normalizeIpLiteral(raw);
  if (net.isIP(normalized) !== family) throw new Error(errorCode);
  return family === 4 ? bytesToIpv4(ipv4ToBytes(normalized)) : bytesToIpv6(ipv6ToBytes(normalized));
}

function normalizeInteger(value, min, max, errorCode) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(errorCode);
  return number;
}

function normalizeCacheConfig(value = {}) {
  const cacheConfig = {
    enabled: true,
    maxEntries: 20000,
    minTtl: 30,
    maxTtl: 600,
    staleTtl: 60,
    optimistic: false,
    optimisticAnswerTtl: 30,
    optimisticMaxAge: 43200,
    ...(value || {})
  };
  cacheConfig.enabled = cacheConfig.enabled !== false;
  cacheConfig.optimistic = cacheConfig.optimistic === true;
  cacheConfig.maxEntries = normalizeInteger(cacheConfig.maxEntries, 100, 1000000, 'bad_cache_max_entries');
  cacheConfig.minTtl = normalizeInteger(cacheConfig.minTtl, 0, 86400, 'bad_cache_min_ttl');
  cacheConfig.maxTtl = normalizeInteger(cacheConfig.maxTtl, 1, 86400, 'bad_cache_max_ttl');
  cacheConfig.staleTtl = normalizeInteger(cacheConfig.staleTtl, 0, 86400, 'bad_cache_stale_ttl');
  cacheConfig.optimisticAnswerTtl = normalizeInteger(cacheConfig.optimisticAnswerTtl, 1, 3600, 'bad_cache_optimistic_answer_ttl');
  cacheConfig.optimisticMaxAge = normalizeInteger(cacheConfig.optimisticMaxAge, 1, 604800, 'bad_cache_optimistic_max_age');
  if (cacheConfig.maxTtl < cacheConfig.minTtl) throw new Error('bad_cache_ttl_range');
  return cacheConfig;
}

function normalizeEcsConfig(value = {}) {
  const ecs = {
    enabled: true,
    ipv4Prefix: 24,
    ipv6Prefix: 56,
    defaultIpv4: '114.114.114.114',
    ...(value || {})
  };
  ecs.enabled = ecs.enabled !== false;
  ecs.ipv4Prefix = normalizeInteger(ecs.ipv4Prefix, 0, 32, 'bad_ecs_ipv4_prefix');
  ecs.ipv6Prefix = normalizeInteger(ecs.ipv6Prefix, 0, 128, 'bad_ecs_ipv6_prefix');
  ecs.defaultIpv4 = String(ecs.defaultIpv4 || '').trim();
  if (ecs.defaultIpv4 && net.isIP(ecs.defaultIpv4) !== 4) throw new Error('bad_ecs_default_ipv4');
  return ecs;
}

function normalizeQueryLogConfig(value = {}) {
  const queryLog = {
    enabled: true,
    maxEntries: 1000,
    retentionHours: 2160,
    anonymizeClientIp: true,
    ignoredEnabled: false,
    ignored: [],
    ...(value || {})
  };
  queryLog.enabled = queryLog.enabled !== false;
  queryLog.anonymizeClientIp = queryLog.anonymizeClientIp !== false;
  queryLog.ignoredEnabled = queryLog.ignoredEnabled === true;
  queryLog.ignored = normalizeQueryLogIgnoredList(queryLog.ignored);
  queryLog.maxEntries = normalizeInteger(queryLog.maxEntries, 20, 5000, 'bad_query_log_max_entries');
  queryLog.retentionHours = normalizeInteger(queryLog.retentionHours ?? 2160, 1, 8760, 'bad_query_log_retention');
  return queryLog;
}

function normalizeStatisticsConfig(value = {}) {
  const statistics = {
    enabled: true,
    retentionHours: 24,
    ignoredEnabled: false,
    ignored: [],
    ...(value || {})
  };
  statistics.enabled = statistics.enabled !== false;
  statistics.ignoredEnabled = statistics.ignoredEnabled === true;
  statistics.ignored = normalizeQueryLogIgnoredList(statistics.ignored);
  statistics.retentionHours = normalizeInteger(statistics.retentionHours ?? 24, 1, 8760, 'bad_stats_retention');
  return statistics;
}

function normalizeAccessConfig(value = {}) {
  const access = {
    allowedClients: [],
    blockedClients: [],
    blockedHosts: [],
    ...(value || {})
  };
  access.allowedClients = normalizeAccessClientList(access.allowedClients);
  access.blockedClients = normalizeAccessClientList(access.blockedClients);
  access.blockedHosts = normalizeDomainList(access.blockedHosts);
  return access;
}

function normalizeAdminProfile(value = {}) {
  const profile = value && typeof value === 'object' ? value : {};
  return {
    language: 'zh-CN',
    theme: normalizeProfileTheme(profile.theme)
  };
}

function normalizeProfileTheme(value, strict = false) {
  const theme = String(value ?? 'auto').trim().toLowerCase();
  if (['auto', 'light', 'dark'].includes(theme)) return theme;
  if (strict) throw new Error('bad_profile_theme');
  return 'auto';
}

function getAdminProfile() {
  return {
    name: adminAuth.username,
    language: 'zh-CN',
    theme: normalizeProfileTheme(config.admin?.profile?.theme)
  };
}

function updateAdminProfile(value = {}) {
  const profile = value && typeof value === 'object' ? value : {};
  const theme = normalizeProfileTheme(profile.theme, true);
  config.admin = {
    ...config.admin,
    profile: { language: 'zh-CN', theme }
  };
  saveConfig();
  return getAdminProfile();
}

function normalizeAccessClientList(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
  return [...new Set(items.map(normalizeClientIdentifier).filter(Boolean))];
}

function normalizeDomainList(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
  return [...new Set(items.map(normalizeDomain).filter(Boolean))];
}

function normalizeQueryLogIgnoredList(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
  return [...new Set(items.map(normalizeQueryLogIgnoredDomain).filter(Boolean))];
}

function normalizeQueryLogIgnoredDomain(value) {
  const raw = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .replace(/^\|\|/, '')
    .replace(/\^$/, '')
    .replace(/^\*\./, '');
  return normalizeDomain(raw);
}

function saveConfig() {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n');
}

function normalizePublicBaseUrl(value) {
  const raw = String(value || '').trim().replace(/\/+$/, '');
  if (!raw) return `https://${config.domain}`;
  const parsed = new URL(raw);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new Error('bad_public_url');
  return parsed.origin;
}

function normalizePublicUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const parsed = new URL(raw);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new Error('bad_public_url');
  return parsed.toString();
}

function normalizePanelPath(value) {
  let panelPath = String(value || '/admin/').trim();
  if (!panelPath.startsWith('/')) panelPath = '/' + panelPath;
  panelPath = panelPath.replace(/\/{2,}/g, '/');
  if (!panelPath.endsWith('/')) panelPath += '/';
  return panelPath;
}

function normalizeDohPrefix(value) {
  let prefix = String(value || '').trim();
  prefix = prefix.replace(/^https?:\/\/[^/]+/i, '');
  prefix = prefix.replace(/\/dns-query$/i, '');
  prefix = prefix.replace(/^\/+|\/+$/g, '');
  if (!prefix) return '';
  if (prefix.includes('..') || !/^[A-Za-z0-9._~/-]+$/.test(prefix)) {
    throw new Error('bad_doh_prefix');
  }
  return '/' + prefix.replace(/\/{2,}/g, '/');
}

function normalizeDohPath(value) {
  let raw = String(value || '/dns-query').trim();
  raw = raw.replace(/^https?:\/\/[^/]+/i, '');
  if (!raw.startsWith('/')) raw = '/' + raw;
  raw = raw.replace(/\/{2,}/g, '/');
  if (!raw.endsWith('/dns-query')) raw = raw.replace(/\/+$/g, '') + '/dns-query';
  const prefix = normalizeDohPrefix(raw);
  return `${prefix}/dns-query`;
}

function normalizePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad_port');
  return port;
}

function normalizePlainDnsHost(value) {
  const host = String(value || '0.0.0.0').trim();
  if (!host) return '0.0.0.0';
  if (host === 'localhost' || net.isIP(host)) return host;
  throw new Error('bad_plain_dns_host');
}

function normalizeTlsFilePath(value, errorCode = 'bad_tls_file_path') {
  const file = String(value || '').trim();
  if (!file || file.length > 2048 || file.includes('\0') || !path.isAbsolute(file)) throw new Error(errorCode);
  return path.normalize(file);
}

function parseEndpointPort(value) {
  const raw = String(value || '').trim();
  const match = raw.match(/:(\d+)$/);
  return match ? Number(match[1]) : 0;
}

function normalizeDoqEndpoint(value, domain) {
  const raw = String(value || '').trim();
  let host = raw.replace(/^\[|\]$/g, '').replace(/:\d+$/, '');
  if (!host) host = domain;
  if (!/^[A-Za-z0-9.-]+$/.test(host) && !net.isIP(host)) throw new Error('bad_doq_endpoint');
  return host;
}

function formatDoqEndpoint(host, port) {
  const cleanHost = normalizeDoqEndpoint(host, config.domain);
  const cleanPort = normalizePort(port);
  if (net.isIP(cleanHost) === 6) return `[${cleanHost}]:${cleanPort}`;
  return `${cleanHost}:${cleanPort}`;
}

function normalizeUpstreams(value) {
  return normalizeUpstreamConfiguration(value, {
    errorCode: 'bad_upstream',
    requireDefaults: true
  });
}

function normalizeOptionalUpstreams(value, errorCode = 'bad_upstream') {
  const items = Array.isArray(value) ? value : String(value || '').split(/\r?\n|,/);
  const upstreams = [];
  for (const item of items) {
    const raw = String(item || '').trim();
    if (!raw) continue;
    let normalized;
    try {
      normalized = normalizeUpstreamAddress(raw);
    } catch {
      throw new Error(errorCode);
    }
    if (!upstreams.includes(normalized)) upstreams.push(normalized);
  }
  return upstreams;
}

function normalizeBootstrapDns(value) {
  const upstreams = normalizeOptionalUpstreams(value, 'bad_bootstrap_dns');
  for (const upstream of upstreams) {
    const target = parseUpstreamAddress(upstream);
    if (!net.isIP(target.host) || !['udp', 'tcp'].includes(target.protocol)) {
      throw new Error('bad_bootstrap_dns');
    }
  }
  return upstreams;
}

function getDohPrefix() {
  const pathValue = config.service?.dohPath || '/dns-query';
  return pathValue === '/dns-query' ? '' : pathValue.replace(/\/dns-query$/, '');
}

function protectionStatus() {
  const enabled = config.filter.enabled !== false;
  const pauseUntil = normalizeProtectionPauseUntil(config.filter.pauseUntil);
  const remainingMs = enabled ? Math.max(0, pauseUntil - Date.now()) : 0;
  return {
    enabled,
    active: enabled && remainingMs <= 0,
    paused: enabled && remainingMs > 0,
    pauseUntil: remainingMs > 0 ? pauseUntil : 0,
    remainingMs
  };
}

function isFilteringActive() {
  return protectionStatus().active;
}

function ensureDataFiles() {
  const files = [
    config.rules.blockFile,
    config.rules.allowFile,
    config.rules.rewriteFile,
    config.rules.subscriptionFile,
    config.rules.allowSubscriptionFile,
    config.clients.file,
    config.logFile,
    config.statsFile
  ];
  for (const file of files) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (!fs.existsSync(file)) fs.writeFileSync(file, file === config.clients.file ? '[]\n' : file.endsWith('.json') ? '{}' : '');
  }
  fs.mkdirSync(config.rules.downloadDir, { recursive: true });
  fs.mkdirSync(config.rules.allowDownloadDir, { recursive: true });
}

function ensureAdminAuth() {
  const username = config.admin.username || 'admin';
  const file = config.admin.passwordFile || path.join(path.dirname(config.statsFile), 'admin-password');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!fs.existsSync(file)) {
    const temporaryPassword = crypto.randomBytes(18).toString('base64url');
    fs.writeFileSync(file, hashPassword(temporaryPassword) + '\n', { mode: 0o600 });
    console.warn(`temporary admin password generated for ${username}: ${temporaryPassword}`);
  }
  return {
    username,
    passwordFile: file,
    passwordHash: fs.readFileSync(file, 'utf8').trim(),
    sessionTtlMs: (config.admin.sessionTtlSeconds || 86400) * 1000
  };
}

function loadStats() {
  try {
    const loaded = JSON.parse(fs.readFileSync(config.statsFile, 'utf8'));
    const buckets = pruneStatsBuckets(loadStatsBuckets(loaded), config.statistics.retentionHours);
    const parsedResetAt = Number(loaded?.resetAt) || Date.parse(loaded?.resetAt || '');
    const resetAt = Number.isFinite(parsedResetAt) && parsedResetAt > 0
      ? parsedResetAt
      : buckets.length
        ? 0
        : Date.now();
    return { buckets, stats: aggregateStatsBuckets(buckets), resetAt };
  } catch {
    return { buckets: [], stats: emptyStats(), resetAt: Date.now() };
  }
}

function saveStats() {
  try {
    applyStatisticsRetention();
    fs.writeFileSync(config.statsFile, JSON.stringify({ version: 2, resetAt: statsResetAt, buckets: statsBuckets }, null, 2));
  } catch {
    // best effort
  }
}

function emptyStats() {
  return emptyStatsSnapshot();
}

function clearStats(now = Date.now()) {
  statsBuckets = [];
  stats = emptyStats();
  statsResetAt = now;
  saveStats();
}

function applyStatisticsRetention(now = Date.now()) {
  const retained = pruneStatsBuckets(statsBuckets, config.statistics.retentionHours, now);
  if (retained.length === statsBuckets.length) return false;
  statsBuckets = retained;
  stats = aggregateStatsBuckets(statsBuckets);
  return true;
}

function currentStatsBucket(now = Date.now()) {
  const bucket = ensureStatsBucket(statsBuckets, now);
  applyStatisticsRetention(now);
  return bucket;
}

function updateStats(mutator) {
  const bucket = currentStatsBucket();
  mutator(stats);
  mutator(bucket);
}

function runRetentionMaintenance() {
  if (applyStatisticsRetention()) saveStats();
  trimRecentQueries();
  queryLogStore.rotateIfDue().catch(() => {});
}

function shouldRecordStats() {
  return config.statistics?.enabled !== false;
}

function recordStat(key, value = 1) {
  if (!shouldRecordStats()) return;
  updateStats((target) => {
    target[key] = (target[key] || 0) + value;
  });
}

function recordStatMap(mapName, key, value = 1) {
  if (!shouldRecordStats() || !key) return;
  updateStats((target) => {
    target[mapName] ||= {};
    target[mapName][key] = (target[mapName][key] || 0) + value;
  });
}

function recordDashboardRankings(qname, action, clientIp, clientProfile, ignored) {
  if (ignored || !shouldRecordStats()) return;
  const domain = normalizeDomain(qname);
  const client = dashboardClientKey(clientIp, clientProfile);
  const bucket = currentStatsBucket();
  const bucketLimit = statsRankingBucketLimit();
  for (const [target, limit] of [[stats, AGGREGATE_RANK_MAP_LIMIT], [bucket, bucketLimit]]) {
    target.rankingCount = (target.rankingCount || 0) + 1;
    incrementBoundedNumberMap(target, 'byDomain', domain, limit);
    incrementBoundedNumberMap(target, 'byClient', client, limit);
    if (isDashboardBlockedAction(action)) incrementBoundedNumberMap(target, 'byBlockedDomain', domain, limit);
  }
}

function statsRankingBucketLimit() {
  const retentionHours = Math.max(1, Number(config.statistics?.retentionHours) || 24);
  return clamp(Math.floor(12_288 / retentionHours), 32, 512);
}

function incrementBoundedNumberMap(target, mapName, key, limit) {
  const normalizedKey = String(key || '').trim();
  if (!normalizedKey || ['__proto__', 'prototype', 'constructor'].includes(normalizedKey)) return;
  target[mapName] ||= {};
  const map = target[mapName];
  if (Object.prototype.hasOwnProperty.call(map, normalizedKey)) {
    map[normalizedKey] = (Number(map[normalizedKey]) || 0) + 1;
    return;
  }
  if (Object.keys(map).length < limit) map[normalizedKey] = 1;
}

function dashboardClientKey(clientIp, clientProfile) {
  const name = String(clientProfile?.name || '').trim();
  if (name) return name;
  const address = String(clientIp || '').trim();
  return config.queryLog?.anonymizeClientIp === false ? address : anonymizeIp(address);
}

function isDashboardBlockedAction(action) {
  return ['block', 'block-cname', 'block-service', 'block-safebrowsing', 'block-parental', 'safe-search'].includes(String(action || ''));
}

function backfillDashboardRankings() {
  if (!stats.total || stats.rankingCount || !recentQueries.length || !statsBuckets.length) return;
  const bounds = dashboardWindowBounds(config.statistics.retentionHours);
  const effectiveStart = Math.max(bounds.start, Number(statsResetAt) || 0);
  const ignoredClientIds = clients.filter((client) => client.ignoreStatistics === true).map((client) => client.id);
  const rows = selectDashboardRows(recentQueries, {
    retentionHours: bounds.retentionHours,
    now: bounds.end,
    start: effectiveStart,
    enabled: true,
    ignoredEnabled: config.statistics.ignoredEnabled === true,
    ignoredDomains: config.statistics.ignored || [],
    ignoredClientIds
  });
  const bucketsByStart = new Map(statsBuckets.map((bucket) => [bucket.start, bucket.stats]));
  const limit = statsRankingBucketLimit();
  let count = 0;
  for (const row of rows) {
    if (count >= stats.total) break;
    const timestamp = Date.parse(row?.time || '');
    const bucket = bucketsByStart.get(statsBucketStart(timestamp));
    if (!bucket) continue;
    bucket.rankingCount = (bucket.rankingCount || 0) + 1;
    incrementBoundedNumberMap(bucket, 'byDomain', row.qname, limit);
    incrementBoundedNumberMap(bucket, 'byClient', row.clientName || row.client, limit);
    if (isDashboardBlockedAction(row.action)) incrementBoundedNumberMap(bucket, 'byBlockedDomain', row.qname, limit);
    count += 1;
  }
  if (!count) return;
  stats = aggregateStatsBuckets(statsBuckets);
  saveStats();
}

function loadClients() {
  try {
    return normalizeClientList(JSON.parse(fs.readFileSync(config.clients.file, 'utf8')));
  } catch {
    return [];
  }
}

function saveClients(nextClients = clients) {
  fs.mkdirSync(path.dirname(config.clients.file), { recursive: true });
  fs.writeFileSync(config.clients.file, JSON.stringify(nextClients, null, 2) + '\n');
}

function normalizeClientList(value) {
  const source = Array.isArray(value) ? value : Array.isArray(value?.clients) ? value.clients : [];
  const seenIds = new Set();
  return source.map((item, index) => normalizeClientProfile(item, index))
    .filter(Boolean)
    .map((item) => {
      let id = item.id;
      while (seenIds.has(id)) id = crypto.randomBytes(8).toString('base64url');
      seenIds.add(id);
      return { ...item, id };
    });
}

function normalizeClientProfile(item, index = 0) {
  const name = String(item?.name || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  const note = String(item?.note || '').replace(/\s+/g, ' ').trim().slice(0, 160);
  const tags = normalizeClientTags(item?.tags);
  const rawIdentifiers = Array.isArray(item?.identifiers)
    ? item.identifiers
    : String(item?.identifiers || item?.identifier || '').split(/[\r\n,]+/);
  const identifiers = [...new Set(rawIdentifiers.map(normalizeClientIdentifier).filter(Boolean))];
  if (!name || !identifiers.length) return null;
  const rawId = String(item?.id || '').trim();
  const id = /^[A-Za-z0-9_-]{6,64}$/.test(rawId) ? rawId : crypto.createHash('sha1').update(`${index}:${name}:${identifiers.join(',')}`).digest('hex').slice(0, 16);
  const ignoreQueryLog = item?.ignoreQueryLog === true || item?.ignore_querylog === true;
  const ignoreStatistics = item?.ignoreStatistics === true || item?.ignore_statistics === true;
  const legacyDisableFiltering = item?.disableFiltering === true || item?.disable_filtering === true;
  const hasUseGlobalSettings = Object.prototype.hasOwnProperty.call(item || {}, 'useGlobalSettings') ||
    Object.prototype.hasOwnProperty.call(item || {}, 'use_global_settings');
  const hasFilteringEnabled = Object.prototype.hasOwnProperty.call(item || {}, 'filteringEnabled') ||
    Object.prototype.hasOwnProperty.call(item || {}, 'filtering_enabled');
  const safeSearchInput = item?.safeSearch ?? item?.safe_search;
  const hasSafeSearch = safeSearchInput && typeof safeSearchInput === 'object' && !Array.isArray(safeSearchInput);
  const hasSafeBrowsing = Object.prototype.hasOwnProperty.call(item || {}, 'safeBrowsingEnabled') ||
    Object.prototype.hasOwnProperty.call(item || {}, 'safe_browsing_enabled');
  const hasParental = Object.prototype.hasOwnProperty.call(item || {}, 'parentalEnabled') ||
    Object.prototype.hasOwnProperty.call(item || {}, 'parental_enabled');
  const useGlobalSettings = hasUseGlobalSettings
    ? (item?.useGlobalSettings ?? item?.use_global_settings) !== false
    : hasFilteringEnabled || hasSafeSearch || hasSafeBrowsing || hasParental ? false : !legacyDisableFiltering;
  const filteringEnabled = hasFilteringEnabled
    ? (item?.filteringEnabled ?? item?.filtering_enabled) !== false
    : !legacyDisableFiltering;
  const safeSearch = normalizeSafeSearchConfig(hasSafeSearch ? safeSearchInput : config.filter.safeSearch);
  const safeBrowsingEnabled = hasSafeBrowsing
    ? (item?.safeBrowsingEnabled ?? item?.safe_browsing_enabled) === true
    : config.filter.safeBrowsing.enabled === true;
  const parentalEnabled = hasParental
    ? (item?.parentalEnabled ?? item?.parental_enabled) === true
    : config.filter.parental.enabled === true;
  const disableFiltering = !useGlobalSettings && !filteringEnabled;
  const hasUseGlobalBlockedServices = Object.prototype.hasOwnProperty.call(item || {}, 'useGlobalBlockedServices') ||
    Object.prototype.hasOwnProperty.call(item || {}, 'use_global_blocked_services');
  const useGlobalBlockedServices = hasUseGlobalBlockedServices
    ? (item?.useGlobalBlockedServices ?? item?.use_global_blocked_services) !== false
    : true;
  const blockedServices = normalizeBlockedServices(item?.blockedServices ?? item?.blocked_services);
  const blockedServicesSchedule = normalizeBlockedServicesSchedule(item?.blockedServicesSchedule ?? item?.blocked_services_schedule);
  const disableEcs = item?.disableEcs === true || item?.disable_ecs === true;
  const upstreams = normalizeClientUpstreams(item?.upstreams);
  const upstreamsCacheEnabled = item?.upstreamsCacheEnabled === true || item?.upstreams_cache_enabled === true;
  const upstreamsCacheSize = normalizeClientCacheSize(item?.upstreamsCacheSize ?? item?.upstreams_cache_size);
  return {
    id,
    name,
    identifiers,
    note,
    tags,
    ignoreQueryLog,
    ignoreStatistics,
    useGlobalSettings,
    filteringEnabled,
    safeSearch,
    safeBrowsingEnabled,
    parentalEnabled,
    disableFiltering,
    useGlobalBlockedServices,
    blockedServices,
    blockedServicesSchedule,
    disableEcs,
    upstreams,
    upstreamsCacheEnabled,
    upstreamsCacheSize
  };
}

function normalizeClientTags(value) {
  const source = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
  return [...new Set(source
    .map((item) => String(item || '').replace(/\s+/g, ' ').trim().slice(0, 40))
    .filter(Boolean))]
    .slice(0, 12);
}

function normalizeClientUpstreams(value) {
  return normalizeUpstreamConfiguration(value, {
    errorCode: 'bad_client_upstream',
    ignoreInvalid: true
  });
}

function normalizeClientCacheSize(value) {
  const size = Number(value ?? 0);
  return Number.isInteger(size) && size >= 0 && size <= UINT32_MAX ? size : 0;
}

function normalizeClientIdentifier(value) {
  let raw = String(value || '').trim().replace(/^v[46]:/i, '').replace(/^\[|\]$/g, '');
  if (!raw) return '';
  if (raw.includes('/')) {
    const [address, prefixText] = raw.split('/');
    const ip = normalizeIpLiteral(address);
    const family = net.isIP(ip);
    const prefix = Number(prefixText);
    if (!family || !Number.isInteger(prefix)) return '';
    if ((family === 4 && (prefix < 0 || prefix > 32)) || (family === 6 && (prefix < 0 || prefix > 128))) return '';
    const bytes = family === 4 ? ipv4ToBytes(ip) : ipv6ToBytes(ip);
    const masked = maskBytes(bytes, prefix);
    return `${family === 4 ? bytesToIpv4(masked) : bytesToIpv6(masked)}/${prefix}`;
  }
  const ip = normalizeIpLiteral(raw);
  const family = net.isIP(ip);
  if (family === 4) return bytesToIpv4(ipv4ToBytes(ip));
  if (family === 6) return bytesToIpv6(ipv6ToBytes(ip));
  return '';
}

function normalizeIpLiteral(value) {
  const ip = String(value || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  return ip.startsWith('::ffff:') && net.isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip;
}

function findClientProfile(clientIp) {
  const ip = normalizeIpLiteral(clientIp);
  if (!net.isIP(ip)) return null;
  const exact = normalizeClientIdentifier(ip);
  const anonymous = anonymizeIp(ip);
  return clients.find((client) => client.identifiers.some((identifier) => (
    identifier === exact ||
    identifier === anonymous ||
    matchesClientIdentifier(identifier, ip)
  ))) || null;
}

function recordRuntimeClient(item = {}) {
  const address = normalizeIpLiteral(item.clientIp);
  if (!net.isIP(address)) return;
  const now = Date.now();
  let entry = runtimeClients.get(address);
  if (!entry) {
    if (runtimeClients.size >= RUNTIME_CLIENT_LIMIT) {
      let oldestAddress = '';
      let oldestAt = Infinity;
      for (const [candidateAddress, candidate] of runtimeClients) {
        const candidateAt = Number(candidate.lastSeenAt) || 0;
        if (candidateAt < oldestAt) {
          oldestAt = candidateAt;
          oldestAddress = candidateAddress;
        }
      }
      if (oldestAddress) runtimeClients.delete(oldestAddress);
    }
    entry = {
      address,
      firstSeenAt: now,
      lastSeenAt: now,
      requests: 0,
      blocked: 0,
      cached: 0,
      protocols: new Set(),
      types: new Set(),
      reverseDnsName: '',
      reverseDnsStatus: 'idle',
      reverseDnsCheckedAt: 0,
      reverseDnsNextAt: 0,
      reverseDnsResolver: '',
      reverseDnsScope: '',
      reverseDnsError: '',
      whoisInfo: null,
      whoisStatus: 'idle',
      whoisCheckedAt: 0,
      whoisNextAt: 0,
      whoisServer: '',
      whoisError: ''
    };
    runtimeClients.set(address, entry);
  }
  entry.lastSeenAt = now;
  entry.requests = Math.min(Number.MAX_SAFE_INTEGER, entry.requests + 1);
  if (isDashboardBlockedAction(item.action) || ['refused', 'rate-limit'].includes(String(item.action || ''))) {
    entry.blocked = Math.min(Number.MAX_SAFE_INTEGER, entry.blocked + 1);
  }
  if (item.cached === true) entry.cached = Math.min(Number.MAX_SAFE_INTEGER, entry.cached + 1);
  if (item.protocol) entry.protocols.add(String(item.protocol).slice(0, 24));
  if (item.qtype) entry.types.add(String(item.qtype).slice(0, 24));
  scheduleRuntimeClientReverseLookup(entry);
  scheduleRuntimeClientWhoisLookup(entry);
}

function getRuntimeClients() {
  refreshRuntimeClientSources();
  const dhcpSnapshot = config.dhcp?.enabled === true && runtimeClientSourceSettings().dhcp ? dhcpRuntime.snapshot() : null;
  const addresses = runtimeClientAddresses(dhcpSnapshot);
  return [...addresses].map((address) => runtimeClientForAddress(address, dhcpSnapshot))
    .sort((left, right) => Date.parse(right.lastSeenAt) - Date.parse(left.lastSeenAt) || right.requests - left.requests || left.address.localeCompare(right.address));
}

function runtimeClientForAddress(address, dhcpSnapshot = null) {
  const entry = runtimeClients.get(address) || null;
  const profile = findClientProfile(address);
  const sourceSettings = runtimeClientSourceSettings();
  const reverseDnsEnabled = sourceSettings.rdns === true;
  const whoisEnabled = sourceSettings.whois === true;
  const reverseDnsName = String(entry?.reverseDnsName || '').trim();
  const whoisInfo = profile || !whoisEnabled ? {} : normalizeWhoisInfo(entry?.whoisInfo);
  const hosts = sourceSettings.hosts ? runtimeClientSourceCache.hosts.records.get(address) || null : null;
  const arp = sourceSettings.arp ? runtimeClientSourceCache.arp.records.get(address) || null : null;
  const dhcpLease = runtimeClientDhcpLeaseForAddress(address, dhcpSnapshot);
  const automatic = runtimeClientAutomaticSource({ hosts, dhcpLease, reverseDnsName, arp, whoisInfo });
  const fallbackTimestamp = runtimeClientSourceTimestamp({ hosts, arp, dhcpSnapshot });
  const firstSeenAt = Number(entry?.firstSeenAt) || fallbackTimestamp || Date.now();
  const lastSeenAt = Number(entry?.lastSeenAt) || fallbackTimestamp || firstSeenAt;
  return {
    address,
    name: profile?.name || automatic.name || '',
    note: profile?.note || '',
    tags: profile?.tags || [],
    clientId: profile?.id || '',
    known: Boolean(profile),
    source: profile ? 'persistent' : automatic.source,
    hosts: hosts ? { hostname: hosts.hostname, aliases: hosts.aliases || [] } : null,
    arp: arp ? { mac: arp.mac, device: arp.device } : null,
    dhcp: dhcpLease,
    requests: Number(entry?.requests) || 0,
    blocked: Number(entry?.blocked) || 0,
    cached: Number(entry?.cached) || 0,
    protocols: entry ? [...entry.protocols].sort() : [],
    types: entry ? [...entry.types].sort() : [],
    firstSeenAt: new Date(firstSeenAt).toISOString(),
    lastSeenAt: new Date(lastSeenAt).toISOString(),
    queryLogAnonymized: config.queryLog?.anonymizeClientIp !== false,
    reverseDns: {
      enabled: reverseDnsEnabled,
      status: profile ? 'managed' : reverseDnsEnabled ? (entry?.reverseDnsStatus || 'idle') : 'disabled',
      hostname: reverseDnsName,
      checkedAt: entry?.reverseDnsCheckedAt ? new Date(entry.reverseDnsCheckedAt).toISOString() : '',
      nextLookupAt: entry?.reverseDnsNextAt ? new Date(entry.reverseDnsNextAt).toISOString() : '',
      resolver: entry?.reverseDnsResolver || '',
      scope: entry?.reverseDnsScope || '',
      error: entry?.reverseDnsError || ''
    },
    whois: {
      enabled: whoisEnabled,
      status: profile
        ? 'managed'
        : whoisEnabled
          ? (entry?.whoisStatus || (isPublicWhoisAddress(address) ? 'idle' : 'not-applicable'))
          : 'disabled',
      info: Object.keys(whoisInfo).length ? whoisInfo : null,
      checkedAt: entry?.whoisCheckedAt ? new Date(entry.whoisCheckedAt).toISOString() : '',
      nextLookupAt: entry?.whoisNextAt ? new Date(entry.whoisNextAt).toISOString() : '',
      server: entry?.whoisServer || '',
      error: entry?.whoisError || ''
    }
  };
}

function runtimeClientAutomaticSource(value = {}) {
  if (value.hosts) return { source: 'hosts', name: String(value.hosts.hostname || '').trim() };
  if (value.dhcpLease) return { source: 'dhcp', name: String(value.dhcpLease.hostname || '').trim() };
  if (value.reverseDnsName) return { source: 'rdns', name: value.reverseDnsName };
  if (value.arp) return { source: 'arp', name: '' };
  if (value.whoisInfo && Object.keys(value.whoisInfo).length) return { source: 'whois', name: '' };
  return { source: 'dns-query', name: '' };
}

function runtimeClientAddresses(dhcpSnapshot = null) {
  const addresses = new Set(runtimeClients.keys());
  const add = (address) => {
    if (addresses.size >= RUNTIME_CLIENT_SOURCE_LIMIT) return;
    const normalized = normalizeIpLiteral(address);
    if (net.isIP(normalized)) addresses.add(normalized);
  };
  const sources = runtimeClientSourceSettings();
  if (sources.hosts) runtimeClientSourceCache.hosts.records.forEach((_, address) => add(address));
  if (sources.arp) runtimeClientSourceCache.arp.records.forEach((_, address) => add(address));
  if (sources.dhcp && dhcpSnapshot?.running === true) {
    for (const lease of dhcpSnapshot.leases || []) add(lease?.ip);
    for (const lease of config.dhcp?.staticLeases || []) add(lease?.ip);
  }
  return addresses;
}

function runtimeClientSourceTimestamp(value = {}) {
  const timestamps = [];
  if (value.hosts) timestamps.push(Number(value.hosts.discoveredAt) || 0);
  if (value.arp) timestamps.push(Number(value.arp.discoveredAt) || 0);
  if (value.dhcpSnapshot?.running === true) timestamps.push(Date.parse(value.dhcpSnapshot.startedAt || '') || 0);
  return Math.max(0, ...timestamps);
}

function runtimeClientSourceSettings(value = config) {
  return value.clients?.runtimeSources || { whois: true, hosts: true, arp: true, dhcp: true, rdns: value.dns?.resolveClients === true };
}

function refreshRuntimeClientSources(options = {}) {
  const force = options.force === true;
  const sources = runtimeClientSourceSettings();
  refreshRuntimeClientSourceCache('hosts', sources.hosts === true, RUNTIME_CLIENT_HOSTS_FILE, parseHostsFile, force);
  refreshRuntimeClientSourceCache('arp', sources.arp === true, RUNTIME_CLIENT_ARP_FILE, parseLinuxArpTable, force);
}

function refreshRuntimeClientSourceCache(kind, enabled, filename, parser, force) {
  const cache = runtimeClientSourceCache[kind];
  if (!enabled || !filename) {
    cache.records = new Map();
    cache.refreshedAt = Date.now();
    cache.error = '';
    return;
  }
  if (!force && Date.now() - cache.refreshedAt < RUNTIME_CLIENT_SOURCE_REFRESH_MS) return;
  try {
    const records = new Map();
    const discoveredAt = Date.now();
    for (const record of parser(fs.readFileSync(filename, 'utf8'))) {
      const address = normalizeIpLiteral(record?.address);
      if (!net.isIP(address) || records.size >= RUNTIME_CLIENT_SOURCE_LIMIT) continue;
      if (!records.has(address)) records.set(address, {
        ...record,
        address,
        discoveredAt: Number(cache.records.get(address)?.discoveredAt) || discoveredAt
      });
    }
    cache.records = records;
    cache.refreshedAt = Date.now();
    cache.error = '';
  } catch (error) {
    cache.records = new Map();
    cache.refreshedAt = Date.now();
    cache.error = String(error?.code || error?.message || 'source_read_failed').slice(0, 160);
  }
}

function runtimeClientDhcpLeaseForAddress(address, snapshot = null) {
  if (config.dhcp?.enabled !== true || runtimeClientSourceSettings().dhcp !== true) return null;
  const runtime = snapshot || dhcpRuntime.snapshot();
  if (runtime?.running !== true) return null;
  return resolveRuntimeClientDhcpLease(address, {
    dynamicLeases: runtime.leases,
    staticLeases: config.dhcp.staticLeases
  });
}

function scheduleRuntimeClientReverseLookup(entry, options = {}) {
  if (!entry || config.dns.resolveClients !== true || findClientProfile(entry.address)) return;
  const now = Date.now();
  if (options.force !== true && Number(entry.reverseDnsNextAt) > now) return;
  if (runtimeClientReverseLookups.has(entry.address)) return;

  const generation = runtimeClientReverseGeneration;
  const lookup = { generation, promise: null };
  entry.reverseDnsStatus = 'pending';
  entry.reverseDnsError = '';
  runtimeClientReverseLookups.set(entry.address, lookup);
  lookup.promise = new Promise((resolve) => setImmediate(resolve))
    .then(() => resolveRuntimeClientHostname(entry.address))
    .then((result) => {
      if (
        config.dns.resolveClients !== true ||
        generation !== runtimeClientReverseGeneration ||
        runtimeClients.get(entry.address) !== entry ||
        findClientProfile(entry.address)
      ) return;
      const checkedAt = Date.now();
      entry.reverseDnsName = result.hostname || '';
      entry.reverseDnsStatus = result.status;
      entry.reverseDnsCheckedAt = checkedAt;
      entry.reverseDnsNextAt = checkedAt + result.ttlMs;
      entry.reverseDnsResolver = result.resolver || '';
      entry.reverseDnsScope = result.scope || '';
      entry.reverseDnsError = result.error || '';
    })
    .catch((error) => {
      if (
        config.dns.resolveClients !== true ||
        generation !== runtimeClientReverseGeneration ||
        runtimeClients.get(entry.address) !== entry ||
        findClientProfile(entry.address)
      ) return;
      const checkedAt = Date.now();
      entry.reverseDnsName = '';
      entry.reverseDnsStatus = 'error';
      entry.reverseDnsCheckedAt = checkedAt;
      entry.reverseDnsNextAt = checkedAt + RUNTIME_CLIENT_RDNS_RETRY_MS;
      entry.reverseDnsError = String(error?.message || 'reverse_dns_failed').slice(0, 160);
    })
    .finally(() => {
      if (runtimeClientReverseLookups.get(entry.address) === lookup) runtimeClientReverseLookups.delete(entry.address);
      if (
        config.dns.resolveClients === true &&
        generation !== runtimeClientReverseGeneration &&
        runtimeClients.get(entry.address) === entry &&
        !findClientProfile(entry.address)
      ) scheduleRuntimeClientReverseLookup(entry, { force: true });
    });
}

async function resolveRuntimeClientHostname(address) {
  const reverseName = runtimeClientReverseName(address);
  if (!reverseName) throw new Error('bad_client_address');
  const packet = buildQuery(reverseName, QTYPE.PTR);
  let result;
  let scope;

  if (isPrivateClientAddress(address)) {
    scope = 'private';
    if (config.dns.privateReverseEnabled !== true) {
      return runtimeClientReverseUnavailable(scope, 'private_reverse_disabled');
    }
    const selection = selectUpstreamConfiguration(
      config.dns.privateReverseUpstreams || [],
      reverseName,
      QTYPE.PTR,
      { fallbackDefaults: [], defaultRoute: '私有反向 DNS' }
    );
    if (!selection?.upstreams?.length) {
      return runtimeClientReverseUnavailable(scope, 'private_reverse_upstream_unavailable');
    }
    result = await querySequentialUpstreams(selection.upstreams, packet, { recordStats: false });
  } else {
    scope = 'public';
    result = await queryUpstreams(packet, { family: 0 }, { recordStats: false });
  }

  const decoded = decodeDnsResponse(result.response, { maxAnswers: 16 });
  const answer = decoded.answers.find((item) => item.type === 'PTR' && String(item.value || '').trim());
  if (!answer) {
    return {
      hostname: '',
      status: 'not-found',
      ttlMs: RUNTIME_CLIENT_RDNS_NEGATIVE_MS,
      resolver: result.upstream || '',
      scope,
      error: ''
    };
  }
  const hostname = String(answer.value || '').trim().replace(/\.+$/, '').slice(0, 253);
  const answerTtlMs = Math.max(0, Number(answer.ttl) || 0) * 1000;
  return {
    hostname,
    status: hostname ? 'resolved' : 'not-found',
    ttlMs: hostname
      ? Math.max(RUNTIME_CLIENT_RDNS_SUCCESS_MIN_MS, Math.min(RUNTIME_CLIENT_RDNS_SUCCESS_MAX_MS, answerTtlMs))
      : RUNTIME_CLIENT_RDNS_NEGATIVE_MS,
    resolver: result.upstream || '',
    scope,
    error: ''
  };
}

function runtimeClientReverseUnavailable(scope, error) {
  return {
    hostname: '',
    status: 'unavailable',
    ttlMs: RUNTIME_CLIENT_RDNS_NEGATIVE_MS,
    resolver: '',
    scope,
    error
  };
}

function runtimeClientReverseName(address) {
  const ip = normalizeIpLiteral(address);
  const family = net.isIP(ip);
  if (family === 4) return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  if (family === 6) {
    return `${ipv6ToBytes(ip).toString('hex').split('').reverse().join('.')}.ip6.arpa`;
  }
  return '';
}

function isPrivateClientAddress(address) {
  const ip = normalizeIpLiteral(address);
  if (isLocalAddress(ip)) return true;
  if (net.isIP(ip) !== 4) return false;
  const bytes = ipv4ToBytes(ip);
  return bytes[0] === 169 && bytes[1] === 254;
}

function runtimeClientReverseDnsSignature(value = config) {
  return JSON.stringify([
    value.dns?.resolveClients === true,
    value.dns?.privateReverseEnabled === true,
    value.dns?.privateReverseUpstreams || [],
    value.upstreams || [],
    value.fallbackUpstreams || [],
    value.bootstrapDns || [],
    value.upstreamMode || 'sequential',
    value.timeoutMs || 0
  ]);
}

function syncRuntimeClientReverseDns(previousConfig, nextConfig) {
  if (runtimeClientReverseDnsSignature(previousConfig) === runtimeClientReverseDnsSignature(nextConfig)) return;
  runtimeClientReverseGeneration += 1;
  const enabled = nextConfig.dns?.resolveClients === true;
  for (const entry of runtimeClients.values()) {
    entry.reverseDnsName = '';
    entry.reverseDnsStatus = enabled ? 'idle' : 'disabled';
    entry.reverseDnsCheckedAt = 0;
    entry.reverseDnsNextAt = 0;
    entry.reverseDnsResolver = '';
    entry.reverseDnsScope = '';
    entry.reverseDnsError = '';
    if (enabled) scheduleRuntimeClientReverseLookup(entry, { force: true });
  }
}

function refreshRuntimeClientReverseDnsProfiles() {
  if (config.dns.resolveClients !== true) return;
  for (const entry of runtimeClients.values()) {
    if (!findClientProfile(entry.address)) scheduleRuntimeClientReverseLookup(entry, { force: true });
  }
}

function scheduleRuntimeClientWhoisLookup(entry, options = {}) {
  if (!entry) return;
  const enabled = runtimeClientSourceSettings().whois === true;
  if (!enabled) {
    entry.whoisStatus = 'disabled';
    return;
  }
  if (findClientProfile(entry.address)) {
    entry.whoisStatus = 'managed';
    return;
  }
  if (!isPublicWhoisAddress(entry.address)) {
    entry.whoisInfo = null;
    entry.whoisStatus = 'not-applicable';
    entry.whoisCheckedAt = 0;
    entry.whoisNextAt = 0;
    entry.whoisServer = '';
    entry.whoisError = '';
    return;
  }
  const now = Date.now();
  if (options.force !== true && Number(entry.whoisNextAt) > now) return;
  if (runtimeClientWhoisLookups.has(entry.address)) return;

  const generation = runtimeClientWhoisGeneration;
  const lookup = { generation, promise: null };
  entry.whoisStatus = 'pending';
  entry.whoisError = '';
  runtimeClientWhoisLookups.set(entry.address, lookup);
  lookup.promise = new Promise((resolve) => setImmediate(resolve))
    .then(() => runtimeWhoisResolver.lookup(entry.address))
    .then((result) => {
      if (
        runtimeClientSourceSettings().whois !== true ||
        generation !== runtimeClientWhoisGeneration ||
        runtimeClients.get(entry.address) !== entry ||
        findClientProfile(entry.address)
      ) return;
      const checkedAt = Date.parse(result.checkedAt || '') || Date.now();
      const nextAt = Date.parse(result.nextLookupAt || '') || checkedAt + RUNTIME_CLIENT_WHOIS_CACHE_TTL_MS;
      const info = normalizeWhoisInfo(result.info);
      entry.whoisInfo = Object.keys(info).length ? info : null;
      entry.whoisStatus = result.status || (entry.whoisInfo ? 'resolved' : 'not-found');
      entry.whoisCheckedAt = checkedAt;
      entry.whoisNextAt = nextAt;
      entry.whoisServer = result.server || '';
      entry.whoisError = result.error || '';
    })
    .catch((error) => {
      if (
        runtimeClientSourceSettings().whois !== true ||
        generation !== runtimeClientWhoisGeneration ||
        runtimeClients.get(entry.address) !== entry ||
        findClientProfile(entry.address)
      ) return;
      const checkedAt = Date.now();
      entry.whoisInfo = null;
      entry.whoisStatus = 'error';
      entry.whoisCheckedAt = checkedAt;
      entry.whoisNextAt = checkedAt + RUNTIME_CLIENT_WHOIS_CACHE_TTL_MS;
      entry.whoisServer = '';
      entry.whoisError = String(error?.message || 'whois_query_failed').slice(0, 160);
    })
    .finally(() => {
      if (runtimeClientWhoisLookups.get(entry.address) === lookup) runtimeClientWhoisLookups.delete(entry.address);
      if (
        runtimeClientSourceSettings().whois === true &&
        generation !== runtimeClientWhoisGeneration &&
        runtimeClients.get(entry.address) === entry &&
        !findClientProfile(entry.address)
      ) scheduleRuntimeClientWhoisLookup(entry, { force: true });
    });
}

function syncRuntimeClientWhois(previousConfig, nextConfig) {
  const previousEnabled = runtimeClientSourceSettings(previousConfig).whois === true;
  const nextEnabled = runtimeClientSourceSettings(nextConfig).whois === true;
  if (previousEnabled === nextEnabled) return;
  runtimeClientWhoisGeneration += 1;
  for (const entry of runtimeClients.values()) {
    entry.whoisInfo = null;
    entry.whoisStatus = nextEnabled ? 'idle' : 'disabled';
    entry.whoisCheckedAt = 0;
    entry.whoisNextAt = 0;
    entry.whoisServer = '';
    entry.whoisError = '';
    if (nextEnabled) scheduleRuntimeClientWhoisLookup(entry, { force: true });
  }
}

function refreshRuntimeClientWhoisProfiles() {
  if (runtimeClientSourceSettings().whois !== true) return;
  for (const entry of runtimeClients.values()) {
    if (!findClientProfile(entry.address)) scheduleRuntimeClientWhoisLookup(entry, { force: true });
  }
}

function matchesClientIdentifier(identifier, ip) {
  if (!identifier.includes('/')) return normalizeClientIdentifier(ip) === identifier;
  return isIpInCidr(ip, identifier);
}

function isIpInCidr(ip, cidr) {
  const [network, prefixText] = String(cidr || '').split('/');
  const address = normalizeIpLiteral(ip);
  const family = net.isIP(address);
  const networkFamily = net.isIP(network);
  const prefix = Number(prefixText);
  if (!family || family !== networkFamily || !Number.isInteger(prefix)) return false;
  if ((family === 4 && (prefix < 0 || prefix > 32)) || (family === 6 && (prefix < 0 || prefix > 128))) return false;
  const ipBytes = family === 4 ? ipv4ToBytes(address) : ipv6ToBytes(address);
  const networkBytes = family === 4 ? ipv4ToBytes(network) : ipv6ToBytes(network);
  return Buffer.compare(maskBytes(ipBytes, prefix), maskBytes(networkBytes, prefix)) === 0;
}

function checkAccess(clientIp, qname) {
  const blockedClients = config.access?.blockedClients || [];
  if (blockedClients.some((identifier) => matchesClientIdentifier(identifier, clientIp))) {
    return { allowed: false, rule: 'access:blocked-client' };
  }
  const allowedClients = config.access?.allowedClients || [];
  if (allowedClients.length && !allowedClients.some((identifier) => matchesClientIdentifier(identifier, clientIp))) {
    return { allowed: false, rule: 'access:not-allowed-client' };
  }
  const host = normalizeDomain(qname);
  const blockedHost = (config.access?.blockedHosts || []).find((domain) => host === domain || host.endsWith('.' + domain));
  if (blockedHost) return { allowed: false, rule: `access:blocked-host:${blockedHost}` };
  return { allowed: true, rule: '' };
}

function checkDnsRateLimit(clientIp, now = Date.now()) {
  const rate = Number(config.dns?.rateLimit || 0);
  if (!Number.isFinite(rate) || rate <= 0) return { allowed: true, key: '', limit: 0 };
  const address = normalizeIpLiteral(clientIp);
  if ((config.dns.rateLimitWhitelist || []).some((identifier) => matchesClientIdentifier(identifier, address))) {
    return { allowed: true, key: '', limit: rate, whitelisted: true };
  }
  const family = net.isIP(address);
  const prefix = family === 4
    ? config.dns.rateLimitSubnetIpv4
    : family === 6
      ? config.dns.rateLimitSubnetIpv6
      : 0;
  let key = `client:${address || 'unknown'}`;
  if (family) {
    const bytes = family === 4 ? ipv4ToBytes(address) : ipv6ToBytes(address);
    const masked = maskBytes(bytes, prefix);
    key = `v${family}:${family === 4 ? bytesToIpv4(masked) : bytesToIpv6(masked)}/${prefix}`;
  }
  const current = dnsRateLimitBuckets.get(key) || { tokens: rate, updatedAt: now, lastSeenAt: now };
  const elapsed = Math.max(0, now - current.updatedAt);
  current.tokens = Math.min(rate, current.tokens + elapsed * rate / 1000);
  current.updatedAt = now;
  current.lastSeenAt = now;
  const allowed = current.tokens >= 1;
  if (allowed) current.tokens -= 1;
  dnsRateLimitBuckets.set(key, current);
  return { allowed, key, limit: rate, whitelisted: false };
}

function pruneDnsRateLimitBuckets(now = Date.now()) {
  for (const [key, bucket] of dnsRateLimitBuckets) {
    if (now - Number(bucket?.lastSeenAt || 0) > 60_000) dnsRateLimitBuckets.delete(key);
  }
}

function loadRecentQueries() {
  try {
    const rows = queryLogStore.loadRecent(queryLogMaxEntries())
      .filter((row) => row && row.time && row.qname);
    recentQueries.splice(0, recentQueries.length, ...rows);
    trimRecentQueries();
  } catch {
    recentQueries.splice(0, recentQueries.length);
  }
}

function queryLogMaxEntries() {
  return config.queryLog?.maxEntries || 1000;
}

function queryLogStoreOptions() {
  return {
    logFile: config.logFile,
    retentionHours: config.queryLog?.retentionHours,
    maxMemoryEntries: queryLogMaxEntries()
  };
}

function configureQueryLogStore() {
  queryLogStore.configure(queryLogStoreOptions());
}

function trimRecentQueries(now = Date.now()) {
  const retained = pruneTimedRows(recentQueries, config.queryLog.retentionHours, queryLogMaxEntries(), now);
  if (retained.length === recentQueries.length) return false;
  recentQueries.splice(0, recentQueries.length, ...retained);
  return true;
}

async function clearQueryLog() {
  recentQueries.splice(0, recentQueries.length);
  await queryLogStore.clear();
}

function recentQueryParams(url) {
  const params = url.searchParams;
  const integerParam = (name, fallback, min, max) => {
    const value = Number(params.get(name));
    if (!Number.isFinite(value)) return fallback;
    return Math.max(min, Math.min(max, Math.floor(value)));
  };
  return {
    paged: ['offset', 'cursor', 'older_than', 'limit', 'search', 'status', 'reason', 'response_status', 'client', 'type', 'protocol'].some((key) => params.has(key)),
    cursorPaging: params.has('cursor') || params.has('older_than'),
    offset: integerParam('offset', 0, 0, 1_000_000),
    limit: integerParam('limit', queryLogMaxEntries(), 1, 5000),
    cursor: String(params.get('cursor') || params.get('older_than') || '').trim(),
    search: String(params.get('search') || '').trim().toLowerCase(),
    status: String(params.get('status') || '').trim(),
    action: String(params.get('reason') || params.get('response_status') || '').trim(),
    client: String(params.get('client') || '').trim(),
    type: String(params.get('type') || '').trim(),
    protocol: String(params.get('protocol') || '').trim()
  };
}

function recentActionMatches(row, action) {
  const value = String(row.action || '');
  if (!action) return true;
  if (action === 'block') return value === 'block' || value === 'block-cname';
  if (action === 'cache') return row.cached === true;
  return value === action;
}

function recentStatusKey(row) {
  const action = String(row?.action || '');
  if (action === 'allow') return row?.rule ? 'allowed' : 'processed';
  if (action.includes('block')) return 'blocked';
  if (action === 'rewrite' || action === 'safe-search') return 'rewritten';
  if (action === 'error' || action === 'refused' || action === 'rate-limit') return 'error';
  return 'processed';
}

function recentStatusMatches(row, status) {
  return !status || recentStatusKey(row) === status;
}

function recentQueryMatches(row, filters) {
  if (!recentStatusMatches(row, filters.status)) return false;
  if (!recentActionMatches(row, filters.action)) return false;
  if (filters.client && row.client !== filters.client) return false;
  if (filters.type && row.qtype !== filters.type) return false;
  if (filters.protocol && row.protocol !== filters.protocol) return false;
  if (!filters.search) return true;
  const text = [
    row.client,
    row.clientName,
    row.clientNote,
    row.clientSource,
    row.clientWhois?.orgname,
    row.clientWhois?.city,
    row.clientWhois?.country,
    row.qname,
    row.qtype,
    row.action,
    row.rule,
    row.protocol,
    row.ecs,
    row.source,
    row.upstream,
    row.upstreamMode,
    row.upstreamRoute,
    row.responseMatchType,
    row.responseMatchValue
  ].join(' ').toLowerCase();
  return text.includes(filters.search);
}

function recentClientLabel(row) {
  return row.clientName ? `${row.clientName} (${row.client})` : (row.client || '未知客户端');
}

function recentQueryFacets(rows) {
  const clients = new Map();
  const types = new Set();
  const protocols = new Set();
  const actions = { all: rows.length, allow: 0, block: 0, rewrite: 0, safeBrowsing: 0, parental: 0, safeSearch: 0, refused: 0, error: 0, cache: 0 };
  rows.forEach((row) => {
    if (row.client) clients.set(row.client, recentClientLabel(row));
    if (row.qtype) types.add(String(row.qtype));
    if (row.protocol) protocols.add(String(row.protocol));
    if (row.action === 'allow') actions.allow += 1;
    if (String(row.action || '').includes('block')) actions.block += 1;
    if (row.action === 'block-safebrowsing') actions.safeBrowsing += 1;
    if (row.action === 'block-parental') actions.parental += 1;
    if (row.action === 'rewrite') actions.rewrite += 1;
    if (row.action === 'safe-search') actions.safeSearch += 1;
    if (row.action === 'refused' || row.action === 'rate-limit') actions.refused += 1;
    if (row.action === 'error') actions.error += 1;
    if (row.cached === true) actions.cache += 1;
  });
  return {
    clients: [...clients.entries()].sort((a, b) => a[1].localeCompare(b[1])).map(([value, label]) => ({ value, label })),
    types: [...types].sort().map((value) => ({ value, label: value })),
    protocols: [...protocols].sort().map((value) => ({ value, label: value })),
    actions
  };
}

async function getRecentQueryResponse(url) {
  const filters = recentQueryParams(url);
  const rows = (recentQueries || []).map(decorateRecentQueryClient);
  if (!filters.paged) return { recent: rows, queryLog: config.queryLog };
  if (filters.cursorPaging) {
    const page = await queryLogStore.readPage({
      limit: filters.limit,
      cursor: filters.cursor,
      match: (row) => recentQueryMatches(decorateRecentQueryClient(row), filters)
    });
    return {
      recent: page.rows.map(decorateRecentQueryClient),
      queryLog: config.queryLog,
      total: null,
      totalExact: false,
      unfilteredTotal: recentQueries.length,
      limit: filters.limit,
      hasMore: page.hasMore,
      nextCursor: page.nextCursor,
      oldest: page.oldest,
      complete: page.complete,
      cursorExpired: page.cursorExpired,
      filters: {
        search: filters.search,
        status: filters.status,
        reason: filters.action,
        response_status: filters.action,
        client: filters.client,
        type: filters.type,
        protocol: filters.protocol
      },
      facets: recentQueryFacets(rows)
    };
  }
  const filtered = rows.filter((row) => recentQueryMatches(row, filters));
  const offset = Math.min(filters.offset, filtered.length);
  const limit = filters.limit;
  const pageRows = filtered.slice(offset, offset + limit);
  return {
    recent: pageRows,
    queryLog: config.queryLog,
    total: filtered.length,
    unfilteredTotal: rows.length,
    offset,
    limit,
    hasMore: offset + pageRows.length < filtered.length,
    filters: {
      search: filters.search,
      status: filters.status,
      reason: filters.action,
      response_status: filters.action,
      client: filters.client,
      type: filters.type,
      protocol: filters.protocol
    },
    facets: recentQueryFacets(rows)
  };
}

function decorateRecentQueryClient(row) {
  if (!row || typeof row !== 'object') return row;
  const storedWhois = normalizeWhoisInfo(row.clientWhois);
  const entry = runtimeClientEntryForQueryLog(row.client);
  if (!entry) {
    return {
      ...row,
      clientWhois: Object.keys(storedWhois).length ? storedWhois : null
    };
  }
  const runtime = runtimeClientForAddress(entry.address);
  const runtimeWhois = normalizeWhoisInfo(runtime?.whois?.info);
  const clientWhois = Object.keys(runtimeWhois).length ? runtimeWhois : storedWhois;
  return {
    ...row,
    clientName: row.clientName || runtime?.name || '',
    clientNote: row.clientNote || runtime?.note || '',
    clientTags: Array.isArray(row.clientTags) && row.clientTags.length ? row.clientTags : (runtime?.tags || []),
    clientSource: runtime?.source || row.clientSource || 'dns-query',
    clientWhois: Object.keys(clientWhois).length ? clientWhois : null
  };
}

function runtimeClientEntryForQueryLog(value) {
  const client = String(value || '').trim();
  const exact = normalizeIpLiteral(client);
  if (net.isIP(exact) && runtimeClients.has(exact)) return runtimeClients.get(exact);
  if (!client.includes('/')) return null;
  let match = null;
  for (const entry of runtimeClients.values()) {
    if (anonymizeIp(entry.address) !== client) continue;
    if (match) return null;
    match = entry;
  }
  return match;
}

function loadRules() {
  const allow = createDomainMatcher();
  const block = createDomainMatcher();
  const filterRewrites = createDomainMatcher();
  const rewrites = compileDnsRewrites(readPlainLines(config.rules.rewriteFile));
  const subscriptions = getSubscriptionEntries('block');
  const allowSubscriptions = getSubscriptionEntries('allow');
  const blockItems = readRuleLines(config.rules.blockFile).map((item) => ({ ...item, kind: 'block' }));
  const allowItems = readRuleLines(config.rules.allowFile).map((item) => ({ ...item, kind: 'allow' }));

  for (const entry of subscriptions.filter((item) => item.enabled)) {
    const file = getSubscriptionFile(entry.url, 'block');
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      for (const item of readRuleLines(file)) blockItems.push({ ...item, kind: 'subscription' });
    }
  }

  for (const entry of allowSubscriptions.filter((item) => item.enabled)) {
    const file = getSubscriptionFile(entry.url, 'allow');
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      for (const item of readRuleLines(file)) allowItems.push({ ...item, kind: 'allow-subscription' });
    }
  }

  const disabledRules = collectBadfilterRuleKeys([...blockItems, ...allowItems]);
  let rewriteOrder = 0;
  for (const item of allowItems) {
    if (disabledRules.has(dnsRuleIdentity(item.line))) continue;
    rewriteOrder += 1;
    if (!addFilterDnsRewriteLine(filterRewrites, item, item.kind, rewriteOrder)) addRuleLine(allow, item, item.kind);
  }
  for (const item of blockItems) {
    if (disabledRules.has(dnsRuleIdentity(item.line))) continue;
    rewriteOrder += 1;
    if (
      !addFilterDnsRewriteLine(filterRewrites, item, item.kind, rewriteOrder) &&
      !addHostsDnsRuleLine(filterRewrites, item, item.kind, rewriteOrder)
    ) {
      addBlockRuleLine(block, allow, item, item.kind);
    }
  }

  return {
    allow,
    block,
    filterRewrites,
    rewrites,
    loadedAt: Date.now(),
    blockCount: block.count + filterRewrites.hostRuleCount,
    allowCount: allow.count,
    rewriteCount: rewrites.entries.length + filterRewrites.rewriteCount,
    dedicatedRewriteCount: rewrites.entries.length,
    filterRewriteCount: filterRewrites.rewriteCount,
    filterRewriteExceptionCount: filterRewrites.exceptionCount,
    hostRuleCount: filterRewrites.hostRuleCount
  };
}

function readRuleLines(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  return text.split(/\r?\n/)
    .map((line, index) => ({ line: stripRuleComment(line).trim(), index: index + 1, file }))
    .filter((item) => item.line);
}

function readPlainLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function parseSubscriptionLine(raw, index = 0) {
  let line = String(raw || '').trim();
  if (!line || line.startsWith('!')) return null;
  let enabled = true;
  const disabled = line.match(/^#\s*disabled:?\s+(.+)$/i);
  if (disabled) {
    enabled = false;
    line = disabled[1].trim();
  } else if (line.startsWith('#')) {
    return null;
  }
  const match = line.match(/^(https?:\/\/\S+?)(?:\s+#\s*(.+))?$/i);
  if (!match) return null;
  const url = match[1].trim();
  if (!/^https?:\/\//i.test(url)) return null;
  const name = normalizeSubscriptionName(match[2] || subscriptionNameFromUrl(url));
  return { url, name, enabled, index };
}

function normalizeSubscriptionName(value) {
  return String(value || '')
    .replace(/[\r\n#]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
}

function subscriptionNameFromUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

function formatSubscriptionLine(entry) {
  const url = String(entry.url || '').trim();
  const name = normalizeSubscriptionName(entry.name || subscriptionNameFromUrl(url));
  const suffix = name ? ` # ${name}` : '';
  return `${entry.enabled === false ? '# disabled ' : ''}${url}${suffix}`;
}

function normalizeSubscriptionText(text) {
  const seen = new Set();
  const entries = [];
  String(text || '').split(/\r?\n/).forEach((line, index) => {
    const entry = parseSubscriptionLine(line, index);
    if (!entry || seen.has(entry.url)) return;
    seen.add(entry.url);
    entries.push(entry);
  });
  return entries.map(formatSubscriptionLine).join('\n') + (entries.length ? '\n' : '');
}

function getSubscriptionConfig(target = 'block') {
  if (target === 'allow') {
    return {
      listFile: config.rules.allowSubscriptionFile,
      downloadDir: config.rules.allowDownloadDir
    };
  }
  return {
    listFile: config.rules.subscriptionFile,
    downloadDir: config.rules.downloadDir
  };
}

function getSubscriptionEntries(target = 'block') {
  const subscriptionConfig = getSubscriptionConfig(target);
  if (!fs.existsSync(subscriptionConfig.listFile)) return [];
  const seen = new Set();
  const entries = [];
  fs.readFileSync(subscriptionConfig.listFile, 'utf8').split(/\r?\n/).forEach((line, index) => {
    const entry = parseSubscriptionLine(line, index);
    if (!entry || seen.has(entry.url)) return;
    seen.add(entry.url);
    entries.push(entry);
  });
  return entries;
}

function getSubscriptionFile(url, target = 'block') {
  const subscriptionConfig = getSubscriptionConfig(target);
  const hash = crypto.createHash('sha256').update(url).digest('hex').slice(0, 16);
  return path.join(subscriptionConfig.downloadDir, `${hash}.txt`);
}

function getSubscriptionDetails(target = 'block') {
  return getSubscriptionEntries(target).map((entry) => {
    const file = getSubscriptionFile(entry.url, target);
    let rulesCount = 0;
    let lastUpdated = '';
    let downloaded = false;
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      downloaded = true;
      rulesCount = readRuleLines(file).length;
      lastUpdated = fs.statSync(file).mtime.toISOString();
    }
    return { ...entry, rulesCount, lastUpdated, downloaded };
  });
}

function pruneSubscriptionDownloads(entries, target = 'block') {
  const subscriptionConfig = getSubscriptionConfig(target);
  if (!fs.existsSync(subscriptionConfig.downloadDir)) return;
  const keep = new Set(entries.map((entry) => path.basename(getSubscriptionFile(entry.url, target))));
  for (const name of fs.readdirSync(subscriptionConfig.downloadDir)) {
    if (!/^[a-f0-9]{16}\.txt$/i.test(name) || keep.has(name)) continue;
    fs.rmSync(path.join(subscriptionConfig.downloadDir, name), { force: true });
  }
}

function buildCustomRule(input, target) {
  const raw = String(input || '').trim();
  if (!raw || raw.startsWith('#') || raw.startsWith('!')) return '';
  if (
    raw.startsWith('@@') ||
    raw.startsWith('|') ||
    raw.startsWith('/') ||
    raw.endsWith('|') ||
    raw.includes('*') ||
    raw.includes('^') ||
    parseHostsDnsRule(raw)
  ) {
    return target === 'allow' && raw.startsWith('||') ? `@@${raw}` : raw;
  }
  const domain = normalizeDomain(raw.replace(/^https?:\/\//, '').split('/')[0]);
  if (!domain || !domain.includes('.')) return '';
  return target === 'allow' ? `@@||${domain}^` : `||${domain}^`;
}

function stripRuleComment(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('#')) return '';
  const inlineComment = line.search(/\s+#/);
  return inlineComment >= 0 ? line.slice(0, inlineComment).trimEnd() : line;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('base64url')) {
  const derived = crypto.scryptSync(String(password), salt, 64).toString('base64url');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, encoded) {
  const [method, salt, expected] = String(encoded || '').split('$');
  if (method !== 'scrypt' || !salt || !expected) return false;
  const actual = crypto.scryptSync(String(password), salt, 64);
  const expectedBuffer = Buffer.from(expected, 'base64url');
  return expectedBuffer.length === actual.length && crypto.timingSafeEqual(expectedBuffer, actual);
}

function parseCookies(req) {
  const out = {};
  const cookie = req.headers.cookie || '';
  for (const part of cookie.split(';')) {
    const index = part.indexOf('=');
    if (index > 0) out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return out;
}

function createSession() {
  const id = crypto.randomBytes(32).toString('base64url');
  sessions.set(id, { expiresAt: Date.now() + adminAuth.sessionTtlMs });
  return id;
}

function isSessionValid(id) {
  const session = sessions.get(id);
  if (!session) return false;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(id);
    return false;
  }
  session.expiresAt = Date.now() + adminAuth.sessionTtlMs;
  return true;
}

function sessionCookie(id) {
  const maxAge = Math.floor(adminAuth.sessionTtlMs / 1000);
  return `cleandns_session=${encodeURIComponent(id)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearSessionCookie() {
  return 'cleandns_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax';
}

function createDomainMatcher() {
  return {
    exact: new Map(),
    suffix: new Map(),
    wildcard: [],
    regex: [],
    regexSuffix: new Map(),
    count: 0,
    rewriteCount: 0,
    exceptionCount: 0,
    hostRuleCount: 0,
    add(domain, meta, mode = 'suffix', index = '') {
      if (!domain) return;
      if (mode === 'exact') {
        appendDomainRule(this.exact, domain, meta);
      } else if (mode === 'wildcard') {
        this.wildcard.push({ domain, meta });
      } else if (mode === 'regex') {
        try {
          this.regex.push({ re: new RegExp(domain, 'i'), meta });
        } catch {
          return;
        }
      } else if (mode === 'regex-suffix') {
        try {
          appendDomainRule(this.regexSuffix, index, { re: new RegExp(domain, 'i'), meta });
        } catch {
          return;
        }
      } else {
        appendDomainRule(this.suffix, domain, meta);
      }
      this.count += 1;
    },
    candidates(domain) {
      if (!domain) return null;
      const candidates = domainRuleEntries(this.exact.get(domain), true);
      let cursor = domain;
      while (cursor) {
        candidates.push(...domainRuleEntries(this.suffix.get(cursor), true));
        for (const item of domainRuleEntries(this.regexSuffix.get(cursor), true)) {
          if (item.re.test(domain)) candidates.push(item.meta);
        }
        const dot = cursor.indexOf('.');
        if (dot < 0) break;
        cursor = cursor.slice(dot + 1);
      }
      for (const item of this.wildcard) {
        if (domain === item.domain || domain.endsWith('.' + item.domain)) candidates.push(item.meta);
      }
      for (const item of this.regex) {
        if (item.re.test(domain)) candidates.push(item.meta);
      }
      return candidates;
    },
    matches(domain, context = {}) {
      const candidates = this.candidates(domain);
      return candidates ? candidates.filter((meta) => dnsRuleMatchesContext(meta, domain, context)) : [];
    },
    match(domain, context = {}) {
      const candidates = this.candidates(domain);
      return candidates ? selectDomainRule(candidates, domain, context) : null;
    }
  };
}

function appendDomainRule(map, domain, meta) {
  const existing = map.get(domain);
  if (!existing) map.set(domain, meta);
  else if (Array.isArray(existing)) existing.push(meta);
  else map.set(domain, [existing, meta]);
}

function domainRuleEntries(value, reverse = false) {
  if (!value) return [];
  if (!Array.isArray(value)) return [value];
  return reverse ? [...value].reverse() : value;
}

function selectDomainRule(entries, domain, context) {
  let regular = null;
  let important = null;
  for (const meta of entries) {
    if (!dnsRuleMatchesContext(meta, domain, context)) continue;
    if (meta.important === true) important ||= meta;
    else regular ||= meta;
  }
  return important || regular;
}

function dnsRuleMatchesContext(meta, domain, context = {}) {
  const modifiers = meta?.modifiers;
  if (!modifiers) return true;
  const qtype = Number(context.qtype || 0);
  if (modifiers.dnsTypes) {
    if (modifiers.dnsTypes.include.length) {
      if (!modifiers.dnsTypes.include.includes(qtype)) return false;
    } else if (modifiers.dnsTypes.exclude.includes(qtype)) return false;
  }
  if (modifiers.denyAllow?.some((allowed) => domain === allowed || domain.endsWith('.' + allowed))) return false;
  if (modifiers.clients && !dnsClientConditionMatches(modifiers.clients, context)) return false;
  if (modifiers.clientTags && !dnsClientTagConditionMatches(modifiers.clientTags, context)) return false;
  return true;
}

function dnsClientConditionMatches(condition, context) {
  const matches = (selector) => {
    if (selector.kind === 'ip') return matchesClientIdentifier(selector.value, context.clientIp || '');
    return String(context.clientProfile?.name || '').trim().toLowerCase() === selector.value;
  };
  if (condition.exclude.some(matches)) return false;
  return !condition.include.length || condition.include.some(matches);
}

function dnsClientTagConditionMatches(condition, context) {
  const tags = new Set((context.clientProfile?.tags || []).map((tag) => String(tag).trim().toLowerCase()));
  if (condition.exclude.some((tag) => tags.has(tag))) return false;
  return !condition.include.length || condition.include.some((tag) => tags.has(tag));
}

function addFilterDnsRewriteLine(matcher, item, kind, order) {
  if (!/(?:[$,])\s*dnsrewrite(?:=|,|$)/i.test(String(item.line || ''))) return false;
  const parsed = parseFilterDnsRewriteRule(item.line);
  if (!parsed) return false;
  const meta = {
    kind: parsed.exception ? `${kind}:dnsrewrite-exception` : `${kind}:dnsrewrite`,
    source: path.basename(item.file),
    rule: item.line,
    order,
    exception: parsed.exception,
    disableAll: parsed.disableAll,
    rewrite: parsed.rewrite,
    modifiers: parsed.modifiers,
    important: parsed.modifiers?.important === true
  };
  matcher.add(parsed.pattern.value, meta, parsed.pattern.mode, parsed.pattern.index);
  if (parsed.exception) matcher.exceptionCount += 1;
  else matcher.rewriteCount += 1;
  return true;
}

function addHostsDnsRuleLine(matcher, item, kind, order) {
  const parsed = parseHostsDnsRule(item.line);
  if (!parsed || parsed.exception) return false;
  const rrtype = parsed.family === 4 ? QTYPE.A : QTYPE.AAAA;
  const rewrite = dnsRewriteRecordValue(
    rrtype,
    parsed.ip,
    parsed.family === 4 ? ipv4ToBytes(parsed.ip) : ipv6ToBytes(parsed.ip)
  );
  for (const hostname of parsed.hostnames) {
    matcher.add(hostname, {
      kind: `${kind}:hosts`,
      source: path.basename(item.file),
      rule: item.line,
      order,
      exception: false,
      disableAll: false,
      rewrite,
      modifiers: null,
      important: false,
      hostRule: true
    }, 'exact');
    matcher.hostRuleCount += 1;
  }
  return true;
}

function parseHostsDnsRule(input) {
  let line = String(input || '').trim();
  if (!line) return null;
  const exception = line.startsWith('@@');
  if (exception) line = line.slice(2).trim();
  const inlineComment = line.search(/\s+#/);
  if (inlineComment >= 0) line = line.slice(0, inlineComment).trimEnd();
  const tokens = line.split(/\s+/);
  if (tokens.length < 2) return null;
  const family = net.isIP(tokens[0]);
  if (!family) return null;
  const hostnames = [];
  for (const token of tokens.slice(1)) {
    const hostname = normalizeHostsHostname(token);
    if (hostname && !hostnames.includes(hostname)) hostnames.push(hostname);
  }
  if (!hostnames.length) return null;
  return {
    ip: family === 6 ? tokens[0].toLowerCase() : tokens[0],
    family,
    hostnames,
    exception
  };
}

function normalizeHostsHostname(input) {
  const value = String(input || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!value || value.length > 253 || net.isIP(value) || !/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/i.test(value)) return '';
  if (value.split('.').some((label) => label.length > 63)) return '';
  return value;
}

function parseFilterDnsRewriteRule(input) {
  const parts = rawDnsRuleParts(input);
  if (!parts) return null;
  let rewriteToken = '';
  const conditionTokens = [];
  for (const token of parts.modifiers) {
    const separator = token.indexOf('=');
    const name = (separator < 0 ? token : token.slice(0, separator)).trim().toLowerCase();
    if (name === 'dnsrewrite') {
      if (rewriteToken) return null;
      rewriteToken = token;
    } else {
      conditionTokens.push(token);
    }
  }
  if (!rewriteToken) return null;

  const pattern = parseDnsRule(parts.pattern);
  if (!pattern) return null;
  const modifiers = conditionTokens.length ? parseDnsRuleModifiers(conditionTokens.join(',')) : null;
  if (conditionTokens.length && !modifiers) return null;

  const exception = isExceptionRule(parts.pattern);
  const separator = rewriteToken.indexOf('=');
  if (separator < 0) {
    return exception ? { pattern, modifiers, exception, disableAll: true, rewrite: null } : null;
  }
  const values = splitDnsModifierValues(rewriteToken.slice(separator + 1), '\0');
  if (!values || values.length !== 1) return null;
  const rewrite = parseFilterDnsRewriteValue(values[0]);
  if (!rewrite) return null;
  return { pattern, modifiers, exception, disableAll: false, rewrite };
}

function parseFilterDnsRewriteValue(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return null;
  const firstSeparator = raw.indexOf(';');
  if (firstSeparator < 0) {
    const rcode = dnsRewriteRcode(raw);
    if (rcode >= 0) return dnsRewriteRcodeValue(rcode);
    const family = net.isIP(raw);
    if (family === 4) return dnsRewriteRecordValue(QTYPE.A, raw, ipv4ToBytes(raw));
    if (family === 6) return dnsRewriteRecordValue(QTYPE.AAAA, raw.toLowerCase(), ipv6ToBytes(raw));
    const target = normalizeDnsRewriteName(raw);
    return target ? dnsRewriteCnameValue(target) : null;
  }

  const secondSeparator = raw.indexOf(';', firstSeparator + 1);
  if (secondSeparator < 0) return null;
  const rcode = dnsRewriteRcode(raw.slice(0, firstSeparator));
  if (rcode < 0) return null;
  const typeName = raw.slice(firstSeparator + 1, secondSeparator).trim().toUpperCase();
  const value = raw.slice(secondSeparator + 1).trim();
  if (rcode !== RCODE.NOERROR) return !typeName && !value ? dnsRewriteRcodeValue(rcode) : null;
  if (!typeName) return value ? null : dnsRewriteRcodeValue(RCODE.NOERROR);

  const rrtype = dnsRuleTypeCode(typeName);
  if (rrtype === QTYPE.A && net.isIP(value) === 4) return dnsRewriteRecordValue(rrtype, value, ipv4ToBytes(value));
  if (rrtype === QTYPE.AAAA && net.isIP(value) === 6) return dnsRewriteRecordValue(rrtype, value.toLowerCase(), ipv6ToBytes(value));
  if (rrtype === QTYPE.CNAME) {
    const target = normalizeDnsRewriteName(value);
    return target ? dnsRewriteCnameValue(target) : null;
  }
  if (rrtype === QTYPE.NS || rrtype === QTYPE.PTR) {
    const target = normalizeDnsRewriteName(value, true);
    return target ? dnsRewriteRecordValue(rrtype, target, encodeDnsRewriteName(target)) : null;
  }
  if (rrtype === QTYPE.TXT) {
    const rdata = encodeDnsRewriteTxt(value);
    return rdata ? dnsRewriteRecordValue(rrtype, value, rdata) : null;
  }
  if (rrtype === QTYPE.MX) return parseDnsRewriteMxValue(value);
  if (rrtype === QTYPE.SRV) return parseDnsRewriteSrvValue(value);
  if (rrtype === QTYPE.CAA) return parseDnsRewriteCaaValue(value);
  return null;
}

function dnsRewriteRcode(value) {
  const name = String(value || '').trim().toUpperCase();
  return Object.prototype.hasOwnProperty.call(RCODE, name) ? RCODE[name] : -1;
}

function dnsRewriteRcodeValue(rcode) {
  return {
    kind: rcode === RCODE.NOERROR ? 'nodata' : 'rcode',
    rcode,
    rrtype: 0,
    value: '',
    identity: `rcode:${rcode}`
  };
}

function dnsRewriteCnameValue(target) {
  return {
    kind: 'cname',
    rcode: RCODE.NOERROR,
    rrtype: QTYPE.CNAME,
    value: target,
    identity: `record:${QTYPE.CNAME}:${target}`
  };
}

function dnsRewriteRecordValue(rrtype, value, rdata) {
  const encoded = Buffer.from(rdata || []);
  return {
    kind: 'record',
    rcode: RCODE.NOERROR,
    rrtype,
    value,
    rdata: encoded,
    identity: `record:${rrtype}:${encoded.toString('hex')}`
  };
}

function parseDnsRewriteMxValue(value) {
  const match = String(value || '').match(/^(\d{1,5})\s+(.+)$/);
  if (!match) return null;
  const preference = Number(match[1]);
  const exchange = normalizeDnsRewriteName(match[2], true);
  if (preference > 65535 || !exchange) return null;
  const normalized = `${preference} ${exchange}`;
  return dnsRewriteRecordValue(QTYPE.MX, normalized, Buffer.concat([u16(preference), encodeDnsRewriteName(exchange)]));
}

function parseDnsRewriteSrvValue(value) {
  const match = String(value || '').match(/^(\d{1,5})\s+(\d{1,5})\s+(\d{1,5})\s+(.+)$/);
  if (!match) return null;
  const priority = Number(match[1]);
  const weight = Number(match[2]);
  const port = Number(match[3]);
  const target = normalizeDnsRewriteName(match[4], true);
  if ([priority, weight, port].some((number) => number > 65535) || !target) return null;
  const normalized = `${priority} ${weight} ${port} ${target}`;
  return dnsRewriteRecordValue(QTYPE.SRV, normalized, Buffer.concat([
    u16(priority),
    u16(weight),
    u16(port),
    encodeDnsRewriteName(target)
  ]));
}

function parseDnsRewriteCaaValue(value) {
  const match = String(value || '').match(/^(\d{1,3})\s+([A-Za-z0-9-]{1,15})\s+(.+)$/);
  if (!match) return null;
  const flags = Number(match[1]);
  const tag = Buffer.from(match[2].toLowerCase(), 'ascii');
  const answer = Buffer.from(match[3], 'utf8');
  if (flags > 255 || answer.length > 4096) return null;
  const normalized = `${flags} ${tag.toString('ascii')} ${match[3]}`;
  return dnsRewriteRecordValue(QTYPE.CAA, normalized, Buffer.concat([Buffer.from([flags, tag.length]), tag, answer]));
}

function normalizeDnsRewriteName(value, allowRoot = false) {
  const raw = String(value || '').trim();
  if (raw === '.') return allowRoot ? '.' : '';
  const name = raw.toLowerCase().replace(/\.+$/, '');
  if (!name || Buffer.byteLength(name, 'ascii') > 253) return '';
  const labels = name.split('.');
  if (labels.some((label) => !label || Buffer.byteLength(label, 'ascii') > 63 || !/^[a-z0-9_-]+$/i.test(label))) return '';
  return name;
}

function encodeDnsRewriteName(value) {
  if (value === '.') return Buffer.from([0]);
  return Buffer.concat([
    ...value.split('.').map((label) => {
      const bytes = Buffer.from(label, 'ascii');
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    }),
    Buffer.from([0])
  ]);
}

function encodeDnsRewriteTxt(value) {
  const input = Buffer.from(String(value ?? ''), 'utf8');
  if (input.length > 4096) return null;
  if (!input.length) return Buffer.from([0]);
  const chunks = [];
  for (let offset = 0; offset < input.length; offset += 255) {
    const chunk = input.subarray(offset, offset + 255);
    chunks.push(Buffer.from([chunk.length]), chunk);
  }
  return Buffer.concat(chunks);
}

function resolveFilterDnsRewrite(matcher, domain, qtype, context, allow = null) {
  if (!matcher) return { matched: false };
  const entries = matcher.matches(domain, context).filter((entry) => (
    entry.hostRule === true || entry.disableAll || dnsRewriteAppliesToQuery(entry.rewrite, qtype)
  ));
  if (!entries.length) return { matched: false };

  const exceptions = entries.filter((entry) => entry.exception);
  let positive = entries.filter((entry) => !entry.exception && entry.rewrite);
  positive = positive.filter((entry) => entry.hostRule === true || !exceptions.some((exception) => (
    dnsRewriteExceptionDisables(exception, entry)
  )));
  if (allow) {
    positive = positive.filter((entry) => entry.important === true && allow.important !== true);
  }
  if (!positive.length) return { matched: false };

  const important = positive.filter((entry) => entry.important === true);
  const selected = (important.length ? important : positive).sort((left, right) => left.order - right.order);
  const explicitRewrites = selected.filter((entry) => entry.hostRule !== true);
  const effective = explicitRewrites.length ? explicitRewrites : selected;
  const hostRule = !explicitRewrites.length && effective.some((entry) => entry.hostRule === true);
  const cnames = effective.filter((entry) => entry.rewrite.kind === 'cname');
  if (cnames.length) {
    const entry = cnames[cnames.length - 1];
    if (entry.rewrite.value === domain) return { matched: false };
    return {
      matched: true,
      kind: 'cname',
      value: entry.rewrite.value,
      entries: [entry]
    };
  }

  const errors = effective.filter((entry) => entry.rewrite.kind === 'rcode');
  if (errors.length) {
    const entry = errors[errors.length - 1];
    return {
      matched: true,
      kind: 'rcode',
      rcode: entry.rewrite.rcode,
      entries: [entry]
    };
  }

  const records = effective.filter((entry) => entry.rewrite.kind === 'record' && entry.rewrite.rrtype === qtype);
  if (records.length) {
    const responseRecords = hostRule
      ? records.filter((entry, index, all) => all.findIndex((item) => item.rewrite.identity === entry.rewrite.identity) === index)
      : records;
    return {
      matched: true,
      kind: 'record',
      rrtype: qtype,
      values: responseRecords.map((entry) => entry.rewrite.value),
      records: responseRecords.map((entry) => entry.rewrite.rdata),
      entries: records,
      hostRule
    };
  }

  const nodata = effective.filter((entry) => entry.rewrite.kind === 'nodata');
  if (nodata.length) return { matched: true, kind: 'nodata', entries: [nodata[nodata.length - 1]] };
  if (hostRule) return { matched: true, kind: 'nodata', entries: effective, hostRule: true };
  return { matched: false };
}

function dnsRewriteAppliesToQuery(rewrite, qtype) {
  if (!rewrite) return false;
  if (rewrite.kind === 'record') return rewrite.rrtype === qtype;
  return true;
}

function dnsRewriteExceptionDisables(exception, entry) {
  if (!exception || !entry || (entry.important === true && exception.important !== true)) return false;
  return exception.disableAll === true || exception.rewrite?.identity === entry.rewrite?.identity;
}

function filterDnsRewriteRuleLabel(rewrite) {
  return rewrite.entries?.[0]?.rule || 'dnsrewrite';
}

function filterDnsRewriteRules(rewrite) {
  return (rewrite.entries || []).map((entry) => entry.rule).filter(Boolean);
}

function addRuleLine(matcher, item, kind) {
  const raw = item.line;
  const hosts = parseHostsDnsRule(raw);
  if (hosts) {
    const meta = { kind, source: path.basename(item.file), rule: raw };
    for (const hostname of hosts.hostnames) matcher.add(hostname, meta, 'exact');
    return true;
  }
  const parsed = parseDnsRule(raw);
  if (!parsed) return false;
  const meta = { kind, source: path.basename(item.file), rule: raw };
  if (parsed.modifiers) {
    meta.modifiers = parsed.modifiers;
    meta.important = parsed.modifiers.important === true;
  }
  matcher.add(parsed.value, meta, parsed.mode, parsed.index);
  return true;
}

function addBlockRuleLine(blockMatcher, allowMatcher, item, kind) {
  const target = isExceptionRule(item.line) ? allowMatcher : blockMatcher;
  const targetKind = target === allowMatcher ? `${kind}:exception` : kind;
  return addRuleLine(target, item, targetKind);
}

function isExceptionRule(line) {
  return String(line || '').trim().startsWith('@@');
}

function collectBadfilterRuleKeys(items) {
  const disabled = new Set();
  for (const item of items) {
    const target = badfilterTargetIdentity(item.line);
    if (target) disabled.add(target);
  }
  return disabled;
}

function badfilterTargetIdentity(input) {
  const parts = rawDnsRuleParts(input);
  if (!parts) return '';
  const remaining = [];
  let badfilter = false;
  for (const token of parts.modifiers) {
    const name = token.split('=', 1)[0].trim().toLowerCase();
    if (name === 'badfilter') badfilter = true;
    else remaining.push(token);
  }
  return badfilter ? dnsRuleIdentityFromParts(parts.pattern, remaining) : '';
}

function dnsRuleIdentity(input) {
  const parts = rawDnsRuleParts(input);
  return parts ? dnsRuleIdentityFromParts(parts.pattern, parts.modifiers) : '';
}

function rawDnsRuleParts(input) {
  const line = String(input || '').trim();
  if (!line) return null;
  let splitAt = -1;
  if (line.startsWith('/') || line.startsWith('@@/')) {
    const closingSlash = line.lastIndexOf('/');
    if (closingSlash > 0 && line[closingSlash + 1] === '$') splitAt = closingSlash + 1;
  } else {
    splitAt = line.indexOf('$');
  }
  if (splitAt < 0) return { pattern: line, modifiers: [] };
  const pattern = line.slice(0, splitAt).trim();
  const modifiers = splitDnsModifierTokens(line.slice(splitAt + 1));
  if (!modifiers?.length) return null;
  return pattern ? { pattern, modifiers } : null;
}

function dnsRuleIdentityFromParts(pattern, modifiers) {
  const normalizedModifiers = modifiers.map((token) => token.toLowerCase()).sort();
  return pattern.toLowerCase() + (normalizedModifiers.length ? '$' + normalizedModifiers.join(',') : '');
}

function parseDnsRule(input) {
  let line = String(input || '').trim();
  if (!line) return null;
  if (line.startsWith('@@')) line = line.slice(2).trim();
  if (!line || isCosmeticRule(line)) return null;

  const split = splitDnsRuleModifiers(line);
  if (!split) return null;
  line = split.pattern;

  const hosts = parseHostsDnsRule(line);
  if (hosts) {
    const parsed = { value: hosts.hostnames[0], mode: 'exact' };
    return split.modifiers ? { ...parsed, modifiers: split.modifiers } : parsed;
  }

  let parsed;
  const address = parseDnsRuleAddress(line);
  if (address) parsed = { value: address, mode: 'exact' };
  else if (line.startsWith('||') && /^\|\|[A-Za-z0-9._-]+\^?$/.test(line)) parsed = parseAdblockDomainRule(line.slice(2), 'suffix');
  else if (line.startsWith('/') && line.lastIndexOf('/') > 0) parsed = parseRegexDnsRule(line);
  else if (line.includes('*') || line.includes('^') || line.startsWith('|') || line.endsWith('|')) parsed = parseAdblockDnsMask(line);
  else if (/^https?:\/\//i.test(line)) parsed = parseUrlDnsRule(line);
  else parsed = parsePlainDnsRule(line);
  return parsed && split.modifiers ? { ...parsed, modifiers: split.modifiers } : parsed;
}

function parseDnsRuleAddress(input) {
  let candidate = String(input || '').trim();
  if (candidate.startsWith('||')) {
    candidate = candidate.slice(2);
    if (candidate.endsWith('^')) candidate = candidate.slice(0, -1);
  } else if (candidate.startsWith('|') && candidate.endsWith('|') && candidate.length > 2) {
    candidate = candidate.slice(1, -1);
  } else if (candidate.includes('|') || candidate.includes('^') || candidate.includes('*')) {
    return '';
  }
  const ip = normalizeIpLiteral(candidate);
  const family = net.isIP(ip);
  if (family === 4) return bytesToIpv4(ipv4ToBytes(ip));
  if (family === 6) return bytesToIpv6(ipv6ToBytes(ip));
  return '';
}

function isCosmeticRule(line) {
  return /##|#@#|#\?#|#\$#|%#/.test(line);
}

function parseAdblockDomainRule(body, defaultMode) {
  const match = String(body || '').trim().match(/^([A-Za-z0-9._-]+)\^?$/);
  if (!match) return null;
  return parsedDomain(match[1], defaultMode);
}

function splitDnsRuleModifiers(line) {
  let splitAt = -1;
  if (line.startsWith('/')) {
    const closingSlash = line.lastIndexOf('/');
    if (closingSlash > 0 && line[closingSlash + 1] === '$') splitAt = closingSlash + 1;
  } else {
    splitAt = line.indexOf('$');
  }
  if (splitAt < 0) return { pattern: line, modifiers: null };
  const pattern = line.slice(0, splitAt).trim();
  const modifiers = parseDnsRuleModifiers(line.slice(splitAt + 1));
  return pattern && modifiers ? { pattern, modifiers } : null;
}

function parseDnsRuleModifiers(value) {
  const result = { important: false, dnsTypes: null, denyAllow: [], clients: null, clientTags: null };
  const tokens = splitDnsModifierTokens(value);
  if (!tokens?.length) return null;
  for (const token of tokens) {
    const separator = token.indexOf('=');
    const name = (separator < 0 ? token : token.slice(0, separator)).toLowerCase();
    const modifierValue = separator < 0 ? '' : token.slice(separator + 1).trim();
    if (name === 'important' && !modifierValue) {
      result.important = true;
      continue;
    }
    if (name === 'dnstype' && modifierValue) {
      result.dnsTypes = parseDnsTypeModifier(modifierValue);
      if (!result.dnsTypes) return null;
      continue;
    }
    if (name === 'denyallow' && modifierValue) {
      result.denyAllow = parseDenyAllowModifier(modifierValue);
      if (!result.denyAllow.length) return null;
      continue;
    }
    if (name === 'client' && modifierValue) {
      result.clients = parseDnsClientModifier(modifierValue);
      if (!result.clients) return null;
      continue;
    }
    if (name === 'ctag' && modifierValue) {
      result.clientTags = parseDnsClientTagModifier(modifierValue);
      if (!result.clientTags) return null;
      continue;
    }
    // Unsupported request-specific and rewrite modifiers must not become broad blocks.
    return null;
  }
  return result;
}

function parseDnsTypeModifier(value) {
  const include = [];
  const exclude = [];
  const values = splitDnsModifierValues(value, '|');
  if (!values?.length) return null;
  for (const raw of values) {
    const token = raw.trim().toUpperCase();
    if (!token) return null;
    const negated = token.startsWith('~');
    const code = dnsRuleTypeCode(negated ? token.slice(1) : token);
    if (!code) return null;
    const target = negated ? exclude : include;
    if (!target.includes(code)) target.push(code);
  }
  return { include, exclude };
}

function dnsRuleTypeCode(value) {
  if (/^TYPE\d{1,5}$/.test(value)) {
    const code = Number(value.slice(4));
    return code >= 1 && code <= 65535 ? code : 0;
  }
  return DNS_RULE_QTYPE[value] || 0;
}

function parseDenyAllowModifier(value) {
  const domains = [];
  const values = splitDnsModifierValues(value, '|');
  if (!values?.length) return [];
  for (const raw of values) {
    const domain = normalizeDomain(raw);
    if (!domain || !domain.includes('.') || net.isIP(domain)) return [];
    if (!domains.includes(domain)) domains.push(domain);
  }
  return domains;
}

function parseDnsClientModifier(value) {
  const values = splitDnsModifierValues(value, '|');
  if (!values?.length) return null;
  const condition = { include: [], exclude: [] };
  for (const raw of values) {
    const excluded = raw.startsWith('~');
    const candidate = (excluded ? raw.slice(1) : raw).trim();
    if (!candidate) return null;
    const identifier = normalizeClientIdentifier(candidate);
    const selector = identifier
      ? { kind: 'ip', value: identifier }
      : { kind: 'name', value: candidate.toLowerCase() };
    const target = excluded ? condition.exclude : condition.include;
    if (!target.some((item) => item.kind === selector.kind && item.value === selector.value)) target.push(selector);
  }
  return condition;
}

function parseDnsClientTagModifier(value) {
  const values = splitDnsModifierValues(value, '|');
  if (!values?.length) return null;
  const condition = { include: [], exclude: [] };
  for (const raw of values) {
    const excluded = raw.startsWith('~');
    const tag = (excluded ? raw.slice(1) : raw).trim().toLowerCase();
    if (!tag || tag.length > 80 || !/^[a-z0-9_-]+$/.test(tag)) return null;
    const target = excluded ? condition.exclude : condition.include;
    if (!target.includes(tag)) target.push(tag);
  }
  return condition;
}

function splitDnsModifierTokens(value) {
  const tokens = [];
  let current = '';
  let quote = '';
  let escaped = false;
  for (const character of String(value || '')) {
    if (escaped) {
      current += '\\' + character;
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      current += character;
      if (character === quote) quote = '';
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      current += character;
      continue;
    }
    if (character === ',') {
      if (!current.trim()) return null;
      tokens.push(current.trim());
      current = '';
      continue;
    }
    current += character;
  }
  if (escaped || quote || !current.trim()) return null;
  tokens.push(current.trim());
  return tokens;
}

function splitDnsModifierValues(value, delimiter) {
  const values = [];
  let current = '';
  let quote = '';
  let escaped = false;
  for (const character of String(value || '')) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = '';
      else current += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === delimiter) {
      if (!current.trim()) return null;
      values.push(current.trim());
      current = '';
      continue;
    }
    current += character;
  }
  if (escaped || quote || !current.trim()) return null;
  values.push(current.trim());
  return values;
}

function parseRegexDnsRule(line) {
  const last = line.lastIndexOf('/');
  if (last <= 0 || last !== line.length - 1) return null;
  const pattern = line.slice(1, last);
  if (!isSafeDnsRegexPattern(pattern)) return null;
  try {
    new RegExp(pattern, 'i');
  } catch {
    return null;
  }
  return { value: pattern, mode: 'regex' };
}

function isSafeDnsRegexPattern(pattern) {
  if (!pattern || pattern.length > 512 || /[\u0000-\u001f\u007f]/.test(pattern)) return false;
  if (/\\(?:[1-9]|k<)/.test(pattern) || /\(\?(?!:)/.test(pattern)) return false;
  const groups = [];
  let lastToken = 'start';
  let closedGroup = null;
  let inClass = false;
  let escaped = false;
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (escaped) {
      escaped = false;
      lastToken = 'atom';
      closedGroup = null;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (inClass) {
      if (character === ']') inClass = false;
      continue;
    }
    if (character === '[') {
      inClass = true;
      lastToken = 'atom';
      closedGroup = null;
      continue;
    }
    if (character === '(') {
      if (pattern[index + 1] === '?' && pattern[index + 2] === ':') index += 2;
      groups.push({ quantified: false, alternation: false });
      lastToken = 'open';
      closedGroup = null;
      continue;
    }
    if (character === ')') {
      if (!groups.length) return false;
      closedGroup = groups.pop();
      lastToken = 'group';
      continue;
    }
    if (character === '|') {
      if (groups.length) groups[groups.length - 1].alternation = true;
      lastToken = 'alternation';
      closedGroup = null;
      continue;
    }
    const bounded = character === '{' ? pattern.slice(index).match(/^\{\d+(?:,\d*)?\}/) : null;
    const quantifier = character === '*' || character === '+' || character === '?' || Boolean(bounded);
    if (quantifier) {
      if (lastToken === 'start' || lastToken === 'open' || lastToken === 'alternation' || lastToken === 'quantifier') return false;
      if (lastToken === 'group' && closedGroup && (closedGroup.quantified || closedGroup.alternation)) return false;
      if (groups.length) groups[groups.length - 1].quantified = true;
      if (bounded) index += bounded[0].length - 1;
      lastToken = 'quantifier';
      closedGroup = null;
      continue;
    }
    lastToken = 'atom';
    closedGroup = null;
  }
  return !escaped && !inClass && groups.length === 0;
}

function parseAdblockDnsMask(line) {
  let pattern = String(line || '').trim();
  if (!pattern || pattern.length > 1024 || /[/$?#=&]/.test(pattern)) return null;
  const domainAnchor = pattern.startsWith('||');
  const startAnchor = !domainAnchor && pattern.startsWith('|');
  if (domainAnchor) pattern = pattern.slice(2);
  else if (startAnchor) pattern = pattern.slice(1);
  const endAnchor = pattern.endsWith('|');
  if (endAnchor) pattern = pattern.slice(0, -1);
  const domainEnd = pattern.endsWith('^');
  if (domainEnd) pattern = pattern.slice(0, -1);
  if (!pattern || pattern.includes('^') || pattern.includes('|') || !/[a-z0-9_]/i.test(pattern)) return null;

  if (domainAnchor && !pattern.includes('*') && /^[A-Za-z0-9._-]+$/.test(pattern)) {
    return parsedDomain(pattern, 'suffix');
  }
  if (startAnchor && (endAnchor || domainEnd) && !pattern.includes('*') && /^[A-Za-z0-9._-]+$/.test(pattern)) {
    return parsedDomain(pattern, 'exact');
  }

  let expression = domainAnchor ? '(?:^|\\.)' : startAnchor ? '^' : '';
  for (const character of pattern) {
    if (character === '*') expression += '.*';
    else if (/[A-Za-z0-9_-]/.test(character)) expression += character;
    else if (character === '.') expression += '\\.';
    else return null;
  }
  if (endAnchor || domainEnd) expression += '$';
  const lastStar = pattern.lastIndexOf('*');
  const suffix = (endAnchor || domainEnd) && pattern[lastStar + 1] === '.'
    ? normalizeDomain(pattern.slice(lastStar + 2).replace(/\^.*$/, ''))
    : '';
  return { value: expression, mode: suffix ? 'regex-suffix' : 'regex', index: suffix };
}

function parseUrlDnsRule(line) {
  try {
    const parsed = new URL(line);
    const hasPath = parsed.pathname && parsed.pathname !== '/';
    if (hasPath || parsed.search || parsed.hash) return null;
    return parsedDomain(parsed.hostname, 'suffix');
  } catch {
    return null;
  }
}

function parsePlainDnsRule(line) {
  if (/[/$?#=&|^]/.test(line)) return null;
  return parsedDomain(line, 'exact');
}

function parsedDomain(value, mode) {
  const candidate = String(value || '').trim().toLowerCase().replace(/\.+$/, '').replace(/^\.+/, '');
  if (
    !candidate ||
    candidate.length > 253 ||
    net.isIP(candidate) ||
    !/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/i.test(candidate) ||
    candidate.split('.').some((label) => label.length > 63)
  ) return null;
  const domain = normalizeDomain(candidate);
  return { value: domain, mode };
}

function startHttpServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
      if (url.pathname === '/healthz') return json(res, 200, { ok: true, uptime: Math.floor((Date.now() - startedAt) / 1000) });
      if (url.pathname === '/favicon.ico') return serveFavicon(res);
      if (url.pathname === config.service.dohPath) return handleDoh(req, res, url);
      if (url.pathname === '/' || url.pathname === '/clean-dns' || url.pathname === '/admin/') return servePanel(res);
      if (url.pathname.startsWith('/api/')) return handleApi(req, res, url);
      notFound(res);
    } catch (err) {
      console.error(err);
      json(res, 500, { error: 'internal_error' });
    }
  });
  server.listen(config.http.port, config.http.host, () => {
    console.log(`cleandns http listening on ${config.http.host}:${config.http.port}`);
  });
}

function startUdpServer() {
  const udp = dgram.createSocket('udp4');
  udp.on('message', async (message, rinfo) => {
    const proxy = parseProxyV2(message);
    const packet = proxy ? message.subarray(proxy.offset) : message;
    const clientIp = proxy?.srcIp || rinfo.address;
    try {
      const response = await resolveDns(packet, clientIp, proxy?.protocol || 'udp');
      udp.send(response, rinfo.port, rinfo.address);
    } catch (err) {
      const failed = buildErrorResponse(packet, RCODE.SERVFAIL);
      udp.send(failed, rinfo.port, rinfo.address);
    }
  });
  udp.bind(config.udp.port, config.udp.host, () => {
    console.log(`cleandns udp listening on ${config.udp.host}:${config.udp.port}`);
  });
}

async function applyDhcpRuntime() {
  if (!DHCP_RUNTIME_SUPPORTED || config.dhcp?.enabled !== true) {
    dhcpRuntimeStatus = await dhcpRuntime.sync({ enabled: false });
    return dhcpRuntimeStatus;
  }
  const interfaces = collectDhcpInterfaces(dhcpNetworkInterfaces());
  const validation = validateDhcpConfig(config.dhcp, interfaces);
  if (!validation.valid) {
    throw new Error(validation.errors[0]?.code || 'dhcp_config_invalid');
  }
  const serverAddress = dhcpInterfaceIpv4ForConfig(config.dhcp, validation.selectedInterface);
  if (!serverAddress?.address) throw new Error('interface_subnet_mismatch');
  const bindAddress = dhcpRuntimeBindAddress(serverAddress.address);
  dhcpRuntimeStatus = await dhcpRuntime.sync({
    enabled: true,
    config: config.dhcp,
    bindAddress,
    serverIp: serverAddress.address,
    port: DHCP_RUNTIME_PORT
  });
  return dhcpRuntimeStatus;
}

function dhcpRuntimeBindAddress(serverAddress) {
  const testAddress = process.env.NODE_ENV === 'test' ? String(process.env.CLEANDNS_DHCP_TEST_BIND_ADDRESS || '').trim() : '';
  return net.isIP(testAddress) === 4 ? testAddress : serverAddress;
}

async function applyPlainDnsRuntime() {
  await stopPlainDnsRuntime();
  const enabled = config.service?.plainDnsEnabled === true;
  const host = config.service?.plainDnsHost || '0.0.0.0';
  const port = config.service?.plainDnsPort || 53;
  plainDnsRuntime = { enabled, udp: false, tcp: false, host, port, error: '' };
  if (!enabled) return plainDnsRuntime;

  try {
    plainDnsUdpServer = await startPlainDnsUdp(host, port);
    plainDnsRuntime.udp = true;
    plainDnsTcpServer = await startPlainDnsTcp(host, port);
    plainDnsRuntime.tcp = true;
    console.log(`cleandns plain dns listening on ${host}:${port} udp/tcp`);
    return plainDnsRuntime;
  } catch (err) {
    await stopPlainDnsRuntime();
    plainDnsRuntime = {
      enabled,
      udp: false,
      tcp: false,
      host,
      port,
      error: err.message || 'plain_dns_start_failed'
    };
    throw err;
  }
}

function stopPlainDnsRuntime() {
  return Promise.all([closeUdpServer(plainDnsUdpServer), closeTcpServer(plainDnsTcpServer)]).then(() => {
    plainDnsUdpServer = null;
    plainDnsTcpServer = null;
    plainDnsRuntime = {
      enabled: false,
      udp: false,
      tcp: false,
      host: config.service?.plainDnsHost || '',
      port: config.service?.plainDnsPort || 0,
      error: ''
    };
  });
}

function closeUdpServer(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    try {
      server.close(() => resolve());
    } catch {
      resolve();
    }
  });
}

function closeTcpServer(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    server.close(() => resolve());
  });
}

function startPlainDnsUdp(host, port) {
  return new Promise((resolve, reject) => {
    const family = net.isIP(host) === 6 ? 'udp6' : 'udp4';
    const udp = dgram.createSocket(family);
    let settled = false;
    udp.on('message', async (message, rinfo) => {
      const clientIp = normalizeRemoteIp(rinfo.address);
      try {
        const response = await resolveDns(message, clientIp, 'dns-udp');
        udp.send(response, rinfo.port, rinfo.address);
      } catch {
        const failed = buildErrorResponse(message, RCODE.SERVFAIL);
        udp.send(failed, rinfo.port, rinfo.address);
      }
    });
    udp.once('error', (err) => {
      if (!settled) {
        settled = true;
        reject(new Error(`plain_dns_udp_${err.code || 'error'}`));
      } else {
        plainDnsRuntime.error = `plain_dns_udp_${err.code || 'error'}`;
      }
    });
    udp.bind(port, host, () => {
      settled = true;
      resolve(udp);
    });
  });
}

function startPlainDnsTcp(host, port) {
  return new Promise((resolve, reject) => {
    const tcp = net.createServer((socket) => handlePlainDnsTcpSocket(socket));
    let settled = false;
    tcp.once('error', (err) => {
      if (!settled) {
        settled = true;
        reject(new Error(`plain_dns_tcp_${err.code || 'error'}`));
      } else {
        plainDnsRuntime.error = `plain_dns_tcp_${err.code || 'error'}`;
      }
    });
    tcp.listen(port, host, () => {
      settled = true;
      resolve(tcp);
    });
  });
}

function handlePlainDnsTcpSocket(socket) {
  let buffer = Buffer.alloc(0);
  const clientIp = normalizeRemoteIp(socket.remoteAddress || '');
  socket.on('error', () => {});
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > 65537) {
      socket.destroy();
      return;
    }
    while (buffer.length >= 2) {
      const size = buffer.readUInt16BE(0);
      if (buffer.length < size + 2) break;
      const packet = buffer.subarray(2, size + 2);
      buffer = buffer.subarray(size + 2);
      resolveDns(packet, clientIp, 'dns-tcp').then((response) => {
        const prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(response.length, 0);
        socket.write(Buffer.concat([prefix, response]));
      }).catch(() => {
        const failed = buildErrorResponse(packet, RCODE.SERVFAIL);
        const prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(failed.length, 0);
        socket.write(Buffer.concat([prefix, failed]));
      });
    }
  });
}

function normalizeRemoteIp(value) {
  return String(value || '').replace(/^::ffff:/, '') || '0.0.0.0';
}

async function handleDoh(req, res, url) {
  if (config.service?.dohEnabled === false) return notFound(res);
  if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res);
  let packet;
  if (req.method === 'GET') {
    const dns = url.searchParams.get('dns');
    if (!dns) return json(res, 400, { error: 'missing_dns_query' });
    packet = Buffer.from(dns.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } else {
    const contentType = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (contentType && contentType !== 'application/dns-message') return json(res, 415, { error: 'unsupported_content_type' });
    packet = await readBody(req, 65535);
  }
  const clientIp = getClientIp(req);
  const response = await resolveDns(packet, clientIp, 'doh');
  res.writeHead(200, {
    'content-type': 'application/dns-message',
    'cache-control': 'no-store',
    'content-length': response.length
  });
  res.end(response);
}

function getClientIp(req) {
  if (config.admin.trustProxy) {
    const cf = firstHeaderIp(req.headers['cf-connecting-ip']);
    if (cf) return cf;
    const xff = firstHeaderIp(req.headers['x-forwarded-for']);
    if (xff) return xff;
    const real = firstHeaderIp(req.headers['x-real-ip']);
    if (real) return real;
  }
  const remote = req.socket.remoteAddress || '';
  return remote.startsWith('::ffff:') ? remote.slice(7) : remote;
}

function firstHeaderIp(value) {
  if (!value) return '';
  const ip = String(value).split(',')[0].trim();
  return net.isIP(ip) ? ip : '';
}

async function resolveDns(packet, clientIp, protocol) {
  const queryStarted = Date.now();
  const elapsedMs = () => Date.now() - queryStarted;
  const parsed = parseQuestion(packet);
  if (!parsed) return buildErrorResponse(packet, RCODE.FORMERR);

  const qtypeName = QTYPE_NAME[parsed.qtype] || String(parsed.qtype);
  const clientProfile = findClientProfile(clientIp);
  const usesGlobalSettings = clientProfile?.useGlobalSettings !== false;
  const clientFilteringEnabled = usesGlobalSettings || clientProfile?.filteringEnabled !== false;
  const filteringActive = isFilteringActive() && clientFilteringEnabled;
  const safeSearchSettings = usesGlobalSettings ? config.filter.safeSearch : clientProfile.safeSearch;
  const safeBrowsingEnabled = usesGlobalSettings
    ? config.filter.safeBrowsing.enabled === true
    : clientProfile?.safeBrowsingEnabled === true;
  const parentalEnabled = usesGlobalSettings
    ? config.filter.parental.enabled === true
    : clientProfile?.parentalEnabled === true;
  const statsIgnored = isStatisticsIgnored(parsed.qname) || clientProfile?.ignoreStatistics === true;
  const stat = (key, value = 1) => {
    if (!statsIgnored) recordStat(key, value);
  };
  const statMap = (mapName, key, value = 1) => {
    if (!statsIgnored) recordStatMap(mapName, key, value);
  };
  stat('total');
  statMap('byType', qtypeName);

  const incomingEcs = extractEcs(packet);
  const ecs = clientProfile?.disableEcs === true
    ? { key: 'client-disabled', family: 0, sourcePrefix: 0, scopePrefix: 0, address: Buffer.alloc(0) }
    : makeEcs(clientIp, incomingEcs);
  const finish = (response, item, originalResponse = null) => {
    const duration = elapsedMs();
    stat('processingCount');
    stat('processingTimeMs', duration);
    recordDashboardRankings(parsed.qname, item.action, clientIp, clientProfile, statsIgnored);
    recordResolvedQuery({
      qname: parsed.qname,
      qtype: qtypeName,
      clientIp,
      protocol,
      cached: false,
      ecs: ecs.key,
      elapsedMs: duration,
      ...item
    }, response, originalResponse);
    return response;
  };
  const access = checkAccess(clientIp, parsed.qname);
  if (!access.allowed) {
    stat('blocked');
    statMap('byRule', access.rule);
    return finish(buildErrorResponse(packet, RCODE.REFUSED), { action: 'refused', rule: access.rule, source: 'access' });
  }

  const rateLimit = checkDnsRateLimit(clientIp);
  if (!rateLimit.allowed) {
    const rule = `dns:rate-limit:${rateLimit.key}`;
    stat('errors');
    statMap('byRule', rule);
    return finish(buildErrorResponse(packet, RCODE.REFUSED), { action: 'rate-limit', rule, source: 'dns-settings' });
  }

  if (config.dns.disableIpv6 === true && parsed.qtype === QTYPE.AAAA) {
    const rule = 'dns:disable-ipv6';
    stat('blocked');
    statMap('byRule', rule);
    return finish(buildNoDataResponse(packet, parsed), { action: 'block-ipv6', rule, source: 'dns-settings' });
  }

  if (config.dns.refuseAny !== false && parsed.qtype === QTYPE.ANY) {
    const rule = 'dns:refuse-any';
    stat('blocked');
    statMap('byRule', rule);
    return finish(buildErrorResponse(packet, RCODE.REFUSED), { action: 'refused', rule, source: 'dns-settings' });
  }

  const policy = policyHash(clientProfile);
  const dnssecProfile = dnssecCacheProfile(packet, config.dns.dnssecEnabled === true);
  const cacheKey = `${parsed.qname}|${parsed.qtype}|${ecs.key}|${policy}|${dnssecProfile}`;

  const rewrite = config.filter.rewritesEnabled !== false
    ? resolveDnsRewrite(rules.rewrites, parsed.qname, parsed.qtype)
    : { matched: false };
  if (rewrite.matched && rewrite.kind !== 'passthrough') {
    stat('rewritten');
    return finish(buildRewriteResponse(packet, parsed, rewrite), {
      action: 'rewrite',
      rule: dnsRewriteRuleLabel(rewrite),
      source: 'rewrite'
    });
  }

  const filterMatchContext = { qtype: parsed.qtype, clientIp, clientProfile };
  const allow = filteringActive ? rules.allow.match(parsed.qname, filterMatchContext) : null;
  const filterRewrite = resolveFilterDnsRewrite(rules.filterRewrites, parsed.qname, parsed.qtype, filterMatchContext, allow);
  if (filterRewrite.matched && (filterRewrite.hostRule !== true || filteringActive)) {
    const rule = filterDnsRewriteRuleLabel(filterRewrite);
    if (filterRewrite.hostRule === true) {
      stat('blocked');
      stat('blockedFiltering');
    } else {
      stat('rewritten');
    }
    statMap('byRule', rule);
    return finish(filterRewrite.hostRule === true
      ? buildHostsRuleResponse(packet, parsed, filterRewrite)
      : buildFilterDnsRewriteResponse(packet, parsed, filterRewrite), {
      action: filterRewrite.hostRule === true ? 'block' : 'rewrite',
      rule,
      matchedRules: filterDnsRewriteRules(filterRewrite),
      source: filterRewrite.hostRule === true ? 'filter-hosts' : 'filter-rewrite'
    });
  }
  const blocked = filteringActive ? rules.block.match(parsed.qname, filterMatchContext) : null;
  if (blocked?.important === true && allow?.important !== true) {
    stat('blocked');
    stat('blockedFiltering');
    statMap('byRule', blocked.rule);
    return finish(buildBlockedResponse(packet, parsed), { action: 'block', rule: blocked.rule, source: 'filter' });
  }
  const serviceBlocked = filteringActive && !allow ? matchBlockedService(parsed.qname, clientProfile) : null;
  if (serviceBlocked) {
    stat('blocked');
    stat('blockedFiltering');
    statMap('byRule', serviceBlocked.rule);
    return finish(buildBlockedResponse(packet, parsed), { action: 'block-service', rule: serviceBlocked.rule, source: 'filter' });
  }

  if (blocked && !allow) {
    stat('blocked');
    stat('blockedFiltering');
    statMap('byRule', blocked.rule);
    return finish(buildBlockedResponse(packet, parsed), { action: 'block', rule: blocked.rule, source: 'filter' });
  }

  const domainProtection = filteringActive && !allow
    ? await domainProtectionChecker.check(parsed.qname, {
      safeBrowsing: { ...config.filter.safeBrowsing, enabled: safeBrowsingEnabled },
      parental: { ...config.filter.parental, enabled: parentalEnabled }
    })
    : null;
  if (domainProtection?.blocked) {
    const safeBrowsing = domainProtection.service === 'safeBrowsing';
    stat('blocked');
    stat(safeBrowsing ? 'safeBrowsing' : 'parental');
    statMap('byRule', domainProtection.rule);
    return finish(buildBlockedResponse(packet, parsed), {
      action: safeBrowsing ? 'block-safebrowsing' : 'block-parental',
      rule: domainProtection.rule,
      source: safeBrowsing ? 'safe-browsing' : 'parental'
    });
  }

  const safeSearch = filteringActive && !allow
    ? matchSafeSearch(parsed.qname, parsed.qtype, safeSearchSettings)
    : null;
  if (safeSearch?.kind === 'ip') {
    stat('safeSearch');
    statMap('byRule', safeSearch.rule);
    return finish(buildAnswerResponse(packet, parsed, QTYPE.A, 60, ipv4ToBytes(safeSearch.value)), { action: 'safe-search', rule: safeSearch.rule, source: 'safe-search' });
  }
  if (safeSearch?.kind === 'nodata') {
    stat('safeSearch');
    statMap('byRule', safeSearch.rule);
    return finish(buildNoDataResponse(packet, parsed), { action: 'safe-search', rule: safeSearch.rule, source: 'safe-search' });
  }

  const queryPacket = safeSearch?.kind === 'cname' ? buildQuery(safeSearch.value, parsed.qtype) : packet;
  const responseAction = safeSearch ? 'safe-search' : 'allow';
  const responseRule = safeSearch?.rule || allow?.rule || '';
  const finishBlockedUpstreamResponse = (response, upstreamResult) => {
    if (safeSearch || config.filter.cnameCheck === false || !filteringActive || allow) return null;
    const hit = findBlockedDnsResponse(response, filterMatchContext);
    if (!hit) return null;
    stat('blocked');
    stat('blockedFiltering');
    statMap('byRule', hit.rule);
    return finish(buildBlockedResponse(packet, parsed), {
      action: 'block-cname',
      rule: hit.rule,
      matchedRules: hit.matchedRules,
      source: hit.source,
      responseMatchType: hit.responseMatchType,
      responseMatchValue: hit.responseMatchValue,
      upstream: upstreamResult.upstream || '',
      upstreamMode: upstreamResult.upstreamMode || '',
      upstreamRoute: upstreamResult.upstreamRoute || '',
      upstreamElapsedMs: upstreamResult.elapsedMs || 0
    }, response);
  };

  const responseCache = responseCacheForClient(clientProfile);
  const cached = responseCacheGet(responseCache, cacheKey);
  const cacheCheckedAt = Date.now();
  if (cached && cached.expireAt > cacheCheckedAt) {
    stat('cached');
    stat(safeSearch ? 'safeSearch' : 'allowed');
    if (safeSearch) statMap('byRule', safeSearch.rule);
    return finish(cachedDnsResponse(cached, packet.readUInt16BE(0)), { action: responseAction, rule: responseRule, cached: true, source: responseCacheSource(responseCache), upstream: cached.upstream || '', upstreamMode: cached.upstreamMode || '', upstreamRoute: cached.upstreamRoute || '', upstreamElapsedMs: cached.upstreamElapsedMs || 0 });
  }

  if (cached && optimisticCacheUsable(cached, cacheCheckedAt)) {
    scheduleOptimisticRefresh({
      cacheKey,
      responseCache,
      queryPacket,
      packet,
      parsed,
      ecs,
      clientProfile,
      safeSearch,
      dnssecRequested: dnssecProfile === 'dnssec',
      filteringActive,
      allowed: Boolean(allow),
      filterMatchContext
    });
    stat('cached');
    stat(safeSearch ? 'safeSearch' : 'allowed');
    if (safeSearch) statMap('byRule', safeSearch.rule);
    return finish(cachedDnsResponse(cached, packet.readUInt16BE(0), 'optimistic'), { action: responseAction, rule: responseRule, cached: true, source: responseCacheSource(responseCache, 'optimistic'), upstream: cached.upstream || '', upstreamMode: cached.upstreamMode || '', upstreamRoute: cached.upstreamRoute || '', upstreamElapsedMs: cached.upstreamElapsedMs || 0 });
  }

  if (pending.has(cacheKey)) {
    try {
      const upstreamResult = await pending.get(cacheKey);
      const response = normalizeDnsResponseTtls(upstreamResult.response);
      const blockedResponse = finishBlockedUpstreamResponse(response, upstreamResult);
      if (blockedResponse) return blockedResponse;
      stat(safeSearch ? 'safeSearch' : 'allowed');
      if (safeSearch) statMap('byRule', safeSearch.rule);
      return finish(patchResponseId(response, packet.readUInt16BE(0)), { action: responseAction, rule: responseRule, source: 'in-flight', upstream: upstreamResult.upstream || '', upstreamMode: upstreamResult.upstreamMode || '', upstreamRoute: upstreamResult.upstreamRoute || '', upstreamElapsedMs: upstreamResult.elapsedMs || 0 });
    } catch {
      // fall through
    }
  }

  const upstreamPromise = queryUpstreams(queryPacket, ecs, {
    recordStats: !statsIgnored,
    clientProfile,
    privateReverse: isPrivateReversePtr(parsed),
    dnssecRequested: dnssecProfile === 'dnssec'
  })
    .then((result) => safeSearch?.kind === 'cname'
      ? { ...result, response: buildSafeSearchCnameResponse(packet, parsed, safeSearch.value, result.response) }
      : result)
    .finally(() => pending.delete(cacheKey));
  pending.set(cacheKey, upstreamPromise);

  try {
    const upstreamResult = await upstreamPromise;
    let response = normalizeDnsResponseTtls(upstreamResult.response);
    stat('upstream');

    const blockedResponse = finishBlockedUpstreamResponse(response, upstreamResult);
    if (blockedResponse) return blockedResponse;

    if (responseCache) {
      const ttl = clamp(extractMinTtl(response) || config.cache.minTtl, config.cache.minTtl, config.cache.maxTtl);
      const cachedAt = Date.now();
      responseCacheSet(responseCache, cacheKey, {
        response: patchResponseId(response, 0),
        cachedAt,
        expireAt: cachedAt + ttl * 1000,
        upstream: upstreamResult.upstream || '',
        upstreamMode: upstreamResult.upstreamMode || '',
        upstreamRoute: upstreamResult.upstreamRoute || '',
        upstreamElapsedMs: upstreamResult.elapsedMs || 0
      });
    }
    stat(safeSearch ? 'safeSearch' : 'allowed');
    if (safeSearch) statMap('byRule', safeSearch.rule);
    return finish(response, { action: responseAction, rule: responseRule, source: safeSearch ? 'safe-search' : 'upstream', upstream: upstreamResult.upstream || '', upstreamMode: upstreamResult.upstreamMode || '', upstreamRoute: upstreamResult.upstreamRoute || '', upstreamElapsedMs: upstreamResult.elapsedMs || 0 });
  } catch (err) {
    stat('errors');
    if (cached && cached.expireAt + config.cache.staleTtl * 1000 > Date.now()) {
      stat(safeSearch ? 'safeSearch' : 'allowed');
      if (safeSearch) statMap('byRule', safeSearch.rule);
      return finish(cachedDnsResponse(cached, packet.readUInt16BE(0), 'stale'), { action: responseAction, rule: responseRule, cached: true, source: responseCacheSource(responseCache, 'stale'), upstream: cached.upstream || '', upstreamMode: cached.upstreamMode || '', upstreamRoute: cached.upstreamRoute || '', upstreamElapsedMs: cached.upstreamElapsedMs || 0 });
    }
    console.error('upstream error', err.message || err);
    return finish(buildErrorResponse(packet, RCODE.SERVFAIL), { action: 'error', rule: err.message || 'upstream error', source: 'error' });
  }
}

function recordResolvedQuery(item, response, originalResponse = null) {
  const decoded = decodeDnsResponse(response, { maxAnswers: 16 });
  const original = Buffer.isBuffer(originalResponse)
    ? decodeDnsResponse(originalResponse, { maxAnswers: 16 })
    : null;
  recordQuery({
    ...item,
    responseCode: decoded.rcode,
    responseStatus: decoded.status,
    responseFlags: decoded.flags,
    answerCount: decoded.answerCount,
    answersTruncated: decoded.answersTruncated,
    answers: decoded.answers,
    originalResponseCode: original?.rcode ?? null,
    originalResponseStatus: original?.status || '',
    originalAnswerCount: original?.answerCount || 0,
    originalAnswersTruncated: original?.answersTruncated === true,
    originalAnswers: original?.answers || []
  });
}

function effectiveBlockedServicesPolicy(clientProfile = null, now = new Date()) {
  const useGlobal = !clientProfile || clientProfile.useGlobalBlockedServices !== false;
  const enabled = normalizeBlockedServices(useGlobal ? config.filter.blockedServices : clientProfile.blockedServices);
  const schedule = normalizeBlockedServicesSchedule(useGlobal ? config.filter.blockedServicesSchedule : clientProfile.blockedServicesSchedule);
  return {
    useGlobal,
    enabled,
    schedule,
    scheduleStatus: blockedServicesScheduleStatus(schedule, now)
  };
}

function matchBlockedService(domain, clientProfile = null) {
  const policy = effectiveBlockedServicesPolicy(clientProfile);
  if (policy.scheduleStatus.paused) return null;
  const enabled = new Set(policy.enabled);
  if (!enabled.size) return null;
  for (const service of BLOCKED_SERVICE_CATALOG) {
    if (!enabled.has(service.id)) continue;
    if (blockedServiceMatchesDomain(domain, BLOCKED_SERVICE_MATCHERS.get(service.id))) {
      return { kind: 'blocked-service', service: service.id, name: service.name, rule: `service:${service.id}` };
    }
  }
  return null;
}

async function checkFilteringPolicy(name, qtype, clientIp) {
  const clientProfile = findClientProfile(clientIp);
  const usesGlobalSettings = clientProfile?.useGlobalSettings !== false;
  const clientFilteringEnabled = usesGlobalSettings || clientProfile?.filteringEnabled !== false;
  const filteringActive = isFilteringActive() && clientFilteringEnabled;
  const safeSearchSettings = usesGlobalSettings ? config.filter.safeSearch : clientProfile.safeSearch;
  const safeBrowsingEnabled = usesGlobalSettings
    ? config.filter.safeBrowsing.enabled === true
    : clientProfile?.safeBrowsingEnabled === true;
  const parentalEnabled = usesGlobalSettings
    ? config.filter.parental.enabled === true
    : clientProfile?.parentalEnabled === true;
  const context = { qtype, clientIp, clientProfile };
  const base = {
    hostname: name,
    qtype: DNS_RULE_QTYPE_NAME[qtype] || `TYPE${qtype}`,
    client: {
      ip: clientIp,
      id: clientProfile?.id || '',
      name: clientProfile?.name || '',
      tags: clientProfile?.tags || []
    },
    protection: protectionStatus(),
    filteringActive,
    rules: [],
    rewrite: null,
    service: null
  };

  const dedicatedRewrite = config.filter.rewritesEnabled !== false
    ? resolveDnsRewrite(rules.rewrites, name, qtype)
    : { matched: false };
  if (dedicatedRewrite.matched && dedicatedRewrite.kind !== 'passthrough') {
    return {
      ...base,
      status: 'rewritten',
      reason: dedicatedRewrite.loop ? 'rewrite_loop' : 'rewrite',
      source: 'rewrite',
      rules: dedicatedRewrite.entries.map((entry) => filteringCheckRule({
        rule: entry.original,
        source: path.basename(config.rules.rewriteFile),
        kind: 'rewrite'
      })),
      rewrite: summarizeFilteringRewrite(dedicatedRewrite)
    };
  }

  const allow = filteringActive ? rules.allow.match(name, context) : null;
  const filterRewrite = resolveFilterDnsRewrite(rules.filterRewrites, name, qtype, context, allow);
  if (filterRewrite.matched && (filterRewrite.hostRule !== true || filteringActive)) {
    return {
      ...base,
      status: filterRewrite.hostRule === true ? 'blocked' : 'rewritten',
      reason: filterRewrite.hostRule === true ? 'hosts_rule' : 'filter_rewrite',
      source: filterRewrite.hostRule === true ? 'filter-hosts' : 'filter-rewrite',
      rules: filterRewrite.entries.map(filteringCheckRule),
      rewrite: summarizeFilteringRewrite(filterRewrite)
    };
  }

  const blocked = filteringActive ? rules.block.match(name, context) : null;
  if (blocked?.important === true && allow?.important !== true) {
    return filteringCheckMatch(base, 'blocked', 'important_block', 'filter', blocked);
  }

  const blockedService = filteringActive && !allow ? matchBlockedService(name, clientProfile) : null;
  if (blockedService) {
    return {
      ...base,
      status: 'blocked',
      reason: 'blocked_service',
      source: 'blocked-service',
      service: { id: blockedService.service, name: blockedService.name },
      rules: [filteringCheckRule({ rule: blockedService.rule, source: 'blocked-services', kind: 'blocked-service' })]
    };
  }

  if (blocked && !allow) return filteringCheckMatch(base, 'blocked', 'block', 'filter', blocked);

  const domainProtection = filteringActive && !allow
    ? await domainProtectionChecker.check(name, {
      safeBrowsing: { ...config.filter.safeBrowsing, enabled: safeBrowsingEnabled },
      parental: { ...config.filter.parental, enabled: parentalEnabled }
    })
    : null;
  if (domainProtection?.blocked) {
    const safeBrowsing = domainProtection.service === 'safeBrowsing';
    return {
      ...base,
      status: 'blocked',
      reason: safeBrowsing ? 'safe_browsing' : 'parental',
      source: safeBrowsing ? 'safe-browsing' : 'parental',
      service: { id: domainProtection.service, name: domainProtection.service },
      rules: [filteringCheckRule({ rule: domainProtection.rule, source: domainProtection.service, kind: domainProtection.service })]
    };
  }

  const safeSearch = filteringActive && !allow ? matchSafeSearch(name, qtype, safeSearchSettings) : null;
  if (safeSearch) {
    return {
      ...base,
      status: 'rewritten',
      reason: 'safe_search',
      source: 'safe-search',
      service: { id: safeSearch.service, name: safeSearch.service },
      rules: [filteringCheckRule({ rule: safeSearch.rule, source: 'safe-search', kind: 'safe-search' })],
      rewrite: {
        kind: safeSearch.kind,
        type: safeSearch.kind === 'ip' ? 'A' : safeSearch.kind === 'cname' ? 'CNAME' : '',
        rcode: RCODE.NOERROR,
        values: safeSearch.value ? [safeSearch.value] : []
      }
    };
  }

  if (allow) return filteringCheckMatch(base, 'allowed', 'allow', 'filter', allow);
  return { ...base, status: 'not_filtered', reason: filteringActive ? 'not_found' : 'protection_disabled', source: '' };
}

function filteringCheckMatch(base, status, reason, source, meta) {
  return { ...base, status, reason, source, rules: meta ? [filteringCheckRule(meta)] : [] };
}

function filteringCheckRule(meta = {}) {
  return {
    text: String(meta.rule || ''),
    source: String(meta.source || ''),
    kind: String(meta.kind || ''),
    important: meta.important === true
  };
}

function summarizeFilteringRewrite(rewrite = {}) {
  const recordType = rewrite.rrtype || rewrite.qtype || 0;
  const entryValue = rewrite.entries?.[0]?.value;
  const values = rewrite.kind === 'nodata' || rewrite.kind === 'rcode'
    ? []
    : Array.isArray(rewrite.values)
      ? rewrite.values
      : (rewrite.value || entryValue) ? [rewrite.value || entryValue] : [];
  return {
    kind: rewrite.kind || '',
    type: QTYPE_NAME[recordType] || (rewrite.kind === 'cname' ? 'CNAME' : ''),
    rcode: Number.isInteger(rewrite.rcode) ? rewrite.rcode : RCODE.NOERROR,
    values
  };
}

async function queryUpstreams(originalPacket, ecs, options = {}) {
  const selection = selectConfiguredUpstreams(originalPacket, options);
  const ecsPacket = addOrReplaceEcs(originalPacket, ecs);
  const packet = config.dns.dnssecEnabled === true || options.dnssecRequested === true
    ? enableDnssecRequest(ecsPacket)
    : ecsPacket;
  try {
    const result = await queryUpstreamSet(selection.upstreams, packet, selection.mode, options);
    return { ...result, upstreamMode: selection.mode, upstreamRoute: selection.route };
  } catch (primaryError) {
    const canUseFallback = selection.scope === 'global' && (config.fallbackUpstreams || []).length;
    if (!canUseFallback) throw primaryError;
    try {
      const result = await querySequentialUpstreams(config.fallbackUpstreams, packet, options);
      return { ...result, upstreamMode: 'fallback', upstreamRoute: `${selection.route} -> 后备 DNS` };
    } catch (fallbackError) {
      throw new Error(`primary: ${primaryError.message}; fallback: ${fallbackError.message}`);
    }
  }
}

function selectConfiguredUpstreams(packet, options = {}) {
  const question = parseQuestion(packet) || { qname: '', qtype: 0 };
  const globalDefaults = compileUpstreamConfiguration(config.upstreams).defaults;
  const layers = [];
  const clientUpstreams = options.clientProfile?.upstreams || [];
  if (clientUpstreams.length) {
    layers.push({
      lines: clientUpstreams,
      mode: 'client',
      scope: 'client',
      defaultRoute: '客户端默认上游'
    });
  }
  const privateReverseUpstreams = options.privateReverse && config.dns.privateReverseEnabled === true
    ? (config.dns.privateReverseUpstreams || [])
    : [];
  if (privateReverseUpstreams.length) {
    layers.push({
      lines: privateReverseUpstreams,
      mode: 'private-reverse',
      scope: 'private-reverse',
      defaultRoute: '私有反向默认上游'
    });
  }
  layers.push({
    lines: config.upstreams,
    mode: normalizeUpstreamMode(config.upstreamMode),
    scope: 'global',
    defaultRoute: '默认上游'
  });

  for (const layer of layers) {
    const selected = selectUpstreamConfiguration(layer.lines, question.qname, question.qtype, {
      fallbackDefaults: globalDefaults,
      defaultRoute: layer.defaultRoute
    });
    if (selected) return { ...selected, mode: layer.mode, scope: layer.scope };
  }
  throw new Error('no upstreams');
}

function queryUpstreamSet(upstreams, packet, mode, options = {}) {
  if (mode === 'parallel') return queryParallelUpstreams(upstreams, packet, options);
  if (mode === 'fastest') return queryFastestUpstream(upstreams, packet, options);
  return querySequentialUpstreams(upstreams, packet, options);
}

function isPrivateReversePtr(parsed) {
  return parsed?.qtype === QTYPE.PTR && isPrivateReverseName(parsed.qname);
}

function isPrivateReverseName(qname) {
  const name = normalizeDomain(qname);
  if (name.endsWith('.in-addr.arpa')) {
    const labels = name.slice(0, -'.in-addr.arpa'.length).split('.');
    if (labels.length !== 4 || labels.some((label) => !/^\d{1,3}$/.test(label))) return false;
    const octets = labels.reverse().map(Number);
    if (octets.some((octet) => octet < 0 || octet > 255)) return false;
    return isPrivateReverseIpv4(octets);
  }
  if (name.endsWith('.ip6.arpa')) {
    const labels = name.slice(0, -'.ip6.arpa'.length).split('.');
    if (labels.length !== 32 || labels.some((label) => !/^[0-9a-f]$/.test(label))) return false;
    const nibbles = labels.reverse().join('');
    return nibbles.startsWith('fc') || nibbles.startsWith('fd') || nibbles.startsWith('fe80');
  }
  return false;
}

function isPrivateReverseIpv4(octets) {
  return octets[0] === 10 ||
    octets[0] === 127 ||
    (octets[0] === 169 && octets[1] === 254) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
}

async function querySequentialUpstreams(upstreams, packet, options = {}) {
  const errors = [];
  for (const upstream of upstreams) {
    try {
      const result = await querySingleUpstream(upstream, packet, options);
      return result;
    } catch (err) {
      errors.push(`${upstream}: ${err.message}`);
    }
  }
  throw new Error(errors.join('; ') || 'no upstreams');
}

async function queryParallelUpstreams(upstreams, packet, options = {}) {
  const attempts = upstreams.map((upstream) => querySingleUpstream(upstream, packet, options));
  try {
    return await Promise.any(attempts);
  } catch {
    const results = await Promise.allSettled(attempts);
    throw new Error(results.map((result, index) => `${upstreams[index]}: ${result.reason?.message || result.reason || 'failed'}`).join('; ') || 'no upstreams');
  }
}

async function queryFastestUpstream(upstreams, packet, options = {}) {
  const attempts = upstreams.map((upstream) => querySingleUpstream(upstream, packet, options));
  try {
    const result = await Promise.any(attempts);
    return result;
  } catch {
    const results = await Promise.allSettled(attempts);
    throw new Error(results.map((result, index) => `${upstreams[index]}: ${result.reason?.message || result.reason || 'failed'}`).join('; ') || 'no upstreams');
  }
}

async function querySingleUpstream(upstream, packet, options = {}) {
  const started = Date.now();
  try {
    const transportOptions = options.transportOptions || configuredUpstreamTransportOptions();
    const response = await queryDnsUpstream(upstream, packet, config.timeoutMs, transportOptions);
    const rcode = response.length >= 4 ? response[3] & 0x0f : -1;
    if (rcode !== RCODE.NOERROR && rcode !== RCODE.NXDOMAIN) {
      throw new Error(`upstream_rcode_${rcode}`);
    }
    const elapsedMs = Date.now() - started;
    if (options.recordStats !== false) recordUpstreamResult(upstream, elapsedMs, true);
    return { upstream, response, elapsedMs };
  } catch (err) {
    if (options.recordStats !== false) recordUpstreamResult(upstream, Date.now() - started, false);
    throw err;
  }
}

async function queryDomainProtectionService(service, question) {
  const packet = buildQuery(question, QTYPE.TXT);
  const parsed = parseUpstreamAddress(service.upstream);
  const transportOptions = parsed.host === 'family.adguard-dns.com'
    ? { lookup: adguardProtectionLookup }
    : configuredUpstreamTransportOptions();
  return queryDnsUpstream(service.upstream, packet, service.timeoutMs, transportOptions);
}

function adguardProtectionLookup(_hostname, options, callback) {
  const requestedFamily = typeof options === 'number' ? options : Number(options?.family || 0);
  const addresses = ADGUARD_PROTECTION_BOOTSTRAP.filter((item) => !requestedFamily || item.family === requestedFamily);
  if (!addresses.length) return callback(Object.assign(new Error('adguard_protection_bootstrap_unavailable'), { code: 'ENOTFOUND' }));
  if (options?.all === true) return callback(null, addresses.map((item) => ({ ...item })));
  return callback(null, addresses[0].address, addresses[0].family);
}

function recordUpstreamResult(upstream, elapsedMs, ok) {
  if (!shouldRecordStats()) return;
  updateStats((target) => {
    target.upstreams ||= {};
    const item = target.upstreams[upstream] || { responses: 0, errors: 0, totalMs: 0 };
    if (ok) {
      item.responses += 1;
      item.totalMs += Math.max(0, Number(elapsedMs) || 0);
    } else {
      item.errors += 1;
    }
    target.upstreams[upstream] = item;
  });
}

async function testSingleUpstream(upstream, packet, timeoutMs, options = {}) {
  const started = Date.now();
  try {
    const response = await queryDnsUpstream(upstream, packet, timeoutMs, options.transportOptions || {});
    const elapsedMs = Date.now() - started;
    const decoded = decodeDnsResponse(response);
    return {
      upstream,
      role: options.role || 'primary',
      route: options.route || '',
      routeCount: Math.max(0, Number(options.routeCount) || 0),
      ok: true,
      elapsedMs,
      answers: decoded.answers || [],
      rcode: decoded.rcode,
      dnssecAuthenticated: decoded.flags?.authenticatedData === true
    };
  } catch (err) {
    return {
      upstream,
      role: options.role || 'primary',
      route: options.route || '',
      routeCount: Math.max(0, Number(options.routeCount) || 0),
      ok: false,
      elapsedMs: Date.now() - started,
      error: err.message || String(err)
    };
  }
}

function configuredUpstreamTransportOptions() {
  return (config.bootstrapDns || []).length ? { lookup: configuredBootstrapLookup } : {};
}

function configuredBootstrapLookup(hostname, options, callback) {
  resolveBootstrapHostname(
    hostname,
    options,
    config.bootstrapDns || [],
    config.timeoutMs,
    bootstrapLookupCache,
    bootstrapLookupPending
  ).then(
    (addresses) => completeBootstrapLookup(addresses, options, callback),
    (error) => callback(bootstrapLookupError(error))
  );
}

function createBootstrapLookup(upstreams, timeoutMs) {
  const lookupCache = new Map();
  const lookupPending = new Map();
  return (hostname, options, callback) => {
    resolveBootstrapHostname(hostname, options, upstreams, timeoutMs, lookupCache, lookupPending).then(
      (addresses) => completeBootstrapLookup(addresses, options, callback),
      (error) => callback(bootstrapLookupError(error))
    );
  };
}

function completeBootstrapLookup(addresses, options, callback) {
  if (options?.all === true) return callback(null, addresses);
  const first = addresses[0];
  callback(null, first.address, first.family);
}

function bootstrapLookupError(error) {
  const next = error instanceof Error ? error : new Error(String(error || 'bootstrap_lookup_failed'));
  next.code ||= 'ENOTFOUND';
  return next;
}

async function resolveBootstrapHostname(hostname, options, upstreams, timeoutMs, lookupCache, lookupPending) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  const addressFamily = net.isIP(host);
  if (addressFamily) return [{ address: host, family: addressFamily }];
  if (!host || !(upstreams || []).length) throw new Error('bootstrap_dns_missing');
  const family = typeof options === 'number' ? options : Number(options?.family || 0);
  const normalizedFamily = family === 4 || family === 6 ? family : 0;
  const key = `${host}|${normalizedFamily}`;
  const cached = lookupCache.get(key);
  if (cached && cached.expireAt > Date.now()) return cached.addresses.map((item) => ({ ...item }));
  if (lookupPending.has(key)) return lookupPending.get(key);

  const task = (async () => {
    const families = normalizedFamily ? [normalizedFamily] : [4, 6];
    const results = await Promise.allSettled(families.map((item) => queryBootstrapFamily(host, item, upstreams, timeoutMs)));
    const addresses = [];
    let ttl = 600;
    for (const result of results) {
      if (result.status !== 'fulfilled') continue;
      for (const record of result.value) {
        if (!addresses.some((item) => item.address === record.address)) addresses.push({ address: record.address, family: record.family });
        ttl = Math.min(ttl, Math.max(1, Number(record.ttl) || 60));
      }
    }
    if (!addresses.length) {
      const reasons = results.filter((result) => result.status === 'rejected').map((result) => result.reason?.message || String(result.reason));
      throw new Error(reasons.join('; ') || 'bootstrap_lookup_failed');
    }
    lookupCache.set(key, { addresses, expireAt: Date.now() + Math.max(30, Math.min(600, ttl)) * 1000 });
    while (lookupCache.size > 256) lookupCache.delete(lookupCache.keys().next().value);
    return addresses.map((item) => ({ ...item }));
  })().finally(() => lookupPending.delete(key));
  lookupPending.set(key, task);
  return task;
}

async function queryBootstrapFamily(hostname, family, upstreams, timeoutMs) {
  const qtype = family === 6 ? QTYPE.AAAA : QTYPE.A;
  const packet = buildQuery(hostname, qtype);
  const errors = [];
  for (const upstream of upstreams) {
    try {
      const response = await queryDnsUpstream(upstream, packet, timeoutMs);
      const decoded = decodeDnsResponse(response);
      if (decoded.rcode !== RCODE.NOERROR) throw new Error(`bootstrap_rcode_${decoded.rcode}`);
      const records = (decoded.answers || [])
        .filter((answer) => answer.type === (family === 6 ? 'AAAA' : 'A') && net.isIP(answer.value) === family)
        .map((answer) => ({ address: answer.value, family, ttl: answer.ttl }));
      if (records.length) return records;
      errors.push(`${upstream}: no_${family === 6 ? 'aaaa' : 'a'}_answer`);
    } catch (error) {
      errors.push(`${upstream}: ${error.message || error}`);
    }
  }
  throw new Error(errors.join('; ') || 'bootstrap_lookup_failed');
}

function clearBootstrapLookupCache() {
  bootstrapLookupCache.clear();
  bootstrapLookupPending.clear();
}

function makeEcs(ip, fallbackEcs = null) {
  let normalized = ip || '';
  if (normalized.startsWith('::ffff:')) normalized = normalized.slice(7);
  if (fallbackEcs && (!net.isIP(normalized) || isLocalAddress(normalized))) return fallbackEcs;
  if (!net.isIP(normalized) && config.ecs.defaultIpv4) normalized = config.ecs.defaultIpv4;
  const family = net.isIP(normalized);
  if (!config.ecs.enabled || !family) return { key: 'none', family: 0, sourcePrefix: 0, scopePrefix: 0, address: Buffer.alloc(0) };
  if (family === 4) {
    const prefix = config.ecs.ipv4Prefix;
    const bytes = ipv4ToBytes(normalized);
    const masked = maskBytes(bytes, prefix);
    return { key: `v4:${bytesToIpv4(masked)}/${prefix}`, family: 1, sourcePrefix: prefix, scopePrefix: 0, address: masked.subarray(0, Math.ceil(prefix / 8)) };
  }
  const prefix = config.ecs.ipv6Prefix;
  const bytes = ipv6ToBytes(normalized);
  const masked = maskBytes(bytes, prefix);
  return { key: `v6:${bytesToIpv6(masked)}/${prefix}`, family: 2, sourcePrefix: prefix, scopePrefix: 0, address: masked.subarray(0, Math.ceil(prefix / 8)) };
}

function extractEcs(packet) {
  try {
    const q = parseQuestion(packet);
    if (!q) return null;
    let offset = q.questionEnd;
    const arcount = packet.readUInt16BE(10);
    for (let i = 0; i < arcount; i++) {
      const nameInfo = readName(packet, offset);
      if (!nameInfo) return null;
      offset = nameInfo.offset;
      if (offset + 10 > packet.length) return null;
      const type = packet.readUInt16BE(offset);
      const rdlen = packet.readUInt16BE(offset + 8);
      offset += 10;
      if (type === 41) {
        const end = offset + rdlen;
        let opt = offset;
        while (opt + 4 <= end) {
          const code = packet.readUInt16BE(opt);
          const len = packet.readUInt16BE(opt + 2);
          const data = opt + 4;
          if (data + len > end) return null;
          if (code === 8 && len >= 4) {
            const family = packet.readUInt16BE(data);
            const sourcePrefix = packet[data + 2];
            const scopePrefix = packet[data + 3];
            const sourceBytes = family === 1 ? 4 : family === 2 ? 16 : 0;
            if (!sourceBytes) return null;
            const provided = packet.subarray(data + 4, data + len);
            const full = Buffer.alloc(sourceBytes);
            provided.copy(full, 0, 0, Math.min(provided.length, full.length));
            const masked = maskBytes(full, sourcePrefix);
            return {
              key: family === 1 ? `v4:${bytesToIpv4(masked)}/${sourcePrefix}` : `v6:${bytesToIpv6(masked)}/${sourcePrefix}`,
              family,
              sourcePrefix,
              scopePrefix,
              address: masked.subarray(0, Math.ceil(sourcePrefix / 8))
            };
          }
          opt = data + len;
        }
      }
      offset += rdlen;
    }
  } catch {
    return null;
  }
  return null;
}

function isLocalAddress(ip) {
  if (!net.isIP(ip)) return false;
  if (ip === '127.0.0.1' || ip === '::1') return true;
  if (net.isIP(ip) === 4) {
    const b = ipv4ToBytes(ip);
    return b[0] === 10 || b[0] === 127 || (b[0] === 172 && b[1] >= 16 && b[1] <= 31) || (b[0] === 192 && b[1] === 168);
  }
  return ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd') || ip.toLowerCase().startsWith('fe80:');
}

function addOrReplaceEcs(packet, ecs) {
  if (!ecs.family) return packet;
  try {
    const q = parseQuestion(packet);
    if (!q) return packet;
    const header = Buffer.from(packet.subarray(0, 12));
    let arcount = packet.readUInt16BE(10);
    const beforeAdditional = packet.subarray(12, q.questionEnd);
    let offset = q.questionEnd;
    const additions = [];
    for (let i = 0; i < arcount; i++) {
      const start = offset;
      const nameInfo = readName(packet, offset);
      offset = nameInfo.offset;
      if (offset + 10 > packet.length) return packet;
      const type = packet.readUInt16BE(offset);
      const rdlen = packet.readUInt16BE(offset + 8);
      offset += 10;
      const rdataStart = offset;
      offset += rdlen;
      if (offset > packet.length) return packet;
      if (type === 41) {
        const opt = rebuildOptWithoutEcs(packet.subarray(start, offset), rdataStart - start, rdlen);
        if (opt) additions.push(opt);
      } else {
        additions.push(packet.subarray(start, offset));
      }
    }
    const ecsOpt = buildEcsOption(ecs);
    let optIndex = additions.findIndex((rr) => rr.length >= 11 && rr[0] === 0 && rr.readUInt16BE(1) === 41);
    if (optIndex >= 0) {
      const rr = additions[optIndex];
      const oldRdataLen = rr.readUInt16BE(9);
      const rebuilt = Buffer.concat([rr.subarray(0, 9), u16(oldRdataLen + ecsOpt.length), rr.subarray(11), ecsOpt]);
      additions[optIndex] = rebuilt;
    } else {
      additions.push(buildOptRecord(ecsOpt));
      arcount += 1;
    }
    header.writeUInt16BE(additions.length, 10);
    return Buffer.concat([header, beforeAdditional, ...additions]);
  } catch {
    return packet;
  }
}

function rebuildOptWithoutEcs(rr, rdataHeaderLen, rdlen) {
  const rdata = rr.subarray(rdataHeaderLen, rdataHeaderLen + rdlen);
  const options = [];
  let off = 0;
  while (off + 4 <= rdata.length) {
    const code = rdata.readUInt16BE(off);
    const len = rdata.readUInt16BE(off + 2);
    const end = off + 4 + len;
    if (end > rdata.length) return null;
    if (code !== 8) options.push(rdata.subarray(off, end));
    off = end;
  }
  const newRdata = Buffer.concat(options);
  return Buffer.concat([rr.subarray(0, 9), u16(newRdata.length), newRdata]);
}

function buildOptRecord(options) {
  return Buffer.concat([
    Buffer.from([0]),
    u16(41),
    u16(1232),
    Buffer.from([0, 0, 0, 0]),
    u16(options.length),
    options
  ]);
}

function buildEcsOption(ecs) {
  const data = Buffer.concat([u16(ecs.family), Buffer.from([ecs.sourcePrefix, ecs.scopePrefix]), ecs.address]);
  return Buffer.concat([u16(8), u16(data.length), data]);
}

function parseQuestion(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 17) return null;
  const qdcount = packet.readUInt16BE(4);
  if (qdcount < 1) return null;
  const name = readName(packet, 12);
  if (!name || name.offset + 4 > packet.length) return null;
  const qtype = packet.readUInt16BE(name.offset);
  const qclass = packet.readUInt16BE(name.offset + 2);
  return { id: packet.readUInt16BE(0), qname: normalizeDomain(name.name), qtype, qclass, questionEnd: name.offset + 4 };
}

function readName(packet, offset, depth = 0) {
  if (depth > 16) return null;
  const labels = [];
  let jumped = false;
  let cursor = offset;
  let finalOffset = offset;
  while (cursor < packet.length) {
    const len = packet[cursor];
    if ((len & 0xc0) === 0xc0) {
      if (cursor + 1 >= packet.length) return null;
      const pointer = ((len & 0x3f) << 8) | packet[cursor + 1];
      const pointed = readName(packet, pointer, depth + 1);
      if (!pointed) return null;
      labels.push(...pointed.name.split('.').filter(Boolean));
      finalOffset = cursor + 2;
      jumped = true;
      break;
    }
    if (len === 0) {
      finalOffset = cursor + 1;
      break;
    }
    cursor += 1;
    if (cursor + len > packet.length) return null;
    labels.push(packet.subarray(cursor, cursor + len).toString('ascii'));
    cursor += len;
    if (!jumped) finalOffset = cursor;
  }
  return { name: labels.join('.'), offset: finalOffset };
}

function buildErrorResponse(query, rcode) {
  if (!Buffer.isBuffer(query) || query.length < 12) return Buffer.alloc(0);
  const q = parseQuestion(query);
  const header = Buffer.from(query.subarray(0, 12));
  header[2] = 0x81;
  header[3] = 0x80 | (rcode & 0x0f);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  return Buffer.concat([header, q ? query.subarray(12, q.questionEnd) : Buffer.alloc(0)]);
}

function buildBlockedResponse(query, parsed) {
  const mode = config.filter.blockMode;
  if (mode === 'refused') return buildErrorResponse(query, RCODE.REFUSED);
  if (mode === 'nxdomain') return buildErrorResponse(query, RCODE.NXDOMAIN);
  if (mode === 'nodata') return buildNoDataResponse(query, parsed);
  const ttl = config.dns.blockedResponseTtl;
  const ipv4 = mode === 'custom' ? config.dns.blockingIpv4 : '0.0.0.0';
  const ipv6 = mode === 'custom' ? config.dns.blockingIpv6 : '::';
  if (parsed.qtype === QTYPE.A) return buildAnswerResponse(query, parsed, QTYPE.A, ttl, ipv4ToBytes(ipv4));
  if (parsed.qtype === QTYPE.AAAA) return buildAnswerResponse(query, parsed, QTYPE.AAAA, ttl, ipv6ToBytes(ipv6));
  return buildNoDataResponse(query, parsed);
}

function buildRewriteResponse(query, parsed, rewrite) {
  if (rewrite.kind === 'cname') {
    return buildCnameResponse(query, parsed, rewrite.value, null, 120);
  }
  if (rewrite.kind === 'address' && rewrite.qtype === QTYPE.A) {
    return buildAnswersResponse(query, parsed, QTYPE.A, 120, rewrite.values.map(ipv4ToBytes));
  }
  if (rewrite.kind === 'address' && rewrite.qtype === QTYPE.AAAA) {
    return buildAnswersResponse(query, parsed, QTYPE.AAAA, 120, rewrite.values.map(ipv6ToBytes));
  }
  return buildNoDataResponse(query, parsed);
}

function buildFilterDnsRewriteResponse(query, parsed, rewrite) {
  if (rewrite.kind === 'cname') return buildCnameResponse(query, parsed, rewrite.value, null, 120);
  if (rewrite.kind === 'rcode') return buildErrorResponse(query, rewrite.rcode);
  if (rewrite.kind === 'record') return buildAnswersResponse(query, parsed, rewrite.rrtype, 120, rewrite.records);
  return buildNoDataResponse(query, parsed);
}

function buildHostsRuleResponse(query, parsed, rewrite) {
  if (config.filter.blockMode === 'default' && rewrite.kind === 'record') {
    return buildAnswersResponse(query, parsed, rewrite.rrtype, config.dns.blockedResponseTtl, rewrite.records);
  }
  return buildBlockedResponse(query, parsed);
}

function dnsRewriteRuleLabel(rewrite) {
  const entry = rewrite.entries?.[0];
  const domain = entry?.domain || 'unknown';
  const answer = rewrite.kind === 'address'
    ? rewrite.values.join(',')
    : rewrite.value || entry?.value || rewrite.kind;
  return `rewrite:${domain}->${answer}`;
}

function buildNoDataResponse(query, parsed) {
  const header = Buffer.from(query.subarray(0, 12));
  header[2] = 0x81;
  header[3] = 0x80;
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  return Buffer.concat([header, query.subarray(12, parsed.questionEnd)]);
}

function buildAnswerResponse(query, parsed, type, ttl, rdata) {
  return buildAnswersResponse(query, parsed, type, ttl, [rdata]);
}

function buildAnswersResponse(query, parsed, type, ttl, records) {
  const values = records.map((record) => Buffer.from(record || []));
  if (!values.length) return buildNoDataResponse(query, parsed);
  const header = Buffer.from(query.subarray(0, 12));
  header[2] = 0x81;
  header[3] = 0x80;
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(values.length, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  const answers = values.map((rdata) => Buffer.concat([
    Buffer.from([0xc0, 0x0c]),
    u16(type),
    u16(1),
    u32(ttl),
    u16(rdata.length),
    rdata
  ]));
  return Buffer.concat([header, query.subarray(12, parsed.questionEnd), ...answers]);
}

function patchResponseId(response, id) {
  const copy = Buffer.from(response);
  if (copy.length >= 2) copy.writeUInt16BE(id, 0);
  return copy;
}

function normalizeDnsResponseTtls(response) {
  return rewriteDnsResponseTtls(response, (ttl) => clamp(ttl, config.cache.minTtl, config.cache.maxTtl));
}

function cachedDnsResponse(entry, id, mode = 'fresh') {
  let response;
  if (mode === 'optimistic') {
    response = rewriteDnsResponseTtls(entry.response, () => config.cache.optimisticAnswerTtl);
  } else if (mode === 'stale') {
    response = rewriteDnsResponseTtls(entry.response, () => 1);
  } else {
    const cachedAt = Number(entry.cachedAt) || Date.now();
    const ageSeconds = Math.max(0, Math.floor((Date.now() - cachedAt) / 1000));
    response = rewriteDnsResponseTtls(entry.response, (ttl) => Math.max(0, ttl - ageSeconds));
  }
  return patchResponseId(response, id);
}

function rewriteDnsResponseTtls(packet, transform) {
  const copy = Buffer.from(packet || []);
  try {
    if (copy.length < 12) return copy;
    const qd = copy.readUInt16BE(4);
    const records = copy.readUInt16BE(6) + copy.readUInt16BE(8) + copy.readUInt16BE(10);
    let offset = 12;
    for (let i = 0; i < qd; i += 1) {
      const name = readName(copy, offset);
      if (!name || name.offset + 4 > copy.length) return Buffer.from(packet || []);
      offset = name.offset + 4;
    }
    for (let i = 0; i < records; i += 1) {
      const name = readName(copy, offset);
      if (!name || name.offset + 10 > copy.length) return Buffer.from(packet || []);
      offset = name.offset;
      const type = copy.readUInt16BE(offset);
      const ttlOffset = offset + 4;
      const length = copy.readUInt16BE(offset + 8);
      if (type !== DNS_TYPE_OPT && type !== 249 && type !== 250) {
        const current = copy.readUInt32BE(ttlOffset);
        const next = Math.max(0, Math.min(UINT32_MAX, Math.floor(Number(transform(current)) || 0)));
        copy.writeUInt32BE(next, ttlOffset);
      }
      offset += 10 + length;
      if (offset > copy.length) return Buffer.from(packet || []);
    }
    return copy;
  } catch {
    return Buffer.from(packet || []);
  }
}

function extractMinTtl(packet) {
  try {
    if (packet.length < 12) return 0;
    const qd = packet.readUInt16BE(4);
    const an = packet.readUInt16BE(6);
    const ns = packet.readUInt16BE(8);
    let offset = 12;
    for (let i = 0; i < qd; i++) {
      const name = readName(packet, offset);
      if (!name) return 0;
      offset = name.offset + 4;
    }
    let min = null;
    for (let i = 0; i < an + ns; i++) {
      const name = readName(packet, offset);
      if (!name) return min ?? 0;
      offset = name.offset;
      if (offset + 10 > packet.length) return min ?? 0;
      const ttl = packet.readUInt32BE(offset + 4);
      const len = packet.readUInt16BE(offset + 8);
      min = min === null ? ttl : Math.min(min, ttl);
      offset += 10 + len;
      if (offset > packet.length) return min ?? 0;
    }
    return min ?? 0;
  } catch {
    return 0;
  }
}

function findBlockedDnsResponse(packet, context = {}) {
  if (!Buffer.isBuffer(packet) || packet.length < 12) return null;
  try {
    const qd = packet.readUInt16BE(4);
    const an = packet.readUInt16BE(6);
    let offset = 12;
    for (let index = 0; index < qd; index += 1) {
      const name = readName(packet, offset);
      if (!name || name.offset + 4 > packet.length) return null;
      offset = name.offset + 4;
    }
    for (let index = 0; index < an; index += 1) {
      const name = readName(packet, offset);
      if (!name || name.offset + 10 > packet.length) return null;
      const headerOffset = name.offset;
      const type = packet.readUInt16BE(headerOffset);
      const length = packet.readUInt16BE(headerOffset + 8);
      const valueOffset = headerOffset + 10;
      const end = valueOffset + length;
      if (end > packet.length) return null;

      const candidates = responseFilterCandidates(packet, type, valueOffset, end);
      for (const candidate of candidates) {
        const hit = matchDnsResponseValue(candidate.value, type, context);
        if (hit) {
          return {
            ...hit,
            responseMatchType: candidate.type,
            responseMatchValue: candidate.value
          };
        }
      }
      offset = end;
    }
  } catch {
    return null;
  }
  return null;
}

function responseFilterCandidates(packet, type, offset, end) {
  if (type === QTYPE.CNAME) {
    const cname = normalizeDomain(readName(packet, offset)?.name || '');
    return cname ? [{ type: 'CNAME', value: cname }] : [];
  }
  if (type === QTYPE.A && end - offset === 4) {
    return [{ type: 'A', value: bytesToIpv4(packet.subarray(offset, end)) }];
  }
  if (type === QTYPE.AAAA && end - offset === 16) {
    return [{ type: 'AAAA', value: bytesToIpv6(packet.subarray(offset, end)) }];
  }
  if (type !== QTYPE.HTTPS && type !== QTYPE.SVCB) return [];
  return serviceBindingHintCandidates(packet, type, offset, end);
}

function serviceBindingHintCandidates(packet, type, offset, end) {
  if (offset + 3 > end) return [];
  const target = readName(packet, offset + 2);
  if (!target || target.offset > end) return [];
  const recordType = QTYPE_NAME[type] || `TYPE${type}`;
  const candidates = [];
  let cursor = target.offset;
  while (cursor < end) {
    if (cursor + 4 > end) return candidates;
    const key = packet.readUInt16BE(cursor);
    const length = packet.readUInt16BE(cursor + 2);
    const valueOffset = cursor + 4;
    const valueEnd = valueOffset + length;
    if (valueEnd > end) return candidates;
    if (key === 4 && length % 4 === 0) {
      for (let addressOffset = valueOffset; addressOffset < valueEnd; addressOffset += 4) {
        candidates.push({
          type: `${recordType} ipv4hint`,
          value: bytesToIpv4(packet.subarray(addressOffset, addressOffset + 4))
        });
      }
    } else if (key === 6 && length % 16 === 0) {
      for (let addressOffset = valueOffset; addressOffset < valueEnd; addressOffset += 16) {
        candidates.push({
          type: `${recordType} ipv6hint`,
          value: bytesToIpv6(packet.subarray(addressOffset, addressOffset + 16))
        });
      }
    }
    cursor = valueEnd;
  }
  return candidates;
}

function matchDnsResponseValue(value, qtype, context = {}) {
  const candidate = qtype === QTYPE.CNAME ? normalizeDomain(value) : parseDnsRuleAddress(value);
  if (!candidate) return null;
  const matchContext = { ...context, qtype };
  const allow = rules.allow.match(candidate, matchContext);
  const blocked = rules.block.match(candidate, matchContext);
  if (blocked && (!allow || (blocked.important === true && allow.important !== true))) {
    return {
      rule: blocked.rule,
      matchedRules: [blocked.rule].filter(Boolean),
      source: 'filter'
    };
  }
  if (qtype !== QTYPE.CNAME) return null;
  const hostRule = resolveFilterDnsRewrite(rules.filterRewrites, candidate, qtype, matchContext, allow);
  if (!hostRule.matched || hostRule.hostRule !== true) return null;
  return {
    rule: filterDnsRewriteRuleLabel(hostRule),
    matchedRules: filterDnsRewriteRules(hostRule),
    source: 'filter-hosts'
  };
}

function getDhcpStatus(candidate = config.dhcp) {
  const interfaces = collectDhcpInterfaces(dhcpNetworkInterfaces());
  const validation = validateDhcpConfig(candidate, interfaces);
  const normalized = validation.config;
  const serverAddress = dhcpInterfaceIpv4ForConfig(normalized, validation.selectedInterface);
  const currentConfig = dhcpConfigSignature(normalized) === dhcpConfigSignature(config.dhcp);
  const runtime = currentConfig ? dhcpRuntime.snapshot() : dhcpRuntimeStatus;
  const configured = Boolean(
    normalized.interfaceName
    || normalized.gateway
    || normalized.subnetMask
    || normalized.rangeStart
    || normalized.rangeEnd
    || normalized.dnsServers.length
    || normalized.staticLeases.length
  );
  const runtimeReady = DHCP_RUNTIME_SUPPORTED && validation.ready && Boolean(serverAddress);
  const running = normalized.enabled === true && runtimeReady && runtime.running === true;
  const effectiveWarnings = [
    ...validation.warnings,
    ...(normalized.enabled === true && !normalized.dnsServers.length ? [{ code: 'dns_servers_missing', field: 'dnsServers', detail: '' }] : [])
  ];
  const validationReason = validation.errors[0]?.code || '';
  const reason = !DHCP_RUNTIME_SUPPORTED
    ? 'dhcp_runtime_unavailable'
    : normalized.enabled === true && !runtimeReady
      ? validationReason || 'dhcp_config_invalid'
      : runtime.error || '';
  const state = !DHCP_RUNTIME_SUPPORTED
    ? 'unavailable'
    : running
      ? 'running'
      : normalized.enabled === true && !runtimeReady
        ? 'invalid'
        : runtime.error
          ? 'error'
          : 'stopped';
  return {
    enabled: normalized.enabled === true,
    configured,
    supported: DHCP_RUNTIME_SUPPORTED,
    running,
    state,
    reason,
    interfaceName: normalized.interfaceName,
    interface: validation.selectedInterface,
    serverAddress: serverAddress?.address || '',
    port: runtime.port || DHCP_RUNTIME_PORT,
    dnsServers: normalized.dnsServers,
    interfaces,
    validation: {
      valid: validation.valid,
      ready: runtimeReady,
      configReady: validation.ready,
      errors: validation.errors,
      warnings: effectiveWarnings
    },
    config: normalized,
    leases: currentConfig ? runtime.leases || [] : [],
    staticLeases: normalized.staticLeases
  };
}

function dhcpNetworkInterfaces() {
  const fixture = String(process.env.CLEANDNS_DHCP_INTERFACES_JSON || '').trim();
  if (fixture) {
    try {
      const parsed = JSON.parse(fixture);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {}
  }
  return os.networkInterfaces();
}

function dhcpConfigSignature(value) {
  return JSON.stringify(normalizeDhcpConfig(value));
}

async function updateDhcpStaticLease(body) {
  const action = String(body?.action || '').trim().toLowerCase();
  const leases = [...config.dhcp.staticLeases];
  const previousMac = normalizeDhcpMac(body?.previousMac || body?.mac || body?.lease?.mac);
  let nextConfig;
  if (action === 'delete') {
    if (!previousMac) throw new Error('dhcp_static_lease_not_found');
    const next = leases.filter((entry) => entry.mac !== previousMac);
    if (next.length === leases.length) throw new Error('dhcp_static_lease_not_found');
    nextConfig = normalizeDhcpConfig({ ...config.dhcp, staticLeases: next });
  } else {
    const checked = validateDhcpStaticLease(body?.lease);
    if (!checked.valid) throw new Error(checked.errors[0]?.code || 'dhcp_static_lease_invalid');
    const lease = checked.lease;
    const editingIndex = action === 'update' ? leases.findIndex((entry) => entry.mac === previousMac) : -1;
    if (!['add', 'update'].includes(action) || (action === 'update' && editingIndex < 0)) {
      throw new Error('dhcp_static_lease_action_invalid');
    }
    if (leases.some((entry, index) => index !== editingIndex && entry.mac === lease.mac)) {
      throw new Error('static_lease_mac_duplicate');
    }
    if (leases.some((entry, index) => index !== editingIndex && entry.ip === lease.ip)) {
      throw new Error('static_lease_ip_duplicate');
    }
    if (editingIndex >= 0) leases[editingIndex] = lease;
    else leases.push(lease);
    nextConfig = normalizeDhcpConfig({ ...config.dhcp, staticLeases: leases });
  }
  const validation = validateDhcpConfig(nextConfig, collectDhcpInterfaces(dhcpNetworkInterfaces()));
  if (!validation.valid) throw new Error(validation.errors[0]?.code || 'dhcp_config_invalid');
  const previousDhcp = config.dhcp;
  config.dhcp = nextConfig;
  saveConfig();
  try {
    await applyDhcpRuntime();
  } catch (error) {
    config.dhcp = previousDhcp;
    saveConfig();
    await applyDhcpRuntime().catch(() => {});
    throw error;
  }
}

function handleApi(req, res, url) {
  if (req.method === 'POST' && url.pathname === '/api/login') {
    return readJson(req).then((body) => {
      const username = String(body.username || '');
      const password = String(body.password || '');
      if (username !== adminAuth.username || !verifyPassword(password, adminAuth.passwordHash)) {
        return json(res, 401, { error: 'invalid_credentials' });
      }
      const sessionId = createSession();
      json(res, 200, { ok: true, username: adminAuth.username, profile: getAdminProfile() }, { 'set-cookie': sessionCookie(sessionId) });
    }).catch(() => json(res, 400, { error: 'bad_json' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/logout') {
    const id = parseCookies(req).cleandns_session;
    if (id) sessions.delete(id);
    return json(res, 200, { ok: true }, { 'set-cookie': clearSessionCookie() });
  }
  if (req.method === 'GET' && url.pathname === '/api/session') {
    return json(res, 200, { authenticated: isAuthorized(req), username: adminAuth.username, profile: getAdminProfile() });
  }
  if (!isAuthorized(req, url)) return json(res, 401, { error: 'unauthorized' });
  if (req.method === 'GET' && url.pathname === '/api/profile') {
    return json(res, 200, getAdminProfile());
  }
  if (req.method === 'PUT' && url.pathname === '/api/profile') {
    return readJson(req).then((body) => {
      json(res, 200, updateAdminProfile(body));
    }).catch((err) => json(res, 400, { error: err.message || 'bad_profile' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/tls/status') {
    return json(res, 200, inspectTlsConfiguration(config));
  }
  if (req.method === 'POST' && url.pathname === '/api/tls/validate') {
    return readJson(req).then((body) => {
      const candidate = tlsConfigurationCandidate(body);
      json(res, 200, inspectTlsConfiguration(candidate));
    }).catch((err) => json(res, 400, { error: err.message || 'tls_validation_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/tls/config') {
    return readJson(req).then(async (body) => {
      const candidate = tlsConfigurationCandidate(body);
      const tls = inspectTlsConfiguration(candidate);
      if (tls.status === 'invalid') return json(res, 400, { error: 'tls_configuration_invalid', tls });
      const result = await commitServiceConfig(candidate.service);
      await refreshDoqRuntimeStatus({ force: true });
      json(res, 200, { ok: true, tls: inspectTlsConfiguration(config), settings: getSettings(), protocols: getProtocolStatus(), status: getStatus(), ...result });
    }).catch((err) => json(res, 400, { error: err.message || 'tls_config_failed' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/apple/doh.mobileconfig') {
    try {
      const profile = buildDohMobileConfig({ serverUrl: getSettings().dohUrl, displayName: 'CleanDNS' });
      return mobileConfig(res, profile, 'CleanDNS-DoH.mobileconfig');
    } catch (err) {
      return json(res, 400, { error: err.message || 'mobileconfig_failed' });
    }
  }
  if (req.method === 'GET' && url.pathname === '/api/status') {
    return refreshDoqRuntimeStatus().then(() => json(res, 200, getStatus(url.searchParams.get('period'))));
  }
  if (req.method === 'POST' && url.pathname === '/api/stats/clear') {
    clearStats();
    return json(res, 200, { ok: true, status: getStatus() });
  }
  if (req.method === 'POST' && url.pathname === '/api/cache/clear') {
    const removed = clearDnsCaches();
    return json(res, 200, { ok: true, removed: removed.total, removedByScope: removed, status: getStatus() });
  }
  if (req.method === 'POST' && url.pathname === '/api/protection') {
    return readJson(req).then((body) => {
      config.filter = { ...config.filter };
      if (Object.prototype.hasOwnProperty.call(body, 'durationMs')) {
        const durationMs = normalizeInteger(body.durationMs, 1000, 86400000, 'bad_duration');
        config.filter.enabled = true;
        config.filter.pauseUntil = Date.now() + durationMs;
      } else if (Object.prototype.hasOwnProperty.call(body, 'enabled')) {
        config.filter.enabled = Boolean(body.enabled);
        config.filter.pauseUntil = 0;
      } else {
        return json(res, 400, { error: 'bad_protection' });
      }
      config = normalizeConfig(config);
      saveConfig();
      clearDnsCaches();
      return json(res, 200, { ok: true, status: getStatus(), settings: getSettings() });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_protection' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/recent') {
    return getRecentQueryResponse(url)
      .then((payload) => json(res, 200, payload))
      .catch((err) => json(res, 500, { error: err.message || 'query_log_read_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/recent/clear') {
    return clearQueryLog()
      .then(() => json(res, 200, { ok: true, recent: recentQueries, status: getStatus() }))
      .catch((err) => json(res, 500, { error: err.message || 'query_log_clear_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/access/client') {
    return readJson(req).then((body) => {
      const client = normalizeClientIdentifier(body.client);
      if (!client || client.includes('/')) return json(res, 400, { error: 'bad_client' });
      const action = String(body.action || '').trim().toLowerCase();
      if (!['disallow', 'allow'].includes(action)) return json(res, 400, { error: 'bad_action' });
      const blockedClients = new Set(config.access.blockedClients || []);
      if (action === 'disallow') blockedClients.add(client);
      else blockedClients.delete(client);
      config.access = normalizeAccessConfig({ ...config.access, blockedClients: [...blockedClients] });
      saveConfig();
      clearDnsCaches();
      return json(res, 200, {
        ok: true,
        action,
        client,
        access: {
          allowedClients: config.access.allowedClients,
          blockedClients: config.access.blockedClients,
          blockedHosts: config.access.blockedHosts
        },
        settings: getSettings(),
        status: getStatus()
      });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_client_action' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/clients') {
    return json(res, 200, { clients, runtimeClients: getRuntimeClients() });
  }
  if (req.method === 'POST' && url.pathname === '/api/clients') {
    return readJson(req).then((body) => {
      clients = normalizeClientList(body.clients);
      saveClients();
      clearDnsCaches();
      refreshRuntimeClientReverseDnsProfiles();
      refreshRuntimeClientWhoisProfiles();
      json(res, 200, { ok: true, clients, runtimeClients: getRuntimeClients(), status: getStatus() });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_clients' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/blocked-services') {
    return json(res, 200, getBlockedServices());
  }
  if (req.method === 'POST' && url.pathname === '/api/blocked-services/update') {
    return refreshBlockedServicesCatalog('manual').then((autoUpdate) => json(res, 200, {
      ok: true,
      autoUpdate,
      blockedServices: getBlockedServices(),
      status: getStatus()
    })).catch((err) => json(res, err?.code === 'blocked_services_update_running' ? 409 : 500, {
      error: err.message || 'blocked_services_update_failed',
      autoUpdate: getBlockedServicesAutoUpdateStatus()
    }));
  }
  if (req.method === 'POST' && url.pathname === '/api/blocked-services/auto-update') {
    return readJson(req).then((body) => {
      const nextRules = { ...config.rules };
      if (Object.prototype.hasOwnProperty.call(body, 'enabled')) {
        nextRules.blockedServicesAutoUpdateEnabled = body.enabled !== false;
      }
      if (Object.prototype.hasOwnProperty.call(body, 'intervalHours')) {
        nextRules.blockedServicesAutoUpdateIntervalHours = normalizeInteger(
          body.intervalHours,
          24,
          720,
          'bad_blocked_services_auto_update_interval'
        );
      }
      if (Object.prototype.hasOwnProperty.call(body, 'onStartup')) {
        nextRules.blockedServicesAutoUpdateOnStartup = body.onStartup !== false;
      }
      config = normalizeConfig({ ...config, rules: nextRules });
      saveConfig();
      startBlockedServicesAutoUpdater({ runStartup: false, resetSchedule: true });
      json(res, 200, {
        ok: true,
        autoUpdate: getBlockedServicesAutoUpdateStatus(),
        blockedServices: getBlockedServices(),
        settings: getSettings(),
        status: getStatus()
      });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_blocked_services_auto_update' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/dhcp/status') {
    return json(res, 200, getDhcpStatus());
  }
  if (req.method === 'POST' && url.pathname === '/api/dhcp/check') {
    return readJson(req).then((body) => {
      const candidate = { ...config.dhcp, ...(body?.config || body || {}) };
      json(res, 200, getDhcpStatus(candidate));
    }).catch((err) => json(res, 400, { error: err.message || 'dhcp_check_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/dhcp/static-leases') {
    return readJson(req).then(async (body) => {
      await updateDhcpStaticLease(body);
      json(res, 200, { ok: true, dhcp: getDhcpStatus(), settings: getSettings() });
    }).catch((err) => json(res, 400, { error: err.message || 'dhcp_static_lease_failed' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/rules') {
    return json(res, 200, {
      block: fs.readFileSync(config.rules.blockFile, 'utf8'),
      allow: fs.readFileSync(config.rules.allowFile, 'utf8'),
      rewrite: fs.readFileSync(config.rules.rewriteFile, 'utf8'),
      subscriptions: fs.readFileSync(config.rules.subscriptionFile, 'utf8'),
      allowSubscriptions: fs.readFileSync(config.rules.allowSubscriptionFile, 'utf8'),
      subscriptionDetails: getSubscriptionDetails('block'),
      allowSubscriptionDetails: getSubscriptionDetails('allow'),
      subscriptionAutoUpdate: getSubscriptionAutoUpdateStatus()
    });
  }
  if (req.method === 'POST' && url.pathname === '/api/subscription-auto-update') {
    return readJson(req).then((body) => {
      const nextRules = { ...config.rules };
      if (Object.prototype.hasOwnProperty.call(body, 'enabled')) nextRules.autoUpdateEnabled = body.enabled !== false;
      if (Object.prototype.hasOwnProperty.call(body, 'intervalHours')) {
        nextRules.autoUpdateIntervalHours = normalizeInteger(body.intervalHours, 1, 168, 'bad_rules_auto_update_interval');
      }
      if (Object.prototype.hasOwnProperty.call(body, 'onStartup')) nextRules.autoUpdateOnStartup = body.onStartup !== false;
      if (Object.prototype.hasOwnProperty.call(body, 'onChange')) nextRules.autoUpdateOnChange = body.onChange !== false;
      config = normalizeConfig({ ...config, rules: nextRules });
      saveConfig();
      startSubscriptionAutoUpdater({ runStartup: false });
      json(res, 200, {
        ok: true,
        subscriptionAutoUpdate: getSubscriptionAutoUpdateStatus(),
        settings: getSettings(),
        status: getStatus()
      });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_subscription_auto_update' }));
  }
  if (req.method === 'GET' && url.pathname === '/api/settings') {
    return json(res, 200, getSettings());
  }
  if (req.method === 'GET' && url.pathname === '/api/protocols') {
    return refreshDoqRuntimeStatus().then(() => json(res, 200, getProtocolStatus()));
  }
  if (req.method === 'GET' && url.pathname === '/api/protocols/defaults') {
    return json(res, 200, getProtocolResetPreview());
  }
  if (req.method === 'POST' && url.pathname === '/api/protocols') {
    return readJson(req).then(async (body) => {
      const nextService = protocolBodyToService(body, config.service);
      const result = await commitServiceConfig(nextService);
      await refreshDoqRuntimeStatus({ force: true });
      json(res, 200, { ok: true, protocols: getProtocolStatus(), settings: getSettings(), status: getStatus(), ...result });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_protocol_settings' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/protocols/reset') {
    return readJson(req).then(async () => {
      const nextService = protocolResetService(config.service, config.domain);
      const result = await commitServiceConfig(nextService);
      await refreshDoqRuntimeStatus({ force: true });
      json(res, 200, { ok: true, protocols: getProtocolStatus(), settings: getSettings(), status: getStatus(), defaults: getProtocolResetPreview(), ...result });
    }).catch((err) => json(res, 400, { error: err.message || 'protocol_reset_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/settings') {
    return readJson(req).then(async (body) => {
      const nextService = { ...config.service };
      if (Object.prototype.hasOwnProperty.call(body, 'dohPath')) nextService.dohPath = normalizeDohPath(body.dohPath);
      if (Object.prototype.hasOwnProperty.call(body, 'dohPrefix')) nextService.dohPath = `${normalizeDohPrefix(body.dohPrefix)}/dns-query`;
      if (Object.prototype.hasOwnProperty.call(body, 'dohEnabled')) nextService.dohEnabled = body.dohEnabled !== false;
      if (Object.prototype.hasOwnProperty.call(body, 'plainDnsEnabled')) nextService.plainDnsEnabled = body.plainDnsEnabled === true;
      if (Object.prototype.hasOwnProperty.call(body, 'plainDnsHost')) nextService.plainDnsHost = normalizePlainDnsHost(body.plainDnsHost);
      if (Object.prototype.hasOwnProperty.call(body, 'plainDnsPort')) nextService.plainDnsPort = normalizePort(body.plainDnsPort || 53);
      if (Object.prototype.hasOwnProperty.call(body, 'dohPublicBaseUrl')) nextService.dohPublicBaseUrl = normalizePublicBaseUrl(body.dohPublicBaseUrl);
      if (Object.prototype.hasOwnProperty.call(body, 'panelPublicUrl')) nextService.panelPublicUrl = normalizePublicUrl(body.panelPublicUrl);
      if (Object.prototype.hasOwnProperty.call(body, 'doqEnabled')) nextService.doqEnabled = body.doqEnabled !== false;
      if (Object.prototype.hasOwnProperty.call(body, 'doqPort')) nextService.doqPort = normalizePort(body.doqPort);
      if (Object.prototype.hasOwnProperty.call(body, 'doqEndpoint')) {
        nextService.doqEndpoint = normalizeDoqEndpoint(body.doqEndpoint, config.domain);
      }
      const nextConfig = { ...config, service: nextService };
      if (Object.prototype.hasOwnProperty.call(body, 'upstreams')) nextConfig.upstreams = normalizeUpstreams(body.upstreams);
      if (Object.prototype.hasOwnProperty.call(body, 'fallbackUpstreams')) {
        nextConfig.fallbackUpstreams = normalizeOptionalUpstreams(body.fallbackUpstreams, 'bad_fallback_upstream');
      }
      if (Object.prototype.hasOwnProperty.call(body, 'bootstrapDns')) nextConfig.bootstrapDns = normalizeBootstrapDns(body.bootstrapDns);
      if (Object.prototype.hasOwnProperty.call(body, 'upstreamMode')) nextConfig.upstreamMode = normalizeUpstreamMode(body.upstreamMode);
      if (
        Object.prototype.hasOwnProperty.call(body, 'dnsDnssecEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsDisableIpv6') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsRefuseAny') ||
        Object.prototype.hasOwnProperty.call(body, 'clientReverseDnsEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'privateReverseEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'privateReverseUpstreams') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsRateLimit') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsRateLimitSubnetIpv4') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsRateLimitSubnetIpv6') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsRateLimitWhitelist') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsBlockingIpv4') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsBlockingIpv6') ||
        Object.prototype.hasOwnProperty.call(body, 'dnsBlockedResponseTtl')
      ) {
        nextConfig.dns = normalizeDnsConfig({
          ...config.dns,
          dnssecEnabled: Object.prototype.hasOwnProperty.call(body, 'dnsDnssecEnabled') ? body.dnsDnssecEnabled : config.dns.dnssecEnabled,
          disableIpv6: Object.prototype.hasOwnProperty.call(body, 'dnsDisableIpv6') ? body.dnsDisableIpv6 : config.dns.disableIpv6,
          refuseAny: Object.prototype.hasOwnProperty.call(body, 'dnsRefuseAny') ? body.dnsRefuseAny : config.dns.refuseAny,
          resolveClients: Object.prototype.hasOwnProperty.call(body, 'clientReverseDnsEnabled') ? body.clientReverseDnsEnabled : config.dns.resolveClients,
          privateReverseEnabled: Object.prototype.hasOwnProperty.call(body, 'privateReverseEnabled') ? body.privateReverseEnabled : config.dns.privateReverseEnabled,
          privateReverseUpstreams: Object.prototype.hasOwnProperty.call(body, 'privateReverseUpstreams') ? body.privateReverseUpstreams : config.dns.privateReverseUpstreams,
          rateLimit: Object.prototype.hasOwnProperty.call(body, 'dnsRateLimit') ? body.dnsRateLimit : config.dns.rateLimit,
          rateLimitSubnetIpv4: Object.prototype.hasOwnProperty.call(body, 'dnsRateLimitSubnetIpv4') ? body.dnsRateLimitSubnetIpv4 : config.dns.rateLimitSubnetIpv4,
          rateLimitSubnetIpv6: Object.prototype.hasOwnProperty.call(body, 'dnsRateLimitSubnetIpv6') ? body.dnsRateLimitSubnetIpv6 : config.dns.rateLimitSubnetIpv6,
          rateLimitWhitelist: Object.prototype.hasOwnProperty.call(body, 'dnsRateLimitWhitelist') ? body.dnsRateLimitWhitelist : config.dns.rateLimitWhitelist,
          blockingIpv4: Object.prototype.hasOwnProperty.call(body, 'dnsBlockingIpv4') ? body.dnsBlockingIpv4 : config.dns.blockingIpv4,
          blockingIpv6: Object.prototype.hasOwnProperty.call(body, 'dnsBlockingIpv6') ? body.dnsBlockingIpv6 : config.dns.blockingIpv6,
          blockedResponseTtl: Object.prototype.hasOwnProperty.call(body, 'dnsBlockedResponseTtl') ? body.dnsBlockedResponseTtl : config.dns.blockedResponseTtl
        });
      }
      if (Object.prototype.hasOwnProperty.call(body, 'timeoutMs')) nextConfig.timeoutMs = normalizeInteger(body.timeoutMs, 100, 30000, 'bad_timeout');
      if (
        Object.prototype.hasOwnProperty.call(body, 'cacheEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheMaxEntries') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheMinTtl') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheMaxTtl') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheStaleTtl') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheOptimistic') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheOptimisticAnswerTtl') ||
        Object.prototype.hasOwnProperty.call(body, 'cacheOptimisticMaxAge')
      ) {
        nextConfig.cache = normalizeCacheConfig({
          ...config.cache,
          enabled: Object.prototype.hasOwnProperty.call(body, 'cacheEnabled') ? body.cacheEnabled : config.cache.enabled,
          maxEntries: Object.prototype.hasOwnProperty.call(body, 'cacheMaxEntries') ? body.cacheMaxEntries : config.cache.maxEntries,
          minTtl: Object.prototype.hasOwnProperty.call(body, 'cacheMinTtl') ? body.cacheMinTtl : config.cache.minTtl,
          maxTtl: Object.prototype.hasOwnProperty.call(body, 'cacheMaxTtl') ? body.cacheMaxTtl : config.cache.maxTtl,
          staleTtl: Object.prototype.hasOwnProperty.call(body, 'cacheStaleTtl') ? body.cacheStaleTtl : config.cache.staleTtl,
          optimistic: Object.prototype.hasOwnProperty.call(body, 'cacheOptimistic') ? body.cacheOptimistic : config.cache.optimistic,
          optimisticAnswerTtl: Object.prototype.hasOwnProperty.call(body, 'cacheOptimisticAnswerTtl') ? body.cacheOptimisticAnswerTtl : config.cache.optimisticAnswerTtl,
          optimisticMaxAge: Object.prototype.hasOwnProperty.call(body, 'cacheOptimisticMaxAge') ? body.cacheOptimisticMaxAge : config.cache.optimisticMaxAge
        });
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'ecsEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'ecsIpv4Prefix') ||
        Object.prototype.hasOwnProperty.call(body, 'ecsIpv6Prefix') ||
        Object.prototype.hasOwnProperty.call(body, 'ecsDefaultIpv4')
      ) {
        nextConfig.ecs = normalizeEcsConfig({
          ...config.ecs,
          enabled: Object.prototype.hasOwnProperty.call(body, 'ecsEnabled') ? body.ecsEnabled : config.ecs.enabled,
          ipv4Prefix: Object.prototype.hasOwnProperty.call(body, 'ecsIpv4Prefix') ? body.ecsIpv4Prefix : config.ecs.ipv4Prefix,
          ipv6Prefix: Object.prototype.hasOwnProperty.call(body, 'ecsIpv6Prefix') ? body.ecsIpv6Prefix : config.ecs.ipv6Prefix,
          defaultIpv4: Object.prototype.hasOwnProperty.call(body, 'ecsDefaultIpv4') ? body.ecsDefaultIpv4 : config.ecs.defaultIpv4
        });
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'filterEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'rewritesEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'blockMode') ||
        Object.prototype.hasOwnProperty.call(body, 'cnameCheck') ||
        Object.prototype.hasOwnProperty.call(body, 'safeBrowsingEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'parentalEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'safeSearch')
      ) {
        nextConfig.filter = { ...config.filter };
        if (Object.prototype.hasOwnProperty.call(body, 'filterEnabled')) nextConfig.filter.enabled = Boolean(body.filterEnabled);
        if (Object.prototype.hasOwnProperty.call(body, 'rewritesEnabled')) nextConfig.filter.rewritesEnabled = body.rewritesEnabled !== false;
        if (Object.prototype.hasOwnProperty.call(body, 'blockMode')) nextConfig.filter.blockMode = normalizeBlockMode(body.blockMode);
        if (Object.prototype.hasOwnProperty.call(body, 'cnameCheck')) nextConfig.filter.cnameCheck = Boolean(body.cnameCheck);
        if (Object.prototype.hasOwnProperty.call(body, 'safeBrowsingEnabled')) {
          nextConfig.filter.safeBrowsing = { ...config.filter.safeBrowsing, enabled: body.safeBrowsingEnabled === true };
        }
        if (Object.prototype.hasOwnProperty.call(body, 'parentalEnabled')) {
          nextConfig.filter.parental = { ...config.filter.parental, enabled: body.parentalEnabled === true };
        }
        if (Object.prototype.hasOwnProperty.call(body, 'safeSearch')) nextConfig.filter.safeSearch = normalizeSafeSearchConfig(body.safeSearch);
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'queryLogEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'queryLogMaxEntries') ||
        Object.prototype.hasOwnProperty.call(body, 'queryLogRetentionHours') ||
        Object.prototype.hasOwnProperty.call(body, 'queryLogAnonymizeClientIp') ||
        Object.prototype.hasOwnProperty.call(body, 'queryLogIgnoredEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'queryLogIgnoredDomains')
      ) {
        nextConfig.queryLog = normalizeQueryLogConfig({
          ...config.queryLog,
          enabled: Object.prototype.hasOwnProperty.call(body, 'queryLogEnabled') ? body.queryLogEnabled : config.queryLog.enabled,
          maxEntries: Object.prototype.hasOwnProperty.call(body, 'queryLogMaxEntries') ? body.queryLogMaxEntries : config.queryLog.maxEntries,
          retentionHours: Object.prototype.hasOwnProperty.call(body, 'queryLogRetentionHours') ? body.queryLogRetentionHours : config.queryLog.retentionHours,
          anonymizeClientIp: Object.prototype.hasOwnProperty.call(body, 'queryLogAnonymizeClientIp') ? body.queryLogAnonymizeClientIp : config.queryLog.anonymizeClientIp,
          ignoredEnabled: Object.prototype.hasOwnProperty.call(body, 'queryLogIgnoredEnabled') ? body.queryLogIgnoredEnabled : config.queryLog.ignoredEnabled,
          ignored: Object.prototype.hasOwnProperty.call(body, 'queryLogIgnoredDomains') ? body.queryLogIgnoredDomains : config.queryLog.ignored
        });
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'statsEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'statsRetentionHours') ||
        Object.prototype.hasOwnProperty.call(body, 'statsIgnoredEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'statsIgnoredDomains')
      ) {
        nextConfig.statistics = normalizeStatisticsConfig({
          ...config.statistics,
          enabled: Object.prototype.hasOwnProperty.call(body, 'statsEnabled') ? body.statsEnabled : config.statistics.enabled,
          retentionHours: Object.prototype.hasOwnProperty.call(body, 'statsRetentionHours') ? body.statsRetentionHours : config.statistics.retentionHours,
          ignoredEnabled: Object.prototype.hasOwnProperty.call(body, 'statsIgnoredEnabled') ? body.statsIgnoredEnabled : config.statistics.ignoredEnabled,
          ignored: Object.prototype.hasOwnProperty.call(body, 'statsIgnoredDomains') ? body.statsIgnoredDomains : config.statistics.ignored
        });
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'accessAllowedClients') ||
        Object.prototype.hasOwnProperty.call(body, 'accessBlockedClients') ||
        Object.prototype.hasOwnProperty.call(body, 'accessBlockedHosts')
      ) {
        nextConfig.access = normalizeAccessConfig({
          ...config.access,
          allowedClients: Object.prototype.hasOwnProperty.call(body, 'accessAllowedClients') ? body.accessAllowedClients : config.access.allowedClients,
          blockedClients: Object.prototype.hasOwnProperty.call(body, 'accessBlockedClients') ? body.accessBlockedClients : config.access.blockedClients,
          blockedHosts: Object.prototype.hasOwnProperty.call(body, 'accessBlockedHosts') ? body.accessBlockedHosts : config.access.blockedHosts
        });
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'dhcpEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpInterfaceName') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpGateway') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpSubnetMask') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpRangeStart') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpRangeEnd') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpLeaseMinutes') ||
        Object.prototype.hasOwnProperty.call(body, 'dhcpDnsServers')
      ) {
        const dhcpCandidate = {
          ...config.dhcp,
          enabled: Object.prototype.hasOwnProperty.call(body, 'dhcpEnabled') ? body.dhcpEnabled : config.dhcp.enabled,
          interfaceName: Object.prototype.hasOwnProperty.call(body, 'dhcpInterfaceName') ? body.dhcpInterfaceName : config.dhcp.interfaceName,
          gateway: Object.prototype.hasOwnProperty.call(body, 'dhcpGateway') ? body.dhcpGateway : config.dhcp.gateway,
          subnetMask: Object.prototype.hasOwnProperty.call(body, 'dhcpSubnetMask') ? body.dhcpSubnetMask : config.dhcp.subnetMask,
          rangeStart: Object.prototype.hasOwnProperty.call(body, 'dhcpRangeStart') ? body.dhcpRangeStart : config.dhcp.rangeStart,
          rangeEnd: Object.prototype.hasOwnProperty.call(body, 'dhcpRangeEnd') ? body.dhcpRangeEnd : config.dhcp.rangeEnd,
          leaseMinutes: Object.prototype.hasOwnProperty.call(body, 'dhcpLeaseMinutes') ? body.dhcpLeaseMinutes : config.dhcp.leaseMinutes,
          dnsServers: Object.prototype.hasOwnProperty.call(body, 'dhcpDnsServers') ? body.dhcpDnsServers : config.dhcp.dnsServers
        };
        const dhcpValidation = validateDhcpConfig(dhcpCandidate, collectDhcpInterfaces(dhcpNetworkInterfaces()));
        const dnsError = dhcpValidation.errors.find((entry) => entry.field === 'dnsServers');
        if (dnsError) throw new Error(dnsError.code || 'dns_server_invalid');
        nextConfig.dhcp = normalizeDhcpConfig(dhcpCandidate);
        if (nextConfig.dhcp.enabled && !DHCP_RUNTIME_SUPPORTED) throw new Error('dhcp_runtime_unavailable');
        if (nextConfig.dhcp.enabled) {
          if (!dhcpValidation.valid) throw new Error(dhcpValidation.errors[0]?.code || 'dhcp_config_invalid');
        }
      }
      if (
        Object.prototype.hasOwnProperty.call(body, 'clientWhoisEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'clientHostsEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'clientArpEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'clientDhcpEnabled') ||
        Object.prototype.hasOwnProperty.call(body, 'clientReverseDnsEnabled')
      ) {
        const currentSources = runtimeClientSourceSettings();
        nextConfig.clients = {
          ...config.clients,
          runtimeSources: normalizeRuntimeClientSources({
            ...currentSources,
            whois: Object.prototype.hasOwnProperty.call(body, 'clientWhoisEnabled') ? body.clientWhoisEnabled : currentSources.whois,
            hosts: Object.prototype.hasOwnProperty.call(body, 'clientHostsEnabled') ? body.clientHostsEnabled : currentSources.hosts,
            arp: Object.prototype.hasOwnProperty.call(body, 'clientArpEnabled') ? body.clientArpEnabled : currentSources.arp,
            dhcp: Object.prototype.hasOwnProperty.call(body, 'clientDhcpEnabled') ? body.clientDhcpEnabled : currentSources.dhcp,
            rdns: Object.prototype.hasOwnProperty.call(body, 'clientReverseDnsEnabled') ? body.clientReverseDnsEnabled : currentSources.rdns
          }, Object.prototype.hasOwnProperty.call(body, 'clientReverseDnsEnabled') ? body.clientReverseDnsEnabled : config.dns.resolveClients)
        };
      }
      const previousConfig = config;
      const oldDohPath = config.service.dohPath;
      const oldDoqPort = config.service.doqPort;
      const oldDohEnabled = config.service.dohEnabled !== false;
      const oldDoqEnabled = config.service.doqEnabled !== false;
      const oldPlainDnsEnabled = config.service.plainDnsEnabled === true;
      const oldPlainDnsHost = config.service.plainDnsHost;
      const oldPlainDnsPort = config.service.plainDnsPort;
      const oldDhcpSignature = dhcpConfigSignature(config.dhcp);
      config = normalizeConfig(nextConfig);
      const dhcpChanged = dhcpConfigSignature(config.dhcp) !== oldDhcpSignature;
      dnsRateLimitBuckets.clear();
      domainProtectionChecker.clear();
      clearBootstrapLookupCache();
      configureQueryLogStore();
      saveConfig();
      clearDnsCaches();
      syncRuntimeClientReverseDns(previousConfig, config);
      syncRuntimeClientWhois(previousConfig, config);
      refreshRuntimeClientSources({ force: true });
      let dohSync = null;
      let dohRuntimeSync = null;
      let doqSync = null;
      let plainDnsSync = null;
      let dhcpSync = null;
      try {
        if (config.service.dohPath !== oldDohPath) {
          dohSync = await syncDohPath(config.service.dohPath);
        }
        if ((config.service.dohEnabled !== false) !== oldDohEnabled) {
          dohRuntimeSync = {
            enabled: config.service.dohEnabled !== false,
            mode: config.service.dohEnabled !== false ? 'enabled' : 'disabled'
          };
        }
        if (config.service.doqPort !== oldDoqPort || (config.service.doqEnabled !== false) !== oldDoqEnabled) {
          doqSync = await syncDoqService(config.service.doqEnabled !== false, config.service.doqPort);
        }
        if (
          config.service.plainDnsEnabled !== oldPlainDnsEnabled ||
          config.service.plainDnsHost !== oldPlainDnsHost ||
          config.service.plainDnsPort !== oldPlainDnsPort
        ) {
          plainDnsSync = await applyPlainDnsRuntime();
        }
        if (dhcpChanged) {
          dhcpSync = await applyDhcpRuntime();
        }
      } catch (err) {
        const failedConfig = config;
        config = previousConfig;
        dnsRateLimitBuckets.clear();
        domainProtectionChecker.clear();
        clearBootstrapLookupCache();
        configureQueryLogStore();
        saveConfig();
        clearDnsCaches();
        syncRuntimeClientReverseDns(failedConfig, previousConfig);
        refreshRuntimeClientSources({ force: true });
        if (failedConfig.service.dohPath !== previousConfig.service.dohPath) {
          await syncDohPath(previousConfig.service.dohPath).catch(() => {});
        }
        if (failedConfig.service.doqPort !== previousConfig.service.doqPort || (failedConfig.service.doqEnabled !== false) !== (previousConfig.service.doqEnabled !== false)) {
          await syncDoqService(previousConfig.service.doqEnabled !== false, previousConfig.service.doqPort).catch(() => {});
        }
        await applyPlainDnsRuntime().catch(() => {});
        await applyDhcpRuntime().catch(() => {});
        throw err;
      }
      const statsPruned = applyStatisticsRetention();
      trimRecentQueries();
      await queryLogStore.rotateIfDue({ force: true }).catch(() => {});
      if (statsPruned) saveStats();
      await refreshDoqRuntimeStatus({ force: true });
      json(res, 200, { ok: true, settings: getSettings(), status: getStatus(), dohSync, dohRuntimeSync, doqSync, plainDnsSync, dhcpSync });
    }).catch((err) => json(res, 400, { error: err.message || 'bad_settings' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/rules') {
    return readJson(req).then((body) => {
      const autoUpdateTargets = [];
      if (typeof body.block === 'string') fs.writeFileSync(config.rules.blockFile, normalizeTextFile(body.block));
      if (typeof body.allow === 'string') fs.writeFileSync(config.rules.allowFile, normalizeTextFile(body.allow));
      if (typeof body.rewrite === 'string') fs.writeFileSync(config.rules.rewriteFile, normalizeTextFile(body.rewrite));
      if (typeof body.subscriptions === 'string') {
        fs.writeFileSync(config.rules.subscriptionFile, normalizeSubscriptionText(body.subscriptions));
        pruneSubscriptionDownloads(getSubscriptionEntries('block'), 'block');
        autoUpdateTargets.push('block');
      }
      if (typeof body.allowSubscriptions === 'string') {
        fs.writeFileSync(config.rules.allowSubscriptionFile, normalizeSubscriptionText(body.allowSubscriptions));
        pruneSubscriptionDownloads(getSubscriptionEntries('allow'), 'allow');
        autoUpdateTargets.push('allow');
      }
      rules = loadRules();
      clearDnsCaches();
      if (config.rules.autoUpdateOnChange !== false && autoUpdateTargets.length) {
        queueSubscriptionAutoUpdate('subscription-change', autoUpdateTargets);
      }
      json(res, 200, { ok: true, status: getStatus(), subscriptionAutoUpdate: getSubscriptionAutoUpdateStatus() });
    }).catch(() => json(res, 400, { error: 'bad_json' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/rules/add') {
    return readJson(req).then((body) => {
      const target = body.target === 'allow' ? 'allow' : 'block';
      const line = buildCustomRule(body.value, target);
      if (!line) return json(res, 400, { error: 'bad_rule' });
      const file = target === 'allow' ? config.rules.allowFile : config.rules.blockFile;
      const lines = readPlainLines(file);
      if (!lines.some((item) => item.trim() === line)) {
        fs.writeFileSync(file, normalizeTextFile([...lines, line].join('\n')));
      }
      rules = loadRules();
      clearDnsCaches();
      json(res, 200, { ok: true, rule: line, target, status: getStatus() });
    }).catch(() => json(res, 400, { error: 'bad_json' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/rules/delete') {
    return readJson(req).then((body) => {
      const target = body.target === 'allow' ? 'allow' : 'block';
      const value = String(body.value || '').trim();
      if (!value) return json(res, 400, { error: 'bad_rule' });
      const file = target === 'allow' ? config.rules.allowFile : config.rules.blockFile;
      const lines = readPlainLines(file).filter((line) => line.trim() !== value);
      fs.writeFileSync(file, normalizeTextFile(lines.join('\n')));
      rules = loadRules();
      clearDnsCaches();
      json(res, 200, { ok: true, target, status: getStatus() });
    }).catch(() => json(res, 400, { error: 'bad_json' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/reload') {
    rules = loadRules();
    clearDnsCaches();
    return json(res, 200, { ok: true, status: getStatus() });
  }
  if (req.method === 'POST' && url.pathname === '/api/update-subscriptions') {
    return readJson(req).catch(() => ({})).then((body) => updateSubscriptions(body.target === 'allow' ? 'allow' : 'block')).then((result) => {
      rules = loadRules();
      clearDnsCaches();
      json(res, 200, { ok: true, result, status: getStatus(), subscriptionAutoUpdate: getSubscriptionAutoUpdateStatus() });
    }).catch((err) => json(res, 500, { error: err.message || 'update_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/blocked-services') {
    return readJson(req).then((body) => {
      const nextFilter = { ...config.filter };
      if (Object.prototype.hasOwnProperty.call(body, 'enabled')) {
        nextFilter.blockedServices = normalizeBlockedServices(body.enabled);
      }
      if (Object.prototype.hasOwnProperty.call(body, 'ids')) {
        nextFilter.blockedServices = normalizeBlockedServices(body.ids);
      }
      if (Object.prototype.hasOwnProperty.call(body, 'schedule')) {
        nextFilter.blockedServicesSchedule = normalizeBlockedServicesSchedule(body.schedule);
      }
      config.filter = nextFilter;
      saveConfig();
      clearDnsCaches();
      json(res, 200, { ok: true, blockedServices: getBlockedServices(), status: getStatus() });
    }).catch(() => json(res, 400, { error: 'bad_json' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/test-upstreams') {
    return readJson(req).then(async (body) => {
      const upstreams = Object.prototype.hasOwnProperty.call(body, 'upstreams') ? normalizeUpstreams(body.upstreams) : config.upstreams;
      const fallbackUpstreams = Object.prototype.hasOwnProperty.call(body, 'fallbackUpstreams')
        ? normalizeOptionalUpstreams(body.fallbackUpstreams, 'bad_fallback_upstream')
        : config.fallbackUpstreams;
      const bootstrapDns = Object.prototype.hasOwnProperty.call(body, 'bootstrapDns') ? normalizeBootstrapDns(body.bootstrapDns) : config.bootstrapDns;
      const privateReverseUpstreams = Object.prototype.hasOwnProperty.call(body, 'privateReverseUpstreams')
        ? normalizeUpstreamConfiguration(body.privateReverseUpstreams, { errorCode: 'bad_private_reverse_upstream' })
        : config.dns.privateReverseUpstreams;
      const timeoutMs = Object.prototype.hasOwnProperty.call(body, 'timeoutMs') ? normalizeInteger(body.timeoutMs, 100, 30000, 'bad_timeout') : config.timeoutMs;
      const name = normalizeDomain(body.name || 'example.com');
      const type = String(body.type || 'A').toUpperCase();
      if (!name || !QTYPE[type]) return json(res, 400, { error: 'bad_query' });
      const packet = buildQuery(name, QTYPE[type]);
      const dnssecEnabled = Object.prototype.hasOwnProperty.call(body, 'dnssecEnabled')
        ? body.dnssecEnabled === true
        : config.dns.dnssecEnabled === true;
      const testPacket = dnssecEnabled ? enableDnssecRequest(packet) : packet;
      const transportOptions = bootstrapDns.length ? { lookup: createBootstrapLookup(bootstrapDns, timeoutMs) } : {};
      const upstreamEntries = upstreamConfigurationEntries(upstreams);
      const privateReverseEntries = upstreamConfigurationEntries(privateReverseUpstreams);
      const selected = selectUpstreamConfiguration(upstreams, name, QTYPE[type], { defaultRoute: '默认上游' });
      const results = await Promise.all([
        ...upstreamEntries.map((entry) => testSingleUpstream(entry.upstream, testPacket, timeoutMs, {
          role: 'primary',
          route: summarizeUpstreamRoutes(entry.routes),
          routeCount: entry.routes.length,
          transportOptions
        })),
        ...fallbackUpstreams.map((upstream) => testSingleUpstream(upstream, testPacket, timeoutMs, { role: 'fallback', route: '后备 DNS', transportOptions })),
        ...bootstrapDns.map((upstream) => testSingleUpstream(upstream, testPacket, timeoutMs, { role: 'bootstrap', route: 'Bootstrap' })),
        ...privateReverseEntries.map((entry) => testSingleUpstream(entry.upstream, testPacket, timeoutMs, {
          role: 'private-reverse',
          route: summarizeUpstreamRoutes(entry.routes, '私有反向默认上游'),
          routeCount: entry.routes.length,
          transportOptions
        }))
      ]);
      json(res, 200, {
        ok: true,
        name,
        type,
        timeoutMs,
        dnssecEnabled,
        selectedRoute: selected?.route || '',
        selectedUpstreams: selected?.upstreams || [],
        configuration: upstreamConfigurationSummary(upstreams),
        privateReverseConfiguration: upstreamConfigurationSummary(privateReverseUpstreams),
        results
      });
    }).catch((err) => json(res, 400, { error: err.message || 'test_upstreams_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/filter/check') {
    return readJson(req).then(async (body) => {
      const name = normalizeDomain(body.name || body.hostname || '');
      const type = String(body.type || body.qtype || 'A').trim().toUpperCase();
      const qtype = dnsRuleTypeCode(type);
      const requestedClient = String(body.clientIp || body.client || '').trim();
      const clientIp = normalizeIpLiteral(requestedClient || getClientIp(req));
      if (!name || name.length > 253 || !qtype) return json(res, 400, { error: 'bad_query' });
      if (!net.isIP(clientIp)) return json(res, 400, { error: 'bad_client' });
      json(res, 200, await checkFilteringPolicy(name, qtype, clientIp));
    }).catch((err) => json(res, 500, { error: err.message || 'filter_check_failed' }));
  }
  if (req.method === 'POST' && url.pathname === '/api/test') {
    return readJson(req).then(async (body) => {
      const name = normalizeDomain(body.name || '');
      const type = String(body.type || 'A').toUpperCase();
      if (!name || !QTYPE[type]) return json(res, 400, { error: 'bad_query' });
      const packet = buildQuery(name, QTYPE[type]);
      const response = await resolveDns(packet, body.clientIp || getClientIp(req), 'test');
      json(res, 200, decodeDnsResponse(response));
    }).catch((err) => json(res, 500, { error: err.message || 'test_failed' }));
  }
  notFound(res);
}

function isAuthorized(req) {
  return isSessionValid(parseCookies(req).cleandns_session);
}

function dashboardPeriodOptions(maxHours) {
  const max = Math.max(1, Math.floor(Number(maxHours) || 24));
  return [...new Set([24, 7 * 24, 30 * 24, 90 * 24]
    .filter((hours) => hours <= max)
    .concat(max))]
    .sort((a, b) => a - b);
}

function normalizeDashboardPeriodHours(value, maxHours) {
  const max = Math.max(1, Math.floor(Number(maxHours) || 24));
  if (value === undefined || value === null || value === '') return max;
  const requested = Math.floor(Number(value));
  if (!Number.isFinite(requested) || requested < 1) return max;
  return Math.min(requested, max);
}

function getStatus(requestedPeriod = null) {
  const now = Date.now();
  const maxPeriodHours = Math.max(1, Number(config.statistics.retentionHours) || 24);
  const periodHours = normalizeDashboardPeriodHours(requestedPeriod, maxPeriodHours);
  const periodBuckets = pruneStatsBuckets(statsBuckets, periodHours, now);
  const periodStats = periodHours === maxPeriodHours ? stats : aggregateStatsBuckets(periodBuckets);
  const settings = getSettings();
  const runtimeClientList = getRuntimeClients();
  const clientCache = clientCacheStats();
  const dhcpStatus = getDhcpStatus();
  const averageProcessingMs = periodStats.processingCount > 0
    ? periodStats.processingTimeMs / periodStats.processingCount
    : 0;
  const publicStats = { ...periodStats };
  delete publicStats.byDomain;
  delete publicStats.byBlockedDomain;
  delete publicStats.byClient;
  return {
    domain: config.domain,
    uptime: Math.floor((Date.now() - startedAt) / 1000),
    node: process.version,
    host: os.hostname(),
    startedAt: new Date(startedAt).toISOString(),
    http: config.http,
    udp: config.udp,
    rules: {
      loadedAt: new Date(rules.loadedAt).toISOString(),
      block: rules.blockCount,
      allow: rules.allowCount,
      rewrite: rules.rewriteCount,
      dedicatedRewrite: rules.dedicatedRewriteCount,
      filterRewrite: rules.filterRewriteCount,
      filterRewriteException: rules.filterRewriteExceptionCount,
      hosts: rules.hostRuleCount,
      safeSearch: safeSearchRuleCount(),
      subscriptionAutoUpdate: getSubscriptionAutoUpdateStatus()
    },
    cache: {
      enabled: config.cache.enabled !== false,
      entries: cache.size,
      globalEntries: cache.size,
      clientCaches: clientCache.caches,
      clientEntries: clientCache.entries,
      clientBytes: clientCache.bytes,
      totalEntries: cache.size + clientCache.entries,
      optimistic: config.cache.optimistic === true,
      optimisticAnswerTtl: config.cache.optimisticAnswerTtl,
      optimisticMaxAge: config.cache.optimisticMaxAge,
      optimisticRefreshes: optimisticRefreshes.size,
      maxEntries: config.cache.maxEntries,
      minTtl: config.cache.minTtl,
      maxTtl: config.cache.maxTtl,
      staleTtl: config.cache.staleTtl
    },
    stats: {
      ...publicStats,
      avgProcessingMs: averageProcessingMs
    },
    statistics: {
      enabled: config.statistics.enabled !== false,
      retentionHours: config.statistics.retentionHours,
      periodHours,
      maxPeriodHours,
      periodOptions: dashboardPeriodOptions(maxPeriodHours),
      buckets: periodBuckets.length,
      totalBuckets: statsBuckets.length,
      ignoredEnabled: config.statistics.ignoredEnabled === true,
      ignored: config.statistics.ignored || [],
      series: buildStatsSeries(statsBuckets, periodHours, now)
    },
    dashboard: getDashboardStats(periodHours, periodStats, now),
    endpoints: {
      doh: settings.dohUrl,
      panel: settings.panelPublicUrl,
      doq: formatDoqEndpoint(settings.doqEndpoint, settings.doqPort),
      plainDns: `${settings.plainDnsHost}:${settings.plainDnsPort}`
    },
    protocols: {
      plainDns: {
        enabled: settings.plainDnsEnabled,
        running: plainDnsRuntime.udp === true && plainDnsRuntime.tcp === true,
        udp: plainDnsRuntime.udp === true,
        tcp: plainDnsRuntime.tcp === true,
        host: settings.plainDnsHost,
        port: settings.plainDnsPort,
        error: plainDnsRuntime.error || ''
      },
      doh: {
        enabled: settings.dohEnabled,
        running: settings.dohEnabled,
        path: settings.dohPath,
        url: settings.dohUrl
      },
      doq: {
        enabled: settings.doqEnabled,
        running: settings.doqEnabled && doqRuntimeStatus.running === true,
        verified: settings.doqEnabled ? doqRuntimeStatus.verified === true : true,
        state: settings.doqEnabled ? doqRuntimeStatus.activeState : 'disabled',
        subState: settings.doqEnabled ? doqRuntimeStatus.subState : 'disabled',
        pid: settings.doqEnabled ? doqRuntimeStatus.pid : 0,
        error: settings.doqEnabled ? doqRuntimeStatus.error : '',
        checkedAt: doqRuntimeStatus.checkedAt,
        host: settings.doqEndpoint,
        port: settings.doqPort,
        endpoint: formatDoqEndpoint(settings.doqEndpoint, settings.doqPort)
      }
    },
    filter: {
      ...config.filter,
      blockMode: blockModeLabel(config.filter.blockMode),
      blockModeValue: config.filter.blockMode,
      displayMode: blockModeLabel(config.filter.blockMode),
      modeText: blockModeLabel(config.filter.blockMode),
      blockModeLabel: blockModeLabel(config.filter.blockMode),
      blockModeText: blockModeLabel(config.filter.blockMode)
    },
    domainProtection: domainProtectionChecker.status(),
    protection: protectionStatus(),
    queryLog: {
      enabled: config.queryLog.enabled !== false,
      maxEntries: config.queryLog.maxEntries,
      retentionHours: config.queryLog.retentionHours,
      anonymizeClientIp: config.queryLog.anonymizeClientIp !== false,
      ignoredEnabled: config.queryLog.ignoredEnabled === true,
      ignored: config.queryLog.ignored || [],
      entries: recentQueries.length,
      memoryEntries: recentQueries.length,
      storage: queryLogStore.status()
    },
    access: {
      allowedClients: config.access.allowedClients,
      blockedClients: config.access.blockedClients,
      blockedHosts: config.access.blockedHosts
    },
    blockedServices: getBlockedServices(),
    clients: {
      count: clients.length,
      runtimeCount: runtimeClientList.length,
      runtimeSources: getRuntimeClientSourceStatus(),
      customUpstreams: clients.filter((client) => hasConfiguredUpstreamPolicy(client.upstreams)).length,
      customUpstreamCaches: clients.filter((client) => (
        hasConfiguredUpstreamPolicy(client.upstreams) &&
        client.upstreamsCacheEnabled === true &&
        normalizeClientCacheSize(client.upstreamsCacheSize) > 0
      )).length,
      customProtection: clients.filter((client) => client.useGlobalSettings === false).length,
      customSafeBrowsing: clients.filter((client) => client.useGlobalSettings === false && client.safeBrowsingEnabled === true).length,
      customParental: clients.filter((client) => client.useGlobalSettings === false && client.parentalEnabled === true).length,
      customSafeSearch: clients.filter((client) => client.useGlobalSettings === false && client.safeSearch?.enabled === true).length,
      customBlockedServices: clients.filter((client) => client.useGlobalBlockedServices === false).length,
      filteringDisabled: clients.filter((client) => client.disableFiltering === true).length,
      ecsDisabled: clients.filter((client) => client.disableEcs === true).length
    },
    dhcp: {
      enabled: dhcpStatus.enabled,
      configured: dhcpStatus.configured,
      supported: dhcpStatus.supported,
      running: dhcpStatus.running,
      state: dhcpStatus.state,
      reason: dhcpStatus.reason,
      interfaceName: dhcpStatus.interfaceName,
      serverAddress: dhcpStatus.serverAddress,
      port: dhcpStatus.port,
      validation: dhcpStatus.validation,
      staticLeaseCount: dhcpStatus.staticLeases.length,
      leaseCount: dhcpStatus.leases.length
    },
    ecs: config.ecs,
    dns: config.dns,
    timeoutMs: config.timeoutMs,
    upstreamMode: config.upstreamMode,
    service: {
      dohPath: settings.dohPath,
      dohPrefix: settings.dohPrefix,
      dohEnabled: settings.dohEnabled,
      plainDnsEnabled: settings.plainDnsEnabled,
      plainDnsHost: settings.plainDnsHost,
      plainDnsPort: settings.plainDnsPort,
      doqEnabled: settings.doqEnabled,
      doqPort: settings.doqPort,
      doqMode: settings.doqEnabled ? 'native' : 'disabled',
      dnsEngine: 'CleanDNS 统一 DNS 内核',
      doqEngine: 'CleanDNS 统一 DNS 内核',
      doqRuntime: 'CleanDNS 主服务托管的原生子进程',
      doqModule: 'CleanDNS 原生 DoQ 入口',
      doqTransport: 'quic-go',
      doqCacheOwner: 'cleandns-core',
      doqProcessModel: 'main-service-managed-child',
      doqParentPid: process.pid,
      doqCoreEndpoint: `${config.udp.host}:${config.udp.port}`,
      doqPid: settings.doqEnabled ? doqRuntimeStatus.pid : 0
    },
    upstreams: config.upstreams,
    upstreamConfiguration: upstreamConfigurationSummary(config.upstreams),
    fallbackUpstreams: config.fallbackUpstreams || [],
    bootstrapDns: config.bootstrapDns || []
  };
}

function getRuntimeClientSourceStatus() {
  const enabled = runtimeClientSourceSettings();
  return {
    whois: {
      enabled: enabled.whois === true,
      ...runtimeWhoisResolver.status()
    },
    hosts: {
      enabled: enabled.hosts === true,
      count: enabled.hosts ? runtimeClientSourceCache.hosts.records.size : 0,
      refreshedAt: runtimeClientSourceCache.hosts.refreshedAt ? new Date(runtimeClientSourceCache.hosts.refreshedAt).toISOString() : '',
      error: enabled.hosts ? runtimeClientSourceCache.hosts.error : ''
    },
    arp: {
      enabled: enabled.arp === true,
      count: enabled.arp ? runtimeClientSourceCache.arp.records.size : 0,
      refreshedAt: runtimeClientSourceCache.arp.refreshedAt ? new Date(runtimeClientSourceCache.arp.refreshedAt).toISOString() : '',
      error: enabled.arp ? runtimeClientSourceCache.arp.error : ''
    },
    dhcp: { enabled: enabled.dhcp === true },
    rdns: { enabled: enabled.rdns === true }
  };
}

function getDashboardStats(periodHours = config.statistics.retentionHours, periodStats = stats, now = Date.now()) {
  const bounds = dashboardWindowBounds(periodHours, now);
  const effectiveStart = Math.max(bounds.start, Number(statsResetAt) || 0);
  const statisticsTotal = Number(periodStats.total || 0);
  const rankingCount = Number(periodStats.rankingCount || 0);
  return {
    window: rankingCount,
    retentionHours: bounds.retentionHours,
    startedAt: new Date(effectiveStart).toISOString(),
    endedAt: bounds.endedAt,
    resetAt: statsResetAt ? new Date(statsResetAt).toISOString() : '',
    statisticsTotal,
    coverage: config.statistics.enabled === false
      ? 'disabled'
      : rankingCount >= statisticsTotal
        ? 'complete'
        : 'partial',
    rankingSource: 'statistics',
    topQueriedDomains: topCountsFromMap(periodStats.byDomain),
    topBlockedDomains: topCountsFromMap(periodStats.byBlockedDomain),
    topClients: topCountsFromMap(periodStats.byClient),
    upstreams: getDashboardUpstreams(periodStats)
  };
}

function getDashboardUpstreams(periodStats = stats) {
  const activeUpstreams = getActiveUpstreamNames();
  return [...activeUpstreams].map((name) => {
    const item = periodStats.upstreams?.[name] || {};
    const responses = item.responses || 0;
    return {
      name,
      responses,
      errors: item.errors || 0,
      avgMs: responses ? Math.round((item.totalMs || 0) / responses) : 0
    };
  }).sort((a, b) => b.responses - a.responses || a.name.localeCompare(b.name)).slice(0, 8);
}

function getActiveUpstreamNames() {
  const upstreams = new Set();
  addConfiguredUpstreamNames(upstreams, config.upstreams);
  for (const upstream of config.fallbackUpstreams || []) addActiveUpstreamName(upstreams, upstream);
  for (const client of clients || []) {
    addConfiguredUpstreamNames(upstreams, client.upstreams);
  }
  if (config.dns?.privateReverseEnabled === true) {
    addConfiguredUpstreamNames(upstreams, config.dns?.privateReverseUpstreams);
  }
  return upstreams;
}

function addConfiguredUpstreamNames(upstreams, lines) {
  for (const upstream of upstreamConfigurationTargets(lines || [])) addActiveUpstreamName(upstreams, upstream);
}

function summarizeUpstreamRoutes(routes, defaultLabel = '默认上游') {
  const labels = (routes || []).map((route) => route === 'default' ? defaultLabel : route);
  const visible = labels.slice(0, 3).map((label) => label.length > 120 ? `${label.slice(0, 117)}...` : label);
  if (labels.length > visible.length) visible.push(`另 ${labels.length - visible.length} 条规则`);
  return visible.join(' / ');
}

function hasConfiguredUpstreamPolicy(lines) {
  const summary = upstreamConfigurationSummary(lines || []);
  return summary.targets > 0 || summary.routes > 0;
}

function addActiveUpstreamName(upstreams, value) {
  const upstream = String(value || '').trim();
  if (upstream) upstreams.add(upstream);
}

function topCountsFromMap(value, limit = 8) {
  return Object.entries(value || {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

function getBlockedServices() {
  const enabled = normalizeBlockedServices(config.filter.blockedServices || []);
  const schedule = normalizeBlockedServicesSchedule(config.filter.blockedServicesSchedule);
  const rulesTotal = BLOCKED_SERVICE_CATALOG.reduce((total, item) => total + Number(item.rules?.length || 0), 0);
  const domainsTotal = BLOCKED_SERVICE_CATALOG.reduce((total, item) => total + Number(item.domains?.length || 0), 0);
  const iconsTotal = BLOCKED_SERVICE_CATALOG.reduce((total, item) => total + (item.iconSvg ? 1 : 0), 0);
  return {
    enabled,
    schedule,
    scheduleStatus: blockedServicesScheduleStatus(schedule),
    groups: BLOCKED_SERVICE_GROUPS,
    source: BLOCKED_SERVICE_DATA.source || '',
    sourceProject: BLOCKED_SERVICE_DATA.sourceProject || '',
    generatedAt: BLOCKED_SERVICE_DATA.generatedAt || '',
    autoUpdate: getBlockedServicesAutoUpdateStatus(),
    totals: {
      services: BLOCKED_SERVICE_CATALOG.length,
      groups: BLOCKED_SERVICE_GROUPS.length,
      rules: rulesTotal,
      domains: domainsTotal,
      icons: iconsTotal
    },
    catalog: BLOCKED_SERVICE_CATALOG.map((item) => ({
      id: item.id,
      name: item.name,
      group: item.group,
      groupName: item.groupName,
      domains: item.domains,
      rules: item.rules || [],
      rulesCount: item.rules?.length || item.domains.length,
      iconSvg: item.iconSvg || '',
      enabled: enabled.includes(item.id)
    }))
  };
}

function getProtocolStatus() {
  const settings = getSettings();
  return {
    plainDns: {
      enabled: settings.plainDnsEnabled,
      running: plainDnsRuntime.udp === true && plainDnsRuntime.tcp === true,
      udp: plainDnsRuntime.udp === true,
      tcp: plainDnsRuntime.tcp === true,
      host: settings.plainDnsHost,
      port: settings.plainDnsPort,
      endpoint: `${settings.plainDnsHost}:${settings.plainDnsPort}`,
      error: plainDnsRuntime.error || ''
    },
    doh: {
      enabled: settings.dohEnabled,
      running: settings.dohEnabled,
      path: settings.dohPath,
      url: settings.dohUrl
    },
    doq: {
      enabled: settings.doqEnabled,
      running: settings.doqEnabled && doqRuntimeStatus.running === true,
      verified: settings.doqEnabled ? doqRuntimeStatus.verified === true : true,
      state: settings.doqEnabled ? doqRuntimeStatus.activeState : 'disabled',
      subState: settings.doqEnabled ? doqRuntimeStatus.subState : 'disabled',
      pid: settings.doqEnabled ? doqRuntimeStatus.pid : 0,
      error: settings.doqEnabled ? doqRuntimeStatus.error : '',
      checkedAt: doqRuntimeStatus.checkedAt,
      host: settings.doqEndpoint,
      port: settings.doqPort,
      endpoint: formatDoqEndpoint(settings.doqEndpoint, settings.doqPort),
      engine: 'CleanDNS 统一 DNS 内核',
      processModel: 'main-service-managed-child',
      parentPid: process.pid,
      coreEndpoint: `${config.udp.host}:${config.udp.port}`
    }
  };
}

function tlsConfigurationCandidate(body = {}) {
  const service = { ...config.service };
  if (Object.prototype.hasOwnProperty.call(body, 'certificatePath')) {
    service.doqTlsCertFile = normalizeTlsFilePath(body.certificatePath, 'bad_tls_certificate_path');
  }
  if (Object.prototype.hasOwnProperty.call(body, 'privateKeyPath')) {
    service.doqTlsKeyFile = normalizeTlsFilePath(body.privateKeyPath, 'bad_tls_private_key_path');
  }
  return { ...config, service };
}

function protocolResetService(currentService, domain) {
  return {
    ...currentService,
    dohEnabled: true,
    plainDnsEnabled: false,
    plainDnsHost: '0.0.0.0',
    plainDnsPort: 53,
    doqEnabled: true,
    doqEndpoint: normalizeDoqEndpoint(domain, domain),
    doqPort: 853
  };
}

function getProtocolResetPreview() {
  const next = protocolResetService(config.service, config.domain);
  return {
    defaults: {
      plainDns: { enabled: next.plainDnsEnabled === true, host: next.plainDnsHost, port: next.plainDnsPort },
      doh: { enabled: next.dohEnabled !== false, path: next.dohPath },
      doq: { enabled: next.doqEnabled !== false, host: next.doqEndpoint, port: next.doqPort }
    },
    preserved: {
      dohPath: next.dohPath,
      dohPublicBaseUrl: next.dohPublicBaseUrl,
      panelPath: next.panelPath,
      panelPublicUrl: next.panelPublicUrl,
      certificatePath: next.doqTlsCertFile,
      privateKeyPath: next.doqTlsKeyFile
    }
  };
}

function protocolBodyToService(body, currentService) {
  const nextService = { ...currentService };
  if (Object.prototype.hasOwnProperty.call(body, 'dohEnabled')) nextService.dohEnabled = body.dohEnabled !== false;
  if (Object.prototype.hasOwnProperty.call(body, 'dohPath')) nextService.dohPath = normalizeDohPath(body.dohPath);
  if (Object.prototype.hasOwnProperty.call(body, 'dohPrefix')) nextService.dohPath = `${normalizeDohPrefix(body.dohPrefix)}/dns-query`;
  if (Object.prototype.hasOwnProperty.call(body, 'plainDnsEnabled')) nextService.plainDnsEnabled = body.plainDnsEnabled === true;
  if (Object.prototype.hasOwnProperty.call(body, 'plainDnsHost')) nextService.plainDnsHost = normalizePlainDnsHost(body.plainDnsHost);
  if (Object.prototype.hasOwnProperty.call(body, 'plainDnsPort')) nextService.plainDnsPort = normalizePort(body.plainDnsPort || 53);
  if (Object.prototype.hasOwnProperty.call(body, 'doqEnabled')) nextService.doqEnabled = body.doqEnabled !== false;
  if (Object.prototype.hasOwnProperty.call(body, 'doqEndpoint')) nextService.doqEndpoint = normalizeDoqEndpoint(body.doqEndpoint, config.domain);
  if (Object.prototype.hasOwnProperty.call(body, 'doqPort')) nextService.doqPort = normalizePort(body.doqPort || 853);
  return nextService;
}

async function commitServiceConfig(nextService) {
  const previousConfig = config;
  const oldDohPath = config.service.dohPath;
  const oldDohEnabled = config.service.dohEnabled !== false;
  const oldDoqPort = config.service.doqPort;
  const oldDoqEnabled = config.service.doqEnabled !== false;
  const oldDoqTlsCertFile = config.service.doqTlsCertFile;
  const oldDoqTlsKeyFile = config.service.doqTlsKeyFile;
  const oldPlainDnsEnabled = config.service.plainDnsEnabled === true;
  const oldPlainDnsHost = config.service.plainDnsHost;
  const oldPlainDnsPort = config.service.plainDnsPort;
  config = normalizeConfig({ ...config, service: nextService });
  const doqTlsChanged = config.service.doqTlsCertFile !== oldDoqTlsCertFile || config.service.doqTlsKeyFile !== oldDoqTlsKeyFile;
  saveConfig();
  let dohSync = null;
  let dohRuntimeSync = null;
  let doqSync = null;
  let plainDnsSync = null;
  try {
    if (config.service.dohPath !== oldDohPath) {
      dohSync = await syncDohPath(config.service.dohPath);
    }
    if ((config.service.dohEnabled !== false) !== oldDohEnabled) {
      dohRuntimeSync = {
        enabled: config.service.dohEnabled !== false,
        mode: config.service.dohEnabled !== false ? 'enabled' : 'disabled'
      };
    }
    if (config.service.doqPort !== oldDoqPort || (config.service.doqEnabled !== false) !== oldDoqEnabled || (doqTlsChanged && config.service.doqEnabled !== false)) {
      doqSync = await syncDoqService(config.service.doqEnabled !== false, config.service.doqPort);
    }
    if (
      config.service.plainDnsEnabled !== oldPlainDnsEnabled ||
      config.service.plainDnsHost !== oldPlainDnsHost ||
      config.service.plainDnsPort !== oldPlainDnsPort
    ) {
      plainDnsSync = await applyPlainDnsRuntime();
    }
  } catch (err) {
    const failedConfig = config;
    config = previousConfig;
    saveConfig();
    if (failedConfig.service.dohPath !== previousConfig.service.dohPath) {
      await syncDohPath(previousConfig.service.dohPath).catch(() => {});
    }
    if (
      failedConfig.service.doqPort !== previousConfig.service.doqPort ||
      (failedConfig.service.doqEnabled !== false) !== (previousConfig.service.doqEnabled !== false) ||
      failedConfig.service.doqTlsCertFile !== previousConfig.service.doqTlsCertFile ||
      failedConfig.service.doqTlsKeyFile !== previousConfig.service.doqTlsKeyFile
    ) {
      await syncDoqService(previousConfig.service.doqEnabled !== false, previousConfig.service.doqPort).catch(() => {});
    }
    await applyPlainDnsRuntime().catch(() => {});
    throw err;
  }
  return { dohSync, dohRuntimeSync, doqSync, plainDnsSync };
}

function getSettings() {
  const dohPath = config.service.dohPath || '/dns-query';
  return {
    domain: config.domain,
    dohPath,
    dohPrefix: getDohPrefix(),
    dohEnabled: config.service.dohEnabled !== false,
    dohPublicBaseUrl: config.service.dohPublicBaseUrl,
    dohUrl: `${config.service.dohPublicBaseUrl}${dohPath}`,
    panelPath: config.service.panelPath,
    panelPublicUrl: config.service.panelPublicUrl,
    plainDnsEnabled: config.service.plainDnsEnabled === true,
    plainDnsHost: config.service.plainDnsHost,
    plainDnsPort: config.service.plainDnsPort,
    doqEnabled: config.service.doqEnabled !== false,
    doqEndpoint: config.service.doqEndpoint,
    doqPort: config.service.doqPort,
    tlsCertificatePath: config.service.doqTlsCertFile,
    tlsPrivateKeyPath: config.service.doqTlsKeyFile,
    clientWhoisEnabled: runtimeClientSourceSettings().whois === true,
    clientHostsEnabled: runtimeClientSourceSettings().hosts === true,
    clientArpEnabled: runtimeClientSourceSettings().arp === true,
    clientDhcpEnabled: runtimeClientSourceSettings().dhcp === true,
    clientReverseDnsEnabled: config.dns.resolveClients === true,
    privateReverseEnabled: config.dns.privateReverseEnabled === true,
    privateReverseUpstreams: config.dns.privateReverseUpstreams || [],
    filterEnabled: config.filter.enabled !== false,
    rewritesEnabled: config.filter.rewritesEnabled !== false,
    blockMode: config.filter.blockMode,
    blockModeText: blockModeLabel(config.filter.blockMode),
    blockModeLabel: blockModeLabel(config.filter.blockMode),
    cnameCheck: config.filter.cnameCheck !== false,
    safeSearch: { ...config.filter.safeSearch },
    safeBrowsingEnabled: config.filter.safeBrowsing.enabled === true,
    parentalEnabled: config.filter.parental.enabled === true,
    statsEnabled: config.statistics.enabled !== false,
    statsRetentionHours: config.statistics.retentionHours,
    statsIgnoredEnabled: config.statistics.ignoredEnabled === true,
    statsIgnoredDomains: config.statistics.ignored || [],
    queryLogEnabled: config.queryLog.enabled !== false,
    queryLogMaxEntries: config.queryLog.maxEntries,
    queryLogRetentionHours: config.queryLog.retentionHours,
    queryLogAnonymizeClientIp: config.queryLog.anonymizeClientIp !== false,
    queryLogIgnoredEnabled: config.queryLog.ignoredEnabled === true,
    queryLogIgnoredDomains: config.queryLog.ignored || [],
    accessAllowedClients: config.access.allowedClients,
    accessBlockedClients: config.access.blockedClients,
    accessBlockedHosts: config.access.blockedHosts,
    dnsDnssecEnabled: config.dns.dnssecEnabled === true,
    dnsDisableIpv6: config.dns.disableIpv6 === true,
    dnsRefuseAny: config.dns.refuseAny !== false,
    dnsRateLimit: config.dns.rateLimit,
    dnsRateLimitSubnetIpv4: config.dns.rateLimitSubnetIpv4,
    dnsRateLimitSubnetIpv6: config.dns.rateLimitSubnetIpv6,
    dnsRateLimitWhitelist: config.dns.rateLimitWhitelist || [],
    dnsBlockingIpv4: config.dns.blockingIpv4,
    dnsBlockingIpv6: config.dns.blockingIpv6,
    dnsBlockedResponseTtl: config.dns.blockedResponseTtl,
    timeoutMs: config.timeoutMs,
    upstreamMode: config.upstreamMode,
    cacheMaxEntries: config.cache.maxEntries,
    cacheEnabled: config.cache.enabled !== false,
    cacheMinTtl: config.cache.minTtl,
    cacheMaxTtl: config.cache.maxTtl,
    cacheStaleTtl: config.cache.staleTtl,
    cacheOptimistic: config.cache.optimistic === true,
    cacheOptimisticAnswerTtl: config.cache.optimisticAnswerTtl,
    cacheOptimisticMaxAge: config.cache.optimisticMaxAge,
    ecsEnabled: config.ecs.enabled !== false,
    ecsIpv4Prefix: config.ecs.ipv4Prefix,
    ecsIpv6Prefix: config.ecs.ipv6Prefix,
    ecsDefaultIpv4: config.ecs.defaultIpv4,
    dhcpEnabled: config.dhcp.enabled === true,
    dhcpInterfaceName: config.dhcp.interfaceName || '',
    dhcpGateway: config.dhcp.gateway || '',
    dhcpSubnetMask: config.dhcp.subnetMask || '',
    dhcpRangeStart: config.dhcp.rangeStart || '',
    dhcpRangeEnd: config.dhcp.rangeEnd || '',
    dhcpLeaseMinutes: config.dhcp.leaseMinutes,
    dhcpDnsServers: config.dhcp.dnsServers || [],
    dhcpStaticLeases: config.dhcp.staticLeases || [],
    dhcpRuntimeSupported: DHCP_RUNTIME_SUPPORTED,
    subscriptionAutoUpdate: getSubscriptionAutoUpdateStatus(),
    blockedServicesAutoUpdate: getBlockedServicesAutoUpdateStatus(),
    upstreams: config.upstreams,
    upstreamConfiguration: upstreamConfigurationSummary(config.upstreams),
    fallbackUpstreams: config.fallbackUpstreams || [],
    bootstrapDns: config.bootstrapDns || []
  };
}

async function refreshDoqRuntimeStatus(options = {}) {
  const enabled = config.service.doqEnabled !== false;
  if (!enabled) return doqRuntimeStatus = doqRuntime.snapshot();
  const checkedAt = Date.parse(doqRuntimeStatus.checkedAt || '') || 0;
  if (!options.force && checkedAt && Date.now() - checkedAt < DOQ_RUNTIME_REFRESH_MS) return doqRuntimeStatus;
  doqRuntimeStatus = doqRuntime.snapshot();
  return doqRuntimeStatus;
}

async function syncDoqService(enabled, _port) {
  doqRuntimeStatus = await doqRuntime.sync({
    enabled,
    configPath: CONFIG_PATH,
    listen: DOQ_RUNTIME_LISTEN
  });
  return doqRuntimeStatus;
}

function syncDohPath(dohPath) {
  return new Promise((resolve, reject) => {
    const command = config.service.dohSyncCommand;
    if (!command) return reject(new Error('doh_sync_not_configured'));
    const child = spawn(command, [String(dohPath)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) return resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
      reject(new Error((stderr || stdout || `doh sync failed ${code}`).trim()));
    });
  });
}

async function updateSubscriptions(target = 'block') {
  const entries = getSubscriptionEntries(target);
  pruneSubscriptionDownloads(entries, target);
  const result = [];
  for (const entry of entries.filter((item) => item.enabled)) {
    const file = getSubscriptionFile(entry.url, target);
    try {
      const text = await fetchText(entry.url);
      fs.writeFileSync(file, text);
      result.push({ url: entry.url, name: entry.name, ok: true, bytes: Buffer.byteLength(text), rulesCount: readRuleLines(file).length });
    } catch (err) {
      result.push({ url: entry.url, name: entry.name, ok: false, error: err.message || String(err) });
    }
  }
  return result;
}

function normalizeSubscriptionUpdateTargets(targets = ['block', 'allow']) {
  const input = Array.isArray(targets) ? targets : [targets];
  const normalized = input.map((target) => (target === 'allow' ? 'allow' : 'block'));
  return [...new Set(normalized)];
}

function summarizeSubscriptionUpdate(results) {
  const summary = {
    targets: Object.keys(results),
    total: 0,
    ok: 0,
    failed: 0,
    block: { total: 0, ok: 0, failed: 0 },
    allow: { total: 0, ok: 0, failed: 0 }
  };
  for (const [target, rows] of Object.entries(results)) {
    const bucket = summary[target] || { total: 0, ok: 0, failed: 0 };
    bucket.total = rows.length;
    bucket.ok = rows.filter((row) => row.ok === true).length;
    bucket.failed = rows.filter((row) => row.ok !== true).length;
    summary[target] = bucket;
    summary.total += bucket.total;
    summary.ok += bucket.ok;
    summary.failed += bucket.failed;
  }
  return summary;
}

async function updateSubscriptionTargets(targets = ['block', 'allow']) {
  const results = {};
  for (const target of normalizeSubscriptionUpdateTargets(targets)) {
    results[target] = await updateSubscriptions(target);
  }
  rules = loadRules();
  clearDnsCaches();
  return summarizeSubscriptionUpdate(results);
}

function queueSubscriptionAutoUpdate(reason = 'schedule', targets = ['block', 'allow']) {
  if (config.rules?.autoUpdateEnabled === false) return false;
  for (const target of normalizeSubscriptionUpdateTargets(targets)) {
    subscriptionAutoUpdateState.queuedTargets.add(target);
  }
  if (!subscriptionAutoUpdateState.running) {
    const timer = setTimeout(() => drainSubscriptionAutoUpdateQueue(reason), 0);
    timer.unref?.();
  }
  return true;
}

async function drainSubscriptionAutoUpdateQueue(reason = 'schedule') {
  if (subscriptionAutoUpdateState.running || !subscriptionAutoUpdateState.queuedTargets.size) return;
  subscriptionAutoUpdateState.running = true;
  subscriptionAutoUpdateState.lastStartedAt = new Date().toISOString();
  subscriptionAutoUpdateState.lastReason = reason;
  subscriptionAutoUpdateState.lastError = '';
  let lastSummary = null;
  try {
    while (subscriptionAutoUpdateState.queuedTargets.size) {
      const targets = [...subscriptionAutoUpdateState.queuedTargets];
      subscriptionAutoUpdateState.queuedTargets.clear();
      lastSummary = await updateSubscriptionTargets(targets);
    }
    subscriptionAutoUpdateState.lastSummary = lastSummary;
  } catch (err) {
    subscriptionAutoUpdateState.lastError = err.message || String(err);
  } finally {
    subscriptionAutoUpdateState.lastFinishedAt = new Date().toISOString();
    subscriptionAutoUpdateState.running = false;
    if (subscriptionAutoUpdateState.queuedTargets.size) {
      const timer = setTimeout(() => drainSubscriptionAutoUpdateQueue('queued'), 0);
      timer.unref?.();
    }
  }
}

function startSubscriptionAutoUpdater(options = {}) {
  const runStartup = options.runStartup !== false;
  if (subscriptionAutoUpdateTimer) clearInterval(subscriptionAutoUpdateTimer);
  if (subscriptionAutoUpdateStartupTimer) clearTimeout(subscriptionAutoUpdateStartupTimer);
  subscriptionAutoUpdateTimer = null;
  subscriptionAutoUpdateStartupTimer = null;
  if (config.rules?.autoUpdateEnabled === false) {
    subscriptionAutoUpdateState.nextRunAt = '';
    subscriptionAutoUpdateState.queuedTargets.clear();
    return;
  }
  const intervalMs = Math.max(1, Number(config.rules.autoUpdateIntervalHours || 24)) * 60 * 60 * 1000;
  subscriptionAutoUpdateState.nextRunAt = new Date(Date.now() + intervalMs).toISOString();
  if (runStartup && config.rules.autoUpdateOnStartup !== false) {
    subscriptionAutoUpdateStartupTimer = setTimeout(() => {
      subscriptionAutoUpdateStartupTimer = null;
      queueSubscriptionAutoUpdate('startup', ['block', 'allow']);
    }, 15_000);
    subscriptionAutoUpdateStartupTimer.unref?.();
  }
  subscriptionAutoUpdateTimer = setInterval(() => {
    subscriptionAutoUpdateState.nextRunAt = new Date(Date.now() + intervalMs).toISOString();
    queueSubscriptionAutoUpdate('schedule', ['block', 'allow']);
  }, intervalMs);
  subscriptionAutoUpdateTimer.unref?.();
}

function getSubscriptionAutoUpdateStatus() {
  return {
    enabled: config.rules?.autoUpdateEnabled !== false,
    intervalHours: config.rules?.autoUpdateIntervalHours || 24,
    onStartup: config.rules?.autoUpdateOnStartup !== false,
    onChange: config.rules?.autoUpdateOnChange !== false,
    running: subscriptionAutoUpdateState.running,
    queuedTargets: [...subscriptionAutoUpdateState.queuedTargets],
    lastStartedAt: subscriptionAutoUpdateState.lastStartedAt,
    lastFinishedAt: subscriptionAutoUpdateState.lastFinishedAt,
    lastReason: subscriptionAutoUpdateState.lastReason,
    lastError: subscriptionAutoUpdateState.lastError,
    lastSummary: subscriptionAutoUpdateState.lastSummary,
    nextRunAt: subscriptionAutoUpdateState.nextRunAt
  };
}

function startBlockedServicesAutoUpdater(options = {}) {
  const runStartup = options.runStartup !== false;
  const resetSchedule = options.resetSchedule === true;
  if (blockedServicesAutoUpdateTimer) clearInterval(blockedServicesAutoUpdateTimer);
  if (blockedServicesAutoUpdateStartupTimer) clearTimeout(blockedServicesAutoUpdateStartupTimer);
  blockedServicesAutoUpdateTimer = null;
  blockedServicesAutoUpdateStartupTimer = null;
  if (config.rules?.blockedServicesAutoUpdateEnabled === false) {
    blockedServicesAutoUpdateState.nextRunAt = '';
    blockedServicesAutoUpdateState.scheduled = false;
    blockedServicesAutoUpdateState.queued = false;
    persistBlockedServicesAutoUpdateState({ nextRunAt: '' });
    return;
  }
  const intervalMs = blockedServicesAutoUpdateIntervalMs();
  const persisted = hydrateBlockedServicesAutoUpdateState();
  const persistedNextRunAt = Date.parse(persisted.nextRunAt || '');
  blockedServicesAutoUpdateState.nextRunAt = !resetSchedule && Number.isFinite(persistedNextRunAt) && persistedNextRunAt > Date.now()
    ? persisted.nextRunAt
    : new Date(Date.now() + intervalMs).toISOString();
  persistBlockedServicesAutoUpdateState({ nextRunAt: blockedServicesAutoUpdateState.nextRunAt });
  if (runStartup && config.rules?.blockedServicesAutoUpdateOnStartup !== false) {
    blockedServicesAutoUpdateStartupTimer = setTimeout(() => {
      blockedServicesAutoUpdateStartupTimer = null;
      queueBlockedServicesAutoUpdate('startup');
    }, 30_000);
    blockedServicesAutoUpdateStartupTimer.unref?.();
  }
  blockedServicesAutoUpdateTimer = setInterval(() => {
    queueBlockedServicesAutoUpdate('schedule');
  }, intervalMs);
  blockedServicesAutoUpdateTimer.unref?.();
}

function queueBlockedServicesAutoUpdate(reason = 'schedule') {
  if (config.rules?.blockedServicesAutoUpdateEnabled === false) return false;
  if (blockedServicesAutoUpdateState.running) {
    blockedServicesAutoUpdateState.queued = true;
    return true;
  }
  if (blockedServicesAutoUpdateState.scheduled) return true;
  blockedServicesAutoUpdateState.scheduled = true;
  const timer = setTimeout(() => {
    blockedServicesAutoUpdateState.scheduled = false;
    refreshBlockedServicesCatalog(reason).catch((err) => {
      console.warn(`blocked services catalog update failed: ${err.message || err}`);
    });
  }, 0);
  timer.unref?.();
  return true;
}

async function refreshBlockedServicesCatalog(reason = 'manual') {
  if (blockedServicesAutoUpdateState.running) {
    const error = new Error('blocked_services_update_running');
    error.code = 'blocked_services_update_running';
    throw error;
  }
  blockedServicesAutoUpdateState.running = true;
  blockedServicesAutoUpdateState.lastStartedAt = new Date().toISOString();
  blockedServicesAutoUpdateState.lastReason = reason;
  blockedServicesAutoUpdateState.lastError = '';
  persistBlockedServicesAutoUpdateState({
    lastStartedAt: blockedServicesAutoUpdateState.lastStartedAt,
    lastReason: reason,
    lastError: ''
  });
  const before = {
    services: BLOCKED_SERVICE_CATALOG.length,
    rules: BLOCKED_SERVICE_CATALOG.reduce((total, item) => total + Number(item.rules?.length || 0), 0),
    generatedAt: BLOCKED_SERVICE_DATA.generatedAt || ''
  };
  try {
    const output = await runBlockedServicesUpdater();
    const data = loadBlockedServiceData();
    if (!data.catalog.length || data.source === 'embedded-fallback') {
      throw new Error('blocked_services_catalog_invalid');
    }
    installBlockedServiceData(data);
    clearDnsCaches();
    const afterRules = BLOCKED_SERVICE_CATALOG.reduce((total, item) => total + Number(item.rules?.length || 0), 0);
    const enabled = new Set(config.filter?.blockedServices || []);
    blockedServicesAutoUpdateState.lastSummary = {
      servicesBefore: before.services,
      servicesAfter: BLOCKED_SERVICE_CATALOG.length,
      rulesBefore: before.rules,
      rulesAfter: afterRules,
      generatedAt: BLOCKED_SERVICE_DATA.generatedAt || '',
      enabledRetained: [...enabled].filter((id) => BLOCKED_SERVICE_IDS.has(id)).length,
      output
    };
    blockedServicesAutoUpdateState.lastFinishedAt = new Date().toISOString();
    blockedServicesAutoUpdateState.lastSuccessfulAt = blockedServicesAutoUpdateState.lastFinishedAt;
    blockedServicesAutoUpdateState.nextRunAt = config.rules?.blockedServicesAutoUpdateEnabled === false
      ? ''
      : new Date(Date.now() + blockedServicesAutoUpdateIntervalMs()).toISOString();
    persistBlockedServicesAutoUpdateState({
      lastStartedAt: blockedServicesAutoUpdateState.lastStartedAt,
      lastFinishedAt: blockedServicesAutoUpdateState.lastFinishedAt,
      lastSuccessfulAt: blockedServicesAutoUpdateState.lastSuccessfulAt,
      lastReason: blockedServicesAutoUpdateState.lastReason,
      lastError: '',
      lastSummary: blockedServicesAutoUpdateState.lastSummary,
      nextRunAt: blockedServicesAutoUpdateState.nextRunAt
    });
    return getBlockedServicesAutoUpdateStatus();
  } catch (error) {
    blockedServicesAutoUpdateState.lastError = normalizeBlockedServicesUpdateError(error);
    blockedServicesAutoUpdateState.lastFinishedAt = new Date().toISOString();
    persistBlockedServicesAutoUpdateState({
      lastStartedAt: blockedServicesAutoUpdateState.lastStartedAt,
      lastFinishedAt: blockedServicesAutoUpdateState.lastFinishedAt,
      lastReason: blockedServicesAutoUpdateState.lastReason,
      lastError: blockedServicesAutoUpdateState.lastError
    });
    throw error;
  } finally {
    blockedServicesAutoUpdateState.running = false;
    if (blockedServicesAutoUpdateState.queued) {
      blockedServicesAutoUpdateState.queued = false;
      queueBlockedServicesAutoUpdate('queued');
    }
  }
}

function runBlockedServicesUpdater() {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(BLOCKED_SERVICES_UPDATER_SCRIPT)) {
      reject(new Error('blocked_services_updater_missing'));
      return;
    }
    let child;
    try {
      child = spawn(process.execPath, [BLOCKED_SERVICES_UPDATER_SCRIPT], {
        cwd: __dirname,
        env: {
          ...process.env,
          BLOCKED_SERVICES_TARGET: BLOCKED_SERVICES_CATALOG_FILE,
          BLOCKED_SERVICES_AUTOMATIC: '0',
          BLOCKED_SERVICES_AUTO_UPDATE_STATE: BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE
        },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
    } catch (error) {
      reject(error);
      return;
    }
    let output = '';
    let timedOut = false;
    const append = (chunk) => {
      output = `${output}${String(chunk || '')}`.slice(-4096);
    };
    child.stdout?.on('data', append);
    child.stderr?.on('data', append);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, BLOCKED_SERVICES_UPDATE_TIMEOUT_MS);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      const summary = output.replace(/[\r\n]+/g, ' ').trim().slice(0, 2048);
      if (timedOut) {
        reject(new Error('blocked_services_update_timeout'));
      } else if (code !== 0) {
        reject(new Error(summary || `blocked_services_update_exit_${code || signal || 'unknown'}`));
      } else {
        resolve(summary);
      }
    });
  });
}

function normalizeBlockedServicesUpdateError(error) {
  const message = String(error?.message || error || 'blocked_services_update_failed').replace(/[\r\n]+/g, ' ').trim().slice(0, 512);
  return message || 'blocked_services_update_failed';
}

function blockedServicesAutoUpdateIntervalMs() {
  return Math.max(24, Number(config.rules?.blockedServicesAutoUpdateIntervalHours || 168)) * 60 * 60 * 1000;
}

function hydrateBlockedServicesAutoUpdateState() {
  const persisted = readBlockedServicesAutoUpdateState(BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE);
  if (!persisted.lastStartedAt && !persisted.lastFinishedAt && !persisted.lastSuccessfulAt && !persisted.nextRunAt && !persisted.lastError) {
    return persisted;
  }
  blockedServicesAutoUpdateState.lastStartedAt = persisted.lastStartedAt;
  blockedServicesAutoUpdateState.lastFinishedAt = persisted.lastFinishedAt;
  blockedServicesAutoUpdateState.lastSuccessfulAt = persisted.lastSuccessfulAt;
  blockedServicesAutoUpdateState.lastReason = persisted.lastReason;
  blockedServicesAutoUpdateState.lastError = persisted.lastError;
  blockedServicesAutoUpdateState.lastSummary = persisted.lastSummary;
  blockedServicesAutoUpdateState.nextRunAt = persisted.nextRunAt;
  return persisted;
}

function persistBlockedServicesAutoUpdateState(patch) {
  try {
    const persisted = writeBlockedServicesAutoUpdateState(BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE, patch);
    blockedServicesAutoUpdateState.lastStartedAt = persisted.lastStartedAt;
    blockedServicesAutoUpdateState.lastFinishedAt = persisted.lastFinishedAt;
    blockedServicesAutoUpdateState.lastSuccessfulAt = persisted.lastSuccessfulAt;
    blockedServicesAutoUpdateState.lastReason = persisted.lastReason;
    blockedServicesAutoUpdateState.lastError = persisted.lastError;
    blockedServicesAutoUpdateState.lastSummary = persisted.lastSummary;
    blockedServicesAutoUpdateState.nextRunAt = persisted.nextRunAt;
    return persisted;
  } catch (error) {
    console.warn(`blocked services auto update state write failed: ${error.message || error}`);
    return null;
  }
}

function reloadBlockedServicesCatalogFromDisk(reason = 'systemd') {
  const data = loadBlockedServiceData();
  if (!data.catalog.length || data.source === 'embedded-fallback') {
    throw new Error('blocked_services_catalog_invalid');
  }
  installBlockedServiceData(data);
  clearDnsCaches();
  hydrateBlockedServicesAutoUpdateState();
  if (!blockedServicesAutoUpdateState.lastReason) blockedServicesAutoUpdateState.lastReason = reason;
  return data;
}

function getBlockedServicesAutoUpdateStatus() {
  hydrateBlockedServicesAutoUpdateState();
  return {
    enabled: config.rules?.blockedServicesAutoUpdateEnabled !== false,
    intervalHours: config.rules?.blockedServicesAutoUpdateIntervalHours || 168,
    onStartup: config.rules?.blockedServicesAutoUpdateOnStartup !== false,
    running: blockedServicesAutoUpdateState.running,
    scheduled: blockedServicesAutoUpdateState.scheduled,
    queued: blockedServicesAutoUpdateState.queued,
    lastStartedAt: blockedServicesAutoUpdateState.lastStartedAt,
    lastFinishedAt: blockedServicesAutoUpdateState.lastFinishedAt,
    lastSuccessfulAt: blockedServicesAutoUpdateState.lastSuccessfulAt,
    lastReason: blockedServicesAutoUpdateState.lastReason,
    lastError: blockedServicesAutoUpdateState.lastError,
    lastSummary: blockedServicesAutoUpdateState.lastSummary,
    nextRunAt: blockedServicesAutoUpdateState.nextRunAt
  };
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? import('node:https') : import('node:http');
    client.then((mod) => {
      const req = mod.get(url, { timeout: 20_000, headers: { 'user-agent': 'cleandns/0.1' } }, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
          if (data.length > 20_000_000) req.destroy(new Error('subscription too large'));
        });
        res.on('end', () => resolve(data));
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
    }).catch(reject);
  });
}

function recordQuery(item) {
  recordRuntimeClient(item);
  if (config.queryLog?.enabled === false) return;
  if (isQueryLogIgnored(item.qname)) return;
  const rawClientIp = String(item.clientIp || '').trim();
  const client = config.queryLog?.anonymizeClientIp === false ? rawClientIp : anonymizeIp(rawClientIp);
  const clientProfile = findClientProfile(item.clientIp);
  if (clientProfile?.ignoreQueryLog === true) return;
  const runtimeClient = net.isIP(normalizeIpLiteral(rawClientIp))
    ? runtimeClientForAddress(normalizeIpLiteral(rawClientIp))
    : null;
  const runtimeWhois = normalizeWhoisInfo(runtimeClient?.whois?.info);
  const effectiveSafeSearch = clientProfile?.useGlobalSettings === false
    ? clientProfile.safeSearch
    : config.filter.safeSearch;
  const effectiveSafeBrowsing = clientProfile?.useGlobalSettings === false
    ? clientProfile.safeBrowsingEnabled === true
    : config.filter.safeBrowsing.enabled === true;
  const effectiveParental = clientProfile?.useGlobalSettings === false
    ? clientProfile.parentalEnabled === true
    : config.filter.parental.enabled === true;
  const blockedServicesPolicy = effectiveBlockedServicesPolicy(clientProfile);
  const row = {
    id: crypto.randomUUID(),
    time: new Date().toISOString(),
    qname: item.qname,
    qtype: item.qtype,
    client,
    clientName: clientProfile?.name || runtimeClient?.name || '',
    clientNote: clientProfile?.note || '',
    clientId: clientProfile?.id || '',
    clientTags: clientProfile?.tags || [],
    clientSource: clientProfile ? 'persistent' : runtimeClient?.source || 'dns-query',
    clientWhois: Object.keys(runtimeWhois).length ? runtimeWhois : null,
    clientPolicy: clientProfile ? {
      useGlobalSettings: clientProfile.useGlobalSettings !== false,
      filteringEnabled: clientProfile.useGlobalSettings !== false || clientProfile.filteringEnabled !== false,
      disableFiltering: clientProfile.disableFiltering === true,
      disableEcs: clientProfile.disableEcs === true,
      safeBrowsingEnabled: effectiveSafeBrowsing,
      parentalEnabled: effectiveParental,
      safeSearchEnabled: effectiveSafeSearch?.enabled === true,
      safeSearchServices: Object.entries(effectiveSafeSearch || {}).filter(([key, enabled]) => key !== 'enabled' && enabled === true).length,
      useGlobalBlockedServices: blockedServicesPolicy.useGlobal,
      blockedServices: blockedServicesPolicy.enabled.length,
      blockedServicesScheduleEnabled: blockedServicesPolicy.scheduleStatus.enabled,
      blockedServicesPaused: blockedServicesPolicy.scheduleStatus.paused,
      customUpstreamPolicy: hasConfiguredUpstreamPolicy(clientProfile.upstreams),
      customUpstreams: upstreamConfigurationSummary(clientProfile.upstreams || []).targets,
      upstreamRoutes: upstreamConfigurationSummary(clientProfile.upstreams || []).routes,
      upstreamsCacheEnabled: clientProfile.upstreamsCacheEnabled === true,
      upstreamsCacheSize: normalizeClientCacheSize(clientProfile.upstreamsCacheSize),
      upstreamsCacheActive: Boolean(
        hasConfiguredUpstreamPolicy(clientProfile.upstreams) &&
        clientProfile.upstreamsCacheEnabled === true &&
        normalizeClientCacheSize(clientProfile.upstreamsCacheSize) > 0
      ),
      ignoreStatistics: clientProfile.ignoreStatistics === true
    } : null,
    protocol: item.protocol,
    action: item.action,
    rule: item.rule || '',
    matchedRules: Array.isArray(item.matchedRules)
      ? item.matchedRules.map((rule) => String(rule || '').slice(0, 4096)).filter(Boolean).slice(0, 32)
      : [],
    cached: item.cached,
    ecs: item.ecs,
    source: item.source || '',
    upstream: item.upstream || '',
    upstreamMode: item.upstreamMode || '',
    upstreamRoute: item.upstreamRoute || '',
    elapsedMs: Math.max(0, Number(item.elapsedMs) || 0),
    upstreamElapsedMs: Math.max(0, Number(item.upstreamElapsedMs) || 0),
    responseCode: Number.isInteger(item.responseCode) ? item.responseCode : null,
    responseStatus: String(item.responseStatus || ''),
    responseFlags: normalizeQueryResponseFlags(item.responseFlags),
    answerCount: Math.max(0, Math.floor(Number(item.answerCount) || 0)),
    answersTruncated: item.answersTruncated === true,
    answers: normalizeQueryAnswers(item.answers),
    responseMatchType: String(item.responseMatchType || '').slice(0, 64),
    responseMatchValue: String(item.responseMatchValue || '').slice(0, 2048),
    originalResponseCode: Number.isInteger(item.originalResponseCode) ? item.originalResponseCode : null,
    originalResponseStatus: String(item.originalResponseStatus || ''),
    originalAnswerCount: Math.max(0, Math.floor(Number(item.originalAnswerCount) || 0)),
    originalAnswersTruncated: item.originalAnswersTruncated === true,
    originalAnswers: normalizeQueryAnswers(item.originalAnswers)
  };
  recentQueries.unshift(row);
  trimRecentQueries();
  queryLogStore.append(row).catch(() => {});
}

function normalizeQueryResponseFlags(value) {
  const flags = value && typeof value === 'object' ? value : {};
  return {
    authoritative: flags.authoritative === true,
    truncated: flags.truncated === true,
    recursionAvailable: flags.recursionAvailable === true,
    authenticatedData: flags.authenticatedData === true
  };
}

function normalizeQueryAnswers(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 16).map((answer) => ({
    name: String(answer?.name || '').slice(0, 255),
    type: String(answer?.type || '').slice(0, 16),
    ttl: Math.max(0, Math.min(0xffffffff, Math.floor(Number(answer?.ttl) || 0))),
    value: String(answer?.value || '').slice(0, 2048)
  }));
}

function isQueryLogIgnored(qname) {
  if (config.queryLog?.ignoredEnabled !== true) return false;
  return matchesIgnoredDomain(qname, config.queryLog.ignored || []);
}

function isStatisticsIgnored(qname) {
  if (config.statistics?.ignoredEnabled !== true) return false;
  return matchesIgnoredDomain(qname, config.statistics.ignored || []);
}

function matchesIgnoredDomain(qname, domains) {
  const host = normalizeDomain(qname);
  if (!host) return false;
  return domains.some((domain) => host === domain || host.endsWith('.' + domain));
}

function anonymizeIp(ip) {
  if (!net.isIP(ip)) return '';
  if (net.isIP(ip) === 4) {
    const parts = ip.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  const bytes = ipv6ToBytes(ip);
  return bytesToIpv6(maskBytes(bytes, 56)) + '/56';
}

function policyHash(clientProfile = null) {
  const blockedServicesPolicy = effectiveBlockedServicesPolicy(clientProfile);
  const clientPolicy = clientProfile
    ? `${clientProfile.id}:${clientProfile.useGlobalSettings !== false}:${clientProfile.filteringEnabled !== false}:${clientProfile.safeBrowsingEnabled === true}:${clientProfile.parentalEnabled === true}:${JSON.stringify(clientProfile.safeSearch)}:${clientProfile.useGlobalBlockedServices !== false}:${blockedServicesPolicy.enabled.join(',')}:${JSON.stringify(blockedServicesPolicy.schedule)}:${blockedServicesPolicy.scheduleStatus.paused}:${clientProfile.disableEcs === true}:${(clientProfile.upstreams || []).join(',')}:${clientProfile.upstreamsCacheEnabled === true}:${clientProfile.upstreamsCacheSize || 0}`
    : '';
  return `${rules.loadedAt}:${protectionStatus().active}:${config.filter.rewritesEnabled !== false}:${config.filter.blockMode}:${config.filter.cnameCheck !== false}:${(config.filter.blockedServices || []).join(',')}:${JSON.stringify(normalizeBlockedServicesSchedule(config.filter.blockedServicesSchedule))}:${blockedServicesScheduleStatus().paused}:${config.filter.safeBrowsing.enabled}:${config.filter.parental.enabled}:${JSON.stringify(config.filter.safeSearch)}:${config.dns.disableIpv6}:${config.dns.refuseAny}:${config.dns.privateReverseEnabled}:${(config.dns.privateReverseUpstreams || []).join(',')}:${config.upstreamMode}:${config.upstreams.join(',')}:${(config.fallbackUpstreams || []).join(',')}:${(config.bootstrapDns || []).join(',')}:${clientPolicy}`;
}

function responseCacheForClient(clientProfile = null) {
  const hasCustomUpstreams = hasConfiguredUpstreamPolicy(clientProfile?.upstreams);
  if (hasCustomUpstreams) {
    const maxBytes = normalizeClientCacheSize(clientProfile?.upstreamsCacheSize);
    if (clientProfile?.upstreamsCacheEnabled !== true || maxBytes <= 0) return null;
    let store = clientCaches.get(clientProfile.id);
    if (!store) {
      store = { entries: new Map(), bytes: 0, maxBytes };
      clientCaches.set(clientProfile.id, store);
    } else if (store.maxBytes !== maxBytes) {
      store.maxBytes = maxBytes;
      trimClientCacheStore(store);
    }
    return { kind: 'client', store, generation: cacheGeneration };
  }
  return config.cache.enabled === false ? null : { kind: 'global', store: cache, generation: cacheGeneration };
}

function responseCacheGet(context, key) {
  if (!context) return null;
  const entries = context.kind === 'client' ? context.store.entries : context.store;
  const entry = entries.get(key);
  if (entry) {
    entries.delete(key);
    entries.set(key, entry);
  }
  return entry || null;
}

function responseCacheSet(context, key, entry) {
  if (!context || context.generation !== cacheGeneration) return;
  const normalizedEntry = {
    ...entry,
    cachedAt: Number(entry.cachedAt) || Date.now()
  };
  if (context.kind !== 'client') {
    context.store.delete(key);
    context.store.set(key, normalizedEntry);
    trimCache();
    return;
  }
  const store = context.store;
  const previous = store.entries.get(key);
  if (previous) {
    store.entries.delete(key);
    store.bytes = Math.max(0, store.bytes - (previous.cacheBytes || 0));
  }
  const cacheBytes = responseCacheEntryBytes(key, normalizedEntry);
  if (cacheBytes > store.maxBytes) return;
  store.entries.set(key, { ...normalizedEntry, cacheBytes });
  store.bytes += cacheBytes;
  trimClientCacheStore(store);
}

function responseCacheEntryBytes(key, entry) {
  return Buffer.byteLength(String(key || '')) + Number(entry?.response?.length || 0) + 128;
}

function trimClientCacheStore(store) {
  while (store.bytes > store.maxBytes && store.entries.size) {
    const first = store.entries.keys().next().value;
    const entry = store.entries.get(first);
    store.entries.delete(first);
    store.bytes = Math.max(0, store.bytes - Number(entry?.cacheBytes || 0));
  }
}

function responseCacheSource(context, mode = 'fresh') {
  if (context?.kind === 'client') {
    if (mode === 'optimistic') return 'optimistic-client-cache';
    return mode === 'stale' ? 'stale-client-cache' : 'client-cache';
  }
  if (mode === 'optimistic') return 'optimistic-cache';
  return mode === 'stale' ? 'stale-cache' : 'cache';
}

function optimisticCacheUsable(entry, now = Date.now()) {
  return config.cache.optimistic === true &&
    entry.expireAt <= now &&
    entry.expireAt + config.cache.optimisticMaxAge * 1000 >= now;
}

function scheduleOptimisticRefresh(options) {
  const {
    cacheKey,
    responseCache,
    queryPacket,
    packet,
    parsed,
    ecs,
    clientProfile,
    safeSearch,
    dnssecRequested,
    filteringActive,
    allowed,
    filterMatchContext
  } = options;
  if (!responseCache || optimisticRefreshes.has(cacheKey)) return;
  const refresh = queryUpstreams(queryPacket, ecs, {
    recordStats: false,
    clientProfile,
    privateReverse: isPrivateReversePtr(parsed),
    dnssecRequested
  }).then((result) => safeSearch?.kind === 'cname'
    ? { ...result, response: buildSafeSearchCnameResponse(packet, parsed, safeSearch.value, result.response) }
    : result
  ).then((result) => {
    const response = normalizeDnsResponseTtls(result.response);
    if (!safeSearch && config.filter.cnameCheck && filteringActive && !allowed && findBlockedDnsResponse(response, filterMatchContext)) return;
    const ttl = clamp(extractMinTtl(response) || config.cache.minTtl, config.cache.minTtl, config.cache.maxTtl);
    const cachedAt = Date.now();
    responseCacheSet(responseCache, cacheKey, {
      response: patchResponseId(response, 0),
      cachedAt,
      expireAt: cachedAt + ttl * 1000,
      upstream: result.upstream || '',
      upstreamMode: result.upstreamMode || '',
      upstreamRoute: result.upstreamRoute || '',
      upstreamElapsedMs: result.elapsedMs || 0
    });
  });
  let tracked;
  tracked = refresh.catch(() => {}).finally(() => {
    if (optimisticRefreshes.get(cacheKey) === tracked) optimisticRefreshes.delete(cacheKey);
  });
  optimisticRefreshes.set(cacheKey, tracked);
}

function cacheRetentionSeconds() {
  return Math.max(
    config.cache.staleTtl,
    config.cache.optimistic === true ? config.cache.optimisticMaxAge : 0
  );
}

function pruneClientCaches() {
  const now = Date.now();
  const retentionMs = cacheRetentionSeconds() * 1000;
  for (const [clientId, store] of clientCaches) {
    for (const [key, entry] of store.entries) {
      if (entry.expireAt + retentionMs >= now) continue;
      store.entries.delete(key);
      store.bytes = Math.max(0, store.bytes - Number(entry.cacheBytes || 0));
    }
    if (!store.entries.size) clientCaches.delete(clientId);
  }
}

function clientCacheStats() {
  let entries = 0;
  let bytes = 0;
  for (const store of clientCaches.values()) {
    entries += store.entries.size;
    bytes += store.bytes;
  }
  return { caches: clientCaches.size, entries, bytes };
}

function clearDnsCaches() {
  const client = clientCacheStats();
  const globalEntries = cache.size;
  cacheGeneration += 1;
  cache.clear();
  clientCaches.clear();
  return { globalEntries, clientEntries: client.entries, total: globalEntries + client.entries };
}

function trimCache() {
  if (config.cache.enabled === false) {
    cache.clear();
    return;
  }
  while (cache.size > config.cache.maxEntries) {
    const first = cache.keys().next().value;
    cache.delete(first);
  }
}

function pruneCache() {
  if (config.cache.enabled === false) {
    cache.clear();
    return;
  }
  const now = Date.now();
  const retentionMs = cacheRetentionSeconds() * 1000;
  for (const [key, value] of cache) {
    if (value.expireAt + retentionMs < now) cache.delete(key);
  }
}

function normalizeDomain(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^\.+/, '')
    .replace(/[^a-z0-9._-]/g, '');
}

function normalizeTextFile(text) {
  return String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\s+$/g, '') + '\n';
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('body_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req) {
  return JSON.parse((await readBody(req, 1_000_000)).toString('utf8') || '{}');
}

function json(res, status, body, extraHeaders = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(text),
    ...extraHeaders
  });
  res.end(text);
}

function mobileConfig(res, body, filename) {
  const content = String(body || '');
  res.writeHead(200, {
    'content-type': 'application/x-apple-aspen-config; charset=utf-8',
    'content-disposition': `attachment; filename="${String(filename || 'CleanDNS.mobileconfig').replace(/["\r\n]/g, '')}"`,
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(content)
  });
  res.end(content);
}

function notFound(res) {
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('not found');
}

function methodNotAllowed(res) {
  res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('method not allowed');
}

function servePanel(res) {
  const panelPath = path.join(__dirname, 'panel.html');
  if (!fs.existsSync(panelPath)) {
    return json(res, 500, { error: 'panel_missing' });
  }
  const html = fs.readFileSync(panelPath, 'utf8');
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(html)
  });
  res.end(html);
}

function serveFavicon(res) {
  const iconPath = path.join(__dirname, 'favicon.ico');
  if (!fs.existsSync(iconPath)) return notFound(res);
  const icon = fs.readFileSync(iconPath);
  res.writeHead(200, {
    'content-type': 'image/x-icon',
    'cache-control': 'public, max-age=86400',
    'content-length': icon.length
  });
  res.end(icon);
}
function buildQuery(name, qtype) {
  const id = crypto.randomInt(0, 65536);
  const labels = name.split('.').flatMap((part) => [Buffer.from([part.length]), Buffer.from(part, 'ascii')]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, ...labels, Buffer.from([0]), u16(qtype), u16(1)]);
}

function ipv4ToBytes(ip) {
  return Buffer.from(ip.split('.').map((x) => Number(x) & 255));
}

function bytesToIpv4(buf) {
  return Array.from(buf).join('.');
}

function ipv6ToBytes(ip) {
  const sections = ip.split('::');
  const left = sections[0] ? sections[0].split(':') : [];
  let right = sections[1] ? sections[1].split(':') : [];
  if (right.length && right[right.length - 1].includes('.')) {
    const v4 = ipv4ToBytes(right.pop());
    right.push(v4.readUInt16BE(0).toString(16), v4.readUInt16BE(2).toString(16));
  }
  if (left.length && left[left.length - 1].includes('.')) {
    const v4 = ipv4ToBytes(left.pop());
    left.push(v4.readUInt16BE(0).toString(16), v4.readUInt16BE(2).toString(16));
  }
  const missing = 8 - left.length - right.length;
  const groups = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right].map((x) => parseInt(x || '0', 16));
  const out = Buffer.alloc(16);
  groups.slice(0, 8).forEach((n, i) => out.writeUInt16BE(n & 0xffff, i * 2));
  return out;
}

function bytesToIpv6(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i).toString(16));
  return groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

function maskBytes(bytes, prefix) {
  const out = Buffer.from(bytes);
  const full = Math.floor(prefix / 8);
  const rem = prefix % 8;
  if (full < out.length) {
    if (rem) out[full] &= (0xff << (8 - rem)) & 0xff;
    for (let i = full + (rem ? 1 : 0); i < out.length; i++) out[i] = 0;
  }
  return out;
}

function u16(value) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(value);
  return b;
}

function u32(value) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value >>> 0);
  return b;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
