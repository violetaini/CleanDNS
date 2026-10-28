import net from 'node:net';

const MAC_PATTERN = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/;
const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const VIRTUAL_INTERFACE_PATTERN = /^(?:br-|docker|veth|virbr|vmnet|vboxnet|tun|tap|wg|zt|tailscale|utun)/i;

export function normalizeDhcpConfig(value = {}) {
  const source = value && typeof value === 'object' ? value : {};
  const result = {
    enabled: source.enabled === true,
    interfaceName: normalizeText(source.interfaceName, 80),
    gateway: normalizeIpv4(source.gateway),
    subnetMask: normalizeIpv4(source.subnetMask),
    rangeStart: normalizeIpv4(source.rangeStart),
    rangeEnd: normalizeIpv4(source.rangeEnd),
    leaseMinutes: normalizeInteger(source.leaseMinutes ?? 1440, 5, 525600, 'bad_dhcp_lease'),
    dnsServers: normalizeDhcpDnsServers(source.dnsServers),
    staticLeases: []
  };

  const seenMacs = new Set();
  const seenIps = new Set();
  for (const candidate of Array.isArray(source.staticLeases) ? source.staticLeases : []) {
    const lease = normalizeDhcpStaticLease(candidate);
    if (!lease || seenMacs.has(lease.mac) || seenIps.has(lease.ip)) continue;
    seenMacs.add(lease.mac);
    seenIps.add(lease.ip);
    result.staticLeases.push(lease);
  }
  result.staticLeases.sort((a, b) => compareIpv4(a.ip, b.ip));
  return result;
}

export function normalizeDhcpDnsServers(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(/[\r\n,]+/);
  const servers = [];
  for (const item of values) {
    const server = normalizeIpv4(item);
    if (server && !servers.includes(server)) servers.push(server);
    if (servers.length >= 8) break;
  }
  return servers;
}

export function normalizeDhcpStaticLease(value = {}) {
  const source = value && typeof value === 'object' ? value : {};
  const mac = normalizeMac(source.mac);
  const ip = normalizeIpv4(source.ip);
  const hostname = normalizeHostname(source.hostname);
  if (!mac || !ip || (source.hostname && !hostname)) return null;
  return { mac, ip, hostname };
}

export function normalizeDhcpMac(value) {
  return normalizeMac(value);
}

export function validateDhcpStaticLease(value = {}) {
  const source = value && typeof value === 'object' ? value : {};
  const errors = [];
  const mac = normalizeMac(source.mac);
  const ip = normalizeIpv4(source.ip);
  const hostname = normalizeHostname(source.hostname);
  if (!mac) errors.push(issue('mac_invalid', 'mac'));
  if (!ip) errors.push(issue('ip_invalid', 'ip'));
  if (String(source.hostname || '').trim() && !hostname) errors.push(issue('hostname_invalid', 'hostname'));
  return {
    valid: errors.length === 0,
    errors,
    lease: errors.length ? null : { mac, ip, hostname }
  };
}

export function collectDhcpInterfaces(networkInterfaces = {}) {
  return Object.entries(networkInterfaces || {}).map(([name, values]) => {
    const addresses = (Array.isArray(values) ? values : []).map(normalizeInterfaceAddress).filter(Boolean);
    const ipv4 = addresses.filter((entry) => entry.family === 4);
    const ipv6 = addresses.filter((entry) => entry.family === 6);
    const privateIpv4 = ipv4.filter((entry) => isPrivateIpv4(entry.address));
    const internal = addresses.length > 0 && addresses.every((entry) => entry.internal);
    const virtual = VIRTUAL_INTERFACE_PATTERN.test(name);
    const primary = privateIpv4[0] || ipv4[0] || ipv6[0] || null;
    return {
      name,
      internal,
      virtual,
      eligible: !internal && privateIpv4.length > 0,
      address: primary?.address || '',
      netmask: primary?.family === 4 ? primary.netmask : '',
      mac: addresses.find((entry) => entry.mac)?.mac || '',
      ipv4,
      ipv6
    };
  }).sort((a, b) => {
    if (a.eligible !== b.eligible) return a.eligible ? -1 : 1;
    if (a.internal !== b.internal) return a.internal ? 1 : -1;
    return a.name.localeCompare(b.name);
  });
}

export function validateDhcpConfig(value = {}, interfaces = []) {
  const config = normalizeDhcpConfig(value);
  const errors = [];
  const warnings = [];
  const selectedInterface = interfaces.find((entry) => entry.name === config.interfaceName) || null;
  const rawDnsServers = Array.isArray(value?.dnsServers) ? value.dnsServers : String(value?.dnsServers || '').split(/[\r\n,]+/).filter(Boolean);
  const normalizedDnsServers = normalizeDhcpDnsServers(rawDnsServers);
  if (rawDnsServers.length !== normalizedDnsServers.length) errors.push(issue('dns_server_invalid', 'dnsServers'));
  if (duplicates(rawDnsServers.map((item) => normalizeIpv4(item)).filter(Boolean)).length) {
    errors.push(issue('dns_server_duplicate', 'dnsServers'));
  }

  if (!config.interfaceName) {
    errors.push(issue('interface_required', 'interfaceName'));
  } else if (!selectedInterface) {
    errors.push(issue('interface_not_found', 'interfaceName'));
  } else if (!selectedInterface.ipv4?.length) {
    errors.push(issue('interface_ipv4_missing', 'interfaceName'));
  } else {
    if (!selectedInterface.ipv4.some((entry) => isPrivateIpv4(entry.address))) {
      errors.push(issue('interface_public_only', 'interfaceName'));
    }
    if (selectedInterface.virtual) warnings.push(issue('interface_virtual', 'interfaceName'));
  }

  for (const field of ['gateway', 'subnetMask', 'rangeStart', 'rangeEnd']) {
    if (!config[field]) errors.push(issue(`${field}_required`, field));
  }

  const mask = config.subnetMask ? ipv4MaskInfo(config.subnetMask) : null;
  if (config.subnetMask && !mask) errors.push(issue('subnet_mask_invalid', 'subnetMask'));
  if (mask && config.gateway && config.rangeStart && config.rangeEnd) {
    const gateway = ipv4ToInteger(config.gateway);
    const start = ipv4ToInteger(config.rangeStart);
    const end = ipv4ToInteger(config.rangeEnd);
    const network = (gateway & mask.mask) >>> 0;
    const broadcast = (network | mask.inverse) >>> 0;
    if (selectedInterface && !dhcpInterfaceIpv4ForConfig(config, selectedInterface)) {
      errors.push(issue('interface_subnet_mismatch', 'interfaceName'));
    }
    if (start > end) errors.push(issue('range_order_invalid', 'rangeEnd'));
    if (((start & mask.mask) >>> 0) !== network) errors.push(issue('range_start_outside_subnet', 'rangeStart'));
    if (((end & mask.mask) >>> 0) !== network) errors.push(issue('range_end_outside_subnet', 'rangeEnd'));
    if (start === network || start === broadcast) errors.push(issue('range_start_reserved', 'rangeStart'));
    if (end === network || end === broadcast) errors.push(issue('range_end_reserved', 'rangeEnd'));
    if (gateway >= start && gateway <= end) errors.push(issue('gateway_inside_range', 'gateway'));

    for (const lease of config.staticLeases) {
      const leaseIp = ipv4ToInteger(lease.ip);
      if (((leaseIp & mask.mask) >>> 0) !== network || leaseIp === network || leaseIp === broadcast) {
        errors.push(issue('static_lease_outside_subnet', 'staticLeases', lease.mac));
      }
    }
  }

  const duplicateMacs = duplicates((Array.isArray(value?.staticLeases) ? value.staticLeases : []).map((item) => normalizeMac(item?.mac)).filter(Boolean));
  const duplicateIps = duplicates((Array.isArray(value?.staticLeases) ? value.staticLeases : []).map((item) => normalizeIpv4(item?.ip)).filter(Boolean));
  if (duplicateMacs.length) errors.push(issue('static_lease_mac_duplicate', 'staticLeases', duplicateMacs.join(',')));
  if (duplicateIps.length) errors.push(issue('static_lease_ip_duplicate', 'staticLeases', duplicateIps.join(',')));

  return {
    valid: errors.length === 0,
    ready: errors.length === 0,
    errors,
    warnings,
    selectedInterface,
    config
  };
}

export function dhcpInterfaceIpv4ForConfig(value = {}, interfaceEntry = null) {
  const config = normalizeDhcpConfig(value);
  const mask = ipv4MaskInfo(config.subnetMask);
  if (!mask || !config.gateway || !interfaceEntry || !Array.isArray(interfaceEntry.ipv4)) return null;
  const network = (ipv4ToInteger(config.gateway) & mask.mask) >>> 0;
  return interfaceEntry.ipv4.find((entry) => {
    if (!isPrivateIpv4(entry?.address)) return false;
    return ((ipv4ToInteger(entry.address) & mask.mask) >>> 0) === network;
  }) || null;
}

export function isPrivateIpv4(value) {
  if (net.isIP(value) !== 4) return false;
  const ip = ipv4ToInteger(value);
  return inRange(ip, '10.0.0.0', 8)
    || inRange(ip, '172.16.0.0', 12)
    || inRange(ip, '192.168.0.0', 16);
}

export function ipv4MaskInfo(value) {
  if (net.isIP(value) !== 4) return null;
  const mask = ipv4ToInteger(value);
  const inverse = (~mask) >>> 0;
  if (((inverse & ((inverse + 1) >>> 0)) >>> 0) !== 0) return null;
  let prefixLength = 0;
  for (let bit = 31; bit >= 0; bit -= 1) {
    if ((mask & (1 << bit)) === 0) break;
    prefixLength += 1;
  }
  if (prefixLength < 1 || prefixLength > 30) return null;
  return { mask, inverse, prefixLength };
}

function normalizeInterfaceAddress(value) {
  const family = value?.family === 4 || value?.family === 'IPv4' ? 4 : value?.family === 6 || value?.family === 'IPv6' ? 6 : 0;
  const address = String(value?.address || '').trim();
  if (!family || net.isIP(address) !== family) return null;
  return {
    address,
    family,
    netmask: String(value?.netmask || '').trim(),
    cidr: String(value?.cidr || '').trim(),
    mac: normalizeMac(value?.mac),
    internal: value?.internal === true,
    scopeid: Number(value?.scopeid) || 0
  };
}

function normalizeMac(value) {
  const raw = String(value || '').trim().toLowerCase().replace(/-/g, ':');
  if (MAC_PATTERN.test(raw)) return raw;
  const compact = raw.replace(/[^0-9a-f]/g, '');
  if (!/^[0-9a-f]{12}$/.test(compact)) return '';
  return compact.match(/.{2}/g).join(':');
}

function normalizeHostname(value) {
  const hostname = String(value || '').trim().replace(/\.+$/, '').slice(0, 253);
  if (!hostname) return '';
  return hostname.split('.').every((label) => HOST_LABEL_PATTERN.test(label)) ? hostname : '';
}

function normalizeIpv4(value) {
  const raw = String(value || '').trim();
  return net.isIP(raw) === 4 ? raw : '';
}

function normalizeText(value, maxLength) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, maxLength);
}

function normalizeInteger(value, min, max, errorCode) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(errorCode);
  return number;
}

function ipv4ToInteger(value) {
  return value.split('.').reduce((result, octet) => ((result << 8) | Number(octet)) >>> 0, 0);
}

function compareIpv4(left, right) {
  return ipv4ToInteger(left) - ipv4ToInteger(right);
}

function inRange(value, network, prefixLength) {
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
  return ((value & mask) >>> 0) === ((ipv4ToInteger(network) & mask) >>> 0);
}

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated];
}

function issue(code, field, detail = '') {
  return { code, field, detail };
}
