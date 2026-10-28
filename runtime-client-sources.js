import net from 'node:net';

const HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i;
const MAC_ADDRESS = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

export function parseHostsFile(value) {
  const records = new Map();
  for (const line of String(value || '').split(/\r?\n/)) {
    const fields = line.replace(/#.*/, '').trim().split(/\s+/).filter(Boolean);
    if (fields.length < 2) continue;
    const address = normalizeAddress(fields[0]);
    if (!address) continue;
    const names = fields.slice(1).map(normalizeHostname).filter(Boolean);
    if (!names.length) continue;
    const current = records.get(address);
    if (!current) {
      records.set(address, { address, hostname: names[0], aliases: unique(names) });
      continue;
    }
    current.aliases = unique([...current.aliases, ...names]);
  }
  return [...records.values()];
}

export function parseLinuxArpTable(value) {
  const records = new Map();
  const lines = String(value || '').split(/\r?\n/);
  for (const line of lines.slice(1)) {
    const fields = line.trim().split(/\s+/).filter(Boolean);
    if (fields.length < 6) continue;
    const address = normalizeAddress(fields[0]);
    const flags = Number.parseInt(fields[2], 16);
    const mac = normalizeMac(fields[3]);
    const device = normalizeDevice(fields[5]);
    if (net.isIP(address) !== 4 || !(flags & 0x2) || !mac || !device) continue;
    if (!records.has(address)) records.set(address, { address, mac, device });
  }
  return [...records.values()];
}

function normalizeAddress(value) {
  let address = String(value || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (address.startsWith('::ffff:') && net.isIP(address.slice(7)) === 4) address = address.slice(7);
  if (net.isIP(address) === 4) return address.split('.').map((part) => String(Number(part))).join('.');
  return net.isIP(address) === 6 ? address : '';
}

function normalizeHostname(value) {
  const hostname = String(value || '').trim().replace(/\.+$/, '').slice(0, 253);
  if (!hostname) return '';
  return hostname.split('.').every((label) => HOSTNAME_LABEL.test(label)) ? hostname : '';
}

function normalizeMac(value) {
  const mac = String(value || '').trim().toLowerCase();
  if (!MAC_ADDRESS.test(mac) || mac === '00:00:00:00:00:00') return '';
  return mac;
}

function normalizeDevice(value) {
  return String(value || '').trim().replace(/[^a-z0-9_.:-]/gi, '').slice(0, 63);
}

function unique(values) {
  return [...new Set(values)];
}
