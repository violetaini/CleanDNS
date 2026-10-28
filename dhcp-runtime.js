import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { normalizeDhcpConfig, normalizeDhcpMac, ipv4MaskInfo } from './dhcp-config.js';

const DHCP_COOKIE = Buffer.from([99, 130, 83, 99]);
const DHCP_PORT_SERVER = 67;
const DHCP_PORT_CLIENT = 68;
const DHCP_OPTIONS_OFFSET = 240;
const DHCP_MESSAGE = {
  DISCOVER: 1,
  OFFER: 2,
  REQUEST: 3,
  DECLINE: 4,
  ACK: 5,
  NAK: 6,
  RELEASE: 7,
  INFORM: 8
};
const OFFER_TTL_MS = 60_000;
const MAX_LEASES = 65_536;

export class ManagedDhcpRuntime {
  constructor(options = {}) {
    this.leaseFile = path.resolve(options.leaseFile || path.join(process.cwd(), 'data', 'dhcp-leases.json'));
    this.now = typeof options.now === 'function' ? options.now : () => Date.now();
    this.onStatus = typeof options.onStatus === 'function' ? options.onStatus : () => {};
    this.socket = null;
    this.config = null;
    this.serverIp = '';
    this.bindAddress = '';
    this.port = DHCP_PORT_SERVER;
    this.leases = new Map();
    this.offers = new Map();
    this.operation = Promise.resolve();
    this.status = this.createStatus();
  }

  sync(options = {}) {
    return this.enqueue(() => this.apply(options));
  }

  close() {
    return this.sync({ enabled: false });
  }

  snapshot() {
    this.pruneExpiredLeases();
    return {
      ...this.status,
      leases: this.listLeases()
    };
  }

  enqueue(task) {
    const next = this.operation.then(task, task);
    this.operation = next.catch(() => {});
    return next;
  }

  async apply(options = {}) {
    await this.stop();
    if (options.enabled !== true) {
      this.setStatus(this.createStatus({ enabled: false, state: 'stopped' }));
      return this.snapshot();
    }

    const config = normalizeDhcpConfig(options.config || {});
    const serverIp = normalizeIpv4(options.serverIp);
    const bindAddress = normalizeIpv4(options.bindAddress || serverIp);
    const port = normalizePort(Object.prototype.hasOwnProperty.call(options, 'port') ? options.port : DHCP_PORT_SERVER);
    if (!serverIp) throw new Error('dhcp_server_address_invalid');
    if (!bindAddress) throw new Error('dhcp_bind_address_invalid');
    if (!config.enabled) throw new Error('dhcp_disabled');
    if (!config.gateway || !config.subnetMask || !config.rangeStart || !config.rangeEnd) throw new Error('dhcp_config_incomplete');
    if (!ipv4MaskInfo(config.subnetMask)) throw new Error('dhcp_subnet_mask_invalid');

    this.config = config;
    this.serverIp = serverIp;
    this.bindAddress = bindAddress;
    this.port = port;
    this.loadLeases();

    const socket = dgram.createSocket('udp4');
    socket.on('message', (packet, rinfo) => {
      this.handleMessage(packet, rinfo).catch((error) => {
        this.setStatus(this.createStatus({
          enabled: true,
          running: true,
          state: 'running',
          error: normalizeRuntimeError(error)
        }));
      });
    });
    socket.on('error', (error) => {
      if (this.socket !== socket) return;
      this.setStatus(this.createStatus({
        enabled: true,
        running: false,
        state: 'error',
        error: normalizeRuntimeError(error)
      }));
    });
    try {
      await bindSocket(socket, port, bindAddress);
    } catch (error) {
      await closeSocket(socket);
      throw error;
    }
    socket.setBroadcast(true);
    this.socket = socket;
    this.port = socket.address().port;
    this.setStatus(this.createStatus({
      enabled: true,
      running: true,
      state: 'running',
      startedAt: new Date(this.now()).toISOString()
    }));
    return this.snapshot();
  }

  async stop() {
    const socket = this.socket;
    const hasRuntimeState = Boolean(socket || this.config);
    this.socket = null;
    this.offers.clear();
    // A newly constructed runtime has no in-memory state.  Do not replace a
    // persisted lease file with an empty one before it has been loaded.
    if (hasRuntimeState) this.saveLeases();
    if (socket) await closeSocket(socket);
    this.setStatus(this.createStatus({ enabled: false, state: 'stopped' }));
  }

  createStatus(overrides = {}) {
    return {
      enabled: false,
      running: false,
      state: 'stopped',
      address: this.bindAddress,
      serverIp: this.serverIp,
      port: this.port,
      startedAt: '',
      error: '',
      ...overrides
    };
  }

  setStatus(status) {
    this.status = status;
    this.onStatus(this.snapshotStatus());
  }

  snapshotStatus() {
    return {
      ...this.status,
      leases: this.listLeases()
    };
  }

  async handleMessage(packet, rinfo) {
    const request = parseDhcpRequest(packet);
    if (!request || !this.socket || !this.status.running) return;
    const messageType = request.options.messageType;
    if (!messageType) return;
    this.pruneExpiredLeases();

    if (messageType === DHCP_MESSAGE.DISCOVER) {
      const ip = this.selectLeaseIp(request);
      if (!ip) return;
      this.offers.set(request.mac, { ip, expiresAt: this.now() + OFFER_TTL_MS });
      await this.reply(request, rinfo, DHCP_MESSAGE.OFFER, ip);
      return;
    }

    if (messageType === DHCP_MESSAGE.REQUEST) {
      if (request.options.serverIdentifier && request.options.serverIdentifier !== this.serverIp) return;
      const ip = this.requestedLeaseIp(request);
      if (!ip) {
        await this.reply(request, rinfo, DHCP_MESSAGE.NAK, '');
        return;
      }
      this.grantLease(request, ip);
      await this.reply(request, rinfo, DHCP_MESSAGE.ACK, ip);
      return;
    }

    if (messageType === DHCP_MESSAGE.INFORM) {
      await this.reply(request, rinfo, DHCP_MESSAGE.ACK, '');
      return;
    }

    if (messageType === DHCP_MESSAGE.RELEASE) {
      if (this.leases.delete(request.mac)) this.saveLeases();
      this.offers.delete(request.mac);
      return;
    }

    if (messageType === DHCP_MESSAGE.DECLINE) {
      this.offers.delete(request.mac);
    }
  }

  selectLeaseIp(request) {
    const staticLease = this.staticLeaseFor(request.mac);
    if (staticLease) return staticLease.ip;
    const existing = this.leases.get(request.mac);
    if (existing && this.isPoolIpAvailable(existing.ip, request.mac)) return existing.ip;
    const offer = this.offers.get(request.mac);
    if (offer && offer.expiresAt > this.now() && this.isPoolIpAvailable(offer.ip, request.mac)) return offer.ip;
    const requested = request.options.requestedIp || request.ciaddr;
    if (requested && this.isPoolIpAvailable(requested, request.mac)) return requested;
    return this.nextAvailablePoolIp(request.mac);
  }

  requestedLeaseIp(request) {
    const staticLease = this.staticLeaseFor(request.mac);
    const requested = request.options.requestedIp || request.ciaddr || this.offers.get(request.mac)?.ip || '';
    if (staticLease) return !requested || requested === staticLease.ip ? staticLease.ip : '';
    if (!requested) return this.selectLeaseIp(request);
    return this.isPoolIpAvailable(requested, request.mac) ? requested : '';
  }

  staticLeaseFor(mac) {
    return this.config?.staticLeases?.find((lease) => lease.mac === mac) || null;
  }

  isPoolIpAvailable(ip, mac) {
    if (!this.isPoolIp(ip)) return false;
    if (ip === this.serverIp || ip === this.config.gateway) return false;
    const staticOwner = this.config.staticLeases.find((lease) => lease.ip === ip);
    if (staticOwner && staticOwner.mac !== mac) return false;
    for (const lease of this.leases.values()) {
      if (lease.ip === ip && lease.mac !== mac && Date.parse(lease.expiresAt) > this.now()) return false;
    }
    for (const [owner, offer] of this.offers) {
      if (owner !== mac && offer.ip === ip && offer.expiresAt > this.now()) return false;
    }
    return true;
  }

  isPoolIp(ip) {
    const value = ipv4ToInteger(ip);
    const start = ipv4ToInteger(this.config.rangeStart);
    const end = ipv4ToInteger(this.config.rangeEnd);
    return value >= start && value <= end;
  }

  nextAvailablePoolIp(mac) {
    const start = ipv4ToInteger(this.config.rangeStart);
    const end = ipv4ToInteger(this.config.rangeEnd);
    const size = Math.min(MAX_LEASES, end - start + 1);
    if (size <= 0) return '';
    const offset = macHash(mac) % size;
    for (let index = 0; index < size; index += 1) {
      const ip = integerToIpv4(start + ((offset + index) % size));
      if (this.isPoolIpAvailable(ip, mac)) return ip;
    }
    return '';
  }

  grantLease(request, ip) {
    this.offers.delete(request.mac);
    if (this.staticLeaseFor(request.mac)) return;
    const startedAt = new Date(this.now()).toISOString();
    const expiresAt = new Date(this.now() + this.config.leaseMinutes * 60_000).toISOString();
    this.leases.set(request.mac, {
      mac: request.mac,
      ip,
      hostname: request.options.hostname,
      startedAt,
      expiresAt
    });
    this.saveLeases();
  }

  async reply(request, rinfo, messageType, ip) {
    const response = buildDhcpResponse({
      request,
      messageType,
      yiaddr: ip,
      serverIp: this.serverIp,
      config: this.config
    });
    const target = replyTarget(request, rinfo);
    await sendDatagram(this.socket, response, target.port, target.address);
  }

  listLeases() {
    this.pruneExpiredLeases();
    return [...this.leases.values()]
      .map((lease) => ({ ...lease }))
      .sort((left, right) => ipv4ToInteger(left.ip) - ipv4ToInteger(right.ip));
  }

  pruneExpiredLeases() {
    const now = this.now();
    let changed = false;
    for (const [mac, lease] of this.leases) {
      if (!lease || Date.parse(lease.expiresAt) <= now) {
        this.leases.delete(mac);
        changed = true;
      }
    }
    for (const [mac, offer] of this.offers) {
      if (!offer || offer.expiresAt <= now) this.offers.delete(mac);
    }
    if (changed) this.saveLeases();
  }

  loadLeases() {
    this.leases.clear();
    try {
      const parsed = JSON.parse(fs.readFileSync(this.leaseFile, 'utf8'));
      const rows = Array.isArray(parsed) ? parsed : parsed?.leases;
      for (const item of Array.isArray(rows) ? rows.slice(0, MAX_LEASES) : []) {
        const mac = normalizeDhcpMac(item?.mac);
        const ip = normalizeIpv4(item?.ip);
        const expiresAt = normalizeTimestamp(item?.expiresAt);
        if (!mac || !ip || !expiresAt || Date.parse(expiresAt) <= this.now() || !this.isPoolIp(ip) || !this.isPoolIpAvailable(ip, mac)) continue;
        this.leases.set(mac, {
          mac,
          ip,
          hostname: normalizeHostname(item?.hostname),
          startedAt: normalizeTimestamp(item?.startedAt) || new Date(this.now()).toISOString(),
          expiresAt
        });
      }
    } catch {}
    this.pruneExpiredLeases();
  }

  saveLeases() {
    try {
      const target = this.leaseFile;
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const data = { version: 1, leases: [...this.leases.values()] };
      const temp = `${target}.tmp-${process.pid}-${Date.now()}`;
      fs.writeFileSync(temp, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
      fs.renameSync(temp, target);
    } catch (error) {
      if (this.status.running) {
        this.status = { ...this.status, error: normalizeRuntimeError(error) };
        this.onStatus(this.snapshotStatus());
      }
    }
  }
}

function parseDhcpRequest(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < DHCP_OPTIONS_OFFSET) return null;
  if (packet[0] !== 1 || packet[1] !== 1 || packet[2] !== 6) return null;
  if (!packet.subarray(236, 240).equals(DHCP_COOKIE)) return null;
  const mac = macFromBuffer(packet.subarray(28, 34));
  if (!mac) return null;
  return {
    packet,
    xid: packet.readUInt32BE(4),
    flags: packet.readUInt16BE(10),
    ciaddr: ipv4FromBuffer(packet.subarray(12, 16)),
    giaddr: ipv4FromBuffer(packet.subarray(24, 28)),
    mac,
    options: parseDhcpOptions(packet.subarray(DHCP_OPTIONS_OFFSET))
  };
}

function parseDhcpOptions(buffer) {
  const options = {
    messageType: 0,
    requestedIp: '',
    serverIdentifier: '',
    hostname: ''
  };
  for (let offset = 0; offset < buffer.length;) {
    const code = buffer[offset];
    offset += 1;
    if (code === 255) break;
    if (code === 0) continue;
    if (offset >= buffer.length) break;
    const length = buffer[offset];
    offset += 1;
    if (offset + length > buffer.length) break;
    const value = buffer.subarray(offset, offset + length);
    offset += length;
    if (code === 53 && length === 1) options.messageType = value[0];
    if (code === 50 && length === 4) options.requestedIp = ipv4FromBuffer(value);
    if (code === 54 && length === 4) options.serverIdentifier = ipv4FromBuffer(value);
    if (code === 12) options.hostname = normalizeHostname(value.toString('ascii'));
  }
  return options;
}

function buildDhcpResponse({ request, messageType, yiaddr, serverIp, config }) {
  const response = Buffer.alloc(DHCP_OPTIONS_OFFSET);
  response[0] = 2;
  request.packet.copy(response, 1, 1, 3);
  request.packet.copy(response, 4, 4, 12);
  request.packet.copy(response, 12, 12, 16);
  if (yiaddr) writeIpv4(response, yiaddr, 16);
  writeIpv4(response, serverIp, 20);
  request.packet.copy(response, 24, 24, 28);
  request.packet.copy(response, 28, 28, 44);
  DHCP_COOKIE.copy(response, 236);

  const options = [
    option(53, Buffer.from([messageType])),
    option(54, ipv4Buffer(serverIp))
  ];
  if (messageType !== DHCP_MESSAGE.NAK) {
    options.push(option(1, ipv4Buffer(config.subnetMask)));
    options.push(option(3, ipv4Buffer(config.gateway)));
    const dnsServers = Array.isArray(config.dnsServers) ? config.dnsServers : [];
    if (dnsServers.length) options.push(option(6, Buffer.concat(dnsServers.map(ipv4Buffer))));
    if (yiaddr) {
      const leaseSeconds = Math.max(300, Math.floor(config.leaseMinutes * 60));
      options.push(option(51, uint32Buffer(leaseSeconds)));
      options.push(option(58, uint32Buffer(Math.max(1, Math.floor(leaseSeconds / 2)))));
      options.push(option(59, uint32Buffer(Math.max(1, Math.floor(leaseSeconds * 0.875)))));
    }
  }
  return Buffer.concat([response, ...options, Buffer.from([255])]);
}

function replyTarget(request, rinfo) {
  if (request.giaddr && request.giaddr !== '0.0.0.0') return { address: request.giaddr, port: DHCP_PORT_SERVER };
  if ((request.flags & 0x8000) !== 0 || !rinfo?.address || rinfo.address === '0.0.0.0') {
    return { address: '255.255.255.255', port: DHCP_PORT_CLIENT };
  }
  return { address: rinfo.address, port: rinfo.port || DHCP_PORT_CLIENT };
}

function option(code, value) {
  return Buffer.concat([Buffer.from([code, value.length]), value]);
}

function bindSocket(socket, port, address) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.off('error', onError);
      if (error) reject(error); else resolve();
    };
    const onError = (error) => finish(error);
    socket.once('error', onError);
    socket.bind(port, address, () => finish());
  });
}

function closeSocket(socket) {
  return new Promise((resolve) => {
    try {
      socket.close(() => resolve());
    } catch {
      resolve();
    }
  });
}

function sendDatagram(socket, packet, port, address) {
  return new Promise((resolve, reject) => {
    if (!socket) return reject(new Error('dhcp_socket_closed'));
    socket.send(packet, port, address, (error) => error ? reject(error) : resolve());
  });
}

function normalizePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('dhcp_port_invalid');
  return port;
}

function normalizeIpv4(value) {
  const address = String(value || '').trim();
  return net.isIP(address) === 4 ? address : '';
}

function normalizeHostname(value) {
  const hostname = String(value || '').replace(/[^a-z0-9.-]/gi, '').replace(/^\.+|\.+$/g, '').slice(0, 253);
  if (!hostname) return '';
  return hostname.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) ? hostname : '';
}

function normalizeTimestamp(value) {
  const time = Date.parse(String(value || ''));
  return Number.isFinite(time) ? new Date(time).toISOString() : '';
}

function normalizeRuntimeError(error) {
  return String(error?.code || error?.message || error || 'dhcp_runtime_error').replace(/[\r\n]+/g, ' ').trim().slice(0, 512);
}

function macFromBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length !== 6) return '';
  return normalizeDhcpMac([...buffer].map((value) => value.toString(16).padStart(2, '0')).join(':'));
}

function ipv4Buffer(address) {
  return Buffer.from(address.split('.').map(Number));
}

function ipv4FromBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length !== 4) return '';
  return [...buffer].join('.');
}

function writeIpv4(buffer, address, offset) {
  ipv4Buffer(address).copy(buffer, offset);
}

function ipv4ToInteger(address) {
  return address.split('.').reduce((value, part) => ((value << 8) | Number(part)) >>> 0, 0);
}

function integerToIpv4(value) {
  const address = value >>> 0;
  return `${(address >>> 24) & 255}.${(address >>> 16) & 255}.${(address >>> 8) & 255}.${address & 255}`;
}

function uint32Buffer(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value >>> 0);
  return buffer;
}

function macHash(mac) {
  let hash = 2166136261;
  for (const char of String(mac)) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}
