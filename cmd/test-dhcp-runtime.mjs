import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ManagedDhcpRuntime } from '../dhcp-runtime.js';

const tempBase = path.resolve(os.tmpdir());
const root = fs.mkdtempSync(path.join(tempBase, 'cleandns-dhcp-runtime-'));
const leaseFile = path.join(root, 'leases.json');
const config = {
  enabled: true,
  interfaceName: 'lan0',
  gateway: '192.168.50.1',
  subnetMask: '255.255.255.0',
  rangeStart: '192.168.50.100',
  rangeEnd: '192.168.50.102',
  leaseMinutes: 60,
  dnsServers: ['192.168.50.2'],
  staticLeases: [{ mac: '00:11:22:33:44:66', ip: '192.168.50.20', hostname: 'printer.lan' }]
};
let runtime;
let client;

try {
  client = await createClient();
  runtime = new ManagedDhcpRuntime({ leaseFile });
  await runtime.sync({ enabled: true, config, bindAddress: '127.0.0.1', serverIp: '192.168.50.2', port: 0 });
  assert.equal(runtime.snapshot().running, true);
  const port = runtime.snapshot().port;
  assert.ok(port > 0);

  const firstMac = '00:11:22:33:44:55';
  const offer = await sendAndReceive(client, port, buildRequest({ type: 1, xid: 0x01020304, mac: firstMac, hostname: 'phone.lan' }));
  assert.equal(offer.type, 2);
  assert.match(offer.yiaddr, /^192\.168\.50\.10[0-2]$/);
  assert.equal(offer.serverIdentifier, '192.168.50.2');
  assert.equal(offer.router, '192.168.50.1');
  assert.equal(offer.dnsServer, '192.168.50.2');

  const ack = await sendAndReceive(client, port, buildRequest({
    type: 3,
    xid: 0x01020305,
    mac: firstMac,
    requestedIp: offer.yiaddr,
    serverIdentifier: '192.168.50.2',
    hostname: 'phone.lan'
  }));
  assert.equal(ack.type, 5);
  assert.equal(ack.yiaddr, offer.yiaddr);
  assert.equal(runtime.snapshot().leases.length, 1);
  assert.equal(runtime.snapshot().leases[0].ip, offer.yiaddr);
  assert.ok(fs.existsSync(leaseFile));

  await runtime.close();
  runtime = new ManagedDhcpRuntime({ leaseFile });
  await runtime.sync({ enabled: true, config, bindAddress: '127.0.0.1', serverIp: '192.168.50.2', port: 0 });
  const restartedPort = runtime.snapshot().port;
  assert.equal(runtime.snapshot().leases.length, 1);
  assert.equal(runtime.snapshot().leases[0].ip, offer.yiaddr);

  const reusedOffer = await sendAndReceive(client, restartedPort, buildRequest({ type: 1, xid: 0x01020306, mac: firstMac }));
  assert.equal(reusedOffer.type, 2);
  assert.equal(reusedOffer.yiaddr, offer.yiaddr);

  const staticOffer = await sendAndReceive(client, restartedPort, buildRequest({ type: 1, xid: 0x01020307, mac: '00:11:22:33:44:66' }));
  assert.equal(staticOffer.type, 2);
  assert.equal(staticOffer.yiaddr, '192.168.50.20');
  const staticAck = await sendAndReceive(client, restartedPort, buildRequest({
    type: 3,
    xid: 0x01020308,
    mac: '00:11:22:33:44:66',
    requestedIp: '192.168.50.20',
    serverIdentifier: '192.168.50.2'
  }));
  assert.equal(staticAck.type, 5);
  assert.equal(runtime.snapshot().leases.length, 1, 'static lease must not be stored as a dynamic lease');

  const nak = await sendAndReceive(client, restartedPort, buildRequest({
    type: 3,
    xid: 0x01020309,
    mac: '00:11:22:33:44:77',
    requestedIp: offer.yiaddr,
    serverIdentifier: '192.168.50.2'
  }));
  assert.equal(nak.type, 6);

  const release = buildRequest({ type: 7, xid: 0x01020310, mac: firstMac, ciaddr: offer.yiaddr, serverIdentifier: '192.168.50.2' });
  client.send(release, restartedPort, '127.0.0.1');
  await sleep(30);
  assert.equal(runtime.snapshot().leases.length, 0);

  await runtime.close();
  assert.equal(runtime.snapshot().running, false);
  console.log('dhcp runtime tests passed');
} finally {
  await runtime?.close().catch(() => {});
  await closeClient(client);
  const resolved = path.resolve(root);
  if (resolved.startsWith(tempBase + path.sep) && path.basename(resolved).startsWith('cleandns-dhcp-runtime-')) {
    fs.rmSync(resolved, { recursive: true, force: true });
  }
}

function buildRequest({ type, xid, mac, requestedIp = '', serverIdentifier = '', ciaddr = '', hostname = '' }) {
  const packet = Buffer.alloc(240);
  packet[0] = 1;
  packet[1] = 1;
  packet[2] = 6;
  packet.writeUInt32BE(xid >>> 0, 4);
  if (ciaddr) ipv4Buffer(ciaddr).copy(packet, 12);
  Buffer.from(mac.split(':').map((part) => Number.parseInt(part, 16))).copy(packet, 28);
  Buffer.from([99, 130, 83, 99]).copy(packet, 236);
  const options = [dhcpOption(53, Buffer.from([type]))];
  if (requestedIp) options.push(dhcpOption(50, ipv4Buffer(requestedIp)));
  if (serverIdentifier) options.push(dhcpOption(54, ipv4Buffer(serverIdentifier)));
  if (hostname) options.push(dhcpOption(12, Buffer.from(hostname, 'ascii')));
  return Buffer.concat([packet, ...options, Buffer.from([255])]);
}

function parseResponse(packet) {
  assert.ok(packet.length >= 240, 'response is too short');
  assert.equal(packet[0], 2, 'response must be BOOTREPLY');
  const options = new Map();
  for (let offset = 240; offset < packet.length;) {
    const code = packet[offset++];
    if (code === 255) break;
    if (code === 0) continue;
    const length = packet[offset++];
    options.set(code, packet.subarray(offset, offset + length));
    offset += length;
  }
  return {
    type: options.get(53)?.[0] || 0,
    yiaddr: ipv4FromBuffer(packet.subarray(16, 20)),
    serverIdentifier: ipv4FromBuffer(options.get(54)),
    router: ipv4FromBuffer(options.get(3)),
    dnsServer: ipv4FromBuffer(options.get(6))
  };
}

async function createClient() {
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', resolve);
  });
  return socket;
}

function sendAndReceive(socket, port, packet) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('dhcp response timeout')), 2000);
    const finish = (error, response) => {
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
      if (error) reject(error); else resolve(parseResponse(response));
    };
    const onMessage = (response) => finish(null, response);
    const onError = (error) => finish(error);
    socket.once('message', onMessage);
    socket.once('error', onError);
    socket.send(packet, port, '127.0.0.1', (error) => {
      if (error) finish(error);
    });
  });
}

function closeClient(socket) {
  return new Promise((resolve) => {
    if (!socket) return resolve();
    try {
      socket.close(resolve);
    } catch {
      resolve();
    }
  });
}

function dhcpOption(code, value) {
  return Buffer.concat([Buffer.from([code, value.length]), value]);
}

function ipv4Buffer(value) {
  return Buffer.from(value.split('.').map(Number));
}

function ipv4FromBuffer(value) {
  return Buffer.isBuffer(value) && value.length === 4 ? [...value].join('.') : '';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
