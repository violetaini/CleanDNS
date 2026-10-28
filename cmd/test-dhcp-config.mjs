import assert from 'node:assert/strict';
import {
  collectDhcpInterfaces,
  dhcpInterfaceIpv4ForConfig,
  normalizeDhcpDnsServers,
  ipv4MaskInfo,
  normalizeDhcpConfig,
  normalizeDhcpMac,
  validateDhcpConfig,
  validateDhcpStaticLease
} from '../dhcp-config.js';

const interfaces = collectDhcpInterfaces({
  eth0: [{ address: '203.0.113.44', netmask: '255.255.255.0', family: 'IPv4', mac: '02:18:9f:2b:a3:73', internal: false, cidr: '203.0.113.44/24' }],
  lan0: [{ address: '192.168.50.2', netmask: '255.255.255.0', family: 'IPv4', mac: '02:00:00:00:00:01', internal: false, cidr: '192.168.50.2/24' }],
  docker0: [{ address: '172.17.0.1', netmask: '255.255.0.0', family: 'IPv4', mac: '02:42:00:00:00:01', internal: false, cidr: '172.17.0.1/16' }],
  lo: [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' }]
});

assert.equal(interfaces.find((entry) => entry.name === 'lan0').eligible, true);
assert.equal(interfaces.find((entry) => entry.name === 'eth0').eligible, false);
assert.equal(interfaces.find((entry) => entry.name === 'docker0').virtual, true);
assert.equal(interfaces.find((entry) => entry.name === 'lo').internal, true);
assert.equal(normalizeDhcpMac('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff');
assert.equal(ipv4MaskInfo('255.255.255.0').prefixLength, 24);
assert.equal(ipv4MaskInfo('255.0.255.0'), null);

const validConfig = normalizeDhcpConfig({
  interfaceName: 'lan0',
  gateway: '192.168.50.1',
  subnetMask: '255.255.255.0',
  rangeStart: '192.168.50.100',
  rangeEnd: '192.168.50.200',
  leaseMinutes: 1440,
  dnsServers: ['192.168.50.2', '1.1.1.1'],
  staticLeases: [
    { mac: 'AA-BB-CC-DD-EE-FF', ip: '192.168.50.20', hostname: 'printer.lan' }
  ]
});
const valid = validateDhcpConfig(validConfig, interfaces);
assert.equal(valid.valid, true, JSON.stringify(valid.errors));
assert.deepEqual(validConfig.staticLeases, [{ mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.50.20', hostname: 'printer.lan' }]);
assert.deepEqual(validConfig.dnsServers, ['192.168.50.2', '1.1.1.1']);
assert.deepEqual(normalizeDhcpDnsServers('1.1.1.1\n8.8.8.8\n1.1.1.1'), ['1.1.1.1', '8.8.8.8']);
assert.equal(dhcpInterfaceIpv4ForConfig(validConfig, interfaces.find((entry) => entry.name === 'lan0'))?.address, '192.168.50.2');

const interfaceMismatch = validateDhcpConfig({ ...validConfig, interfaceName: 'docker0' }, interfaces);
assert.ok(interfaceMismatch.errors.some((entry) => entry.code === 'interface_subnet_mismatch'));

const publicResult = validateDhcpConfig({ ...validConfig, interfaceName: 'eth0', gateway: '203.0.113.1', rangeStart: '203.0.113.100', rangeEnd: '203.0.113.200' }, interfaces);
assert.equal(publicResult.valid, false);
assert.ok(publicResult.errors.some((entry) => entry.code === 'interface_public_only'));

const gatewayInPool = validateDhcpConfig({ ...validConfig, gateway: '192.168.50.150' }, interfaces);
assert.ok(gatewayInPool.errors.some((entry) => entry.code === 'gateway_inside_range'));

const wrongSubnet = validateDhcpConfig({ ...validConfig, rangeEnd: '192.168.51.200' }, interfaces);
assert.ok(wrongSubnet.errors.some((entry) => entry.code === 'range_end_outside_subnet'));

const invalidMask = validateDhcpConfig({ ...validConfig, subnetMask: '255.0.255.0' }, interfaces);
assert.ok(invalidMask.errors.some((entry) => entry.code === 'subnet_mask_invalid'));

const invalidDns = validateDhcpConfig({ ...validConfig, dnsServers: ['192.168.50.2', 'not-an-ip'] }, interfaces);
assert.ok(invalidDns.errors.some((entry) => entry.code === 'dns_server_invalid'));

const duplicateLeases = validateDhcpConfig({
  ...validConfig,
  staticLeases: [
    { mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.50.20' },
    { mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.50.21' },
    { mac: '00:11:22:33:44:55', ip: '192.168.50.20' }
  ]
}, interfaces);
assert.ok(duplicateLeases.errors.some((entry) => entry.code === 'static_lease_mac_duplicate'));
assert.ok(duplicateLeases.errors.some((entry) => entry.code === 'static_lease_ip_duplicate'));

assert.equal(validateDhcpStaticLease({ mac: 'not-a-mac', ip: '192.168.50.20' }).valid, false);
assert.equal(validateDhcpStaticLease({ mac: '00:11:22:33:44:55', ip: '192.168.50.20', hostname: 'bad_name' }).valid, false);
assert.equal(validateDhcpStaticLease({ mac: '00:11:22:33:44:55', ip: '192.168.50.20', hostname: 'camera.lan' }).valid, true);

console.log('dhcp config tests passed');
