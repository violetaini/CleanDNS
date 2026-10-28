import assert from 'node:assert/strict';
import { parseHostsFile, parseLinuxArpTable } from '../runtime-client-sources.js';

assert.deepEqual(parseHostsFile(`
# local mappings
127.0.0.1 localhost loopback
192.168.50.20 media-box media
2001:db8::20 ipv6-host
not-an-ip ignored
192.168.50.20 camera
`), [
  { address: '127.0.0.1', hostname: 'localhost', aliases: ['localhost', 'loopback'] },
  { address: '192.168.50.20', hostname: 'media-box', aliases: ['media-box', 'media', 'camera'] },
  { address: '2001:db8::20', hostname: 'ipv6-host', aliases: ['ipv6-host'] }
]);

assert.deepEqual(parseLinuxArpTable(`IP address       HW type     Flags       HW address            Mask     Device
192.168.50.20    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.50.21    0x1         0x0         aa:bb:cc:dd:ee:01     *        eth0
192.168.50.22    0x1         0x2         00:00:00:00:00:00     *        eth0
192.168.50.20    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1
`), [
  { address: '192.168.50.20', mac: 'aa:bb:cc:dd:ee:ff', device: 'eth0' }
]);

console.log('runtime client source parser tests passed');
