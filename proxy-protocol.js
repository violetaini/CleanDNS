const PROXY_V2_SIGNATURE = Buffer.from([
  0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
]);

export function parseProxyV2(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 16) return null;
  if (!buffer.subarray(0, 12).equals(PROXY_V2_SIGNATURE) || buffer[12] !== 0x21) return null;

  const familyProtocol = buffer[13];
  const addressLength = familyProtocol === 0x11 || familyProtocol === 0x12
    ? 12
    : familyProtocol === 0x21 || familyProtocol === 0x22
      ? 36
      : 0;
  const payloadLength = buffer.readUInt16BE(14);
  const offset = 16 + payloadLength;
  if (buffer.length < offset || payloadLength < addressLength) return null;

  let srcIp = '';
  if (addressLength === 12) srcIp = bytesToIpv4(buffer.subarray(16, 20));
  if (addressLength === 36) srcIp = bytesToIpv6(buffer.subarray(16, 32));

  let alpn = '';
  let cursor = 16 + addressLength;
  while (cursor < offset) {
    if (cursor + 3 > offset) return null;
    const type = buffer[cursor];
    const length = buffer.readUInt16BE(cursor + 1);
    cursor += 3;
    if (cursor + length > offset) return null;
    if (type === 0x01) alpn = buffer.subarray(cursor, cursor + length).toString('ascii');
    cursor += length;
  }

  return {
    srcIp,
    offset,
    alpn,
    protocol: alpn === 'doq' ? 'doq' : ''
  };
}

function bytesToIpv4(buffer) {
  return Array.from(buffer).join('.');
}

function bytesToIpv6(buffer) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buffer.readUInt16BE(i).toString(16));
  return groups.join(':');
}
