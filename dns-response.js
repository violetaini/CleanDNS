const TYPE_NAMES = new Map([
  [1, 'A'],
  [2, 'NS'],
  [5, 'CNAME'],
  [6, 'SOA'],
  [12, 'PTR'],
  [15, 'MX'],
  [16, 'TXT'],
  [28, 'AAAA'],
  [33, 'SRV'],
  [64, 'SVCB'],
  [65, 'HTTPS'],
  [257, 'CAA']
]);

const RCODE_NAMES = new Map([
  [0, 'NOERROR'],
  [1, 'FORMERR'],
  [2, 'SERVFAIL'],
  [3, 'NXDOMAIN'],
  [4, 'NOTIMP'],
  [5, 'REFUSED']
]);

export function decodeDnsResponse(packet, options = {}) {
  const maxAnswers = Math.max(0, Math.min(64, Math.floor(Number(options.maxAnswers) || 16)));
  const flagsValue = Buffer.isBuffer(packet) && packet.length >= 4 ? packet.readUInt16BE(2) : 0;
  const answerCount = Buffer.isBuffer(packet) && packet.length >= 8 ? packet.readUInt16BE(6) : 0;
  const rcode = flagsValue & 0x0f;
  const result = {
    rcode,
    status: rcodeName(rcode),
    question: '',
    answerCount,
    answersTruncated: answerCount > maxAnswers,
    answers: [],
    flags: {
      authoritative: Boolean(flagsValue & 0x0400),
      truncated: Boolean(flagsValue & 0x0200),
      recursionAvailable: Boolean(flagsValue & 0x0080),
      authenticatedData: Boolean(flagsValue & 0x0020)
    }
  };
  if (!Buffer.isBuffer(packet) || packet.length < 12) return result;

  try {
    const questionCount = packet.readUInt16BE(4);
    let offset = 12;
    for (let index = 0; index < questionCount; index += 1) {
      const name = readDnsName(packet, offset);
      if (!name || name.offset + 4 > packet.length) throw new Error('bad_question');
      if (index === 0) result.question = name.name;
      offset = name.offset + 4;
    }

    for (let index = 0; index < answerCount && index < maxAnswers; index += 1) {
      const name = readDnsName(packet, offset);
      if (!name || name.offset + 10 > packet.length) throw new Error('bad_answer');
      offset = name.offset;
      const type = packet.readUInt16BE(offset);
      const ttl = packet.readUInt32BE(offset + 4);
      const length = packet.readUInt16BE(offset + 8);
      const valueOffset = offset + 10;
      const end = valueOffset + length;
      if (end > packet.length) throw new Error('bad_rdata');
      result.answers.push({
        name: name.name,
        type: TYPE_NAMES.get(type) || String(type),
        ttl,
        value: decodeRecordValue(packet, type, valueOffset, length)
      });
      offset = end;
    }
  } catch {
    result.answersTruncated = result.answerCount > result.answers.length;
  }
  return result;
}

export function rcodeName(rcode) {
  const value = Number(rcode);
  return RCODE_NAMES.get(value) || `RCODE_${Number.isFinite(value) ? value : -1}`;
}

function decodeRecordValue(packet, type, offset, length) {
  const end = offset + length;
  if (type === 1 && length === 4) return Array.from(packet.subarray(offset, end)).join('.');
  if (type === 28 && length === 16) return ipv6String(packet.subarray(offset, end));
  if (type === 2 || type === 5 || type === 12) return readDnsName(packet, offset)?.name || hexValue(packet, offset, end);
  if (type === 15 && length >= 3) {
    const exchange = readDnsName(packet, offset + 2);
    return exchange ? `${packet.readUInt16BE(offset)} ${exchange.name}` : hexValue(packet, offset, end);
  }
  if (type === 16) return txtValue(packet, offset, end);
  if (type === 6) return soaValue(packet, offset, end);
  if (type === 33 && length >= 7) return srvValue(packet, offset, end);
  if (type === 257 && length >= 2) return caaValue(packet, offset, end);
  if ((type === 64 || type === 65) && length >= 3) return serviceBindingValue(packet, offset, end);
  return hexValue(packet, offset, end);
}

function txtValue(packet, offset, end) {
  const values = [];
  let cursor = offset;
  while (cursor < end) {
    const length = packet[cursor];
    cursor += 1;
    if (cursor + length > end) return hexValue(packet, offset, end);
    values.push(packet.subarray(cursor, cursor + length).toString('utf8'));
    cursor += length;
  }
  return values.join(' ');
}

function soaValue(packet, offset, end) {
  const primary = readDnsName(packet, offset);
  if (!primary) return hexValue(packet, offset, end);
  const mailbox = readDnsName(packet, primary.offset);
  if (!mailbox || mailbox.offset + 20 > end) return hexValue(packet, offset, end);
  return [
    primary.name,
    mailbox.name,
    packet.readUInt32BE(mailbox.offset),
    packet.readUInt32BE(mailbox.offset + 4),
    packet.readUInt32BE(mailbox.offset + 8),
    packet.readUInt32BE(mailbox.offset + 12),
    packet.readUInt32BE(mailbox.offset + 16)
  ].join(' ');
}

function srvValue(packet, offset, end) {
  const target = readDnsName(packet, offset + 6);
  if (!target || target.offset > end) return hexValue(packet, offset, end);
  return `${packet.readUInt16BE(offset)} ${packet.readUInt16BE(offset + 2)} ${packet.readUInt16BE(offset + 4)} ${target.name}`;
}

function caaValue(packet, offset, end) {
  const tagLength = packet[offset + 1];
  if (offset + 2 + tagLength > end) return hexValue(packet, offset, end);
  const tag = packet.subarray(offset + 2, offset + 2 + tagLength).toString('ascii');
  const value = packet.subarray(offset + 2 + tagLength, end).toString('utf8');
  return `${packet[offset]} ${tag} ${value}`;
}

function serviceBindingValue(packet, offset, end) {
  const target = readDnsName(packet, offset + 2);
  if (!target || target.offset > end) return hexValue(packet, offset, end);
  const params = packet.subarray(target.offset, end);
  return `${packet.readUInt16BE(offset)} ${target.name || '.'}${params.length ? ' ' + params.toString('hex') : ''}`;
}

function readDnsName(packet, offset, depth = 0) {
  if (!Buffer.isBuffer(packet) || depth > 16 || offset < 0 || offset >= packet.length) return null;
  const labels = [];
  let cursor = offset;
  let finalOffset = offset;
  while (cursor < packet.length) {
    const length = packet[cursor];
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= packet.length) return null;
      const pointer = ((length & 0x3f) << 8) | packet[cursor + 1];
      const pointed = readDnsName(packet, pointer, depth + 1);
      if (!pointed) return null;
      if (pointed.name) labels.push(pointed.name);
      finalOffset = cursor + 2;
      break;
    }
    if (length === 0) {
      finalOffset = cursor + 1;
      break;
    }
    cursor += 1;
    if (cursor + length > packet.length) return null;
    labels.push(packet.subarray(cursor, cursor + length).toString('ascii'));
    cursor += length;
    finalOffset = cursor;
  }
  return { name: labels.join('.'), offset: finalOffset };
}

function ipv6String(buffer) {
  const groups = [];
  for (let offset = 0; offset < 16; offset += 2) groups.push(buffer.readUInt16BE(offset).toString(16));
  return groups.join(':');
}

function hexValue(packet, offset, end) {
  return packet.subarray(offset, end).toString('hex');
}
