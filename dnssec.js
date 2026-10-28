const DNS_TYPE_OPT = 41;
const DNS_FLAG_AD = 0x0020;
const EDNS_FLAG_DO = 0x8000;
const DEFAULT_EDNS_UDP_SIZE = 1232;

export function enableDnssecRequest(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 12) return packet;
  const structure = scanDnsPacket(packet);
  if (!structure) return packet;

  const state = dnssecRequestState(packet, structure);
  if (state.ad && state.do) return packet;

  const output = Buffer.from(packet);
  output.writeUInt16BE(output.readUInt16BE(2) | DNS_FLAG_AD, 2);
  if (structure.optRecords.length) {
    for (const record of structure.optRecords) {
      output.writeUInt16BE(output.readUInt16BE(record.ednsFlagsOffset) | EDNS_FLAG_DO, record.ednsFlagsOffset);
    }
    return output;
  }

  if (output.length + 11 > 65535 || structure.additionalCount >= 0xffff) return packet;
  output.writeUInt16BE(structure.additionalCount + 1, 10);
  return Buffer.concat([output, buildOptRecord()]);
}

export function dnssecRequestState(packet, structure = null) {
  if (!Buffer.isBuffer(packet) || packet.length < 12) return { ad: false, do: false };
  const parsed = structure || scanDnsPacket(packet);
  const ad = Boolean(packet.readUInt16BE(2) & DNS_FLAG_AD);
  const dnssecOk = Boolean(parsed?.optRecords.some((record) => (
    packet.readUInt16BE(record.ednsFlagsOffset) & EDNS_FLAG_DO
  )));
  return { ad, do: dnssecOk };
}

export function dnssecCacheProfile(packet, force = false) {
  return force || dnssecRequestState(packet).do ? 'dnssec' : 'plain';
}

function scanDnsPacket(packet) {
  try {
    let offset = 12;
    const questionCount = packet.readUInt16BE(4);
    const answerCount = packet.readUInt16BE(6);
    const authorityCount = packet.readUInt16BE(8);
    const additionalCount = packet.readUInt16BE(10);

    for (let index = 0; index < questionCount; index += 1) {
      offset = skipDnsName(packet, offset);
      if (offset < 0 || offset + 4 > packet.length) return null;
      offset += 4;
    }

    const resourceCount = answerCount + authorityCount;
    for (let index = 0; index < resourceCount; index += 1) {
      const record = readResourceRecord(packet, offset);
      if (!record) return null;
      offset = record.end;
    }

    const optRecords = [];
    for (let index = 0; index < additionalCount; index += 1) {
      const record = readResourceRecord(packet, offset);
      if (!record) return null;
      if (record.type === DNS_TYPE_OPT) optRecords.push(record);
      offset = record.end;
    }
    if (offset !== packet.length) return null;
    return { additionalCount, optRecords };
  } catch {
    return null;
  }
}

function readResourceRecord(packet, offset) {
  const nameEnd = skipDnsName(packet, offset);
  if (nameEnd < 0 || nameEnd + 10 > packet.length) return null;
  const type = packet.readUInt16BE(nameEnd);
  const dataLength = packet.readUInt16BE(nameEnd + 8);
  const end = nameEnd + 10 + dataLength;
  if (end > packet.length) return null;
  return {
    type,
    end,
    ednsFlagsOffset: nameEnd + 6
  };
}

function skipDnsName(packet, offset) {
  let cursor = offset;
  while (cursor < packet.length) {
    const length = packet[cursor];
    if ((length & 0xc0) === 0xc0) return cursor + 1 < packet.length ? cursor + 2 : -1;
    if ((length & 0xc0) !== 0) return -1;
    if (length === 0) return cursor + 1;
    cursor += 1;
    if (cursor + length > packet.length) return -1;
    cursor += length;
  }
  return -1;
}

function buildOptRecord() {
  const record = Buffer.alloc(11);
  record.writeUInt16BE(DNS_TYPE_OPT, 1);
  record.writeUInt16BE(DEFAULT_EDNS_UDP_SIZE, 3);
  record.writeUInt16BE(EDNS_FLAG_DO, 7);
  return record;
}
