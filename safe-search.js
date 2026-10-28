const SAFE_SEARCH_QTYPES = new Set([1, 28, 65]);

export const SAFE_SEARCH_SERVICES = Object.freeze([
  { id: 'bing', name: 'Bing', target: 'strict.bing.com' },
  { id: 'duckduckgo', name: 'DuckDuckGo', target: 'safe.duckduckgo.com' },
  { id: 'ecosia', name: 'Ecosia', target: 'strict-safe-search.ecosia.org' },
  { id: 'google', name: 'Google', target: 'forcesafesearch.google.com' },
  { id: 'pixabay', name: 'Pixabay', target: 'safesearch.pixabay.com' },
  { id: 'yandex', name: 'Yandex', target: '213.180.193.56' },
  { id: 'youtube', name: 'YouTube', target: 'restrictmoderate.youtube.com' }
]);

const SAFE_SEARCH_DEFAULTS = Object.freeze({
  enabled: false,
  bing: true,
  duckduckgo: true,
  ecosia: true,
  google: true,
  pixabay: true,
  yandex: true,
  youtube: true
});

// These domains mirror AdGuard Home's embedded Safe Search rules.  They are
// bundled locally so DNS decisions never depend on a runtime HTTP service.
const GOOGLE_DOMAINS = domainSet(`
www.google.ad www.google.ae www.google.al www.google.am www.google.as www.google.at
www.google.az www.google.ba www.google.be www.google.bf www.google.bg www.google.bi
www.google.bj www.google.bs www.google.bt www.google.by www.google.ca www.google.cat
www.google.cd www.google.cf www.google.cg www.google.ch www.google.ci www.google.cl
www.google.cm www.google.cn www.google.co www.google.co.ao www.google.co.bw www.google.co.ck
www.google.co.cr www.google.co.id www.google.co.il www.google.co.in www.google.co.jp www.google.co.ke
www.google.co.kr www.google.co.ls www.google.co.ma www.google.co.mz www.google.co.nz www.google.co.th
www.google.co.tz www.google.co.ug www.google.co.uk www.google.co.uz www.google.co.ve www.google.co.vi
www.google.co.za www.google.co.zm www.google.co.zw www.google.com.af www.google.com.ag www.google.com.ai
www.google.com.ar www.google.com.au www.google.com.bd www.google.com.bh www.google.com.bn www.google.com.bo
www.google.com.br www.google.com.bz www.google.com.co www.google.com.cu www.google.com.cy www.google.com.do
www.google.com.ec www.google.com.eg www.google.com.et www.google.com.fj www.google.com.gh www.google.com.gi
www.google.com.gt www.google.com.hk www.google.com.jm www.google.com.kh www.google.com.kw www.google.com.lb
www.google.com.ly www.google.com.mm www.google.com.mt www.google.com.mx www.google.com.my www.google.com.na
www.google.com.nf www.google.com.ng www.google.com.ni www.google.com.np www.google.com.om www.google.com.pa
www.google.com.pe www.google.com.pg www.google.com.ph www.google.com.pk www.google.com.pr www.google.com.py
www.google.com.qa www.google.com.sa www.google.com.sb www.google.com.sg www.google.com.sl www.google.com.sv
www.google.com.tj www.google.com.tr www.google.com.tw www.google.com.ua www.google.com.uy www.google.com.vc
www.google.com.vn www.google.com www.google.cv www.google.cz www.google.de www.google.dj
www.google.dk www.google.dm www.google.dz www.google.ee www.google.es www.google.fi
www.google.fm www.google.fr www.google.ga www.google.ge www.google.gg www.google.gl
www.google.gm www.google.gp www.google.gr www.google.gy www.google.hn www.google.hr
www.google.ht www.google.hu www.google.ie www.google.im www.google.iq www.google.is
www.google.it www.google.je www.google.jo www.google.kg www.google.ki www.google.kz
www.google.la www.google.li www.google.lk www.google.lt www.google.lu www.google.lv
www.google.md www.google.me www.google.mg www.google.mk www.google.ml www.google.mn
www.google.ms www.google.mu www.google.mv www.google.mw www.google.ne www.google.nl
www.google.no www.google.nr www.google.nu www.google.pl www.google.pn www.google.ps
www.google.pt www.google.ro www.google.rs www.google.ru www.google.rw www.google.sc
www.google.se www.google.sh www.google.si www.google.sk www.google.sm www.google.sn
www.google.so www.google.sr www.google.st www.google.td www.google.tg www.google.tk
www.google.tl www.google.tm www.google.tn www.google.to www.google.tt www.google.vg
www.google.vu www.google.ws
`);

const YANDEX_DOMAINS = domainSet(`
www.xn--d1acpjx3f.xn--p1ai www.ya.ru www.yandex.az www.yandex.by www.yandex.co.il www.yandex.com.am
www.yandex.com.ge www.yandex.com.ru www.yandex.com.tr www.yandex.com www.yandex.de www.yandex.ee
www.yandex.eu www.yandex.fi www.yandex.fr www.yandex.kz www.yandex.lt www.yandex.lv
www.yandex.md www.yandex.net www.yandex.org www.yandex.pl www.yandex.ru www.yandex.tj
www.yandex.tm www.yandex.uz xn--d1acpjx3f.xn--p1ai ya.ru yandex.az yandex.by
yandex.co.il yandex.com.am yandex.com.ge yandex.com.ru yandex.com.tr yandex.com
yandex.de yandex.ee yandex.eu yandex.fi yandex.fr yandex.kz
yandex.lt yandex.lv yandex.md yandex.net yandex.org yandex.pl
yandex.ru yandex.tj yandex.tm yandex.uz
`);

const RULE_GROUPS = [
  { service: 'bing', domains: domainSet('www.bing.com edgeservices.bing.com'), kind: 'cname', value: 'strict.bing.com' },
  { service: 'duckduckgo', domains: domainSet('duckduckgo.com start.duckduckgo.com www.duckduckgo.com'), kind: 'cname', value: 'safe.duckduckgo.com' },
  { service: 'ecosia', domains: domainSet('www.ecosia.org'), kind: 'cname', value: 'strict-safe-search.ecosia.org' },
  { service: 'google', domains: GOOGLE_DOMAINS, kind: 'cname', value: 'forcesafesearch.google.com' },
  { service: 'pixabay', domains: domainSet('pixabay.com'), kind: 'cname', value: 'safesearch.pixabay.com' },
  { service: 'yandex', domains: YANDEX_DOMAINS, kind: 'ip', value: '213.180.193.56' },
  { service: 'youtube', domains: domainSet('www.youtube.com m.youtube.com youtubei.googleapis.com youtube.googleapis.com www.youtube-nocookie.com'), kind: 'cname', value: 'restrictmoderate.youtube.com' }
];

const RULES_BY_DOMAIN = new Map();
for (const group of RULE_GROUPS) {
  for (const domain of group.domains) {
    RULES_BY_DOMAIN.set(domain, Object.freeze({
      service: group.service,
      kind: group.kind,
      value: group.value,
      rule: `safe-search:${group.service}`
    }));
  }
}

export function normalizeSafeSearchConfig(value) {
  const input = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const normalized = { enabled: input.enabled === true };
  for (const service of SAFE_SEARCH_SERVICES) {
    normalized[service.id] = input[service.id] !== false;
  }
  return normalized;
}

export function matchSafeSearch(domain, qtype, settings) {
  if (!settings?.enabled || !SAFE_SEARCH_QTYPES.has(Number(qtype))) return null;
  const rule = RULES_BY_DOMAIN.get(normalizeDomain(domain));
  if (!rule || settings[rule.service] !== true) return null;
  if (rule.kind === 'ip' && Number(qtype) !== 1) return { ...rule, kind: 'nodata' };
  return rule;
}

export function safeSearchRuleCount() {
  return RULES_BY_DOMAIN.size;
}

export function buildCnameResponse(query, parsed, target, upstreamResponse, ttl = 60) {
  const targetAnswers = parseTargetAnswers(upstreamResponse, parsed.qtype);
  const cname = encodeRecord({
    namePointer: true,
    type: 5,
    classCode: 1,
    ttl,
    rdata: encodeDnsName(target)
  });
  const encodedAnswers = [cname, ...targetAnswers.map(encodeRecord)];
  const header = Buffer.alloc(12);
  header.writeUInt16BE(parsed.id & 0xffff, 0);
  let flags = Buffer.isBuffer(upstreamResponse) && upstreamResponse.length >= 4
    ? upstreamResponse.readUInt16BE(2)
    : 0x8180;
  flags = (flags | 0x8080) & ~0x0020;
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(encodedAnswers.length, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  return Buffer.concat([header, query.subarray(12, parsed.questionEnd), ...encodedAnswers]);
}

export const buildSafeSearchCnameResponse = buildCnameResponse;

function domainSet(text) {
  return new Set(String(text || '').trim().split(/\s+/).map(normalizeDomain).filter(Boolean));
}

function normalizeDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/\.+$/, '');
}

function parseTargetAnswers(packet, qtype) {
  if (!Buffer.isBuffer(packet) || packet.length < 12) return [];
  const records = [];
  try {
    const qd = packet.readUInt16BE(4);
    const an = packet.readUInt16BE(6);
    let offset = 12;
    for (let i = 0; i < qd; i += 1) {
      const questionName = readDnsName(packet, offset);
      if (!questionName || questionName.offset + 4 > packet.length) return [];
      offset = questionName.offset + 4;
    }
    for (let i = 0; i < an; i += 1) {
      const owner = readDnsName(packet, offset);
      if (!owner || owner.offset + 10 > packet.length) break;
      offset = owner.offset;
      const type = packet.readUInt16BE(offset);
      const classCode = packet.readUInt16BE(offset + 2);
      const ttl = packet.readUInt32BE(offset + 4);
      const length = packet.readUInt16BE(offset + 8);
      const rdataOffset = offset + 10;
      const end = rdataOffset + length;
      if (end > packet.length) break;
      const record = decodeTargetRecord(packet, {
        name: owner.name,
        type,
        classCode,
        ttl,
        rdataOffset,
        end
      }, qtype);
      if (record) records.push(record);
      offset = end;
    }
  } catch {
    return [];
  }
  return records;
}

function decodeTargetRecord(packet, record, qtype) {
  const allowed = record.type === 5 ||
    (Number(qtype) === 1 && record.type === 1) ||
    (Number(qtype) === 28 && record.type === 28) ||
    (Number(qtype) === 65 && (record.type === 64 || record.type === 65));
  if (!allowed || record.classCode !== 1) return null;

  let rdata = Buffer.from(packet.subarray(record.rdataOffset, record.end));
  if (record.type === 5) {
    const cname = readDnsName(packet, record.rdataOffset);
    if (!cname) return null;
    rdata = encodeDnsName(cname.name);
  } else if (record.type === 64 || record.type === 65) {
    if (record.rdataOffset + 2 > record.end) return null;
    const target = readDnsName(packet, record.rdataOffset + 2);
    if (!target || target.offset > record.end) return null;
    rdata = Buffer.concat([
      packet.subarray(record.rdataOffset, record.rdataOffset + 2),
      encodeDnsName(target.name),
      packet.subarray(target.offset, record.end)
    ]);
  }
  return {
    name: record.name,
    type: record.type,
    classCode: record.classCode,
    ttl: record.ttl,
    rdata
  };
}

function encodeRecord(record) {
  const owner = record.namePointer ? Buffer.from([0xc0, 0x0c]) : encodeDnsName(record.name);
  const rdata = Buffer.from(record.rdata || []);
  const header = Buffer.alloc(10);
  header.writeUInt16BE(record.type & 0xffff, 0);
  header.writeUInt16BE(record.classCode & 0xffff, 2);
  header.writeUInt32BE(Math.max(0, Number(record.ttl) || 0) >>> 0, 4);
  header.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([owner, header, rdata]);
}

function encodeDnsName(name) {
  const normalized = normalizeDomain(name);
  if (!normalized) return Buffer.from([0]);
  const labels = normalized.split('.').map((label) => {
    const bytes = Buffer.from(label, 'ascii');
    if (!bytes.length || bytes.length > 63) throw new Error('bad_dns_name');
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  });
  const encoded = Buffer.concat([...labels, Buffer.from([0])]);
  if (encoded.length > 255) throw new Error('bad_dns_name');
  return encoded;
}

function readDnsName(packet, offset, depth = 0) {
  if (depth > 16 || offset < 0 || offset >= packet.length) return null;
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
      labels.push(...pointed.name.split('.').filter(Boolean));
      finalOffset = cursor + 2;
      break;
    }
    if ((length & 0xc0) !== 0 || length > 63) return null;
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
