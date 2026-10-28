import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';

export const DEFAULT_TLS_CERT_FILE = '/etc/cleandns/tls/fullchain.pem';
export const DEFAULT_TLS_KEY_FILE = '/etc/cleandns/tls/privkey.pem';

export function inspectTlsConfiguration(config = {}, options = {}) {
  const service = config.service || {};
  const now = normalizeDate(options.now) || new Date();
  const certificatePath = String(service.doqTlsCertFile || DEFAULT_TLS_CERT_FILE).trim();
  const privateKeyPath = String(service.doqTlsKeyFile || DEFAULT_TLS_KEY_FILE).trim();
  const hosts = tlsPublicHosts(config);
  const issues = [];
  const result = {
    enabled: service.dohEnabled !== false || service.doqEnabled !== false,
    serverName: hosts[0] || '',
    hosts,
    certificatePath,
    privateKeyPath,
    certificateSource: 'path',
    subject: '',
    issuer: '',
    serialNumber: '',
    fingerprint256: '',
    notBefore: '',
    notAfter: '',
    dnsNames: [],
    keyType: '',
    chainCertificates: 0,
    validCert: false,
    validKey: false,
    validChain: false,
    validPair: false,
    validTime: false,
    validHost: false,
    hostMatches: [],
    daysRemaining: null,
    certificateFile: fileMetadata(certificatePath),
    privateKeyFile: fileMetadata(privateKeyPath),
    issues,
    status: 'invalid',
    checkedAt: now.toISOString()
  };

  let certificates = [];
  let privateKey = null;
  try {
    const certificatePem = fs.readFileSync(certificatePath, 'utf8');
    certificates = certificatePemBlocks(certificatePem).map((value) => new crypto.X509Certificate(value));
    if (!certificates.length) throw new Error('certificate_empty');
    result.validCert = true;
    result.chainCertificates = certificates.length;
    const leaf = certificates[0];
    result.subject = leaf.subject;
    result.issuer = leaf.issuer;
    result.serialNumber = leaf.serialNumber;
    result.fingerprint256 = leaf.fingerprint256;
    result.notBefore = normalizeDate(leaf.validFrom)?.toISOString() || '';
    result.notAfter = normalizeDate(leaf.validTo)?.toISOString() || '';
    result.dnsNames = certificateDnsNames(leaf);
    result.validChain = verifyCertificateChain(certificates);
    const notBefore = normalizeDate(leaf.validFrom);
    const notAfter = normalizeDate(leaf.validTo);
    result.validTime = Boolean(notBefore && notAfter && now >= notBefore && now <= notAfter);
    result.daysRemaining = notAfter ? Math.ceil((notAfter.getTime() - now.getTime()) / 86_400_000) : null;
    result.hostMatches = hosts.map((host) => certificateHostMatch(leaf, host));
    result.validHost = result.hostMatches.length > 0 && result.hostMatches.every((entry) => entry.valid);
  } catch {
    issues.push({ code: result.certificateFile.exists ? 'certificate_invalid' : 'certificate_missing', severity: 'error' });
  }

  try {
    privateKey = crypto.createPrivateKey(fs.readFileSync(privateKeyPath, 'utf8'));
    result.validKey = true;
    result.keyType = formatKeyType(privateKey);
  } catch {
    issues.push({ code: result.privateKeyFile.exists ? 'private_key_invalid' : 'private_key_missing', severity: 'error' });
  }

  if (result.validCert && result.validKey) {
    try {
      const certificateKey = certificates[0].publicKey.export({ type: 'spki', format: 'der' });
      const privatePublicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
      result.validPair = Buffer.from(certificateKey).equals(Buffer.from(privatePublicKey));
    } catch {
      result.validPair = false;
    }
  }

  if (result.validCert && !result.validTime) issues.push({ code: 'certificate_time_invalid', severity: 'error' });
  if (result.validCert && hosts.length && !result.validHost) issues.push({ code: 'certificate_host_mismatch', severity: 'error' });
  if (result.validCert && !result.validChain) issues.push({ code: 'certificate_chain_invalid', severity: 'warning' });
  if (result.validCert && result.validKey && !result.validPair) issues.push({ code: 'certificate_key_mismatch', severity: 'error' });
  if (result.validTime && Number.isFinite(result.daysRemaining) && result.daysRemaining <= 30) {
    issues.push({ code: 'certificate_expiring', severity: 'warning', value: result.daysRemaining });
  }

  const invalid = !result.validCert || !result.validKey || !result.validPair || !result.validTime || (hosts.length > 0 && !result.validHost);
  result.status = invalid ? 'invalid' : issues.some((issue) => issue.severity === 'warning') ? 'warning' : 'valid';
  return result;
}

export function buildDohMobileConfig({ serverUrl, displayName = 'CleanDNS' } = {}) {
  let endpoint;
  try {
    endpoint = new URL(String(serverUrl || '').trim());
  } catch {
    throw new Error('bad_doh_profile_url');
  }
  if (endpoint.protocol !== 'https:' || !endpoint.hostname || !endpoint.pathname.endsWith('/dns-query')) {
    throw new Error('bad_doh_profile_url');
  }

  const name = String(displayName || 'CleanDNS').replace(/[\r\n]/g, ' ').trim().slice(0, 80) || 'CleanDNS';
  const identifierBase = `net.cleandns.${crypto.createHash('sha256').update(endpoint.href).digest('hex').slice(0, 16)}`;
  const profileUuid = deterministicUuid(`${identifierBase}:profile`);
  const dnsUuid = deterministicUuid(`${identifierBase}:dns`);
  const escapedName = xmlEscape(name);
  const escapedUrl = xmlEscape(endpoint.href);
  const escapedIdentifier = xmlEscape(identifierBase);

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>${escapedUrl}</string>
      </dict>
      <key>PayloadDescription</key>
      <string>${escapedName} DNS-over-HTTPS</string>
      <key>PayloadDisplayName</key>
      <string>${escapedName} DoH</string>
      <key>PayloadIdentifier</key>
      <string>${escapedIdentifier}.dns</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>${dnsUuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>${escapedName} DNS-over-HTTPS profile</string>
  <key>PayloadDisplayName</key>
  <string>${escapedName} DoH</string>
  <key>PayloadIdentifier</key>
  <string>${escapedIdentifier}.profile</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${profileUuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`;
}

function tlsPublicHosts(config) {
  const service = config.service || {};
  const values = [config.domain, hostnameFromUrl(service.dohPublicBaseUrl), hostnameFromEndpoint(service.doqEndpoint)];
  return [...new Set(values.map((value) => String(value || '').trim().toLowerCase()).filter(Boolean))];
}

function hostnameFromUrl(value) {
  try {
    return new URL(String(value || '')).hostname;
  } catch {
    return '';
  }
}

function hostnameFromEndpoint(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.startsWith('[')) return raw.slice(1, raw.indexOf(']'));
  if (net.isIP(raw)) return raw;
  const colon = raw.lastIndexOf(':');
  return colon > 0 && /^\d+$/.test(raw.slice(colon + 1)) ? raw.slice(0, colon) : raw;
}

function fileMetadata(file) {
  try {
    const stat = fs.statSync(file);
    return { exists: stat.isFile(), size: stat.size, modifiedAt: stat.mtime.toISOString() };
  } catch {
    return { exists: false, size: 0, modifiedAt: '' };
  }
}

function certificatePemBlocks(value) {
  return String(value || '').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
}

function certificateDnsNames(certificate) {
  const names = [];
  const source = String(certificate.subjectAltName || '');
  const matcher = /(?:^|,\s*)DNS:([^,]+)/g;
  let match;
  while ((match = matcher.exec(source))) names.push(match[1].trim());
  return [...new Set(names)];
}

function verifyCertificateChain(certificates) {
  if (!certificates.length) return false;
  try {
    if (certificates.length === 1) return certificates[0].verify(certificates[0].publicKey);
    for (let index = 0; index < certificates.length - 1; index += 1) {
      if (!certificates[index].verify(certificates[index + 1].publicKey)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function certificateHostMatch(certificate, host) {
  try {
    const matched = net.isIP(host) ? certificate.checkIP(host) : certificate.checkHost(host);
    return { host, valid: Boolean(matched), matched: matched || '' };
  } catch {
    return { host, valid: false, matched: '' };
  }
}

function formatKeyType(key) {
  const type = String(key.asymmetricKeyType || '').toUpperCase();
  const details = key.asymmetricKeyDetails || {};
  if (type === 'RSA' || type === 'RSA-PSS') return `${type} ${details.modulusLength || ''}`.trim();
  if (type === 'EC') return `EC ${details.namedCurve || ''}`.trim();
  return type || 'UNKNOWN';
}

function normalizeDate(value) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function deterministicUuid(seed) {
  const bytes = crypto.createHash('sha256').update(seed).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`.toUpperCase();
}

function xmlEscape(value) {
  return String(value || '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&apos;'
  })[character]);
}
