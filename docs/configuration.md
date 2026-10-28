# Configuration

Copy `config.example.json` to the private `config.json`, or set `CLEANDNS_CONFIG` to an absolute path. Start from the project directory when using the sample's relative `data/` paths. Use absolute runtime paths for systemd deployments.

| Key | Purpose |
| --- | --- |
| `http.host`, `http.port` | Management/API and DoH listener; loopback port `8055` in the sample |
| `udp.host`, `udp.port` | Internal DNS core; loopback port `8053` |
| `upstreams`, `fallbackUpstreams`, `bootstrapDns` | Upstream, fallback, and bootstrap resolvers |
| `service.dohPath` | DoH path; `/dns-query` in the sample |
| `service.plainDnsEnabled` | Additional UDP/TCP DNS listener; initially disabled |
| `service.doqEnabled`, `doqPort` | Go DoQ listener; initially disabled, example port `8853` |
| `service.doqTlsCertFile`, `doqTlsKeyFile` | Private certificate/key files |
| `service.dohSyncCommand` | Optional privileged proxy integration hook; empty by default |
| `admin.username`, `passwordFile` | Administrator name and salted password-hash file |
| `admin.trustProxy` | Trust forwarding headers only behind a restricted, trusted proxy |
| `rules.*` | Policy files, subscriptions, and catalog updates |
| `clients.file` | Persistent client profiles |
| `queryLog`, `statistics` | Retention, anonymization, and statistics |
| `dhcp` | Optional Linux DHCP and static leases |
| `access` | Allowed/blocked clients and hosts |

Upstream examples: `223.5.5.5`, `tcp://1.1.1.1`, `tls://dns.example.com`, `https://dns.example.com/dns-query`, and `quic://dns.example.com:853`. Parser behavior is covered in `upstream.js` and `cmd/test-upstream-transports.mjs`.

Runtime files under `data/` are ignored by Git. The committed blocked-service catalog is public data; your selections, update state, clients, query history, and credentials are separate files.
