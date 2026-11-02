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

## Per-protocol source IP access

In **DNS settings → Access control**, ordinary DNS (UDP and TCP together), DoH, and DoQ each have a source-IP policy. The corresponding config keys are `access.protocols.plain`, `.doh`, and `.doq`:

```json
{"mode":"custom","allowedClients":["192.0.2.0/24","2001:db8::/32"],"blockedClients":["192.0.2.10"]}
```

- `inherit` (default): use the existing global `access.allowedClients` and `access.blockedClients`.
- `custom`: use this protocol's lists instead of the global source lists. A nonempty allow list rejects all other sources; an empty allow list permits sources not on the block list.
- `unrestricted`: skip source-IP lists for this protocol.

Block entries win over matching allow entries. All modes retain global blocked hostnames, domain filtering, and rate limits. IPv4, IPv6, and CIDR networks are supported. These settings do not enable listeners or change their ports. DoQ uses the original peer address forwarded by its managed helper; keep the internal UDP core bound to loopback and inaccessible to untrusted clients. For DoH behind a reverse proxy, trust forwarding headers only when direct access to the backend is restricted to trusted proxies.

The settings API exposes this map as `accessProtocols`. `POST /api/settings` accepts partial protocol/field updates; omitted groups and dormant lists are preserved. Invalid modes or IP entries reject the entire update. Older settings requests that omit `accessProtocols` retain the current policies. In the panel, **Done** stages a policy; the page's **Save** button persists it.

## Dynamic domain allow lists

Use **Dynamic domain allow list** in Access control for global DDNS names and refresh settings. Each protocol dialog also accepts `allowedDomains` in custom mode. These are source-IP allow lists, distinct from domain filtering: a configured name's current A/AAAA addresses are combined with that policy's fixed IPs. Deny entries still win. A configured name keeps the whitelist active even if none of its addresses can be resolved; DNS failures never turn the service into an unrestricted resolver.

Config fields are `access.allowedDomains`, `access.protocols.<plain|doh|doq>.allowedDomains`, and `access.dynamicRefreshSeconds`. Settings API names are `accessAllowedDomains`, per-policy `allowedDomains` inside `accessProtocols`, and `accessDynamicRefreshSeconds`. Empty domain lists preserve existing behavior. Names are canonicalized to ASCII/lowercase; accept full hostnames only, without URL schemes, ports, paths or wildcards, at most 64 names per list.

The shared refresh setting defaults to **0 (automatic)**. A and AAAA are resolved independently using their minimum returned address-record TTL, bounded to 10–3600 seconds. A fixed interval of 10–86400 seconds is optional. Successful responses replace that family's addresses immediately; explicit NXDOMAIN/NODATA withdraw old addresses immediately. Transient failures retry every 30 seconds and retain old addresses only until the previous scheduled check plus a five-minute grace period. Expiry is enforced when matching requests even if a timer is delayed. No resolved-IP cache or lookup history is persisted; startup requires a fresh resolution.

Queries use a separate resolver with configured UDP bootstrap DNS servers (public `1.1.1.1` and `223.5.5.5` if no UDP bootstrap exists), bypassing the local filtering/ACL pipeline. Keep bootstrap DNS trusted and reachable. Use DDNS records that resolve directly to the actual client egress IP, without CDN proxying. This polls DNS and is subject to upstream caches; it cannot promise instant propagation.

Authenticated `GET /api/access/dynamic` reports addresses, per-family TTL, last/next check, expiry, and state. `POST /api/access/dynamic/refresh` schedules a background check of saved active names, with a ten-second manual throttle. The panel distinguishes staged domain edits from saved active records and shows the current resolution state. Inactive inherited/unrestricted protocol-specific lists are preserved but not queried. No additional listener is enabled.
