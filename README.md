<div align="center">

<img src="assets/avatar.webp" alt="CleanDNS" width="120" />

# **CleanDNS**

[![Version](https://img.shields.io/badge/Version-0.1.0-f97316?style=for-the-badge)](VERSION)
[![Runtime](https://img.shields.io/badge/Runtime-Node.js%2022%2B-22c55e?style=for-the-badge)](package.json)
[![Native Transport](https://img.shields.io/badge/Native%20Transport-Go%201.26%2B-00add8?style=for-the-badge)](go.mod)
[![Frontend](https://img.shields.io/badge/Frontend-HTML%20%2B%20JavaScript-42b883?style=for-the-badge)](panel.html)
[![Configuration](https://img.shields.io/badge/Configuration-JSON-2563eb?style=for-the-badge)](config.example.json)

</div>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README_zh.md">简体中文</a> |
  <a href="README_zh-TW.md">繁體中文</a> |
  <a href="README_ja.md">日本語</a>
</p>

<p align="center">
  <a href="docs/configuration.md">Configuration</a> |
  <a href="docs/deployment.md">Deployment</a> |
  <a href="docs/native-doq.md">Native DoQ</a>
</p>

CleanDNS is a self-hosted DNS filtering service with a responsive administration panel. A Node.js policy engine handles filtering, rewrites, caching, clients, and query statistics; an optional project-owned Go transport provides DNS-over-QUIC.

## Quick Start

Use Node.js 22 or newer. The Node service uses built-in modules and has no external npm runtime dependencies. Go 1.26 or newer is required when building the native DoQ transport.

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
cp config.example.json config.json
npm start
```

Open **http://127.0.0.1:8055/admin/**. The sample listens on loopback; the internal UDP listener uses port `8053`. Use an SSH tunnel or configure the Nginx example to access a remote installation.

The initial username is `admin`. On its first start, CleanDNS generates a random temporary password, prints it in the server console, and stores its salted hash in `data/admin-password`. Use the password printed by your own instance; there is no shared default password. Change it in the panel after signing in.

The sample keeps public plain DNS, DHCP, and DoQ disabled. Configure certificates and access policy before enabling those listeners. See [deployment](docs/deployment.md) and [configuration](docs/configuration.md).

## Features

- DNS-over-HTTPS and optional UDP/TCP plain DNS listeners, with a managed native DNS-over-QUIC transport.
- UDP, TCP, DoT, DoH, and DoQ upstreams; bootstrap DNS, fallback servers, and per-client policies.
- Blocklists, allowlists, subscriptions, DNS rewrites, response filtering, and client-specific controls.
- Blocked-service catalog updates, schedules, Safe Search, safe-browsing, and parental-control options.
- DNS caching with TTL controls, optimistic responses, ECS, DNSSEC request handling, and IPv6 policies.
- Query logs, retention, IP anonymization, dashboard charts, and runtime client discovery.
- Optional Linux DHCP runtime, interface checks, leases, and static leases.
- Light/dark themes, responsive navigation, and a local administrator login. Chitanda SSO is not included in this source snapshot.

## Architecture

```text
Browser / DoH / plain DNS
          │
          ▼
Node.js service ─── filtering / cache / clients / logs
          ▲
          │ original client address via PROXY v2
Go DoQ child process ◀── DNS-over-QUIC clients
```

The main service owns the Go child's lifecycle. Both transports use the same DNS policy pipeline; no separate DoQ system service is needed. [Transport details](docs/native-doq.md).

## Native DoQ

```bash
bash build-cleandns-dns
# Windows: go build -o bin/cleandns-dns.exe ./cmd/cleandns-dns
```

Set the DoQ switch, endpoint, UDP port, and certificate/key paths in your private `config.json`. The sample uses `8853` as an unprivileged example port. The Go transport uses `quic-go`; no third-party `dnsproxy` binary is shipped.

## Project Layout

| Path | Purpose |
| --- | --- |
| `server.js` and root JS modules | DNS policy, protocol handling, sessions, and API |
| `panel.html` | Administration interface |
| `cmd/cleandns-dns/` | Go DoQ server and upstream bridge |
| `cmd/test-*.mjs` | JavaScript regression suites |
| `config.example.json` | Portable configuration without deployment credentials |
| `data/blocked-services.json` | Public blocked-service catalog |
| `nginx/`, `systemd/`, `docs/` | Deployment templates and documentation |

## Development

```bash
npm ci
npm test
go test ./cmd/cleandns-dns
```

Tests use temporary configurations and local fixtures. `npm run audit:local` provides an additional isolated integration check. `cmd/audit-panel.mjs` is an opt-in browser audit for an instance you administer and is not run by CI.

GitHub Actions checks JavaScript, shell entry points, Go tests, and a native build. Production configuration, passwords, sessions, query history, private certificates, compiled binaries, and deployment backups are excluded from this repository.

## Upstream Projects

- [quic-go](https://github.com/quic-go/quic-go): native QUIC transport.
- [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry): blocked-service catalog consumed by the updater.

A project-wide software license has not yet been selected. Third-party components retain their respective licenses.
