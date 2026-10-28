# Native DoQ transport

## Process model

DoQ is part of the CleanDNS service, but it is not currently in the same OS
process as the Node.js core. The exact model is:

```text
cleandns.service (Node.js main process)
  └─ managed child: cleandns-dns (project-owned Go DoQ transport)
       └─ PROXY v2 UDP -> CleanDNS core listener
```

This is intentional. The Node.js runtime used by CleanDNS does not provide a
stable production DoQ server API, while `quic-go` provides the RFC 9250
transport implementation. The main service owns the child lifecycle, port
changes, TLS reloads, restart policy, and shutdown. There is no independent
`cleandns-doq.service` dependency.

The important DNS behavior is still unified: DoH, DoQ, plain DNS, and the
internal core listener all use the same filtering, cache, ECS, rewrite,
upstream, query-log, and statistics pipeline. Moving DoQ into the same PID
would require either a native QUIC binding for Node or migrating that entire
DNS core into Go; it is a separate high-risk architecture project, not a
configuration change.

CleanDNS implements its DNS-over-QUIC transport in the project-owned `cleandns-dns` binary. It uses `github.com/quic-go/quic-go` for QUIC and does not import or run AdGuard `dnsproxy`.

## Request path

```text
DoQ client -> cleandns-dns native DoQ transport -> 127.0.0.1:8053 -> CleanDNS core
```

The DoQ process owns only RFC 9250 framing, TLS/QUIC transport, and forwarding. Filtering, rewrites, ECS policy, caching, client rules, query logging, statistics, and upstream selection remain in the CleanDNS core.

The internal UDP datagram starts with a PROXY protocol v2 header. It carries the original DoQ client address and an ALPN TLV with `doq`, so the core sees the real client IP and records the request protocol correctly.

The inbound listener is a project-owned child process supervised by the CleanDNS main process. It has no independent configuration lifecycle. The Node main process starts, stops, restarts, and observes it whenever the DoQ service or listener port changes. DNS policy remains centralized in the CleanDNS core.

## DoQ upstreams

Upstream addresses can use the AdGuard Home-compatible `quic://host[:port]` syntax. The Node core resolves the host through the configured Bootstrap DNS servers and starts the same `cleandns-dns` binary in `upstream-stdio` mode on demand:

```text
CleanDNS core -> stdin/stdout bridge -> cleandns-dns connection pool -> DoQ upstream
```

This mode opens no local listening port and has no systemd unit. It validates the upstream certificate against the configured host, pools QUIC connections by resolved address and TLS server name, opens one bidirectional stream per query, and restores the caller's DNS message ID after the RFC 9250 zero-ID exchange.

## Protocol behavior

- TLS 1.3 with ALPN `doq`.
- One client-initiated bidirectional stream per query.
- Two-octet DNS message length framing.
- DNS message ID must be zero.
- Client and server close their write side with STREAM FIN.
- 0-RTT and unidirectional streams are rejected.
- RFC 9250 application error codes are used for protocol, timeout, cancellation, and internal failures.
- The TLS certificate and private-key files are checked on each new QUIC handshake. A valid renewed pair is loaded without restarting the service; an incomplete renewal keeps the last valid pair until both files match.

## Build and verify

Requires Go 1.26 or newer.

```bash
cd /opt/cleandns
./build-cleandns-dns /opt/cleandns/bin/cleandns-dns
go version -m /opt/cleandns/bin/cleandns-dns
```

The module list must contain `github.com/quic-go/quic-go` and must not contain `github.com/AdguardTeam/dnsproxy`.

The old `cleandns-doq.service` unit is retired. `cleandns.service` owns the child runtime, including listener startup and port changes.
