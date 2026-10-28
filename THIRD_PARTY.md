# Third-party components

## AdGuard HostlistsRegistry service catalog

`data/blocked-services.json` is a transformed snapshot of the public service catalog from [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry). `cmd/update-blocked-services.mjs` contains the transformation and update logic. This dataset includes service rules, domains, descriptions, and icons supplied by that upstream project.

Upstream source: https://adguardteam.github.io/HostlistsRegistry/assets/services.json

The upstream project is distributed under GNU GPL version 3. Its license is reproduced verbatim in [third_party/HostlistsRegistry.LICENSE](third_party/HostlistsRegistry.LICENSE). This notice applies to the catalog's upstream material; it does not represent a separate licensing decision for CleanDNS-authored source files.

## quic-go and Go module dependencies

The native transport imports [quic-go](https://github.com/quic-go/quic-go), together with the Go modules pinned in `go.mod` and `go.sum`. These dependencies are downloaded by the Go toolchain and are not vendored in this repository. Their upstream copyright and licensing terms continue to apply.
