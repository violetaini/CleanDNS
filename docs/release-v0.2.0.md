## Install and configure in the browser

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/CleanDNS/main/install.sh | sudo bash
```

- Linux x86_64 and arm64 packages include Node.js 24 and the native Go DoQ binary, with SHA-256 checksums and third-party license notices.
- A four-step first-run wizard configures listeners, administrator credentials and upstream DNS, checks ports, then starts the service. Setup uses a one-time installation token and defaults to loopback access.
- The installer separates program releases from configuration and data, retains managed settings during upgrades, and restores the previous managed service if startup fails.
- Existing configured instances bypass onboarding. Standalone HTTP administration now uses the correct API route and session-cookie behavior; HTTPS and trusted reverse proxies keep Secure cookies.
- Management SSO, independent ordinary-DNS/DoH/DoQ IP access policies, and TTL-aware DDNS allowlists are included. IPs, CIDRs and DDNS names can be mixed in a single whitelist editor.

See [the installation guide](https://github.com/violetaini/CleanDNS/blob/main/docs/first-run.md) for SSH forwarding, offline archives and non-systemd usage. Public DNS listeners require an appropriate source access policy; DoQ, DHCP and certificate configuration are optional steps after onboarding.
