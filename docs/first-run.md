# First-run installation

## One-command Linux install

Supported: systemd-based glibc Linux, x86_64 or arm64. The package includes Node.js 24 and the native DoQ binary; Git, npm and Go are not needed on the server. `curl`, `tar`, `sha256sum` and standard Linux utilities are required.

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/CleanDNS/main/install.sh | sudo bash
```

The installer downloads the latest release, verifies its SHA-256 checksum, installs under `/opt/cleandns`, and starts `cleandns.service` as the dedicated `cleandns` account. It never overwrites an unmanaged installation. Configuration is kept in `/etc/cleandns/config.json`; mutable data stays in `/var/lib/cleandns`. Existing managed configuration and data survive upgrades. Re-running the command updates the program; a failed service start restores the previous managed service when available.

Setup listens only on **127.0.0.1:3000**. On a remote server, open a tunnel from your own computer (add your SSH port with `-p` when needed):

```bash
ssh -L 3000:127.0.0.1:3000 -L 8055:127.0.0.1:8055 USER@SERVER
```

Open the installation link printed by the installer, or visit `http://127.0.0.1:3000/setup/` and enter the token from:

```bash
sudo cat /var/lib/cleandns/setup-token
```

The one-time token is stored with mode 0600 and removed after completion. It is carried in a URL fragment or a request header, not a URL query. Setup requests require the token and reject foreign browser origins. No configuration means no DNS service is started until setup is complete.

## The four steps

1. **Start:** supply the installation token.
2. **Listeners:** choose management IP/port and ordinary DNS IP/port. The initial defaults are loopback, management `8055`, DNS `53`, and internal UDP `8053`. Select a LAN address for other devices to use DNS. The internal core remains loopback. Port conflicts are reported without stopping other services.
3. **Account and upstreams:** create a username and password of at least 12 characters, select upstream DNS servers, and optionally enable query logging. Only a salted password hash is saved. Query logging is off by default in the wizard.
4. **Confirm:** review the checks and save. The wizard closes and the normal administration server starts; use the account you just created. DoQ and DHCP remain disabled until configured in the panel. Use a TLS reverse proxy when exposing management beyond a trusted local connection.

If you choose a management port other than 8055, forward that port instead. Setup never overwrites an existing config. A source installation that already has a `config.json` bypasses the wizard and retains its existing authentication behavior.

## Source and container-style installations

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
npm start
```

Node.js 22+ is required for source usage; there are no npm runtime dependencies. With no config, the terminal prints a local setup link. A manually copied `config.example.json` opts into the legacy configuration workflow instead: the application generates a temporary local-admin password if its configured password file is absent.

For installing prebuilt files without systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/CleanDNS/main/install.sh | bash -s -- --no-service --prefix "$HOME/cleandns"
"$HOME/cleandns/run"
```

Configuration/data then stay under that prefix. Choose unprivileged ports if not running with permission to bind port 53. A custom `CLEANDNS_SETUP_HOST` or `CLEANDNS_SETUP_PORT` can be supplied when running `start.mjs` directly; the setup token is still required. The normal installer intentionally keeps setup local.

Pin a release with `--version v0.2.0`. `--archive /path/CleanDNS_v0.2.0_linux_amd64.tar.gz --version v0.2.0` installs an offline archive alongside its `SHASUMS256.txt`. No install mode deletes configuration or user data.

## Service and upgrade operations

```bash
sudo systemctl status cleandns
sudo systemctl restart cleandns
sudo systemctl stop cleandns
```

Program versions live in `/opt/cleandns/releases/`, with `/opt/cleandns/current` selecting the active version. The service gets permission to bind privileged ports, but optional raw-socket DHCP functionality may require an administrator to grant additional capabilities. Proxy reload hooks and certificate access need explicit OS permissions; the installer does not change Nginx, firewall rules, DNS settings, or existing certificate deployments.

The previous service is restored on an installer start/health-check failure. Keep configuration/data backups for manual downgrades; older versions may not support newly configured access policies. Re-running the installer does not recreate the first-run wizard for an already configured instance.
