# Deployment

## Local start

Use Node.js 22 or later. OpenSSL is also needed for TLS regression tests. Copy `config.example.json` to `config.json` and run `npm start` from the project directory. The initial administrator password is printed once and its hash is stored in `data/admin-password`.

## Linux service

Place the source at `/opt/cleandns`, configure absolute runtime paths, and review `systemd/cleandns.service` for your Node executable and service account. It is a system-level service template. DHCP, privileged ports, and proxy-reload hooks require the corresponding OS permissions; the portable sample disables them.

```bash
sudo install -m 0644 systemd/cleandns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cleandns.service
sudo journalctl -u cleandns.service -n 50
```

## HTTPS reverse proxy

Adapt `nginx/cleandns.example.conf` to your hostname and valid certificate. It routes `/admin/`, `/api/`, `/dns-query`, and `/healthz` to the loopback HTTP listener. The template overwrites forwarding headers and clears untrusted Cloudflare identity headers. Enable `admin.trustProxy` only when direct HTTP access is restricted to that trusted proxy.

```bash
sudo nginx -t
sudo nginx -s reload
```

`bin/apply-nginx-doh-path` is an optional privileged helper. It uses `CLEANDNS_NGINX_CONFIG`, defaulting to `/etc/nginx/conf.d/cleandns.conf`. It backs up that file and restores it if Nginx rejects the edit. It is not enabled automatically. Keep an edited location path and its upstream `proxy_pass` consistent.

## DoQ and DHCP

Build with `bash build-cleandns-dns`. On Windows, use `go build -o bin/cleandns-dns.exe ./cmd/cleandns-dns` and set `CLEANDNS_DOQ_RUNTIME_COMMAND` to that executable. The main Node service owns the child process, certificate reloads, and shutdown. Configure Linux DHCP only for the intended network interface.

## Backups

Back up private configuration, password hashes, client profiles, local policy files, and durable runtime state separately. Certificates are managed outside the source tree. Production logs, credentials, and backups are not source files.
