#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

repo=violetaini/CleanDNS
version=latest
prefix=/opt/cleandns
service=yes
archive=
usage() { cat <<'HELP'
CleanDNS Linux installer (glibc, x86_64 / arm64)
  curl -fsSL https://raw.githubusercontent.com/violetaini/CleanDNS/main/install.sh | sudo bash

Options:
  --version v0.2.0       Install a particular release (default: latest).
  --prefix /path         Application directory (default: /opt/cleandns).
  --no-service           Install without systemd; run PREFIX/run manually.
  --archive /path.tar.gz Use a local release archive and adjacent SHASUMS256.txt.
  --help                Show this help.

Existing managed installations retain their configuration and data on upgrade.
Unmanaged installations are never overwritten. Setup listens on 127.0.0.1:3000.
HELP
}
die() { printf 'CleanDNS: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --version|--prefix|--archive) (($# >= 2)) || die "Missing value for $1"; option=$1; value=$2; shift 2; case "$option" in --version) version=$value;; --prefix) prefix=$value;; --archive) archive=$value;; esac;;
    --no-service) service=no; shift;;
    --help|-h) usage; exit 0;;
    *) die "Unknown option: $1";;
  esac
done
[[ $(uname -s) == Linux ]] || die 'Only Linux is supported by this installer; use npm start for source installations.'
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die 'Supported CPUs: x86_64 and arm64.';; esac
[[ $prefix =~ ^/[a-zA-Z0-9._/-]+$ && $prefix != / && $prefix != */../* && $prefix != */.. ]] || die 'Use an absolute application path without spaces or .. components.'
for command in curl tar sha256sum mktemp install awk readlink; do command -v "$command" >/dev/null || die "Required command missing: $command"; done
if [[ $service == yes ]]; then
  [[ $EUID == 0 ]] || die 'Run with sudo, or choose --no-service.'
  command -v systemctl >/dev/null || die 'systemd is required; use --no-service for containers.'
  [[ -d /run/systemd/system ]] || die 'systemd is not running; use --no-service.'
fi
if [[ -d $prefix && ! -f $prefix/.cleandns-managed ]]; then
  [[ -z $(ls -A "$prefix") ]] || die "Unmanaged directory exists: $prefix. Back it up and choose a different --prefix."
fi
work=$(mktemp -d -t cleandns-install.XXXXXXXX)
switch_started=no
cleanup() {
  status=$?
  if [[ $status != 0 && $switch_started == yes && $service == yes ]]; then
    systemctl stop cleandns.service >/dev/null 2>&1 || true
    if [[ -n $old ]]; then ln -s "$old" "$prefix/.current-rollback-$$" && mv -Tf "$prefix/.current-rollback-$$" "$prefix/current"; fi
    if [[ -f $work/previous.service ]]; then
      install -m 0644 "$work/previous.service" /etc/systemd/system/cleandns.service
      systemctl daemon-reload; systemctl start cleandns.service >/dev/null 2>&1 || true
    else
      systemctl disable cleandns.service >/dev/null 2>&1 || true
      rm -f -- /etc/systemd/system/cleandns.service
      systemctl daemon-reload
    fi
    printf 'CleanDNS: Previous managed service restored when available; configuration/data retained.\n' >&2
  fi
  [[ -n ${work:-} && $work == */cleandns-install.* ]] && rm -rf -- "$work"
}
trap cleanup EXIT
if [[ $version == latest ]]; then
  [[ -z $archive ]] || die '--archive requires an explicit --version.'
  final=$(curl -fLsS --retry 3 --connect-timeout 15 --max-time 120 -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
  version=${final##*/}
fi
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]] || die 'Invalid release version.'
name="CleanDNS_${version}_linux_${arch}.tar.gz"
if [[ -n $archive ]]; then
  [[ -f $archive && $(basename "$archive") == "$name" ]] || die "Expected archive named $name"
  cp -- "$archive" "$work/$name"
  cp -- "$(dirname "$archive")/SHASUMS256.txt" "$work/SHASUMS256.txt"
else
  base="https://github.com/$repo/releases/download/$version"
  curl -fLsS --retry 3 --connect-timeout 15 --max-time 600 "$base/$name" -o "$work/$name"
  curl -fLsS --retry 3 --connect-timeout 15 --max-time 120 "$base/SHASUMS256.txt" -o "$work/SHASUMS256.txt"
fi
expected=$(awk -v name="$name" '$2 == name || $2 == "*" name {print $1}' "$work/SHASUMS256.txt")
[[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || die 'Release checksum entry is missing or ambiguous.'
actual=$(sha256sum "$work/$name"); actual=${actual%% *}
[[ ${actual,,} == ${expected,,} ]] || die 'Checksum verification failed; nothing was installed.'
tar -tzf "$work/$name" > "$work/members"
awk 'substr($0,1,9)!="CleanDNS/" || /(^|\/)\.\.(\/|$)/ {bad=1} END {exit bad}' "$work/members" || die 'Unsafe archive paths.'
tar -tvzf "$work/$name" | awk 'substr($0,1,1) ~ /[lh]/ {bad=1} END {exit bad}' || die 'Archive links are not allowed.'
mkdir "$work/package"
tar -xzf "$work/$name" -C "$work/package" --strip-components=1 --no-same-owner --no-same-permissions
[[ -f $work/package/start.mjs && -f $work/package/setup.html && -x $work/package/runtime/bin/node && -x $work/package/bin/cleandns-dns ]] || die 'Incomplete release package.'
[[ $(cat "$work/package/VERSION") == "${version#v}" ]] || die 'Release version mismatch.'
"$work/package/runtime/bin/node" --check "$work/package/start.mjs" || die 'Bundled Node.js cannot run on this system (glibc Linux is required).'
"$work/package/runtime/bin/node" --check "$work/package/server.js"
install -d -m 0755 "$prefix" "$prefix/releases"
release="$prefix/releases/$version"
if [[ -d $release ]]; then
  [[ -f $release/.package.sha256 && $(cat "$release/.package.sha256") == "$actual" ]] || die 'This version already exists with a different package; refusing to overwrite it.'
else
  printf '%s\n' "$actual" > "$work/package/.package.sha256"
  mv -- "$work/package" "$release"
  chmod -R a+rX "$release"
fi
old=$(readlink "$prefix/current" || true)
[[ ! -e $prefix/current || -L $prefix/current ]] || die 'current must be an installer-managed symbolic link.'
if [[ $service == yes ]]; then
  if systemctl cat cleandns.service >/dev/null 2>&1 && [[ ! -f $prefix/.cleandns-managed ]]; then die 'An unmanaged cleandns.service already exists; refusing to replace it.'; fi
  id cleandns >/dev/null 2>&1 || useradd --system --home-dir /var/lib/cleandns --shell /usr/sbin/nologin cleandns
  install -d -o cleandns -g cleandns -m 0750 /etc/cleandns /var/lib/cleandns
  [[ -f /var/lib/cleandns/blocked-services.json ]] || install -o cleandns -g cleandns -m 0644 "$release/data/blocked-services.json" /var/lib/cleandns/blocked-services.json
  [[ ! -f /etc/systemd/system/cleandns.service ]] || cp /etc/systemd/system/cleandns.service "$work/previous.service"
  cat > "$work/cleandns.service" <<UNIT
[Unit]
Description=CleanDNS DNS filtering and administration
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=cleandns
Group=cleandns
WorkingDirectory=$prefix/current
Environment=CLEANDNS_CONFIG=/etc/cleandns/config.json
Environment=CLEANDNS_DATA_DIR=/var/lib/cleandns
Environment=CLEANDNS_SETUP_TOKEN_FILE=/var/lib/cleandns/setup-token
Environment=CLEANDNS_BLOCKED_SERVICES_CATALOG_FILE=/var/lib/cleandns/blocked-services.json
Environment=CLEANDNS_BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE=/var/lib/cleandns/blocked-services-auto-update-state.json
Environment=CLEANDNS_DHCP_LEASE_FILE=/var/lib/cleandns/dhcp-leases.json
ExecStart=$prefix/current/runtime/bin/node $prefix/current/start.mjs
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/cleandns /var/lib/cleandns
LimitNOFILE=65535
KillMode=control-group
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
UNIT
  switch_started=yes
  systemctl stop cleandns.service >/dev/null 2>&1 || true
  install -m 0644 "$work/cleandns.service" /etc/systemd/system/cleandns.service
fi
ln -s "releases/$version" "$prefix/.current-new-$$"
mv -Tf "$prefix/.current-new-$$" "$prefix/current"
touch "$prefix/.cleandns-managed"
if [[ $service == no ]]; then
  cat > "$prefix/run" <<RUN
#!/usr/bin/env bash
set -e
export CLEANDNS_CONFIG='$prefix/config.json'
export CLEANDNS_DATA_DIR='$prefix/data'
export CLEANDNS_SETUP_TOKEN_FILE='$prefix/data/setup-token'
export CLEANDNS_BLOCKED_SERVICES_CATALOG_FILE='$prefix/data/blocked-services.json'
export CLEANDNS_BLOCKED_SERVICES_AUTO_UPDATE_STATE_FILE='$prefix/data/blocked-services-auto-update-state.json'
export CLEANDNS_DHCP_LEASE_FILE='$prefix/data/dhcp-leases.json'
cd '$prefix/current'
exec '$prefix/current/runtime/bin/node' '$prefix/current/start.mjs'
RUN
  chmod 0755 "$prefix/run"; install -d -m 0700 "$prefix/data"
  [[ -f $prefix/data/blocked-services.json ]] || cp "$release/data/blocked-services.json" "$prefix/data/blocked-services.json"
  printf 'Installed %s. Start with: %s/run\nSetup: http://127.0.0.1:3000/setup/ (token: %s/data/setup-token)\n' "$version" "$prefix" "$prefix"
  exit 0
fi
systemctl daemon-reload
systemctl enable cleandns.service >/dev/null
systemctl start cleandns.service
healthy=no
for ((attempt=0;attempt<30;attempt++)); do
  if [[ -f /etc/cleandns/config.json ]]; then
    health=$("$release/runtime/bin/node" -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1]));let h=c.http.host;if(h==="0.0.0.0")h="127.0.0.1";if(h==="::")h="::1";process.stdout.write("http://"+(h.includes(":")?"["+h+"]":h)+":"+c.http.port+"/healthz")' /etc/cleandns/config.json)
  else health=http://127.0.0.1:3000/setup/; fi
  if curl -fsS --connect-timeout 1 --max-time 2 "$health" -o /dev/null 2>/dev/null; then healthy=yes; break; fi
  sleep 1
done
if [[ $healthy != yes ]]; then
  die 'Service health check failed.'
fi
switch_started=no
printf '\nCleanDNS %s installed. Configuration: /etc/cleandns/config.json\n' "$version"
if [[ ! -f /etc/cleandns/config.json ]]; then
  printf 'Open this on the server (or through SSH forwarding):\nhttp://127.0.0.1:3000/setup/#%s\n' "$(cat /var/lib/cleandns/setup-token)"
  printf 'From your computer: ssh -L 3000:127.0.0.1:3000 -L 8055:127.0.0.1:8055 USER@SERVER\n'
else printf 'Existing configuration retained. Management health check passed.\n'; fi
