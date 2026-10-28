# Blocked services catalog updates

CleanDNS keeps the AdGuard Home HostlistsRegistry service catalog current without changing the service IDs selected by an administrator.  The update source only refreshes the catalog metadata, domains, rules, and icons; enabled services remain selected by ID.

## Scheduling model

The Filtering page controls whether automatic updates are enabled and whether the interval is daily, weekly, or monthly.  The CleanDNS main process schedules updates while it is running and writes the last successful update and next due time to `data/blocked-services-auto-update-state.json`.

`cleandns-blocked-services-update.timer` also wakes once per day as a system-level fallback.  Its service reads the same configuration and state file, so it skips work when automatic updates are disabled or not yet due.  It signals the main CleanDNS process with `SIGUSR1` after a successful run; the process reloads the catalog and clears DNS caches without restarting DoH, DNS, or DoQ listeners.

## Installation

Install and enable the included units on a systemd host:

```bash
install -m 0644 systemd/cleandns-blocked-services-update.service /etc/systemd/system/
install -m 0644 systemd/cleandns-blocked-services-update.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cleandns-blocked-services-update.timer
```

Use `systemctl list-timers cleandns-blocked-services-update.timer` to inspect the next fallback check.  Manual updates in the panel are immediate and reset the stored next due time according to the configured interval.
