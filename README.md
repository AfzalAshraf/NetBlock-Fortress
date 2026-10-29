# NetBlock Fortress

**Version 19.0 — DNS-level ad, tracker, and threat-domain filtering with a web dashboard.**

NetBlock is a lightweight DNS forwarder and blocklist manager. It combines selected public feeds, explicit custom block/allow rules, and a query inspector. It does **not** install browser extensions or modify a router/firewall to force clients onto its DNS server.

> **DNS has limits:** DNS can block hostnames, not URL paths, page elements, or ads delivered from the same hostname as the content. YouTube and other video platforms often share ad and content infrastructure; NetBlock intentionally leaves `googlevideo.com` unblocked because blocking it can break video playback. Clients using DoH, DoT, a VPN, or a hard-coded resolver can bypass a DNS filter.

## What changed in v19

- Added a domain-aware parser for hosts files, plain-domain feeds, dnsmasq rules, and hostname-anchored Adblock Plus / AdGuard rules.
- Added an Aggressive Ads profile using HaGeZi Multi Pro++ plus the other enabled ad and tracker feeds.
- Audited feed URLs and removed a YouTube hosts feed that contained thousands of `googlevideo.com` CDN entries and could break playback.
- Replaced substring matching with DNS-label suffix matching, wildcard-subdomain support, IDN normalization, and whitelist-first policy evaluation.
- Feed refreshes are size-limited, validated before use, and atomically replace a last-known-good cache. Unsupported URL/path rules and IP-only feeds are not converted into bogus domain blocks.
- CNAME checks inspect the actual upstream answer chain instead of making an extra DNS lookup for every clean query.
- Added DNS-over-TCP support and TCP fallback for truncated upstream UDP responses.
- Replaced one-thread-per-query DNS handling with bounded UDP/TCP worker pools and bounded per-client tracking.
- Added a rotating JSONL query audit log with the matched domain rule and source feed; logging can be disabled in Settings.
- Installer now runs the service as an unprivileged `netblock` user with only the capability needed to bind DNS port 53.

## Features

- Curated feeds for ads, trackers, malware, phishing, social trackers, adult content, gambling, cryptojacking, and security.
- Balanced, Strict, Aggressive Ads, and Family profiles.
- Custom block rules and whitelist overrides, including root-domain and `*.subdomain` rules.
- DNS rebinding protection, optional DGA heuristic, per-client rate limiting, and DNS `ANY` query refusal.
- DNS over UDP and TCP; upstream IPv4 or IPv6 resolver support.
- Query Inspector showing client, domain, decision, exact matched rule, and source feed.
- Persistent logs capped at approximately 20 MiB across the active file and three rotations; the UI shows the newest 300 events. Logs include client IP addresses.

## Install

### Linux service installer

From a local checkout:

```bash
sudo bash install.sh
```

The installer creates `/opt/netblock`, a Python virtual environment, and a restricted systemd service. It downloads enabled feeds after DNS starts, so an initial feed sync happens in the background. The service logs can be followed with:

```bash
sudo systemctl status netblock
sudo journalctl -u netblock -f
```

For a new installation from the repository's `main` branch:

```bash
curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main/install.sh | sudo bash
```

After installation:

1. Open `http://<server-LAN-IP>:8080`.
2. Sign in with `admin` / `admin123`, then immediately change the password in **Settings**.
3. Set your router's DHCP/DNS configuration to the NetBlock server's LAN IP.
4. Open **Blocklists** and confirm the feed sync status and rule counts.
5. Use **Query Inspector** and the custom allowlist to diagnose or fix false positives.

The installer adds UFW rules for common private LAN ranges only when UFW is active. Review your firewall rules—especially on a VPS. **Do not expose an unrestricted recursive DNS resolver or the dashboard to the public internet.** Use a VPN or a narrowly scoped firewall allowlist for remote access. Existing broad firewall rules are not automatically removed.

### Port 53 conflicts

The installer intentionally does not disable `systemd-resolved` or rewrite `/etc/resolv.conf`. Check listeners with:

```bash
sudo ss -lntup | grep ':53'
```

If another service owns port 53, follow your distribution's resolver documentation and plan how the host itself will resolve DNS before changing it. A different NetBlock DNS port can be configured in `data/config.json`, but most consumer routers expect DNS on port 53.

### Uninstall

```bash
sudo bash uninstall.sh
```

The uninstaller asks for confirmation and removes `/opt/netblock`, including settings, custom rules, feed caches, and query logs. It removes the service account only if the NetBlock installer created it. UFW rules added for private LAN ranges are left in place; review them with `sudo ufw status numbered` and remove them manually if appropriate.

## Profiles and blocklist behavior

- **Balanced:** core ad and threat feeds with lower overlap.
- **Strict:** broader ad, tracker, malware, and threat coverage.
- **Aggressive Ads:** default for new installs; HaGeZi Pro++ plus the other DNS-compatible ad/tracker and threat feeds. It can cause more app breakage.
- **Family:** Strict plus adult and gambling domain feeds.

Feed files and configuration live in `/opt/netblock/data` (or `$NETBLOCK_HOME/data`). Use the dashboard's **Refresh Enabled** button to fetch every enabled feed. Downloads are not committed to this repository. A failed or empty refresh keeps the last valid cache and marks the feed stale/error rather than replacing it with an empty list.

The parser accepts only rules that can be safely represented as DNS hostname blocks. URL paths, cosmetic filters, regex rules, conditional allow rules, and IP/CIDR threat feeds are skipped. A browser-style list can therefore contain many rules that DNS cannot apply; its dashboard count is the number of supported domain rules, not the source file's total filter-rule count.

### Custom rules

Enter one domain or wildcard subdomain per line, for example:

```text
ads.example
*.telemetry.example
```

A whitelist entry takes precedence over blocklists and heuristic detection for that domain and its descendants. Treat whitelist entries as trusted exceptions.

## Privacy and limitations

- Query logging is enabled by default and records client IPs, queried domains, status, and matched rule/source. Disable **Persist query audit log** in Settings if you do not want query history written to disk. Clearing logs removes active and rotated files.
- DNS filtering is not a packet firewall, URL filter, or browser content blocker. It cannot reliably remove first-party/in-stream ads or content sharing an ad hostname.
- Configure the router to hand out this resolver. Devices can otherwise bypass it through DoH/DoT, VPNs, or hard-coded DNS; enforcing resolver use is a separate router/firewall/endpoint policy.
- The DGA detector is heuristic and can produce false positives. Add an explicit whitelist exception for a known-good domain if needed.
- The dashboard is served over HTTP by default. Keep it on a trusted LAN or put it behind a properly secured HTTPS reverse proxy and firewall.

## Development and tests

Python 3.8+ is required. Install dependencies and run the test suite:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The DNS and dashboard servers can be disabled for local policy tests with `NETBLOCK_DISABLE_SERVERS=1`. Runtime configuration is stored outside the repository in `/opt/netblock/data` by default.

## License

MIT
