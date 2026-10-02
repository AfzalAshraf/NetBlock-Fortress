# Changelog

## v19.0 "Omni-Shield" — the micro + macro release

### Coverage
- Blocklist registry: **50 → 131 feeds**, 10 → **21 categories**, each rule tagged with one of
  **16 ad vectors** (macro: banner, video, popup, native, ctv, push, shopping ·
  micro: pixel, sdk, adx, retarget, fingerprint, telemetry, email, shortlink, malvertising).
- New feed sources: AdGuard FiltersRegistry (mobile, in-app banners, popups, annoyances, widgets,
  mail-tracking, spyware, track-params + 10 regional filters), uBlock uAssets (privacy, mobile,
  annoyances, badlists, resource-abuse, link shorteners, unbreak), Hagezi wildcard/adblock/native
  device lists (Samsung/LG/Roku/Fire TV/Xiaomi/Oppo/Vivo/Huawei/TikTok), ShadowWhisperer
  (ads, wild-ads, tracking, marketing, malware, scam, shorteners, fonts, AI, typosquats),
  Perflyst (smart-TV, Fire TV, session replay), d3ward, 1Hosts Lite/Xtra, yHosts, EasyList
  regional mirrors.
- Instant protection: ~260 hardcoded seed rules (ad exchanges, SSPs, SDKs, CTV beacons,
  miners, mail pixels) armed before a single feed downloads.
- Wildcard engine (`*.zone` semantics, OISD `*ads.x` flavour, leading-dot zones, adblock `||x^$opt`).
- Pattern engine: 100+ ad-infrastructure keywords + ~110 advertising host labels, with a
  250-domain trusted-zone exemption list and an "advertiser dashboard" allow list
  (`ads.tiktok.com`, `business.facebook.com`, …) so ad managers keep working.
- Adblock `@@` exceptions are honoured as anti-breakage rules (unbreak feeds).
- Heuristics: entropy/DGA (improved), IDN homograph, brand typosquats (opt-in / nuclear),
  low-reputation TLDs (nuclear only).

### Responses & performance
- Zero-pixel **creative sinkhole** (`sinkhole_mode=fortress`): blocked ad hosts resolve to the
  fortress and receive an empty 1×1 GIF / empty JS / empty CSS (with ad-collapse CSS), so ad
  slots collapse instead of hanging.
- dnslib fix: `DNSRecord` has no `add_rr()` — v18 blocked queries threw and sent **nothing**;
  replies are now built correctly (A → 0.0.0.0, AAAA → ::, or NXDOMAIN, or fortress IP).
- TTL caches for verdicts and upstream answers; LRU with configurable size/TTL.
- Bounded DNS thread pool (was one thread per packet), UDP **and** TCP DNS with proper
  2-byte framing and TCP truncation fallback.
- Optional DNS-over-HTTPS upstream (RFC 8484 wire format) with UDP fallback, and a
  `link-local/.local/.internal` short-circuit.
- Pickled gravity cache keyed on source mtime+size → restart in milliseconds; per-feed parse
  caches; conditional GET (ETag/Last-Modified), 3-attempt backoff, parallel pulls (8 workers).
- Rotating on-disk query log + `data/snapshot.json` so `adquit stats` works even if the
  dashboard is down. Pruned per-client rate maps.

### Control plane
- `adquit` CLI (`bin/adquit`, linked to `/usr/local/bin/adquit`): start/stop/restart/status/logs/
  watch/run, mode, block/allow/unblock, blocklist add, gravity, test, doctor, verify-lists,
  stats/json/top/rules, passwd, protect on|off, install/update/uninstall, rootless `--user`.
- `app.py` gained a real CLI: `--serve --stats --json --watch --test --doctor --rules --top
  --block --allow --unblock --mode --set --get --set-auth --passwd --update-lists --rebuild
  --verify-lists --health --version`.
- Dashboard: new **Ad Coverage Matrix** (per-vector rule counts, feeds and one-click switches),
  **Domain Lab** (8-layer trace, upstream answer inspection, block/allow buttons), 24 h
  sparkline, top-blocked hosts, cache/pattern/wildcard counters, richer feed table with
  micro/macro tagging, per-feed URL, custom feed import form.
- New profile `nuclear`; `off` profile pauses blocking without stopping the resolver;
  profile-specific pattern tuning (balanced = shadow mode).
- Token-authenticated JSON API (`/api/stats`, `/api/lookup`, `/api/block`, `/api/allow`,
  `/api/refresh`, `/api/mode`, `/api/health`) plus `/metrics` in Prometheus format.

### Security & correctness
- Login no longer accepts the literal `admin` after the username is renamed; constant-time
  compares; per-install random session secret and API token; session cookie HttpOnly/SameSite=Lax;
  minimum password length raised to 8; installer generates a random admin password.
- Fixed every dead `hagezi/dns-blocklists` URL (the `hosts/` directory is gone upstream),
  replaced Firebog mirrors with canonical upstreams, tolerant blocklist parser (hosts,
  adblock, plain, wildcard, dnsmasq, markdown, inline comments, IDNA, IP/path lines).
- Config schema versioning + migration (v18 `enabled_lists` ids are remapped to v19 feeds,
  `/opt/netblock` is migrated to `/opt/adquit`).

### Packaging & QA
- One-command `install.sh` (idempotent, sudo-aware, OS/package-manager detection, venv,
  systemd unit + logrotate, systemd-resolved/dnsmasq conflict handling, ufw/firewalld rules,
  rootless user mode, macOS launchd agent, optional flags via env).
- `uninstall.sh` restores resolver settings and can `--keep-data`.
- `Dockerfile` (non-root, healthcheck, `adquit` entrypoint), `docker-compose.yml`, `Makefile`,
  `requirements.txt`, MIT `LICENSE`, `.gitignore`/`.dockerignore`.
- CI: engine + dashboard suite on Python 3.8 / 3.11 / 3.12, CLI contract tests, and a real
  "install then `adquit test` then uninstall" smoke test in a container; release workflow
  publishes a tarball, installer asset and GHCR image.
- `tests/run_tests.py`: 48 assertions covering the parser, every engine layer, DNS reply
  shapes, rate limiter, caches, profiles, config migration, CLI, API auth and page rendering
  (offline by design — no network, no pytest).
