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
  `/api/refresh`, `/api/reload`, `/api/mode`, `/api/health`) plus `/metrics` in Prometheus format.
- Hot reload: `adquit block|allow|unblock` pings `/api/reload`, so rules written from a shell
  take effect in the running resolver without restarting the service.

### Security & correctness
- Login no longer accepts the literal `admin` after the username is renamed; constant-time
  compares; per-install random session secret and API token; session cookie HttpOnly/SameSite=Lax;
  minimum password length raised to 8; installer generates a random admin password.
- Fixed every dead `hagezi/dns-blocklists` URL (the `hosts/` directory is gone upstream),
  replaced Firebog mirrors with canonical upstreams, tolerant blocklist parser (hosts,
  adblock, plain, wildcard, dnsmasq, markdown, inline comments, IDNA, IP/path lines).
- Config schema versioning + migration (v18 `enabled_lists` ids are remapped to v19 feeds,
  `/opt/netblock` is migrated to `/opt/adquit`).

### v19.1 - what the first real-world installs taught us
- **`adquit update` is content-aware now.** It refused a legitimate branch update with
  `refusing to downgrade v19.0 -> v19.0` because it compared only the version stamp (through a
  `sort | head` pipeline that equal versions could trip over). `update_decision` now returns
  `skip` (byte-identical engine - do not bounce the resolver), `go` (newer *or* the same stamp
  with different code, which is normal on a rolling branch), `refuse` (strictly lower version)
  and `nostamp` (v18 / not-Python channel); version maths is pure shell arithmetic, and the
  installed `app.py` is restored whenever a refusal happens. Engine/CLI/installer are stamped
  19.1, and a contract test asserts the three agree.
  (eight new CLI contract checks pin the decision table, the `--force` wiring and the self-heal marker).
- **Boot stops rebuilding the world.** `main()` ran `rebuild_master_blocklist()` on *every*
  start, even after restoring a valid `gravity.cache` - so a 5.1M-rule box spent tens of seconds
  re-reading 131 feeds before it could bind port 53/8080, while `adquit`'s 15-second health probe
  gave up, declared the service dead and restarted it from zero (their log: `gravity cache
  restored` at +6s, `error: service did not become healthy` at +17s). Boot now trusts the cache,
  stores the per-vector/category tallies inside it (no 5M-rule recount), folds a changed
  `custom_blocked.txt` in via `apply_custom_overrides()` (a set diff of hand-written lines, with a
  sidecar tally in `data/meta/gravity.custom` so entries added *or removed* while the service was
  down are honoured without a rebuild), and logs `ready in Ns`. Only an unverifiable cache falls
  back to a rebuild.
- **`_sync_legacy_views()` is lazy.** `BLOCKED_DOMAINS` and `DOMAIN_CATEGORIES` were two more full
  copies of the blocklist built on every boot (~1.5 GB on a 5M-rule box, which is where the
  3.2 GB RSS peak came from); they are now `_LazyView` objects built on first touch, while the two
  small sets the dashboard reads per request stay eager - and cheaper, since the custom tally now
  comes from the user's own file instead of a scan of every rule.
- **`adquit` no longer misreads a warm-up as an outage.** The health wait sizes itself from the
  gravity cache (`30s + MB/2`, capped at 10min, override with `ADQUIT_START_WAIT`), announces what
  it is doing, and returns early when the process dies or systemd marks the unit failed. If the
  unit is up but not answering, `start` says "still loading" instead of `die`-ing and stopping a
  service that was about to come good. `cmd_stop` asks systemd whether the unit was running
  (the port is closed during a warm-up, so it used to answer "not running" and skip the stop that
  `restart` then raced), `cmd_restart` waits for :53/:8080 to be released, and `cmd_status` has a
  third state - `warming up`, with the pid, RSS and peak from `/proc`. `ADQUIT_FORCE=1 sudo adquit update`
  silently failed the hint (env_reset drops it, and `set ADQUIT_FORCE=1` is csh syntax - bash's
  `set` assigns positional parameters). `adquit update [--force]` now rides in argv, is re-read
  after elevation, and `elevate_for` forwards `ADQUIT_FORCE` for anyone who still uses the env form.
  An unrecognised flag is a loud usage error rather than a shrug.
- **A stale guard can no longer wedge an update.** The version check lives in the CLI you already
  have, so a broken one refuses the very update that would repair it. `adquit update` now compares
  its own stamp with the fetched `bin/adquit`: when they differ it installs the channel's CLI and
  re-executes itself once (`ADQUIT_REHEALED`, so the two copies cannot bounce the work back and
  forth). The pristine engine copy is kept per state dir in `data/update-origin.py` and is never
  overwritten, so a restore after the hop still returns *your* file, not something a partial
  update wrote - and it is deleted on success.
- **YouTube ad payload audit**: a user pasted the player's own ad debug blob and we measured
  the engine against every host in it. 10 ad/reporting endpoints were reachable on `strict`
  and are now in the seed - `static.googleadsserving.cn`, `pagead.google.com`,
  `pagead.l.google.com`, `s2.youtube.com`, `dai.google.com`, `adservice.google.<cc>`,
  `app-measurement.com`, `firebaselogging.googleapis.com`, `crashlyticsreports-pa.googleapis.com`,
  `pulse.video` - plus Google's ad-UX endpoints (`myadcenter.google.com`,
  `adstransparency.google.com`). `adssettings.google.com` (the opt-out panel) and advertiser
  dashboards stay reachable on purpose; junk seed entries (`metric.gstatic.com`,
  `ytimg.com.legal`, `roku.com.ads`, `ads.cloudtv`) were removed.
- **Layer 5b**: an ad label inside a *trusted* zone (`pagead.google.co.uk`) is blocked again,
  scoped to Google's own estate so unrelated hosts that merely share a label (`dart.dev`) live.
- **`adquit export ublock` + `GET /adquit.txt`** - an EasyList-style subscription generated
  from live engine state, for the path-level ads a resolver cannot see (`/api/stats/ads`,
  `/ptracking`, `/get_midroll_info`, `www.google.com/pagead/`) plus slot-collapse cosmetics.
  Public by design (a filter client cannot log in) and it contains only blocklist domains.
- **`adquit intel <domain>`** - verdict + RDAP registration age/registrar/nameservers and the
  exact `adquit block` to run, for scam landing pages that rotate faster than feeds do.
- **`adquit lan` / `sudo adquit lan open`** - what is listening, which URLs other devices
  should use, whether ufw/firewalld is in the way; the installer now prints the same hints and
  says so when there is *no* host firewall (a cloud security group being the usual culprit).
- **Root install, normal user**: control verbs (`start/stop/mode/block/allow/...`) re-run
  through sudo instead of failing with `Permission denied` on `/opt/adquit/adquit.pid` and then
  reporting a phantom instance as live; `dns`/`web` ports are read from the service config
  rather than invented from defaults; `adquit start` only prints "live" after `/api/health`
  answers, and otherwise dumps the service log (this is how "✔ fortress live" was lying).
- **Colours**: `printf '...%s...' "$C"` printed literal `\033[32m` because printf only expands
  escapes in its *format*; all prompt/control colours now use ANSI-C quoting.
- Tests: 59 offline (payload-regression class, subscription export, RDAP intel with a stubbed
  network) + 23 CLI contract checks; `tests/test_cli.sh` now times each check, keeps its output
  on failure and raises `::error::` annotations + a step summary on GitHub Actions.

### Robustness at the edges (post-release hardening)
- `python3 app.py --version / --help / --doctor` now work on a box with **no** Python deps
  (a wiped venv, or a bare `python3` run): they print instructions and a real offline
  diagnosis instead of a `ModuleNotFoundError` traceback; starting the service without deps
  exits with code 3 and the same instructions.
- The installer refuses a source ref that is older than itself (`refusing to install
  app.py v18.0 … That branch is behind`) instead of silently mixing a new CLI with an old
  engine, and records the channel in `.adquit/.channel`, which `adquit update` follows.
- README: install-from-branch / install-from-checkout channels, and a troubleshooting table
  for the failures people actually hit (`bash: line 2: ---: command not found` etc).
- `adquit`'s install-link message used `printf '…%N…'`, which bash rejects as an invalid
  format (`printf: `N': invalid format character`) - it truncated the line *and* returned a
  failing status from the helper. Fixed, and the shell files are now clean under
  `shellcheck --severity=warning` (the level CI runs); the bash completion file the installer
  wrote was a no-op loop, now it actually installs a working `complete -F` completion
  alongside the zsh one.

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
- `tests/run_tests.py`: 51 tests covering the parser, every engine layer, DNS reply
  shapes, rate limiter, caches, profiles, config migration, CLI, API auth and page rendering
  (offline by design — no network, no pytest).
