# 🛡️ NetBlock Fortress — `adquit`

**A network-wide ad shield that blocks every micro *and* macro ad — installable with one command and driven by one word.**

```bash
curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main/install.sh | sudo bash
```

Then, on that machine, forever:

```bash
adquit            # start (auto-installs itself if you skipped the one-liner)
```

**v19.2 “Omni-Shield”** — 131 blocklist feeds, 21 categories, 16 ad vectors, a wildcard +
pattern engine for ad infrastructure that no list has seen yet, a zero-pixel creative sinkhole,
and a `adquit` CLI that does everything: start, stop, block, allow, modes, gravity, self-test,
doctor, stats — plus LAN self-hosting, so the box that kills your ads also answers
`media.lan`, `nas.lan` and `dashboard.lan` and can front all of them on port 80.
Single Python file, three PyPI dependencies, no database, no Docker required.

![version](https://img.shields.io/badge/version-19.2-brightgreen)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![deps](https://img.shields.io/badge/dependencies-3-informational)
![license](https://img.shields.io/badge/license-MIT-yellow)
![tests](https://github.com/AfzalAshraf/NetBlock-Fortress/workflows/CI/badge.svg)

---

## What `adquit` does

| | |
|---|---|
| 🎯 **131 feeds / 21 categories** | Ad networks, in-app SDKs, CTV, native, push, exchanges, mail pixels, fingerprinting, telemetry, malware, phishing, spam, cryptojacking, regional filters |
| 🐜 **Micro-ad blocking** | Impression beacons, 1×1 pixels, SDK handshakes, RTB bidding calls, audience-sync, device fingerprinting, session replay, email open tracking |
| 📢 **Macro-ad blocking** | Display banners, pre/mid-roll video endpoints, pop-unders, interstitials, native “sponsored” units, smart-TV ads, push-notification ads, shopping/affiliate units |
| 🧠 **Pattern + wildcard engine** | `*.adnetwork.com` zones, ad-infrastructure host labels (`ads.`, `prebid.`, `banner.`…) and 100+ ad-tech keywords — catches brand-new hosts that no list knows yet |
| 🕳️ **Zero-pixel creative sinkhole** | Optional: sinkhole the ad host to the fortress and answer with an empty GIF/JS/CSS so ad slots collapse instead of hanging on a spinner |
| ⚡ **Fast by design** | TTL decision cache + upstream response cache, bounded DNS thread pool, UDP **and** TCP DNS, pickled gravity cache (instant restart), conditional-GET feed pulls |
| 📊 **Dashboard** | Brave-Shield style analytics, 24 h sparkline, top blocked hosts, per-client inspection, security events, live query log |
| 🧪 **Coverage matrix** | A page that shows exactly which ad vectors are armed, how many rules back each one, and lets you flip macro/micro/CTV/push/exchange/email coverage with one click |
| 🔬 **Domain lab** | Type any hostname and watch the 8-layer decision trace: whitelist → feed → wildcard → unbreak → in-video → keyword pattern → label pattern → heuristics |
| 🤖 **Optional AI triage** | Free-tier OpenRouter classification of unknown domains (off by default) |
| 🔐 **Hardened** | Random session/API tokens, no more “admin works even after rename”, rate limiting, DNS-rebinding guard, DGA + homograph detection, ANY-query refusal |
| 🧰 **`adquit` CLI** | `start stop restart status logs watch mode block allow unblock gravity test doctor stats json top rules passwd protect uninstall` |

---

## Install

### 1. One command (recommended — VPS, box, Raspberry Pi)

```bash
curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main/install.sh | sudo bash
```

The installer is idempotent — run it again to upgrade. It detects the OS and package
manager, creates a private venv, frees udp/53 from `systemd-resolved`, installs the
`adquit` systemd unit + logrotate, opens the firewall, starts a rootless-safe
background blocklist pull, and generates a random dashboard password (printed once).

The one-liner has no pin, so it installs whatever `main` holds. To take a branch or a
fork instead — and to *stay* on that channel, since the installer records it in
`.adquit/.channel` and `adquit update` follows it rather than downgrading you to `main`:

```bash
curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/BRANCH/install.sh \
  | sudo env ADQUIT_REF=BRANCH bash
```

If a ref is *older* than the installer you are running, the install stops out loud
(`refusing to install app.py … That branch is behind`) instead of quietly giving you a
mismatched engine + CLI pair.

No `curl` available? Everything is in this repo:

```bash
git clone https://github.com/AfzalAshraf/NetBlock-Fortress && cd NetBlock-Fortress
sudo bash install.sh
```

…or just let `adquit` bootstrap itself from a checkout:

```bash
./bin/adquit            # installs, starts, prints the dashboard URL
```

### 2. Without root (laptop / any machine)

```bash
ADQUIT_USER=1 bash install.sh          # or: sudo ./bin/adquit install --user
adquit start                           # DNS on :5353, dashboard on :8080
sudo adquit protect                    # point this machine's DNS at 127.0.0.1
```

### 3. Docker

```bash
docker build -t netblock-fortress:19 .
docker run -d --name adquit --network host -v adquit-data:/opt/adquit/data \
  -e ADQUIT_PASSWORD=*** netblock-fortress:19
```

or `docker compose up -d`. Inside the container `adquit` is the entrypoint, so
`docker exec -it adquit adquit stats` works.

### 4. Env knobs for the one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main/install.sh \
  | sudo ADQUIT_MODE=nuclear ADQUIT_PASSWORD=*** ADQUIT_SKIP_LISTS=1 bash
```

| var | meaning | default |
|---|---|---|
| `ADQUIT_MODE` | `off` · `balanced` · `strict` · `family` · `nuclear` | `strict` |
| `ADQUIT_HOME` | install directory | `/opt/adquit` (root) / `~/.adquit` (user) |
| `ADQUIT_PASSWORD` | dashboard password | random, printed once |
| `ADQUIT_DNS_PORT` / `ADQUIT_WEB_PORT` | listener ports | `53` / `8080` |
| `ADQUIT_UPSTREAM` | upstream resolver | `1.1.1.1` |
| `ADQUIT_SKIP_LISTS` | `1` = don’t download feeds during install | `0` |
| `ADQUIT_USER` | `1` = rootless install | `0` |
| `ADQUIT_REPO` / `ADQUIT_REF` | install from a fork/branch | this repo / `main` |

---

## Then: `adquit`

```
adquit                      start the fortress (installs on first run)
adquit status | stats | watch | logs | top
adquit start | stop | restart | run
adquit mode family          off | balanced | strict | family | nuclear
adquit block doubleclick.net my-tracking.biz      # your own blacklist (wildcards ok, hot-reloaded)
adquit allow news.ycombinator.com                 # never blocked again
adquit blocklist add https://example.com/list.txt "My feed"
adquit gravity              re-download every enabled feed and recompile
adquit test                 prove it works: engine self-test + live DNS probe
adquit doctor               port/resolver/dependency/feed diagnostics
adquit verify-lists         check that all 131 feed URLs are reachable
adquit rules google.com     ask the engine about any hostname
adquit intel scam-ads.biz   who owns that landing page (RDAP age/registrar) + verdict
adquit export ublock         publish the same rules as a browser filter list
adquit lan                   why can't my laptop see the dashboard? (and fix it)
adquit lan open [80 443]     open the dashboard (and any other LAN port) in ufw/firewalld
adquit site add media.lan --port 8096   publish a self-hosted site by name; the fortress
                            resolves it itself, so a 5M-rule list can never swallow it
adquit site list | rm NAME    what is published, and take one down
adquit lan-zone add .lan 192.168.1.1    printer.lan / nas.lan: ask the router, never a
                            public resolver (adquit lan-zone list | rm SUFFIX)
adquit proxy install          nginx/Caddy/Apache vhosts: every published site on one port
adquit passwd               rotate the dashboard password
adquit protect on|off       repoint THIS machine's DNS at the fortress
adquit update               pull the newest fortress, rebuild, refresh, restart
                            (follows the install's channel; "already up to date" when the
                             engine is byte-identical, refuses only a real downgrade)
adquit update --force       ... and carry on anyway. Use the flag, not ADQUIT_FORCE=1:
                             sudo rebuilds the environment, so exported variables do not
                             reach the script (ADQUIT_FORCE is re-supplied on elevation,
                             but a flag in argv can never be lost).
adquit uninstall
```

Everything is also reachable without the wrapper: `python3 app.py --help`.

---

## Micro vs macro: the coverage matrix

`adquit` tags every rule with the ad vector it kills, and the dashboard lets you switch
vectors on or off (Settings → *Ad Coverage & Responses*, or the Coverage page).

| kind | vectors | typical traffic |
|---|---|---|
| **macro** | `banner` `video` `popup` `native` `ctv` `push` `shopping` | the ad you can see: display units, pre/mid-roll, pop-unders & interstitials, sponsored/native slots, smart-TV & console ads, browser push ads, shopping/affiliate widgets |
| **micro** | `pixel` `sdk` `adx` `retarget` `fingerprint` `telemetry` `email` `shortlink` `malvertising` | the ad you can’t see: 1×1 impression pixels, mobile in-app SDK traffic (AdMob/AppLovin/Unity/ironSource), RTB & prebid bidding calls, audience-sync/retargeting, canvas fingerprinting, session replay & telemetry pings, mail open pixels, ad redirector shorteners, malvertising |

Turning a vector **off** only relaxes ad blocking — malware/phishing/spam feeds stay armed in
every profile, so safety never depends on ad settings.

### Decision layers (first match wins)

```
0  whitelist + self-protection          ← your own allow list, dashboard hostnames
1  safety feeds (malware/phishing)     ← beat every anti-breakage exception
2  unbreak exceptions (@@ rules)       ← keep ad-manager & payment hosts alive
3  curated feeds: exact → wildcard → parent
4  advertiser dashboards                ← ads.tiktok.com, business.facebook.com, …
5  in-video ad endpoints                ← Google Video ad edges, player telemetry
6  ad-tech keyword patterns             ← adsystem, doubleclick, exoclick, taboola, hotjar …
7  ad-infrastructure host labels        ← ads./prebid./banner./interstitial. (strict+nuclear)
8  heuristics                           ← DGA entropy, IDN homographs, typosquats, low-rep TLDs
```

Layer 6–7 run in **shadow mode** on the `balanced` profile (logged, not blocked) so you can
see what would have broken before you arm it.

### Profiles

| profile | feeds | what to expect |
|---|---|---|
| `off` | 0 | plain resolver; blocking paused (downloads, IoT setup, troubleshooting) |
| `balanced` | 16 | heavy ad networks + malware only, zero breakage, patterns in shadow mode |
| `strict` | 94 | **default** — full macro+micro coverage, CNAME uncloaking, telemetry, threat feeds |
| `family` | 105 | strict + adult/gambling/piracy + SafeSearch enforcement |
| `nuclear` | 125 | every feed incl. regional + Hagezi Ultimate/Pro++, typosquat + low-rep TLD blocking |

---

## Using it

**Dashboard** — `http://<box-ip>:8080`, login `admin` / the password printed at install
(`adquit passwd` to change). Pages: Dashboard · Security Center · Blocklists · **Ad Coverage
Matrix** · **Domain Lab** · Protection Modes · Live Query Logs · Custom Rules · Settings.

**Protect your network** — set your router’s DNS (IPv4) to the fortress IP. Every device —
phones, TVs, consoles, laptops — is covered with zero per-device setup, including apps where
browser extensions cannot go.

**Protect one machine**

```bash
sudo adquit protect          # NetworkManager / systemd-resolved / resolv.conf, auto-detected
sudo adquit protect off      # restore
```

**The browser half (what a resolver cannot do)** — a DNS sinkhole only sees hostnames, so
ads served from a host you keep alive (`youtube.com`, `google.com`) arrive as *paths*. The
fortress therefore publishes an adblock-syntax subscription generated from its own live state:

```bash
adquit export ublock                 # writes data/adquit.ublock.txt
# or subscribe to the live one, in uBlock Origin -> Dashboard -> Import -> "I already know":
http://<fortress-ip>:8080/adquit.txt
```

It carries the path rules (`||youtube.com/api/stats/ads`, `/ptracking`,
`/get_midroll_info`, `||www.google.com/pagead/`…), cosmetics that collapse the empty ad slot,
and every host this box actually blocks - so the browser and the resolver never disagree.
Run it *next to* uBlock's own lists; it is a mirror of your fortress, not a replacement.

**Advertiser / landing-page intel** — when an ad slips through and you want to know what the
"why this ad" link points at:

```bash
adquit intel scam-game-landing.com   # engine verdict + RDAP age/registrar + the block command
adquit block scam-game-landing.com   # arm it (hot-reloaded into the running resolver)
```

**Reaching the dashboard from another device on your Wi-Fi**

```bash
adquit lan                     # what is listening, the URLs, and whether a firewall blocks them
sudo adquit lan open           # open the dashboard port in ufw/firewalld
sudo adquit lan open 80 443    # ...and the ports your own sites will be served on
```

Never forward `:8080` through your router. If the box is a VPS, its *provider* security group
also has to allow the port, or reach it over a tunnel instead: `ssh -N -L 8080:127.0.0.1:8080 you@server`.

**API / metrics**

```bash
TOKEN="$(sudo python3 -c 'import json;print(json.load(open("/opt/adquit/data/config.json"))["api_token"])')"
curl "http://127.0.0.1:8080/api/stats?token=$TOKEN"
curl http://127.0.0.1:8080/metrics          # Prometheus text: rules, per-vector counts, top hosts
curl "http://127.0.0.1:8080/api/lookup?domain=ads.exoclick.com&token=<token>"
```

`/api/block`, `/api/allow`, `/api/refresh`, `/api/reload`, `/api/mode` accept the same token — enough to
wire the fortress into home automation or a dashboard.

---

## Hosting your own sites behind the fortress

The box that answers DNS for your whole network is the friendliest place to put the things you
self-host: no port forwarding, no cloud, no certificate authority. Three verbs cover it.

```bash
# 1. publish a name. The fortress answers it itself - before the block engine runs.
sudo adquit site add media.lan --port 8096              # jellyfin/qbittorrent/grafana/...
sudo adquit site add nas.lan --ip 192.168.1.40 --no-proxy   # a site on another box
sudo adquit site list

# 2. one port for all of them: the fortress writes the vhosts, your web server does the serving
sudo apt install nginx            # or caddy / apache2 - adquit detects which one you have
sudo adquit proxy install --server nginx --port 80      # --no-catchall if :80 already serves other sites
sudo adquit proxy status          # which server was found, what is enabled, what it points at
                                  # (only one server can hold the port - if you already run caddy
                                  #  on :80, install for caddy, not nginx)

# 3. names you do not own: hand them to the router instead of NXDOMAIN
sudo adquit lan-zone add .lan                 # no address = the gateway this box already uses
sudo adquit lan-zone add .lan 10.0.0.1        # ...or name it; an address off your subnet is warned about
```

Then point the devices (or the router's DNS) at the fortress and `http://media.lan/` works from
anywhere on the network — including on devices that already use the fortress *because* it is
their resolver. A `site add` needs no restart: the running resolver picks the record up on the
next query, and it is logged in the dashboard's query log as `Local record` so you can see why it
answered.

| verb | what it changes |
|---|---|
| `site add NAME --port P` | `local_records[NAME] = {"port": P, "host": "127.0.0.1"}` — the name answers with this box's LAN address, the vhost targets the local port |
| `site add NAME --ip A --no-proxy` | DNS only: a name that should point elsewhere and get no vhost |
| `site add NAME --port P --ws` | vhost gets the websocket upgrade headers (websockets, SSE, streams) |
| `lan-zone add .lan ROUTER-IP` | names under `.lan` that you did **not** publish are forwarded to the router; with no address it uses the box's own default gateway, and a resolver that is not on any network this machine has is refused-or-warned (a name is refused outright: this box *is* the DNS, so asking it to resolve its own upstream would loop) |
| `proxy install [--port 80] [--server nginx]` | one managed file of vhosts, validated, reverted if it fails |

If a site lives on another box, `--ip` takes that box's **LAN address** (not an example from a
README): `adquit lan` prints the subnet you are on, and publishing an address outside it prints a
warning, because an unreachable target makes those names time out instead of answering.

`adquit.lan`, `adquit.local` and `<hostname>.local/.lan` resolve to the fortress by design (that
is the URL `adquit lan` prints); `sudo adquit --set answer_fortress_names false` if you want them
silent. Blocked ad hosts keep resolving to the fortress while `sinkhole_mode=fortress`, so after
`proxy install --port 80` an ad slot is served your empty 1×1 pixel over port 80 as well — the
blocker and the web server are the same box on purpose.

**Limits, so nothing surprises you**

* These names exist only while a device asks *this* resolver. A guest on another network, or a
  laptop that switched to mobile data, gets NXDOMAIN — that is the point: no hostname of yours is
  published to the internet.
* Plain HTTP. `proxy install` binds a port and preserves the client's real address
  (`X-Forwarded-For`, and the fortress trusts those headers only from a loopback peer). For
  anything beyond your Wi-Fi, put it behind a tunnel (`tailscale`, `wireguard`) — do not forward
  port 80 to the internet just because the vhosts are one command away.
* Port 80/443 need root, and `--port 80` in sinkhole-fortress mode moves the zero-pixel server to
  `sinkhole_port` 8081 automatically (the vhosts are rewritten to match) because two listeners
  cannot share a port.
* `proxy install` only ever writes files carrying its `adquit-managed` marker, backs up anything it
  replaces to `*.adquit-backup`, and `proxy remove` takes exactly those files away again. It
  validates (`nginx -t` / `caddy validate` / `apache2ctl configtest`) and restores the previous
  config if the new one would not start.
* Caddy is the one server it cannot wire up silently: the rendered `/etc/caddy/adquit.caddyfile`
  needs one line in your Caddyfile (`import adquit.caddyfile`), which `proxy install` prints.
* After `proxy install` owns the port, the dashboard is served by name — `adquit.lan`,
  `<hostname>.local`, and **the box's own addresses**, because that is what gets typed into a phone
  browser. Everything else that lands on the port gets the sinkhole (or a 200), not your dashboard.
* If the web server you picked already listens on that port (caddy on :80 is the common case),
  that is not a conflict: `proxy install` adds vhosts to the server that owns the port and only
  refuses when a *different* server holds it.
  A stock caddy install, though, has a bare `:80 { respond "Hello, world!" }` demo block, and a
  block with no hostname answers *every* host on that port — so `proxy install` points at it and
  tells you to give it a hostname or drop it. It never edits your Caddyfile; only
  `/etc/caddy/adquit.caddyfile`, which you `import`. Caddy allows exactly one global options block per
  Caddyfile, so when yours exists the rendered file explains which two options to add there
  instead of opening a second block.
* `--no-catchall` is for a box that already serves other things on that port: the fortress then
  publishes only its own names and leaves every other `Host` to your existing sites — at the cost
  of the ad splash page on that port (blocked domains keep resolving to the box either way).

---

## What changed in v19.0 (the “major” update)

* **6× the coverage** — 50 → **131 feeds**, 10 → 21 categories, plus 16 tagged ad vectors.
* **New engines** — wildcard zones, ad-keyword + host-label pattern engines, unbreak
  (`@@`) exception handling, IDN homograph and typosquat detection.
* **Zero-pixel creative sinkhole** — ad requests get an empty 1×1 GIF / empty JS-CSS body,
  so pages stop stalling on dead ad frames.
* **Speed** — TTL caches for verdicts *and* upstream answers, bounded thread pool instead of
  one thread per packet, TCP DNS + proper truncation, pickled gravity cache, conditional GETs
  with ETag/Last-Modified and parallel feed downloads.
* **Fixed real bugs from v18** — `DNSRecord.add_rr()` does not exist in dnslib, so blocked
  queries **never received a reply** (clients just timed out); every `hagezi` feed URL pointed
  at a directory that no longer exists; `firebog` mirrors were used where upstream sources are
  available; the login route accepted `admin` even after a rename; the session secret was
  hard-coded; per-client rate maps grew without bound.
* **Packaging** — the `adquit` CLI, a real one-command installer (idempotent, sudo-aware,
  rootless mode, logrotate, firewall, systemd-resolved handoff, v18 migration), Dockerfile +
  compose, CI (tests on 3.8/3.11/3.12 + a containerised install smoke test), release workflow,
  MIT licence, 59-test offline suite (engine, API, UI, exports, dependency gate).
* **Ops** — `adquit doctor`, `adquit test`, `adquit verify-lists`, JSON stats snapshot so
  `adquit stats` answers even when the web layer is down.
* **Fails loudly, never silently** — `python3 app.py --version/--help/--doctor` still answer
  with no Python deps installed (instructions, not a traceback); the installer refuses a ref
  older than itself; `adquit update` verifies the new engine, rolls back on any doubt, follows
  the channel the box was installed from, and restarts a service that had already died.

---

## Troubleshooting

| symptom | meaning / fix |
|---|---|
| `bash: line 2: ---: command not found` and ``unexpected EOF while looking for matching ``'`` | You piped a **markdown document** into bash — that ref’s `install.sh` is not a real script (as `main` was, before v19 was merged). Install from the right branch (`ADQUIT_REF=` above) or from a checkout. |
| `adquit: command not found` | The install never ran (row above), or the CLI is off `PATH`: `/usr/local/bin/adquit` for a root install, `~/.local/bin/adquit` for `ADQUIT_USER=1`. |
| `ModuleNotFoundError: No module named 'flask'` (or `dnslib`, `requests`) | You ran `python3 app.py` with a bare interpreter. `adquit doctor` says exactly this and how to fix it; the installer builds a private venv so you never hand-install anything. |
| `refusing to install app.py v18.0 …` / `no version stamp` | The installer noticed the ref is behind itself and stopped rather than half-installing. Pass `ADQUIT_REF=<branch>` or merge. |
| `service did not become healthy`, or `state down` while `journalctl` shows the unit running | Almost always a **warm-up**, not a crash: loading a 5M-rule gravity cache takes tens of seconds on a small box, and the health probe used to give up at 15s and stop the service mid-boot. v19.1 sizes the wait from the cache and reports `warming up`. Raise it with `ADQUIT_START_WAIT=<seconds>` (e.g. `sudo env ADQUIT_START_WAIT=300 adquit restart`). |
| Restart takes as long as a first install | It shouldn't any more: a boot with a valid gravity cache used to rebuild every feed from disk before binding the port. `adquit logs` now says `gravity cache restored ... ready in Ns` instead of `building gravity from 99 enabled feeds`. |
| `already up to date - engine vX is byte-identical` | Not an error: your channel has no newer commit. Blocklists are updated separately with `adquit gravity`. |
| `refusing to downgrade vA -> vB` | The channel genuinely holds an **older** engine than you run (v19.1+ compares content, not just the stamp, so same-version commits update normally). Point `ADQUIT_REF` at the right branch, or `sudo adquit update --force` to allow it. `ADQUIT_FORCE=1` alone does nothing through `sudo` - the environment is reset. |
| `adquit update` refuses, and the refusal makes no sense | If the CLI on your box predates v19.1 it has no escape hatch of its own: the guard that is misfiring is the one you are running. Re-install in place instead - it refreshes `app.py` **and** the CLI and leaves `data/` (config, custom blocks, allows, lists) alone: `curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/<your-ref>/install.sh \| sudo env ADQUIT_REF=<your-ref> bash` |
| `port 53 is already in use` | `adquit doctor` names the squatter (usually `systemd-resolved`); the installer writes a `DNSStubListener=no` drop-in for exactly that, or use `ADQUIT_DNS_PORT=5353`. |
| something you need got blocked | `adquit allow <domain>` — the whitelist is layer 0 and beats every other rule; `adquit rules <domain>` shows which layer decided. |
| feeds look dead | `adquit verify-lists` reports which of the 131 sources your box can reach; a dead feed is an error badge, never a breakage. |

## Notes, limits and honesty

* This is **DNS-level** blocking. It kills ad traffic at the resolver — including mobile apps,
  smart TVs and consoles — but it cannot re-style a page, so an empty ad box may still be
  drawn. The creative sinkhole is the mitigation: blocked creatives return empty bodies
  instead of hanging.
* YouTube pre-roll: the ad *servers* and player telemetry are blocked, which works for the
  web player and many clients. In-video ads served from `googlevideo.com` itself cannot be
  removed by DNS alone (that needs a client-side extension). Blocking is aggressive-mode
  configurable, and YouTube never breaks: `youtube.com` is in the trusted-zone list.
* `nuclear` will occasionally block something you want. `adquit allow <domain>` (or the
  Domain Lab) fixes it in one command; the whitelist beats every other layer except nothing —
  it is layer 0.
* Feed URLs rot. `adquit verify-lists` tells you which of the 131 sources are reachable from
  your box; a dead feed shows as an error badge in the dashboard and never breaks anything.
* Nothing leaves your network except (optional) AI triage calls and feed downloads.
  Query logs stay in `data/queries.jsonl`, rotated by logrotate. No telemetry, no accounts.

## Development

```bash
make lint      # python + shell syntax and shellcheck
make test      # offline suite (66 engine/API/UI/gate/boot tests) + CLI contract
make run       # foreground dev instance (dns :5353, web :8080)
```

Layout: `app.py` (the whole engine + dashboard, by design one file) · `bin/adquit` (CLI) ·
`install.sh` / `uninstall.sh` (packaging) · `tests/` (fixtures + runners).

## Licence

MIT — see [LICENSE](LICENSE). Blocklist data belongs to its respective maintainers
([Hagezi](https://github.com/hagezi/dns-blocklists),
[AdGuard](https://github.com/AdguardTeam/FiltersRegistry),
[uBlock Origin](https://github.com/uBlockOrigin/uAssets),
[OISD](https://oisd.nl), [StevenBlack](https://github.com/StevenBlack/hosts),
[ShadowWhisperer](https://github.com/ShadowWhisperer/Blocklists),
[Perflyst](https://github.com/Perflyst/PiHoleBlocklist) and many more).
