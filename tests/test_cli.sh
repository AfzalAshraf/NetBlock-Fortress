#!/usr/bin/env bash
# Contract tests for the adquit CLI (offline, rootless, throwaway home).
set -o pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
export ADQUIT_HOME="$TMP" ADQUIT_NO_PIP=1 ADQUIT_DNS_PORT=5398 ADQUIT_WEB_PORT=18098
BIN="$REPO/bin/adquit"
fails=0

check() { # check <label> <cmd...>  - time-bounded, timed, and self-reporting
    local label="$1"; shift
    local out rc t0 t1
    t0=$(date +%s)
    out="$(timeout 90 "$@" 2>&1)"; rc=$?
    t1=$(date +%s)
    if [ "$rc" = "0" ]; then
        printf '  \033[32m✔\033[0m %s \033[2m(%ss)\033[0m\n' "$label" "$((t1 - t0))"
    else
        printf '  \033[31m✘\033[0m %s \033[31m(exit %s after %ss)\033[0m\n' "$label" "$rc" "$((t1 - t0))"
        printf '%s\n' "$out" | tail -n 10 | sed 's/^/      | /'
        fails=$((fails + 1))
        # GitHub swallows job logs behind a blob host; annotations and the step summary do not,
        # so a red CI run is still diagnosable from `gh api .../check-runs/<id>/annotations`.
        if [ -n "${GITHUB_ACTIONS:-}" ]; then
            printf '::error::CLI contract: "%s" exited %s after %ss\n' "$label" "$rc" "$((t1 - t0))"
            printf '%s\n' "$out" | tail -n 5 | while IFS= read -r line; do
                [ -n "$line" ] && printf '::error::  %s\n' "${line:0:180}"
            done
        fi
        if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
            { printf '### ✘ `%s`\n\nexit `%s` after `%ss`\n\n```\n%s\n```\n\n' \
                    "$label" "$rc" "$((t1 - t0))" "$(printf '%s\n' "$out" | tail -n 40)"
            } >> "$GITHUB_STEP_SUMMARY"
        fi
    fi
}

# A deterministic `ip` for the subnet-sanity checks: CI runners vary, this does not.
mkdir -p "$TMP/stub"
cat > "$TMP/stub/ip" <<'STUBIP'
#!/bin/sh
case "$1" in
  -4)    echo '2: eth0    inet 192.0.2.5/24 brd 192.0.2.255 scope global eth0\' ;;
  route) echo 'default via 192.0.2.1 dev eth0 metric 100' ;;
  *)     command ip "$@" ;;
esac
STUBIP
chmod +x "$TMP/stub/ip"

# A `caddy` that knows one verb: validate. Braces balanced means the file loads, an import of a
# missing file does not. It is kept out of $TMP/stub so only the check that wants it sees it -
# otherwise proxy_detect would find a "caddy" on every box in the suite.
mkdir -p "$TMP/stub-caddy"
cat > "$TMP/stub-caddy/caddy" <<'STUBCADDY'
#!/bin/sh
# Enough of `caddy validate` to fail the way caddy fails: braces have to pair, an import has
# to exist, and the one rule a *fragment* can break - a bare `{` global block is only legal as
# the first thing in the file, so importing one after someone's site block is an error.
[ "$1" = validate ] || exit 0
file="$3"
[ -r "$file" ] || exit 0
combined="$(cat "$file")"
imp="$(grep -Eo '^[[:space:]]*import[[:space:]]+[^[:space:]]+' "$file" | head -n1 | awk '{print $2}')"
if [ -n "$imp" ]; then
    case "$imp" in
        /*) ;;
        *) imp="$(dirname "$file")/$imp" ;;
    esac
    if [ ! -r "$imp" ]; then
        echo "Error: File to import not found or unable to stat" >&2
        exit 1
    fi
    combined="$combined
$(cat "$imp")"
fi
open="$(printf '%s\n' "$combined" | tr -cd '{' | wc -c)"
close="$(printf '%s\n' "$combined" | tr -cd '}' | wc -c)"
if [ "$open" != "$close" ]; then
    echo "Error: adapting config using caddyfile: EOF" >&2
    exit 1
fi
if printf '%s\n' "$combined" | grep -Eq '^[[:space:]]*\{[[:space:]]*$'; then
    first="$(printf '%s\n' "$combined" | sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' -e 's/^[[:space:]]*//' | head -n1)"
    if [ "$first" != "{" ]; then
        echo "Error: adapting config using caddyfile: server block without any key is global configuration, and if used, it must be first" >&2
        exit 1
    fi
fi
exit 0
STUBCADDY
chmod +x "$TMP/stub-caddy/caddy"

printf '\n\033[1m  adquit CLI contract\033[0m\n'
check "help renders"              bash -c "$BIN help | grep -q 'START / STOP'"
VER="$(sed -n 's/^[[:space:]]*VERSION[[:space:]]*=[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' "$REPO/app.py" | head -n1)"
check "version string"            bash -c "$BIN version | grep -q '$VER'"
check "CLI, engine and installer agree on the version" \
      bash -c "grep -q 'VERSION_TAG=\"$VER\"' '$REPO/bin/adquit' && grep -q 'INSTALLER_VERSION=\"$VER\"' '$REPO/install.sh'"
check "bash -n bin/adquit"        bash -n "$REPO/bin/adquit"
check "bash -n install.sh"        bash -n "$REPO/install.sh"
check "bash -n uninstall.sh"      bash -n "$REPO/uninstall.sh"
mkdir -p "$TMP/bin" "$TMP/data/lists" "$TMP/data/meta"
cp "$REPO/app.py" "$TMP/app.py"
cp "$REPO/tests/fixtures/hosts_style.txt" "$TMP/data/lists/fx.txt"
python3 - "$TMP" <<'PY'
import json, sys, pathlib
home = pathlib.Path(sys.argv[1])
cfg = {"enabled_lists": ["fx"], "custom_lists": {"fx": {"name": "fx", "cat": "ads",
       "vec": "banner", "url": "file://x"}}, "block_mode": "strict", "dns_port": 5398,
       "web_port": 18098, "api_token": "testtoken", "password_hash": "x"}
(home / "data" / "config.json").write_text(json.dumps(cfg))
PY
check "engine --rules blocks seed domain"   bash -c "python3 $TMP/app.py --rules doubleclick.net | grep -q BLOCK"
check "engine --rules spares github"        bash -c "python3 $TMP/app.py --rules github.com | grep -q ALLOW"
check "adquit block writes custom list"     bash -c "$BIN block probe-me.example >/dev/null && grep -q probe-me.example $TMP/data/custom_blocked.txt"
check "adquit unblock removes it"           bash -c "$BIN unblock probe-me.example >/dev/null && ! grep -q probe-me.example $TMP/data/custom_blocked.txt"
check "adquit allow writes whitelist"       bash -c "$BIN allow ok-site.example >/dev/null && grep -q ok-site.example $TMP/data/custom_whitelist.txt"
check "adquit mode nuclear accepted"        bash -c "$BIN mode nuclear >/dev/null && grep -q nuclear $TMP/data/config.json"
check "adquit mode strict accepted"         bash -c "$BIN mode strict >/dev/null && grep -q strict $TMP/data/config.json"
# Update-safety helpers (app_version / ver_ge / detect_channel) are unit-tested by
# extracting them from bin/adquit - sourcing the script itself would run the CLI.
cat > "$TMP/helpers_test.sh" <<'HELPERTEST'
set -e
REPO="$1"; BIN="$2"; TMP="$3"
sed -n '/^app_version()/,/^}/p;/^ver_ge()/,/^}/p;/^update_decision()/,/^}/p;/^detect_channel()/,/^}/p;/^caddy_config_to_validate()/,/^}/p;/^atomic_install()/,/^}/p' "$BIN" > "$TMP/helpers.sh"
# shellcheck disable=SC1090
. "$TMP/helpers.sh"
have() { command -v "$1" >/dev/null 2>&1; }      # atomic_install probes for `install`; the CLI
                                                # defines `have` further up than we extract from
STAMP="$(sed -n 's/^[[:space:]]*VERSION[[:space:]]*=[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' "$REPO/app.py" | head -n1)"
[ -n "$STAMP" ]                                                     # stamp discoverable
[ "$(app_version "$REPO/app.py")" = "$STAMP" ]
printf 'VERSION = "18.0"\n' > "$TMP/old.py"
[ "$(app_version "$TMP/old.py")" = "18.0" ]                         # older stamp
printf '# comment\n  VERSION   = "19.2"   # trailing note\n' > "$TMP/odd.py"
[ "$(app_version "$TMP/odd.py")" = "19.2" ]                         # tolerant parse
ver_ge "$STAMP" "$STAMP"; ver_ge 20.1 "$STAMP"                      # equal is NOT a downgrade
ver_ge "$STAMP" "$STAMP-rc1"                                        # a pre-release reads as its base
! ver_ge 18.0 "$STAMP"                                              # real downgrade refused
# the decision the update acts on (this is what used to refuse v19.0 -> v19.0)
[ "$(update_decision "$STAMP" "$STAMP" same same)" = skip ]        # unchanged engine: no restart
[ "$(update_decision "$STAMP" "$STAMP" old new)" = go ]            # same stamp, newer code = branch life
[ "$(update_decision "$STAMP" 18.0 x y)" = refuse ]                # channel behind us
[ "$(update_decision 18.0 "$STAMP" x y)" = go ]                    # channel ahead
[ "$(update_decision "$STAMP" "" x y)" = nostamp ]                 # v18 / not-Python channel
[ "$(update_decision "" "$STAMP" "" y)" = go ]                      # nothing installed yet
echo team/xyz > "$TMP/home/.channel"
HOME_DIR="$TMP/home" ADQUIT_REF= sh -c '. "$0/helpers.sh"; [ "$(detect_channel)" = "team/xyz" ]' "$TMP"
HOME_DIR="$TMP/home" ADQUIT_REF=pinned/branch sh -c '. "$0/helpers.sh"; [ "$(detect_channel)" = "pinned/branch" ]' "$TMP"
grep -q MIN_APP_VERSION "$REPO/install.sh"
# the escape hatch must survive sudo: a flag travels in argv, an export does not
grep -q 'adquit update \[--force\]' "$REPO/bin/adquit"                  # help says so
grep -q "usage: adquit update \[--force\]" "$REPO/bin/adquit"           # and so does the error
grep -q 'update|upgrade) shift; cmd_update "$@"' "$REPO/bin/adquit"       # flags reach the function
grep -A10 '^elevate_for()' "$REPO/bin/adquit" | grep -q 'ADQUIT_FORCE='    # env forwarded across sudo
# a stale guard must not be able to wedge an update it cannot judge
grep -q 'ADQUIT_REHEALED' "$REPO/bin/adquit"                               # one-hop marker
grep -q 'restarting the update with it' "$REPO/bin/adquit"                  # hand-off to the fetched CLI
grep -q 'restore_update "$origin"' "$REPO/bin/adquit"                       # engine restored on every refusal
# self-hosting: LAN names and the proxy must stay in step with the engine
grep -q 'adquit site add media.lan' "$REPO/bin/adquit"                        # usage mentions it
grep -q 'adquit lan-zone add' "$REPO/bin/adquit"                              # and the router zones
grep -q 'proxy|portal|set|get|--set|--get)' "$REPO/bin/adquit"                # all of them elevate centrally

# a file being replaced must not disturb whoever is already reading it - the update path renames
# for exactly that reason, and an updater that breaks the updater is the worst kind of surprise
printf 'old line\n' > "$TMP/live.sh"
printf 'new line\n' > "$TMP/new.sh"
exec 9< "$TMP/live.sh"
atomic_install "$TMP/new.sh" "$TMP/live.sh" 0755
[ "$(cat "$TMP/live.sh")" = "new line" ]                     # the new bytes are there
read -r held <&9
[ "$held" = "old line" ]                                     # and the reader kept the old ones
exec 9<&-
[ -x "$TMP/live.sh" ]                                         # mode travels with it
[ -z "$(ls -A "$TMP" | grep -F '.live.sh.adquit.' || true)" ]   # no temp left behind
printf 'nope\n' > "$TMP/src.missing.check"; rm -f "$TMP/src.missing.check"
! atomic_install "$TMP/nonexistent" "$TMP/live.sh"            # a missing source is a failure, not a wipe
[ "$(cat "$TMP/live.sh")" = "new line" ]
! grep -qE '^ *cp( -f)? "[^"]*" "\$target"' "$BIN"           # and the CLI is never written in place

# which config does caddy actually load? theirs, the moment it imports ours - to caddy that pair
# is one file, and checking only our own fragment is how a broken include reaches the service
PFILE="$TMP/adquit.caddyfile"; PCFILE="$TMP/Caddyfile"
: > "$PFILE"
printf 'import adquit.caddyfile\n' > "$PCFILE"
[ "$(caddy_config_to_validate)" = "$PCFILE" ]
printf ':80 {\n}\n' > "$PCFILE"
[ "$(caddy_config_to_validate)" = "$PFILE" ]
grep -q 'adquit-managed' "$REPO/bin/adquit"                                    # only our own files
grep -q 'answer_fortress_names' "$REPO/app.py"                                 # fortress names resolve
grep -q 'local_records' "$REPO/app.py"                                          # ...and sites do too
! grep -qE "(say|warn|die)[[:space:]]+'[^']*%s" "$REPO/bin/adquit"               # say() is not printf
# `update` must heal the CLI too: on a branch, "same version stamp, newer code" is the norm
test "$(grep -c 'cli_refresh "\$(readlink' "$REPO/bin/adquit")" = 2              # skip path and applied path
! grep -q 'cp -f "$HOME_DIR/bin/adquit" /usr/local/bin/adquit' "$REPO/bin/adquit"  # no raw copy around it
grep -q 'never install a CLI that does not parse' "$REPO/bin/adquit"
grep -q 'caddy_has_bare_site' "$REPO/bin/adquit"                                  # their :80 demo is called out
grep -q 'adquit.caddyfile, but that file does not exist' "$REPO/bin/adquit"        # a dangling import is named
grep -q 'def start_portal_server' "$REPO/app.py"                                    # the start page has its own listener
grep -q 'def portal_entries' "$REPO/app.py"                                         # and reads the same registry
grep -q 'portal_enabled' "$REPO/app.py"                                             # switchable from the CLI
grep -q "refusing to install app.py" "$REPO/install.sh"
grep -q 'bg_run "$STATE_DIR/gravity.log"' "$BIN"                   # gravity must not own the pidfile
# a 5M-rule warm-up is not an outage: the probe waits, status says so, stop does not lie
grep -q 'ADQUIT_START_WAIT' "$REPO/bin/adquit"                      # operator override
grep -q 'warming up the engine' "$REPO/bin/adquit"                  # budget announced, sized by cache
grep -q 'still loading blocklists' "$REPO/bin/adquit"               # slow boot != failure
grep -q 'cache_mb' "$REPO/bin/adquit"                                # where the budget comes from
sed -n '/^cmd_stop()/,/^}/p' "$REPO/bin/adquit" | grep -q 'was_unit'          # systemd is the truth
sed -n '/^cmd_status()/,/^}/p' "$REPO/bin/adquit" | grep -q 'warming up'      # three states, not two
sed -n '/^cmd_restart()/,/^}/p' "$REPO/bin/adquit" | grep -q 'port_busy'       # wait for :53/:8080 release
[ "$(grep -c start_detached "$BIN")" -eq 2 ]                       # definition + the one service call site
HELPERTEST
mkdir -p "$TMP/home"
check "update guards: version, channel, pidfile"  bash "$TMP/helpers_test.sh" "$REPO" "$BIN" "$TMP"
# the browser subscription + domain intel must work with no service running at all
check "adquit export ublock writes a list" bash -c "
    '$BIN' export ublock '$TMP/sub.txt' >/dev/null 2>&1
    head -1 '$TMP/sub.txt' | grep -q '^! Title:'
    grep -q '||youtube.com/api/stats/ads' '$TMP/sub.txt'
    grep -q '||doubleclick.net' '$TMP/sub.txt'
    grep -qv '||youtube.com\^' '$TMP/sub.txt' || true
    ! grep -q '^||youtube.com\^$' '$TMP/sub.txt'
    ! grep -q '^||gstatic.com\^$' '$TMP/sub.txt'"
check "adquit intel answers about a domain" bash -c "'$BIN' intel doubleclick.net | grep -q BLOCK"
check "adquit lan prints reachable URLs"    bash -c "'$BIN' lan | grep -E -q 'http://(localhost|127)'"
check "adquit --version answers with no install at all" bash -c "
    '$BIN' --version | grep -q '$VER'
"
check "adquit update rejects an unknown flag" bash -c "'$BIN' update --frorce 2>&1 | grep -q 'unknown option'"
check "adquit test (offline, no live)"      "$BIN" test --no-live
check "adquit status answers with a state line"  bash -c "'$BIN' status | grep -Eq 'state +(live|down|warming up)'"
check "adquit site add/list/rm round-trip" bash -c "
    '$BIN' site add media.lan --port 8096 >/dev/null &&
    '$BIN' site list | grep -q '127.0.0.1:8096' &&
    '$BIN' site rm media.lan >/dev/null &&
    ! '$BIN' site list | grep -q '127.0.0.1:8096'
"
check "adquit site refuses a name it cannot publish" bash -c "
    '$BIN' site add 'bad name.lan' >/dev/null 2>&1; test \$? -ne 0
"
check "adquit site refuses a proxied site with no port" bash -c "
    '$BIN' site add portless.lan >/dev/null 2>&1; test \$? -ne 0
"
check "adquit proxy renders nginx vhosts for the effective web port" bash -c "
    '$BIN' site add media.lan --port 8096 >/dev/null
    '$BIN' proxy install --server nginx --port 80 --dry-run > '$TMP/nginx.conf' 2>&1
    grep -q 'server_name media.lan;' '$TMP/nginx.conf'
    grep -q 'proxy_pass http://127.0.0.1:$ADQUIT_WEB_PORT;' '$TMP/nginx.conf'
    grep -q 'listen 80 default_server;' '$TMP/nginx.conf'
    grep -q 'map \$http_upgrade' '$TMP/nginx.conf'
    ! grep -q 'ServerName \*' '$TMP/nginx.conf'
    tr -cd '{' < '$TMP/nginx.conf' | wc -c > '$TMP/ob'
    tr -cd '}' < '$TMP/nginx.conf' | wc -c > '$TMP/cb'
    cmp -s '$TMP/ob' '$TMP/cb'
    '$BIN' site rm media.lan >/dev/null
"
check "adquit proxy --no-catchall leaves other hosts to the box's own sites" bash -c "
    '$BIN' proxy install --server nginx --port 80 --dry-run --no-catchall > '$TMP/nocat.conf' 2>&1
    ! grep -q 'default_server' '$TMP/nocat.conf'
    '$BIN' proxy install --server nginx --port 80 --dry-run > '$TMP/cat.conf' 2>&1
    grep -q 'default_server' '$TMP/cat.conf'
"
check "adquit will not open a second caddy global block" bash -c "
    printf '{\n\tskip_install\n}\n' > '$TMP/Caddyfile'
    ADQUIT_CADDYFILE='$TMP/Caddyfile' '$BIN' proxy install --server caddy --port 80 --dry-run 2>&1 \
        | grep -q 'already opens a global block'
    '$BIN' proxy install --server caddy --port 80 --dry-run --no-catchall 2>&1 | grep -q 'no-catchall'
"
check "adquit gives the typed address to the start page and the names to the dashboard" bash -c "
    export PATH='$TMP/stub':\$PATH
    '$BIN' proxy install --server nginx --port 80 --dry-run 2>&1 | grep -q 'server_name home.lan.*192.0.2.5'
    '$BIN' proxy install --server nginx --port 80 --dry-run 2>&1 | grep -q 'server_name adquit.lan adquit.local netblock.local'
    '$BIN' --set portal_enabled false >/dev/null 2>&1
    '$BIN' proxy install --server nginx --port 80 --dry-run 2>&1 | grep -q 'server_name adquit.lan.*192.0.2.5'
    '$BIN' --set portal_enabled true >/dev/null 2>&1
"
check "adquit portal reports the start page and how to open it" bash -c "
    '$BIN' portal status | grep -q 'LAN start page' &&
    '$BIN' portal url | grep -Eq '^http://[0-9.]+:[0-9]+/$'
"
check "adquit portal on|off|title go through the engine" bash -c "
    '$BIN' portal off >/dev/null &&
    grep -q 'portal_enabled[^:]*: false' '$ADQUIT_HOME/data/config.json' &&
    '$BIN' portal title 'Garage door' >/dev/null &&
    grep -q 'Garage door' '$ADQUIT_HOME/data/config.json' &&
    '$BIN' portal on >/dev/null &&
    grep -q 'portal_enabled[^:]*: true' '$ADQUIT_HOME/data/config.json'
"
check "adquit routes home.lan and start.lan to the start page" bash -c "
    '$BIN' proxy install --server nginx --port 80 --dry-run 2>&1 | grep -q 'server_name home.lan portal.lan start.lan' &&
    '$BIN' proxy install --server caddy --port 80 --dry-run 2>&1 | grep -q '@adquit_portal host home.lan' &&
    '$BIN' proxy install --server apache --port 80 --dry-run 2>&1 | grep -q 'ServerAlias home.lan'
"
check "adquit says so when the Caddyfile it is about to feed will not load" bash -c "
    export PATH='$TMP/stub-caddy':\$PATH
    printf ':80 {\n\treverse_proxy 127.0.0.1:8080\n' > '$TMP/Caddyfile.broken'
    printf ':80 {\n\treverse_proxy 127.0.0.1:8080\n}\n' > '$TMP/Caddyfile.good'
    ADQUIT_CADDYFILE='$TMP/Caddyfile.broken' \
        '$BIN' proxy install --server caddy --port 80 --dry-run 2>&1 | grep -q 'does not load' &&
    ADQUIT_CADDYFILE='$TMP/Caddyfile.broken' \
        '$BIN' proxy install --server caddy --port 80 --dry-run 2>&1 | grep -q 'caddyfile: EOF' &&
    ! ADQUIT_CADDYFILE='$TMP/Caddyfile.good' \
        '$BIN' proxy install --server caddy --port 80 --dry-run 2>&1 | grep -q 'does not load'
"
check "every documented adquit verb exists in the CLI" \
      bash "$REPO/tests/doc_contract.sh" "$REPO"
check "the caddy fragment is importable anywhere and sets trusted_proxies per proxy" \
      bash "$REPO/tests/caddy_fragment_test.sh" "$REPO" "$TMP/stub-caddy"
check "adquit proxy refuses a bad port and an unknown server" bash -c "
    '$BIN' proxy install --port eight --dry-run >/dev/null 2>&1; test \$? -ne 0
    '$BIN' proxy install --server tomcat --dry-run >/dev/null 2>&1; test \$? -ne 0
"
check "adquit refuses to point a LAN name at an address it cannot reach" bash -c "
    export PATH='$TMP/stub':\$PATH
    '$BIN' lan-zone add lan 240.0.0.1 2>&1 | grep -q 'not on any network' &&
    '$BIN' lan-zone rm lan >/dev/null &&
    '$BIN' site add probe.lan --ip 240.0.0.9 --no-proxy 2>&1 | grep -q 'not on any network' &&
    '$BIN' site rm probe.lan >/dev/null
"
check "adquit finds the router itself and refuses a name as a resolver" bash -c "
    export PATH='$TMP/stub':\$PATH
    '$BIN' lan-zone add lan 2>&1 | grep -q 'resolves through 192.0.2.1' &&
    '$BIN' lan-zone rm lan >/dev/null &&
    '$BIN' lan-zone add lan router.lan 2>&1 | grep -Eq 'needs an address, not a name' &&
    '$BIN' lan-zone list 2>&1 | grep -q '192.0.2.1'
"
check "adquit lan open validates every port it is given" bash -c "
    '$BIN' lan open abc >/dev/null 2>&1; test \$? -ne 0
    '$BIN' lan open 99999 >/dev/null 2>&1; test \$? -ne 0
    '$BIN' lan open 0 >/dev/null 2>&1; test \$? -ne 0
"
check "adquit set/get reach the engine config" bash -c "
    '$BIN' set portal_title 'Garage door' >/dev/null &&
    '$BIN' get portal_title | grep -q 'Garage door'
"
check "adquit site add keeps every site already published" bash -c "
    '$BIN' site add one.lan --port 1111 >/dev/null &&
    '$BIN' site add two.lan --port 2222 >/dev/null &&
    '$BIN' site list | grep -q '127.0.0.1:1111' &&
    '$BIN' site list | grep -q '127.0.0.1:2222' &&
    '$BIN' site rm one.lan >/dev/null &&
    '$BIN' site rm two.lan >/dev/null
"
check "adquit lan-zone add/list/rm round-trip" bash -c "
    '$BIN' lan-zone add lan 127.0.0.1:5399 >/dev/null &&
    '$BIN' lan-zone list | grep -q 'lan' &&
    grep -q 'lan_zones' '$ADQUIT_HOME/data/config.json' &&
    '$BIN' lan-zone rm lan >/dev/null &&
    ! '$BIN' lan-zone list | grep -q '127.0.0.1:5399'
"
check "adquit doctor reports"               bash -c "$BIN doctor | grep -q 'issue' "
check "adquit json is valid json"           bash -c "$BIN json 2>/dev/null | python3 -c 'import json,sys; json.load(sys.stdin)'"
"$BIN" stop >/dev/null 2>&1
rm -rf "$TMP"
printf '\n'
if [ "$fails" = "0" ]; then printf '  \033[32mall CLI contract tests passed\033[0m\n\n'; exit 0
else printf '  \033[31m%s CLI check(s) failed\033[0m\n\n' "$fails"; exit 1; fi
