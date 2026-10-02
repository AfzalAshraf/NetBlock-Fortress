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
sed -n '/^app_version()/,/^}/p;/^ver_ge()/,/^}/p;/^update_decision()/,/^}/p;/^detect_channel()/,/^}/p' "$BIN" > "$TMP/helpers.sh"
# shellcheck disable=SC1090
. "$TMP/helpers.sh"
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
check "adquit doctor reports"               bash -c "$BIN doctor | grep -q 'issue' "
check "adquit json is valid json"           bash -c "$BIN json 2>/dev/null | python3 -c 'import json,sys; json.load(sys.stdin)'"
"$BIN" stop >/dev/null 2>&1
rm -rf "$TMP"
printf '\n'
if [ "$fails" = "0" ]; then printf '  \033[32mall CLI contract tests passed\033[0m\n\n'; exit 0
else printf '  \033[31m%s CLI check(s) failed\033[0m\n\n' "$fails"; exit 1; fi
