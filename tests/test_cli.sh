#!/usr/bin/env bash
# Contract tests for the adquit CLI (offline, rootless, throwaway home).
set -o pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
export ADQUIT_HOME="$TMP" ADQUIT_NO_PIP=1 ADQUIT_DNS_PORT=5398 ADQUIT_WEB_PORT=18098
BIN="$REPO/bin/adquit"
fails=0

check() { # check <label> <cmd...>  (time-bounded: a wedged subcommand must never hang CI)
    local label="$1"; shift
    if timeout 60 "$@" >/dev/null 2>&1; then printf '  \033[32m✔\033[0m %s\n' "$label"
    else printf '  \033[31m✘\033[0m %s\n' "$label"; fails=$((fails + 1)); fi
}

printf '\n\033[1m  adquit CLI contract\033[0m\n'
check "help renders"              bash -c "$BIN help | grep -q 'START / STOP'"
check "version string"            bash -c "$BIN version | grep -q '19.0'"
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
check "adquit test (offline, no live)"      "$BIN" test --no-live
check "adquit doctor reports"               bash -c "$BIN doctor | grep -q 'issue' "
check "adquit json is valid json"           bash -c "$BIN json 2>/dev/null | python3 -c 'import json,sys; json.load(sys.stdin)'"
"$BIN" stop >/dev/null 2>&1
rm -rf "$TMP"
printf '\n'
if [ "$fails" = "0" ]; then printf '  \033[32mall CLI contract tests passed\033[0m\n\n'; exit 0
else printf '  \033[31m%s CLI check(s) failed\033[0m\n\n' "$fails"; exit 1; fi
