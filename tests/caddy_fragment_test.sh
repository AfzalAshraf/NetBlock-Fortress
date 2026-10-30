#!/usr/bin/env bash
# The caddy fragment we hand people has to satisfy two things at once: it must configure the
# proxies correctly, and it must be *importable anywhere* in someone's Caddyfile. Both were
# violated by v19.2/v19.3 until now - the fragment opened a global options block, which caddy
# only accepts as the first thing in a file, so the box that appended the import (as the hint
# invited) got "server block without any key is global configuration, and if used, it must be
# first" and a web server that would not restart.
#
# Run it directly (./tests/caddy_fragment_test.sh) or through tests/test_cli.sh, which passes the
# stub `caddy` that actually enforces caddy's rule. Without that stub the placement test is
# skipped rather than quietly vacuous - say so, because a check that does not check needs a voice.
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
STUB="${2:-}"
BIN="$REPO/bin/adquit"
[ -x "$BIN" ] || [ -r "$BIN" ] || { echo "caddy_fragment: no CLI at $BIN" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/data/lists" "$TMP/data/meta"
cp "$REPO/app.py" "$TMP/app.py"
export ADQUIT_HOME="$TMP" ADQUIT_NO_PIP=1 ADQUIT_DNS_PORT=5398 ADQUIT_WEB_PORT=18098

fail() { echo "caddy_fragment: $*" >&2; exit 1; }

"$BIN" site add media.lan --port 8096 --ws >/dev/null 2>&1 || true
"$BIN" portal on >/dev/null 2>&1 || true
out="$("$BIN" proxy install --server caddy --port 80 --dry-run 2>/dev/null | tail -n +2)"
[ -n "$out" ] || fail "the render came back empty - run this with flask/requests/dnslib installed"

printf '%s\n' "$out" > "$TMP/adquit.caddyfile"

# 1. no global options block: a bare `{` line, wherever it lands, makes this file
#    loadable only as the first import of the main Caddyfile
if printf '%s\n' "$out" | grep -Eq '^[[:space:]]*\{[[:space:]]*$'; then
    fail "the fragment opens a global options block, so it can only be imported first"
fi

# 2. what the global block used to promise is set per proxy instead, and a proxy that
#    trusts no one leaks the proxy's address as the client's
proxies="$(printf '%s\n' "$out" | grep -c 'reverse_proxy')"
trusted="$(printf '%s\n' "$out" | grep -c 'reverse_proxy [^ ]* {')"
[ "$proxies" -gt 0 ] || fail "the fragment proxies nothing at all - the render is wrong"
[ "$proxies" = "$trusted" ] || \
    fail "$proxies reverse_proxy lines but $trusted with a trusted_proxies block: the client's real address is lost"

# ...and the ranges have to be *ranges*. This is the shape that shipped broken once: the global
# form reads `servers { trusted_proxies static private_ranges }`, but inside `reverse_proxy` caddy
# parses each token as an address, so copying the module words gives a config that adapts fine and
# then dies provisioning with "invalid IP address: 'static'".
live_lines="$(printf '%s\n' "$out" | grep -v '^[[:space:]]*#' | grep 'trusted_proxies' || true)"
[ -n "$live_lines" ] || fail "nothing sets trusted_proxies - every visitor will look like 127.0.0.1"
if printf '%s\n' "$live_lines" | grep -qE 'trusted_proxies +(static|private_ranges)'; then
    fail "the fragment puts the global trusted_proxies syntax inside reverse_proxy; caddy cannot provision it"
fi
bad="$(printf '%s\n' "$live_lines" | sed 's/.*trusted_proxies //' | tr ' \t' '\n\n' \
        | grep -vE '^$' | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$|^[0-9a-fA-F:]+(/[0-9]{1,3})?$' | head -n1)"
[ -z "$bad" ] || fail "trusted_proxies got a token that is not an address or range: '$bad'"

printf '%s\n' "$out" | grep -q 'auto_https off' || \
    fail "the fragment stopped mentioning auto_https - the comment is the only thing keeping a .lan name off ACME"

# 3. the rule itself, with the file imported *after* someone else's site block
if [ -n "$STUB" ] && [ -x "$STUB/caddy" ]; then
    printf ':80 {\n\tauto_https off\n}\nimport adquit.caddyfile\n' > "$TMP/Caddyfile"
    if ! out2="$("$BIN" proxy install --server caddy --port 80 --dry-run 2>&1)"; then
        fail "the CLI stopped while checking a valid setup: $(printf '%s' "$out2" | tail -n 3)"
    fi
    if printf '%s\n' "$out2" | grep -q 'must be first\|does not load'; then
        printf '%s\n' "$out2" | sed 's/^/      | /' >&2
        fail "caddy rejects the fragment when it is imported after a site block"
    fi
    # ...and the same stub must still reject a fragment that does open a global block, or
    # this check proves nothing
    printf '{\n\tauto_https off\n}\n:80 {\n}\n' > "$TMP/adquit.caddyfile.bad"
    printf ':80 {\n}\nimport adquit.caddyfile.bad\n' > "$TMP/Caddyfile.bad"
    if "$STUB/caddy" validate --config "$TMP/Caddyfile.bad" --adapter caddyfile >/dev/null 2>&1; then
        fail "the stub caddy does not enforce the rule this test depends on"
    fi
elif [ -n "${ADQUIT_QUIET_STUB_SKIP:-}" ]; then
    :
else
    echo "caddy_fragment: placement test skipped - pass the stub dir (tests/test_cli.sh does)" >&2
fi

echo "caddy_fragment: importable anywhere, $proxies proxies all trusting the LAN"
