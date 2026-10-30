#!/usr/bin/env bash
# Docs versus dispatch: every verb the help text or the README shows to a human must be
# a verb the CLI actually runs.
#
# This exists because v19.0 through v19.2 told people to run `sudo adquit --set
# answer_fortress_names false` and the CLI answered "unknown command" with a usage block
# and exit 2 - the engine accepted the verb, the wrapper never had one. A README command
# that does not dispatch is worse than no README: it is a command people have already
# typed. Nothing else in the suite would notice, because the help text is never executed.
#
# Read-only, no network, no root, no Python: awk and grep.
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
CLI="$REPO/bin/adquit"
[ -r "$CLI" ] || { echo "doc_contract: cannot read $CLI" >&2; exit 2; }

# The dispatch block is the second `case "${1:-}" in` in the CLI (the first is the
# elevation trigger). Pull the labels, aliases included, and drop the option spellings.
dispatch="$(awk '
    /^case "\$\{1:-\}" in$/ { n++; next }
    n == 2 && /^esac$/     { exit }
    n == 2 && /^[[:space:]]+[^[:space:]].*\)/ {
        line = substr($0, 1, index($0, ")") - 1)   # the label list, not the command
        gsub(/"/, "", line)                        # `""|start)` -> `|start)`
        split(line, parts, "|")
        for (i in parts) {
            part = parts[i]
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", part)
            # 0, 1 or 2 leading dashes, spelled out: mawk has no {n,m} intervals, and CI
            # runs on Debian where `awk` is mawk
            if (part ~ /^[a-z][a-z0-9-]*$/ || part ~ /^--?[a-z][a-z0-9-]*$/) print part
        }
    }' "$CLI" | sort -u)"

# `adquit <verb>` in the usage block, including the "stats | top [n] | rules <domain>"
# shape where several verbs share one line.
usage="$(awk '/^usage\(\) \{/,/^\}/' "$CLI" \
        | grep -oE 'adquit [a-z][a-z0-9-]+( \| [a-z][a-z0-9-]+)*' \
        | sed 's/adquit //' | tr '|' '\n' | awk '{print $1}' | sort -u)"

# `adquit <verb>` inside fenced code blocks in the README - prose is not a command, so
# only what is fenced counts.
readme="$(awk '/^```/ { f = !f; next }
               f {
                   line = $0
                   sub(/#.*$/, "", line)      # a trailing comment is prose, not a command:
                                              # "adquit detects which one you have" is a sentence
                   if (line ~ /^[[:space:]]*(sudo[[:space:]]+)?adquit[[:space:]]+([a-z]|-[a-z]|--[a-z])/) print line
               }' "$REPO/README.md" \
        | sed -E 's/^[[:space:]]*(sudo[[:space:]]+)?adquit[[:space:]]+(-{0,2}[a-z][a-z0-9-]*).*/\2/' \
        | sort -u || true)"

fails=0
for verb in $usage; do
    if ! printf '%s\n' "$dispatch" | grep -qxF -- "$verb"; then
        echo "doc_contract: the usage block shows 'adquit $verb' and the CLI does not dispatch it" >&2
        fails=$((fails + 1))
    fi
done
for verb in $readme; do
    case "$verb" in adquit|bash|sudo) continue ;; esac
    if ! printf '%s\n' "$dispatch" | grep -qxF -- "$verb"; then
        echo "doc_contract: README tells people to run 'adquit $verb' and the CLI does not dispatch it" >&2
        fails=$((fails + 1))
    fi
done

# The reverse direction is deliberately not asserted: plenty of dispatched verbs are
# aliases (unblock-domain, whois, sites) or internals (json, run) that have no business
# in the help text. What must not happen is a documented command that is not real.

# Every config key the engine exposes must be reachable from the CLI too, or the README
# has to say so - `adquit set <key>` covers them all, and that verb is checked above.
if [ "$fails" = "0" ]; then
    printf 'doc_contract: %s documented verbs, all dispatched\n' \
        "$(printf '%s\n%s\n' "$usage" "$readme" | grep -c '[a-z]')"
fi
exit "$fails"
