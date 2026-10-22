#!/bin/bash
# Black-box tests: each tests/t/*.sh runs against a fresh copy of the forum, served by
# PHP's built-in server and driven with curl.
#
#   tests/run.sh              run every test
#   tests/run.sh auth votes   run tests/t/auth.sh and tests/t/votes.sh
#   VERBOSE=1 tests/run.sh    show every check, not just failures
#
# Needs php (with pdo_sqlite, curl and fileinfo) and curl. APCu is used when loaded
# (with apc.enable_cli=1), otherwise tests/apcu_stub.php stands in for it.
TESTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export PORT=${PORT:-8099}
names=${@:-$(ls "$TESTS"/t/*.sh | xargs -n1 basename | sed 's/\.sh$//')}
failed=()
for name in $names; do
    export WORK=$(mktemp -d)
    out=$(bash "$TESTS/t/$name.sh" 2>&1); status=$?
    [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null
    if grep -q 'PHP Fatal' "$WORK/php-errors.log" 2>/dev/null && ! grep -q 'EXPECT_FATAL' "$TESTS/t/$name.sh"; then
        out+=$'\n  FAIL PHP fatal error:'$'\n'"$(grep -A3 'PHP Fatal' "$WORK/php-errors.log" | head -8)"
        status=1
    fi
    if [ $status = 0 ]; then
        echo "ok   $name"
        [ -n "$VERBOSE" ] && echo "$out"
    else
        echo "FAIL $name"
        echo "$out" | grep -v '^  ok ' | sed 's/^/     /'
        failed+=("$name")
    fi
    rm -rf "$WORK"
done
if [ ${#failed[@]} -gt 0 ]; then
    echo "${#failed[@]} failed: ${failed[*]}"
    exit 1
fi
echo "all passed"
