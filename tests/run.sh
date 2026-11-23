#!/bin/bash
# Black-box tests: each tests/t/*.sh runs against a fresh copy of the forum, served by
# PHP's built-in server and driven with curl. Tests run side by side, each on its own port.
#
#   tests/run.sh              run every test
#   tests/run.sh auth votes   run tests/t/auth.sh and tests/t/votes.sh
#   VERBOSE=1 tests/run.sh    show every check, not just failures
#   JOBS=1 tests/run.sh       run one test at a time (default: one per CPU)
#   PORT=9000 tests/run.sh    use ports from 9000 up (default: from 8099), two per test
#
# Needs php (with pdo_sqlite, curl and fileinfo) and curl. APCu is used when loaded
# (with apc.enable_cli=1), otherwise tests/apcu_stub.php stands in for it.
TESTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=${PORT:-8099}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}
names=${@:-$(ls "$TESTS"/t/*.sh | xargs -n1 basename | sed 's/\.sh$//')}
RESULTS=$(mktemp -d)

# run_test NAME PORT: leaves the test's output and exit status in $RESULTS
run_test() {
    local name=$1 out status
    export WORK=$(mktemp -d) PORT=$2
    out=$(bash "$TESTS/t/$name.sh" 2>&1); status=$?
    [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null
    if grep -q 'PHP Fatal' "$WORK/php-errors.log" 2>/dev/null && ! grep -q 'EXPECT_FATAL' "$TESTS/t/$name.sh"; then
        out+=$'\n  FAIL PHP fatal error:'$'\n'"$(grep -A3 'PHP Fatal' "$WORK/php-errors.log" | head -8)"
        status=1
    fi
    echo "$out" > "$RESULTS/$name.out"; echo $status > "$RESULTS/$name.status"
    rm -rf "$WORK"
}

i=0
for name in $names; do
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
    run_test "$name" $((BASE + 2 * i)) &
    i=$((i + 1))
done
wait

failed=()
for name in $names; do
    if [ "$(cat "$RESULTS/$name.status" 2>/dev/null)" = 0 ]; then
        echo "ok   $name"
        [ -n "$VERBOSE" ] && cat "$RESULTS/$name.out"
    else
        echo "FAIL $name"
        grep -v '^  ok ' "$RESULTS/$name.out" | sed 's/^/     /'
        failed+=("$name")
    fi
done
rm -rf "$RESULTS"
if [ ${#failed[@]} -gt 0 ]; then
    echo "${#failed[@]} failed: ${failed[*]}"
    exit 1
fi
echo "all passed"
