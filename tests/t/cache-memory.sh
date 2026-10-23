# Cached pages stop being added while APCu is three quarters full, so they can't make it empty itself and lose the
# rate limits. Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"
export APCU_STUB_SHM=100000  # the stand-in for APCu reports this much memory, of which its file uses some
start
sql "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100)
  INSERT INTO threads(title, user_id, ts_created, ts_updated) SELECT 'Thread ' || i, 2, i, i FROM n;
  INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) SELECT id, 2, 'x', 1, 1 FROM threads"
for i in $(seq 100); do C -o /dev/null $B/thread/$i; done
if [ -f "$WORK/apcu.json" ]; then
  check "cache stays under three quarters full" "$(( $(stat -c %s "$WORK/apcu.json") < 80000 ))" 1
  check "but has pages in it" "$(grep -c 'html_thread' "$WORK/apcu.json")" 1
fi
t=$(csrf g login)
for i in 1 2 3 4 5; do C -b "$(J g)" -o /dev/null --data-urlencode "csrf=$t" -d username=alice -d password=wrong-password $B/login; done
check "rate limits still work" "$(C -b "$(J g)" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$t" -d username=alice -d password=wrong-password $B/login)" 429
finish
