# The database is in WAL mode, so pages can be read while another connection is writing.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello content=x >/dev/null
check "journal mode" "$(q 'PRAGMA journal_mode')" wal
php -r '$db = new PDO("sqlite:" . $argv[1]); $db->exec("BEGIN EXCLUSIVE"); $db->exec("UPDATE threads SET title = title"); echo "locked"; sleep(5); $db->exec("COMMIT");' "$DB" > "$WORK/lock" &
for i in $(seq 100); do [ -s "$WORK/lock" ] && break; sleep 0.02; done
check "a page reads while a write is in progress" "$(C -m 1 -b "$(J alice)" -o /dev/null -w '%{http_code}' $B/)" 200
kill $! 2>/dev/null
finish
