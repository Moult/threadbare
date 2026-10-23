# The database is in WAL mode, so pages can be read while another connection is writing.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello content=x >/dev/null
check "journal mode" "$(q 'PRAGMA journal_mode')" wal
php -r '$db = new PDO("sqlite:" . $argv[1]); $db->exec("BEGIN EXCLUSIVE"); $db->exec("UPDATE threads SET views = views + 1"); sleep(8); $db->exec("COMMIT");' "$DB" &
sleep 1
check "a page reads while a write is in progress" "$(C -m 4 -b "$(J alice)" -o /dev/null -w '%{http_code}' $B/)" 200
wait
finish
