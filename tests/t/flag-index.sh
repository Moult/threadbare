# Counting flagged posts, which admins' pages do on every request, reads an index of flags rather than every vote.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start
plan=$(php -r '$db = new PDO("sqlite:" . $argv[1]); foreach ($db->query("EXPLAIN QUERY PLAN SELECT COUNT(DISTINCT post_id) FROM votes WHERE value = -1") as $r) echo $r["detail"];' "$DB")
check "flag count uses the flags index" "$(echo "$plan" | grep -c 'INDEX votes_flags')" 1
check "migration adds it" "$(grep -c 'votes_flags' "$ROOT/migrations/performance-indexes.sql")" 1
finish
