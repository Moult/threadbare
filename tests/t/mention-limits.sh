# A post emails at most 20 people it mentions, and an email to over 1000 people goes in batches SendGrid accepts.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
sql "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1100)
  INSERT INTO users(username, password, email, is_verified, is_approved) SELECT 'user' || i, 'x', 'user' || i || '@example.invalid', 1, 1 FROM n"
P alice post title=Hello "content=$(for i in $(seq 30); do echo -n "@user$i @USER$i "; done)" >/dev/null
check "20 people mentioned are emailed" "$(tail -1 "$WORK/mail.log" | grep -o '@example.invalid' | wc -l)" 20
check "the first 20" "$(tail -1 "$WORK/mail.log" | grep -c 'user20@' ; tail -1 "$WORK/mail.log" | grep -c 'user21@')" "1
0"
plan=$(php -r '$db = new PDO("sqlite:" . $argv[1]); foreach ($db->query("EXPLAIN QUERY PLAN SELECT email FROM users WHERE LOWER(username) = LOWER(\"x\")") as $r) echo $r["detail"];' "$DB")
check "mention lookups use an index" "$(echo "$plan" | grep -c 'INDEX users_username_lower')" 1
sql "INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) SELECT 1, id, 'me too', 1, 1 FROM users WHERE username LIKE 'user%'"
: > "$WORK/mail.log"
P alice thread/1 content=update >/dev/null
check "1100 people in the thread are emailed in two messages" "$(wc -l < "$WORK/mail.log")" 2
check "all of them" "$(grep -o '@example.invalid' "$WORK/mail.log" | wc -l)" 1100
finish
