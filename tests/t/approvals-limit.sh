# The approvals page lists at most 100 held and 100 flagged posts, so a wave of spam can't make it too big to use.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start admin alice
P alice post title=Hello content=x >/dev/null
sql "INSERT INTO users(username, password, email, is_verified) VALUES('spammer', 'x', 'spammer@example.invalid', 1);
  WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 150)
  INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated, is_approved) SELECT 1, 5, 'held ' || i, i, i, 0 FROM n;
  WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 150)
  INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) SELECT 1, 2, 'flagged ' || i, i, i FROM n;
  INSERT INTO votes(user_id, post_id, value) SELECT 3, id, -1 FROM posts WHERE content LIKE 'flagged %'"
page admin approvals > "$WORK/approvals.html"
check "at most 100 held posts" "$(grep -c 'approvals/reject-post/' "$WORK/approvals.html")" 100
check "says there are more held" "$(grep -c 'first 100 of 150 posts' "$WORK/approvals.html")" 1
check "at most 100 flagged posts" "$(grep -c 'approvals/dismiss-flags/' "$WORK/approvals.html")" 100
check "says there are more flagged" "$(grep -c '100 most flagged of 150 posts' "$WORK/approvals.html")" 1
finish
