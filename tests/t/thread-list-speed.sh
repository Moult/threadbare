# Lists of threads stay quick on a big forum: they don't count every post before picking a page of threads.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
sql "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000)
  INSERT INTO threads(title, user_id, ts_created, ts_updated, tags) SELECT 'Thread ' || i, 2, i, i, 'question' FROM n;
  WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10)
  INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) SELECT t.id, 2, 'x', 1, 1 FROM threads AS t, n"
# ms PATH: the quickest of three loads of PATH as alice (members aren't served from the cache), in milliseconds
ms() { for i in 1 2 3; do C -b "$(J alice)" -o /dev/null -w '%{time_total}\n' "$B/$1"; done | sort -n | head -1 | awk '{ printf "%d", $1 * 1000 }'; }
base=$(ms notifications)
check "front page lists the newest thread" "$(page alice '' | grep -c 'Thread 5000')" 1
check "front page within 50ms of a page with no list" "$(( $(ms '') - base < 50 ))" 1
check "tag page within 50ms of a page with no list" "$(( $(ms tag/question) - base < 50 ))" 1
check "last page within 50ms of a page with no list" "$(( $(ms p200) - base < 50 ))" 1
check "reply counts" "$(page alice '' | grep -c '<strong>9</strong> replies')" 25
finish
