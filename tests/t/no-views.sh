# Reading a thread isn't counted: a guest's view doesn't write to the database, and thread lists show no view count.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post 'title=Tee' 'content=x' >/dev/null
sql "CREATE TABLE thread_writes(n); CREATE TRIGGER count_thread_writes AFTER UPDATE ON threads BEGIN INSERT INTO thread_writes VALUES(1); END"
C -c $(J guest) -o /dev/null $B/                                   # a guest that keeps its session cookie
C -b $(J guest) -c $(J guest) -o /dev/null $B/thread/1
check "a guest reading a thread doesn't write to it" "$(q 'SELECT COUNT(*) FROM thread_writes')" 0
check "the front page shows no view count" "$(C $B/ | grep -c ' views,')" 0
finish
