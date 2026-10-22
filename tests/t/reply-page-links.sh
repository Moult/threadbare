# A reply that starts a new page shows up in the page links of a guest's cached earlier pages
source "$(dirname "$0")/../lib.sh"; start alice bob
P alice post 'title=Long thread' 'content=op' >/dev/null
for i in $(seq 2 25); do sql "INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) VALUES(1, 2, 'post $i', 0, 0)"; done
C -o /dev/null "$B/thread/1"  # a guest caches page 1: 25 posts, no page links yet
P bob thread/1 'content=post 26' >/dev/null
check "guest's page 1 links to the new page 2" "$(C "$B/thread/1" | grep -c 'thread/1/p2')" 1
finish
