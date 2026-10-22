# A thread with a net-downvoted post still renders
source "$(dirname "$0")/../lib.sh"; start alice mallory
P alice post 'title=Tee' 'content=x' >/dev/null; P mallory vote post_id=1 vote=-1 page=1 >/dev/null
check "downvote recorded" "$(q 'select value from votes')" "-1"
check "thread renders after net-negative votes" "$(status alice thread/1)" 200
check "shows the downvote" "$(C -b $(J alice) $B/thread/1 | grep -c -- '-1 votes')" 1
finish
