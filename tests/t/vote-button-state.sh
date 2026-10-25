# Your current vote is shown as pressed and can still be taken back
source "$(dirname "$0")/../lib.sh"; start alice mallory
P alice post 'title=Tee' 'content=x' >/dev/null; P mallory vote post_id=1 vote=1 page=1 >/dev/null
html=$(C -b $(J mallory) $B/thread/1 | grep 'name="vote"')
check "upvote button marked active" "$(echo "$html" | grep 'value="1"' | grep -c 'aria-pressed="true"')" 1
check "downvote button not active" "$(echo "$html" | grep 'value="-1"' | grep -c 'aria-pressed="true"')" 0
P mallory vote post_id=1 vote=1 page=1 >/dev/null
check "clicking again still removes the vote" "$(q 'select count(*) from votes')" 0
finish
