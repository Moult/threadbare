# A down vote is an anonymous flag: recorded, and the thread still renders
source "$(dirname "$0")/../lib.sh"; start alice mallory
P alice post 'title=Tee' 'content=x' >/dev/null; P mallory vote post_id=1 vote=-1 page=1 >/dev/null
check "flag recorded" "$(q 'select value from votes')" "-1"
check "thread renders after a flag" "$(status alice thread/1)" 200
check "the author isn't told" "$(page alice thread/1 | grep -c 'flagged\|title="mallory"')" 0
finish
