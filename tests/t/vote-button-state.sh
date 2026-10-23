# Your current reaction or flag is shown as pressed and can still be taken back
source "$(dirname "$0")/../lib.sh"; start alice mallory
P alice post 'title=Tee' 'content=x' >/dev/null
P mallory vote post_id=1 vote=1 page=1 >/dev/null
html=$(page mallory thread/1 | grep 'name="vote"')
check "reaction button marked pressed" "$(echo "$html" | grep 'value="1"' | grep -c 'aria-pressed="true"')" 1
check "flag button not pressed" "$(echo "$html" | grep 'value="-1"' | grep -c 'aria-pressed="true"')" 0
P mallory vote post_id=1 vote=-1 page=1 >/dev/null
html=$(page mallory thread/1 | grep 'name="vote"')
check "flagging replaces the reaction" "$(echo "$html" | grep 'value="-1"' | grep -c 'aria-pressed="true"')" 1
P mallory vote post_id=1 vote=-1 page=1 >/dev/null
check "clicking again still removes the vote" "$(q 'select count(*) from votes')" 0
finish
