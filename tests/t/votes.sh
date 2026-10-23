# React to someone else's post, take the reaction back, no reacting to your own posts
source "$(dirname "$0")/../lib.sh"; start alice bob
P alice post 'title=Vote on me' 'content=x' >/dev/null
check "no vote form on own post" "$(page alice thread/1 | grep -c 'vote-form')" 0
check "vote form on others' posts" "$(page bob thread/1 | grep -c 'vote-form')" 1
P bob vote post_id=1 vote=1 page=1 >/dev/null
check "reaction shows who reacted" "$(page alice thread/1 | grep -c 'title="bob"')" 1
P alice vote post_id=1 vote=1 page=1 >/dev/null
check "own vote refused" "$(q 'SELECT COUNT(*) FROM votes')" 1
P bob vote post_id=1 vote=1 page=1 >/dev/null
check "voting again removes the vote" "$(q 'SELECT COUNT(*) FROM votes')" 0
finish
