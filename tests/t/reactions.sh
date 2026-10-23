# Reactions show who reacted, in order, to everyone; flags are anonymous and only admins see them
source "$(dirname "$0")/../lib.sh"; start admin alice bob mallory
P alice post 'title=React to me' 'content=x' >/dev/null
P mallory vote post_id=1 vote=1 page=1 >/dev/null; P bob vote post_id=1 vote=1 page=1 >/dev/null
html=$(C $B/thread/1)
check "guests see each reactor" "$(echo "$html" | grep -o 'title="\(bob\|mallory\)"' | tr '\n' ' ')" 'title="mallory" title="bob" '
check "reactors link to their profiles" "$(echo "$html" | grep -c 'href="'$B'/profile/4" class="avatar')" 1
check "no vote counts or rabbits" "$(echo "$html" | grep -c ' votes\|🐇')" 0
check "the author sees who reacted" "$(page alice thread/1 | grep -c 'title="bob"')" 1

P bob vote post_id=1 vote=-1 page=1 >/dev/null
check "flagger is no longer listed as reacting" "$(C $B/thread/1 | grep -c 'title="bob"')" 0
check "guests don't see flags" "$(C $B/thread/1 | grep -c 'flagged')" 0
check "members don't see flags" "$(page mallory thread/1 | grep -c 'flagged')" 0
check "admins see the flag count" "$(page admin thread/1 | grep -c '2691; 1 flagged')" 1
check "admin header counts flagged posts" "$(page admin '' | grep -c '>1 flagged<')" 1
a=$(page admin approvals)
check "approvals page lists the flagged post" "$(echo "$a" | grep -c 'post/edit/1"')" 1
check "without saying who flagged it" "$(echo "$a" | grep -c 'bob')" 0
check "members can't dismiss flags" "$(P mallory approvals/dismiss-flags/1)" 403
P admin approvals/dismiss-flags/1 >/dev/null
check "admin dismisses the flags" "$(q 'SELECT COUNT(*) FROM votes WHERE value = -1')" 0
check "reactions stay" "$(q 'SELECT COUNT(*) FROM votes WHERE value = 1')" 1
sql 'DELETE FROM users WHERE username = "mallory"'
check "deleting an account removes its reactions" "$(q 'SELECT COUNT(*) FROM votes')" 0
finish
