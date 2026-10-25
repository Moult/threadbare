# Only a thread's author or an admin can edit it
source "$(dirname "$0")/../lib.sh"; start admin alice mallory
P alice post 'title=Alice thread' 'tags[]=question' 'content=x' >/dev/null
check "other user GET edit form refused" "$(status mallory thread/edit/1)" 403
P mallory thread/edit/1 'title=Hijacked' >/dev/null
check "other user POST edit refused" "$(q 'select title from threads where id=1')" "Alice thread"
P alice thread/edit/1 'title=Alice renamed' >/dev/null
check "owner can still edit" "$(q 'select title from threads where id=1')" "Alice renamed"
P admin thread/edit/1 'title=Admin renamed' >/dev/null
check "admin can still edit" "$(q 'select title from threads where id=1')" "Admin renamed"
finish
