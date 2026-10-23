# An admin who deletes someone else's account stays logged in; deleting your own logs you out
source "$(dirname "$0")/../lib.sh"; start admin alice bob
P admin profile/delete/alice confirm=yes >/dev/null
check "admin deletes alice" "$(q "SELECT COUNT(*) FROM users WHERE username = 'alice'")" 0
check "admin is still logged in" "$(page admin '' | grep -c "G'day there")" 1
P bob profile/delete/$(mkcode bob profile) confirm=yes >/dev/null
check "bob deletes his own account" "$(q "SELECT COUNT(*) FROM users WHERE username = 'bob'")" 0
check "bob is logged out" "$(page bob '' | grep -c "G'day there")" 0
finish
