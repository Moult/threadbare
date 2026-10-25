# An emailed code only works for the account it was issued to, even if someone else logged in gets hold of it
source "$(dirname "$0")/../lib.sh"; start alice bob
code=$(mkcode alice profile)
check "bob can't open alice's edit form" "$(page bob profile/edit/$code | grep -c 'name="bio"')" 0
P bob profile/edit/$code email=alice@example.invalid bio=stolen >/dev/null
check "bob can't edit alice's bio" "$(q "SELECT COUNT(*) FROM users WHERE username = 'alice' AND bio = 'stolen'")" 0
check "bob can't delete alice" "$(P bob profile/delete/$code confirm=yes)" 403
check "alice still exists" "$(q "SELECT COUNT(*) FROM users WHERE username = 'alice'")" 1
check "alice's code still works for alice" "$(page alice profile/edit/$code | grep -c 'name="bio"')" 1
reset=$(mkcode alice reset)
check "bob can't use alice's reset link" "$(page bob reset/$reset | grep -c 'name="password"')" 0
check "reset link works when not logged in" "$(C "$B/reset/$reset" | grep -c 'name="password"')" 1
check "admin still edits by username" "$(login admin; page admin profile/edit/alice | grep -c 'name="bio"')" 1
finish
