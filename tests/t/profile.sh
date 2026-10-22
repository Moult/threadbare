# Edit a profile with the emailed code, view it, turn notifications off
source "$(dirname "$0")/../lib.sh"; start alice
P alice post 'title=Alice posts here' 'content=x' >/dev/null
check "profile shows latest posts" "$(page alice profile/2 | grep -c 'Alice posts here')" 1
P alice profile/edit email=alice@example.invalid >/dev/null
code=$(lastmail profile/edit)
check "profile code emailed" "$([ -n "$code" ] && echo yes)" yes
check "code opens the edit form" "$(page alice profile/edit/$code | grep -c 'name="bio"')" 1
P alice profile/edit/$code email=alice@example.invalid 'bio=I like *rabbits*' >/dev/null
check "bio saved" "$(q "SELECT bio FROM users WHERE username = 'alice'")" 'I like *rabbits*'
check "bio rendered as markdown" "$(C "$B/profile/2" | grep -c '<em>rabbits</em>')" 1
check "missing profile is 404" "$(status alice profile/999)" 404
finish
