# Your own profile shows the Edit profile link
source "$(dirname "$0")/../lib.sh"; start bob
check "own profile shows edit link" "$(C -b $(J bob) $B/profile/3 | grep -c 'Edit profile')" 1
check "others' profile does not" "$(C -b $(J bob) $B/profile/2 | grep -c 'Edit profile')" 0
finish
