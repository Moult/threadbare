# Replying to a thread that doesn't exist is a 404, not a 500
source "$(dirname "$0")/../lib.sh"; start alice
check "reply to missing thread -> 404" "$(P alice thread/999 'content=hello')" 404
check "no post stored" "$(q 'select count(*) from posts')" 0
check "no exception logged" "$(grep -c 'FOREIGN KEY constraint failed' $WORK/php-errors.log)" 0
P alice post 'title=Real thread' 'content=x' >/dev/null
check "reply to real thread still works" "$(P alice thread/1 'content=reply')" 303
check "with page suffix too" "$(P alice thread/999/p2 'content=hello')" 404
finish
