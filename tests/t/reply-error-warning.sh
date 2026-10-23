# A rejected reply shows the thread with the error and logs no PHP warning
source "$(dirname "$0")/../lib.sh"; start alice
P alice post 'title=Hello there' 'content=op' >/dev/null
check "empty reply is rejected" "$(P alice thread/1 'content=')" 400
check "no PHP warning logged" "$(grep -c 'PHP Warning' "$WORK/php-errors.log")" 0
finish
