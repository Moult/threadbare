# Every form POST needs a valid CSRF token
source "$(dirname "$0")/../lib.sh"; start alice
post() { C -b "$(J alice)" -o /dev/null -w '%{http_code}' "$@"; }
check "new thread without token" "$(post -d title=Hello -d content=x "$B/post")" 403
check "new thread with a bad token" "$(post -d csrf=0123 -d title=Hello -d content=x "$B/post")" 403
check "logout without token" "$(post -X POST "$B/logout")" 403
check "nothing was posted" "$(q 'SELECT COUNT(*) FROM threads')" 0
check "still logged in" "$(status alice post)" 200
finish
