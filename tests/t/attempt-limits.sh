# Failed replies and edits count towards rate limits (each is checked with Akismet), and votes, notification toggles
# and mention lookups are rate limited too. Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice bob
P alice post title=Hello content=x >/dev/null
# n TIMES PATH [name=value ...]: POST as bob TIMES times, printing the last status
n() { local times=$1 path=$2; shift 2; unlimit; local a=() s; for kv in "$@"; do a+=(--data-urlencode "$kv"); done
  for i in $(seq $times); do local t=$(csrf bob login); s=$(C -b "$(J bob)" -c "$(J bob)" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$t" "${a[@]}" "$B/$path"); done; echo $s; }
check "a failed reply is a 400" "$(n 1 thread/1 content=)" 400
check "failed replies are limited" "$(n 6 thread/1 content=)" 429
P bob thread/1 content=mine >/dev/null
check "failed post edits are limited" "$(n 6 post/edit/2 content=)" 429
P bob post title=Bobs content=y >/dev/null
check "failed thread edits are limited" "$(n 6 thread/edit/2 title=x)" 429
check "votes are limited" "$(n 31 vote post_id=1 vote=1 page=1)" 429
check "notification toggles are limited" "$(n 11 notifications)" 429
unlimit; for i in $(seq 60); do C -b "$(J bob)" -o /dev/null "$B/mention/@ali"; done
check "mention lookups are limited" "$(status bob mention/@ali)" 429
finish
