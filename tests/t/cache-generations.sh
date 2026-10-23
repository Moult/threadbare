# Writes clear cached pages without listing the whole cache (slow when it's big), and clear only the pages they change.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice bob admin
P alice post title=First content=x >/dev/null; P alice post title=Second content=y >/dev/null
for u in / /thread/1 /thread/2; do C -o /dev/null $B$u; done  # guests fill the cache
sql "UPDATE threads SET title = title || ' changed'"           # behind the cache's back
P bob vote post_id=1 vote=1 page=1 >/dev/null
check "a vote clears its thread" "$(C $B/thread/1 | grep -q 'First changed' && echo yes)" yes
check "but not other threads" "$(C $B/thread/2 | grep -q 'Second changed' || echo yes)" yes
check "nor the front page" "$(C $B/ | grep -q 'changed' || echo yes)" yes
P bob thread/2 content=reply >/dev/null
check "a reply clears its thread" "$(C $B/thread/2 | grep -q 'Second changed' && echo yes)" yes
check "and the front page" "$(C $B/ | grep -q 'First changed' && echo yes)" yes
sql "UPDATE threads SET title = 'Again'"
P admin approvals/dismiss-flags/1 >/dev/null
check "an approvals action clears every page" "$(C $B/thread/2 | grep -q Again && echo yes)" yes
if [ -f "$WORK/apcu.json" ]; then
  check "the cache was never listed" "$(cat "$WORK/apcu.json.listed" 2>/dev/null | wc -l)" 0
fi
finish
