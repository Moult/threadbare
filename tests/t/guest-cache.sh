# Votes reach cached guest pages, and cached guest views are counted
source "$(dirname "$0")/../lib.sh"; start alice mallory
P alice post 'title=Tee' 'content=x' >/dev/null
C -c $(J gA) -o /dev/null $B/thread/1      # guest fills cache
P mallory vote post_id=1 vote=1 page=1 >/dev/null
check "new guest sees the vote" "$(C -c $(J gB) $B/thread/1 | grep -c '+1  votes')" 1
before=$(q 'select views from threads where id=1')
C -c $(J gC) -o /dev/null $B/thread/1; C -c $(J gD) -o /dev/null $B/thread/1
check "cached guest views counted" "$(q 'select views from threads where id=1')" $((before+2))
C -b $(J gC) -o /dev/null $B/thread/1
check "same guest not double-counted" "$(q 'select views from threads where id=1')" $((before+2))
finish
