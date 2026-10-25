# Reactions reach cached guest pages
source "$(dirname "$0")/../lib.sh"; start alice mallory
P alice post 'title=Tee' 'content=x' >/dev/null
C -c $(J gA) -o /dev/null $B/thread/1      # guest fills cache
P mallory vote post_id=1 vote=1 page=1 >/dev/null
check "new guest sees the reaction" "$(C -c $(J gB) $B/thread/1 | grep -c 'title="mallory"')" 1
finish
