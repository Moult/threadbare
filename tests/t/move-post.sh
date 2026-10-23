# Moving a post leaves no empty thread behind, and guests see it in its new thread
source "$(dirname "$0")/../lib.sh"; start admin alice bob
P alice post 'title=Only post' 'content=op' >/dev/null
P admin post/move/1 thread_id=0 >/dev/null
check "moved into a new thread" "$(q 'SELECT thread_id FROM posts WHERE id = 1')" 2
check "old thread is deleted once empty" "$(q 'SELECT COUNT(*) FROM threads WHERE id = 1')" 0
P bob post 'title=Bob thread' 'content=bob op' >/dev/null
P alice thread/2 'content=moving reply' >/dev/null
C -o /dev/null "$B/thread/3"  # a guest caches the target thread
P admin post/move/3 thread_id=3 >/dev/null
check "thread that still has posts is kept" "$(q 'SELECT COUNT(*) FROM threads WHERE id = 2')" 1
check "guest sees the post in its new thread" "$(C "$B/thread/3" | grep -c 'moving reply')" 1
finish
