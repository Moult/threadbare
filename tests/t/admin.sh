# Admins can edit and delete anything and move posts between threads
source "$(dirname "$0")/../lib.sh"; start admin alice bob
P alice post 'title=Alice thread' 'content=alice op' >/dev/null
P bob thread/1 'content=bob reply' >/dev/null
check "admin edits someone's post" "$(P admin post/edit/1 'content=edited by admin')" 303
check "edit saved" "$(q 'SELECT content FROM posts WHERE id = 1')" 'edited by admin'
P admin post/move/2 thread_id=0 >/dev/null
check "move into a new thread" "$(q 'SELECT COUNT(*) FROM threads')" 2
check "moved post's thread belongs to its author" "$(q "SELECT u.username FROM posts p JOIN threads t ON t.id = p.thread_id JOIN users u ON u.id = t.user_id WHERE p.id = 2")" bob
check "non-admin cannot move" "$(P alice post/move/1 thread_id=0)" 303
P admin thread/delete/1 >/dev/null
check "admin deletes a thread" "$(q 'SELECT COUNT(*) FROM threads WHERE id = 1')" 0
finish
