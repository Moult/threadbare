# Start a thread, reply, edit and delete posts, browse by tag, guests can read
source "$(dirname "$0")/../lib.sh"; start alice bob
check "new thread redirects to it" "$(P alice post 'title=First thread' 'tags[]=question' 'content=Hello **world**')" 303
check "thread page renders" "$(status alice thread/1)" 200
check "markdown rendered" "$(page alice thread/1 | grep -c '<strong>world</strong>')" 1
check "listed on the front page" "$(page alice '' | grep -c 'First thread')" 1
check "guest can read the thread" "$(C -o /dev/null -w '%{http_code}' "$B/thread/1")" 200
check "listed under its tag" "$(C "$B/tag/question" | grep -c 'First thread')" 1
check "unknown tag is 404" "$(C -o /dev/null -w '%{http_code}' "$B/tag/nope")" 404
check "reply redirects to the post" "$(P bob thread/1 'content=A reply from bob')" 303
check "reply shown" "$(page alice thread/1 | grep -c 'A reply from bob')" 1
check "reply mails the thread starter" "$(tail -1 "$WORK/mail.log" | grep -c 'alice@example.invalid')" 1
check "author edits own post" "$(P bob post/edit/2 'content=Edited by bob')" 303
check "edit shown" "$(page alice thread/1 | grep -c 'Edited by bob')" 1
check "others cannot edit it" "$(status alice post/edit/2)" 404
P alice post/delete/2 >/dev/null
check "others cannot delete it" "$(q 'SELECT COUNT(*) FROM posts WHERE id = 2')" 1
P bob post/delete/2 >/dev/null
check "author deletes own post" "$(q 'SELECT COUNT(*) FROM posts WHERE id = 2')" 0
check "guest cannot post" "$(C -o /dev/null -w '%{http_code}' -X POST "$B/post")" 303
check "missing thread is 404" "$(status alice thread/999)" 404
finish
