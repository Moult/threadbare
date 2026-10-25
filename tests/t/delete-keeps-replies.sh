# Deleting a thread or an account keeps other people's replies
source "$(dirname "$0")/../lib.sh"; start alice bob admin
P alice post 'title=Alice 1' 'content=alice op' >/dev/null; P bob thread/1 'content=bob reply' >/dev/null
P alice thread/delete/1 >/dev/null
check "thread owner cannot delete others' replies" "$(q "select count(*) from posts where content='bob reply'")" 1
P alice post 'title=Alice 2' 'content=alice solo' >/dev/null; P alice thread/delete/2 >/dev/null
check "owner can delete a thread with only own posts" "$(q "select count(*) from threads where id=2")" 0
P alice post 'title=Alice 3' 'content=alice op3' >/dev/null; P bob thread/3 'content=bob reply3' >/dev/null
P admin thread/delete/3 >/dev/null
check "admin can still delete any thread" "$(q "select count(*) from posts where thread_id=3")" 0
code=$(mkcode alice profile)
P alice profile/delete/$code confirm=yes >/dev/null
check "alice deleted" "$(q "select count(*) from users where username='alice'")" 0
check "bob's reply survives alice's account deletion" "$(q "select count(*) from posts where content='bob reply'")" 1
check "alice's posts gone" "$(q "select count(*) from posts where content like 'alice%'")" 0
check "thread now belongs to bob" "$(q "select u.username from threads t join users u on u.id=t.user_id where t.id=1")" bob
check "thread page renders" "$(status bob thread/1)" 200
finish
