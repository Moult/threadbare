# Posts by new users are held, seen only by their author and admins, until an admin approves the user
source "$(dirname "$0")/../lib.sh"; start admin alice
# newbie (id 5) and spammer (id 6): verified, but not yet approved and not trusted
for u in newbie spammer; do
  php -r '$db = new PDO("sqlite:" . $argv[1]);
    $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute([$argv[2], password_hash("pw-$argv[2]-long", PASSWORD_DEFAULT), "$argv[2]@example.invalid"]);' "$DB" $u
  login $u
done
mails() { cat "$WORK/mail.log" 2>/dev/null | wc -l; }
guest() { C "$B/$1"; }
P alice post 'title=Alice thread' 'content=alice op' >/dev/null  # thread 1, post 1
m0=$(mails)

check "new user can post a thread" "$(P newbie post 'title=Newbie thread' 'content=newbie op')" 303  # thread 2
check "new user can reply" "$(P newbie thread/1 'content=newbie reply @alice')" 303
check "both posts are held" "$(q 'SELECT COUNT(*) FROM posts WHERE is_approved = 0')" 2
check "guests can't see the held thread" "$(C -o /dev/null -w '%{http_code}' "$B/thread/2")" 404
check "other users can't see the held thread" "$(status alice thread/2)" 404
check "others can't reply to the held thread" "$(P alice thread/2 'content=hello')" 404
check "author sees their held thread, marked" "$(page newbie thread/2 | grep -c 'Awaiting approval')" 1
check "admin sees the held thread" "$(status admin thread/2)" 200
check "held thread isn't listed" "$(guest '' | grep -c 'Newbie thread')" 0
check "held reply hidden from guests" "$(guest thread/1 | grep -c 'newbie reply')" 0
check "held reply hidden from other users" "$(page alice thread/1 | grep -c 'newbie reply')" 0
check "author sees their held reply" "$(page newbie thread/1 | grep -c 'newbie reply')" 1
check "held reply isn't counted" "$(guest '' | grep -o '<strong>[0-9-]*</strong> replies' | head -1)" '<strong>0</strong> replies'
check "held reply doesn't bump the thread" "$(q 'SELECT last_user_id FROM threads WHERE id = 1')" 2
P alice vote post_id=3 vote=1 page=1 >/dev/null
check "held post can't be voted on" "$(q 'SELECT COUNT(*) FROM votes')" 0
check "only one email: admins, about the first held post" "$(mails)" $((m0 + 1))
check "admin email names the user" "$(tail -1 "$WORK/mail.log" | grep -c 'admin@example.invalid.*newbie is awaiting approval')" 1
check "admins see the count" "$(page admin '' | grep -c '2 awaiting approval')" 1
check "approvals page lists held posts" "$(page admin approvals | grep -c 'newbie reply')" 1
check "non-admins can't open approvals" "$(status alice approvals)" 403
check "non-admins can't approve" "$(P alice approvals/approve/5)" 403

P admin approvals/approve/5 >/dev/null
check "user is approved" "$(q 'SELECT is_approved FROM users WHERE id = 5')" 1
check "held reply is published" "$(guest thread/1 | grep -c 'newbie reply')" 1
check "held thread is published" "$(guest '' | grep -c 'Newbie thread')" 1
check "published reply bumps the thread" "$(q 'SELECT last_user_id FROM threads WHERE id = 1')" 5
check "alice is notified of the published reply" "$(grep 'newbie commented on Alice thread' "$WORK/mail.log" | grep -c 'alice@example.invalid')" 1
P newbie thread/1 'content=second reply' >/dev/null
check "approved user's posts appear straight away" "$(guest thread/1 | grep -c 'second reply')" 1
check "admins see no count" "$(page admin '' | grep -c 'awaiting approval')" 0

P spammer post 'title=Buy stuff' 'content=spam op' >/dev/null
P spammer thread/1 'content=spam reply' >/dev/null
P admin approvals/reject-post/$(q "SELECT id FROM posts WHERE content = 'spam reply'") >/dev/null
check "rejected post is deleted" "$(q "SELECT COUNT(*) FROM posts WHERE content = 'spam reply'")" 0
check "rejecting a post doesn't approve its author" "$(q 'SELECT is_approved FROM users WHERE id = 6')" 0
P admin approvals/delete-user/6 >/dev/null
check "spam account is deleted" "$(q 'SELECT COUNT(*) FROM users WHERE id = 6')" 0
check "with its held thread" "$(q "SELECT COUNT(*) FROM threads WHERE title = 'Buy stuff'")" 0
P admin approvals/delete-user/5 >/dev/null
check "approved accounts can't be deleted from the queue" "$(q 'SELECT COUNT(*) FROM users WHERE id = 5')" 1
check "approvals page is empty" "$(page admin approvals | grep -c 'Nothing is awaiting approval')" 1
finish
