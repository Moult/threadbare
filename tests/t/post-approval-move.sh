# A post can't be moved into a held thread, which would publish the thread without its held first post
# Runs with the suite from the CI pull request (tests/run.sh)
source "$(dirname "$0")/../lib.sh"; start admin alice
# newbie (id 5): verified, but not yet approved and not trusted
php -r '$db = new PDO("sqlite:" . $argv[1]);
  $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute(["newbie", password_hash("pw-newbie-long", PASSWORD_DEFAULT), "newbie@example.invalid"]);' "$DB"
login newbie

P alice post 'title=Alice thread' 'content=alice op' >/dev/null      # thread 1, post 1
P alice thread/1 'content=alice reply' >/dev/null                    # post 2
P newbie post 'title=Newbie thread' 'content=newbie op' >/dev/null   # thread 2, post 3, held
check "moving into a held thread is refused" "$(P admin post/move/2 thread_id=2)" 400
check "the post stays put" "$(q 'SELECT thread_id FROM posts WHERE id = 2')" 1
check "held thread is still hidden" "$(C -o /dev/null -w '%{http_code}' "$B/thread/2")" 404
check "moving into a new thread still works" "$(P admin post/move/2 thread_id=0)" 303
check "the post is in the new thread" "$(q 'SELECT thread_id FROM posts WHERE id = 2')" 3
finish
