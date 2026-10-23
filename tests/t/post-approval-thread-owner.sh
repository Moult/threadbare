# A thread whose first post goes passes to the first approved poster, not to a held one
# Runs with the suite from the CI pull request (tests/run.sh)
source "$(dirname "$0")/../lib.sh"; start admin alice bob
# newbie (id 5): verified, but not yet approved and not trusted
php -r '$db = new PDO("sqlite:" . $argv[1]);
  $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute(["newbie", password_hash("pw-newbie-long", PASSWORD_DEFAULT), "newbie@example.invalid"]);' "$DB"
login newbie

P alice post 'title=Alice thread' 'content=alice op' >/dev/null  # thread 1, post 1
P newbie thread/1 'content=newbie reply' >/dev/null              # post 2, held
P bob thread/1 'content=bob reply' >/dev/null                    # post 3
P alice post/delete/1 >/dev/null
check "thread passes to bob" "$(q 'SELECT user_id FROM threads WHERE id = 1')" 3
check "held author can't rename the thread" "$(P newbie thread/edit/1 'title=Buy stuff')" 403
check "title is unchanged" "$(q 'SELECT title FROM threads WHERE id = 1')" 'Alice thread'
finish
