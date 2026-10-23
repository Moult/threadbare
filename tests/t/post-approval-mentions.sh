# Mention suggestions leave out accounts awaiting approval
# Runs with the suite from the CI pull request (tests/run.sh)
source "$(dirname "$0")/../lib.sh"; start admin alice
# spammer (id 5): verified, but not yet approved and not trusted
php -r '$db = new PDO("sqlite:" . $argv[1]);
  $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute(["spammer", password_hash("pw-spammer-long", PASSWORD_DEFAULT), "spammer@example.invalid"]);' "$DB"
login spammer

P alice post 'title=Alice thread' 'content=alice op' >/dev/null  # thread 1
P spammer thread/1 'content=spam reply' >/dev/null               # held
check "held account isn't suggested" "$(page alice mention/@s)" '[]'
check "nor in a thread it posted in" "$(page alice mention/1/@s)" '[]'
check "other people still are" "$(page alice mention/@a)" '["admin","alice"]'
P admin approvals/approve/5 >/dev/null
check "once approved, it is" "$(page alice mention/@s)" '["spammer"]'
finish
