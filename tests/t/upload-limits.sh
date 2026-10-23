# Users awaiting approval can't upload files, and other users can upload 20 a day.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice admin
php -r '$db = new PDO("sqlite:" . $argv[1]);
  $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute(["newbie", password_hash("pw-newbie-long", PASSWORD_DEFAULT), "newbie@example.invalid"]);' "$DB"
login newbie
echo hello > "$WORK/a.txt"
up() { unlimit; local t=$(csrf $1 upload); C -b "$(J $1)" -c "$(J $1)" -o /dev/null -w '%{http_code}' -F csrf=$t -F attachment=@"$WORK/a.txt" "$B/upload"; }
check "a user awaiting approval can't upload" "$(up newbie)" 403
check "nor is anything saved" "$(q 'select count(*) from uploads')" 0
sql "UPDATE users SET is_approved = 1 WHERE username = 'newbie'"
check "once approved they can" "$(up newbie)" 200
for i in $(seq 19); do up alice >/dev/null; done
check "uploads saved" "$(q "select count(*) from uploads where user_id = (select id from users where username = 'alice')")" 19
up alice >/dev/null
check "the 21st in a day is refused" "$(up alice)" 429
sql "UPDATE uploads SET ts_created = ts_created - 86400"
check "and allowed the next day" "$(up alice)" 200
for i in $(seq 21); do up admin >/dev/null; done
check "admins have no daily limit" "$(up admin)" 200
finish
