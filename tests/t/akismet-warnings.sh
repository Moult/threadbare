# Posts by untrusted users, which are checked with Akismet, log no PHP warnings, even without a Referer
source "$(dirname "$0")/../lib.sh"; start
php -r '$db = new PDO("sqlite:" . $argv[1]);
    $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute(["carol", password_hash("pw-carol-long", PASSWORD_DEFAULT), "carol@example.invalid"]);' "$DB"
login carol
check "untrusted user posts a thread" "$(P carol post 'title=Hello there' 'content=hello')" 303
check "no PHP warning" "$(grep -c 'PHP Warning' "$WORK/php-errors.log")" 0
finish
