# Helpers sourced by every test. run.sh sets WORK (a fresh temp dir) and PORT.
TESTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(dirname "$TESTS")
APP=$WORK/app; DB=$APP/threadbare.db; B=http://127.0.0.1:$PORT
FAILS=0

# Copy the forum into $APP, stub out email and hCaptcha, create the database with
# users admin, alice, bob and mallory (password "pw-<name>-long"), and start the server.
# alice, bob and mallory are trusted users, so posts skip the Akismet check.
start() {
    mkdir -p "$APP/uploads" "$WORK/sessions"
    : > "$WORK/php-errors.log"   # PHP only creates it on the first error; tests grep it
    cp -rf "$ROOT"/app.php "$ROOT"/Parsedown.php "$ROOT"/db.sql "$ROOT"/templates "$ROOT"/www "$APP"/
    php "$TESTS/stub.php" "$APP/app.php" "$WORK/mail.log" || exit 1
    cat > "$APP/config.php" <<EOF
<?php
return [
    'baseurl' => '$B/', 'websiteTitle' => 'Test Forum', 'tags' => ['question', 'showcase', 'intro', 'introduction'],
    'blurb' => 'Test', 'iqQuestion' => 'Colour?', 'iqAnswer' => 'black', 'emailFrom' => 'noreply@example.invalid',
    'maxUploadMb' => 5, 'salt' => 'test salt', 'cspUrls' => '', 'sessionSavePath' => '$WORK/sessions',
    'akismetKey' => '', 'sendGridKey' => '', 'hCaptchaSiteKey' => '', 'hCaptchaSecretKey' => '',
    'adminUsernames' => ['admin'], 'trustedUsernames' => ['alice', 'bob', 'mallory'],
];
EOF
    php -r '$db = new PDO("sqlite:" . $argv[1]); $db->exec(file_get_contents($argv[2]));
        foreach (["admin", "alice", "bob", "mallory"] as $u) {
            $s = $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)");
            $s->execute([$u, password_hash("pw-$u-long", PASSWORD_DEFAULT), "$u@example.invalid"]);
        }' "$DB" "$APP/db.sql"
    # No opcache: a test may change app.php while the server runs, and opcache can keep serving the old copy
    (cd "$APP/www" || exit 1; APCU_STUB_FILE="$WORK/apcu.json" setsid php -d opcache.enable=0 -d display_errors=0 -d log_errors=1 \
        -d error_log="$WORK/php-errors.log" -S 127.0.0.1:$PORT -t "$APP/www" "$TESTS/router.php" \
        > "$WORK/server.log" 2>&1 < /dev/null & echo $! > "$WORK/server.pid")
    for i in $(seq 50); do curl -s --noproxy '*' -o /dev/null "$B/tags" && break; sleep 0.1; done
    for u in "$@"; do login "$u"; done
}

C() { curl -s --noproxy '*' "$@"; }
J() { echo "$WORK/$1.cookies"; }
# csrf USER PATH: fetch PATH as USER and print the last CSRF token on the page
csrf() { C -b "$(J $1)" -c "$(J $1)" "$B/$2" | grep -o 'name="csrf" value="[0-9a-f]*"' | tail -1 | sed 's/.*value="//;s/"//'; }
# The forum rate-limits by IP and every test request comes from 127.0.0.1
unlimit() { C -o /dev/null "$B/__test/clear-rate-limits"; }
login() { unlimit; rm -f "$(J $1)"; local t=$(csrf $1 login); C -b "$(J $1)" -c "$(J $1)" -o /dev/null --data-urlencode "csrf=$t" --data-urlencode "username=$1" --data-urlencode "password=${2:-pw-$1-long}" "$B/login"; }
# P USER PATH [name=value ...]: POST a form as USER (CSRF token taken from /login), print the status
P() { local u=$1 p=$2; shift 2; unlimit; local t=$(csrf $u login) a=(); for kv in "$@"; do a+=(--data-urlencode "$kv"); done; C -b "$(J $u)" -c "$(J $u)" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$t" "${a[@]}" "$B/$p"; }
status() { C -b "$(J $1)" -o /dev/null -w '%{http_code}' "$B/$2"; }
page() { C -b "$(J $1)" "$B/$2"; }
q() { php -r '$db = new PDO("sqlite:" . $argv[1]); echo $db->query($argv[2])->fetchColumn();' "$DB" "$1"; }
sql() { php -r '$db = new PDO("sqlite:" . $argv[1]); $db->exec("PRAGMA foreign_keys = ON"); $db->exec($argv[2]);' "$DB" "$1"; }
# lastmail PATH: the code from the most recent emailed link to PATH/<code>
lastmail() { tail -1 "$WORK/mail.log" 2>/dev/null | grep -o "$1/[0-9a-f]*" | tail -1 | sed "s#$1/##"; }
# mkcode USER PURPOSE: insert a verification code directly, filling purpose and age when the schema has them
mkcode() { php -r '$db = new PDO("sqlite:" . $argv[1]); $cols = array_column($db->query("PRAGMA table_info(verifications)")->fetchAll(), "name");
    $c = bin2hex(random_bytes(8)); $uid = $db->query("SELECT id FROM users WHERE username = " . $db->quote($argv[2]))->fetchColumn();
    if (in_array("purpose", $cols)) $db->prepare("INSERT INTO verifications(code, user_id, purpose, ts_created) VALUES(?, ?, ?, ?)")->execute([$c, $uid, $argv[3], time()]);
    else $db->prepare("INSERT INTO verifications(code, user_id) VALUES(?, ?)")->execute([$c, $uid]);
    echo $c;' "$DB" "$1" "$2"; }

check() { if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1 (got '$2', want '$3')"; FAILS=$((FAILS + 1)); fi; }
finish() { exit $FAILS; }
