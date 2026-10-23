# The post approval migration approves users who have posted, and leaves those who haven't to be approved
source "$(dirname "$0")/../lib.sh"
OLD=$WORK/old.db
sed '/is_approved/d' "$ROOT/db.sql" > "$WORK/old.sql"  # the schema before the change
php -r '$db = new PDO("sqlite:" . $argv[1]); $db->exec(file_get_contents($argv[2]));
    $db->exec("INSERT INTO users(username, password, email, is_verified) VALUES(\"poster\", \"x\", \"poster@example.invalid\", 1), (\"lurker\", \"x\", \"lurker@example.invalid\", 1)");
    $db->exec("INSERT INTO threads(title, user_id, ts_created, ts_updated) VALUES(\"Old thread\", 1, 0, 0)");
    $db->exec("INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) VALUES(1, 1, \"old post\", 0, 0)");
    $db->exec(file_get_contents($argv[3]));' "$OLD" "$WORK/old.sql" "$ROOT/migrations/post-approval.sql"
oq() { php -r '$db = new PDO("sqlite:" . $argv[1]); echo $db->query($argv[2])->fetchColumn();' "$OLD" "$1"; }
check "user who has posted is approved" "$(oq "SELECT is_approved FROM users WHERE username = 'poster'")" 1
check "user who never posted isn't" "$(oq "SELECT is_approved FROM users WHERE username = 'lurker'")" 0
check "existing posts are approved" "$(oq "SELECT is_approved FROM posts WHERE id = 1")" 1
check "pending index created" "$(oq "SELECT COUNT(*) FROM sqlite_master WHERE name = 'posts_pending'")" 1
finish
