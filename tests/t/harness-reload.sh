# A change a test makes to app.php while the server runs takes effect at once, even within the same second
source "$(dirname "$0")/../lib.sh"; start  # the server caches new files at once (opcache.file_update_protection=0), if opcache is on
check "tags page before the change" "$(status guest tags)" 200
cp -p "$APP/app.php" "$WORK/app.php.orig"
php -r '$f = $argv[1]; file_put_contents($f, str_replace("\$uri === '"'"'tags'"'"'", "\$uri === '"'"'tags-moved'"'"'", file_get_contents($f)));' "$APP/app.php"
touch -r "$WORK/app.php.orig" "$APP/app.php"  # same timestamp, as when a change lands in the same second
check "tags page after the change" "$(status guest tags)" 404
finish
