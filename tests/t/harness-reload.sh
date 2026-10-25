# A change a test makes to app.php while the server runs takes effect at once, even within the same second
source "$(dirname "$0")/../lib.sh"; start
sleep 3  # opcache (if on) only caches files more than 2 seconds old
check "tags page before the change" "$(status guest tags)" 200
cp -p "$APP/app.php" "$WORK/app.php.orig"
php -r '$f = $argv[1]; file_put_contents($f, str_replace("\$uri === '"'"'tags'"'"'", "\$uri === '"'"'tags-moved'"'"'", file_get_contents($f)));' "$APP/app.php"
touch -r "$WORK/app.php.orig" "$APP/app.php"  # same timestamp, as when a change lands in the same second
check "tags page after the change" "$(status guest tags)" 404
finish
