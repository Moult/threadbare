# When an email can't be sent the page says so, with no PHP warnings or deprecations (on PHP 8.5, curl_close() is deprecated)
source "$(dirname "$0")/../lib.sh"
export https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9  # the server can't reach SendGrid
start alice
cp "$ROOT/app.php" "$APP/app.php"  # the real sendEmail() rather than the test stub
check "failed profile code email is a 500" "$(P alice profile/edit email=alice@example.invalid)" 500
check "no PHP warning or deprecation" "$(grep -c 'PHP Warning\|PHP Deprecated' "$WORK/php-errors.log")" 0
finish
