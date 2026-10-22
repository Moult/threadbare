# A failed captcha gives the normal 403 page and sends nothing
source "$(dirname "$0")/../lib.sh"
export https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9  # the server can't reach hCaptcha, so the captcha fails
start
cp "$ROOT/app.php" "$APP/app.php"  # the real checkCaptcha() rather than the test stub
unlimit; t=$(csrf guest reset)
out=$(C -b "$(J guest)" -c "$(J guest)" -w '\n%{http_code}' --data-urlencode "csrf=$t" -d email=alice@example.invalid -d h-captcha-response=x "$B/reset")
check "failed captcha is refused" "$(echo "$out" | tail -1)" 403
check "403 page has the site's title" "$(echo "$out" | grep -c '<title>Test Forum</title>')" 1
check "no reset email sent" "$(cat "$WORK/mail.log" 2>/dev/null | wc -l)" 0
check "no PHP warning" "$(grep -c 'PHP Warning' "$WORK/php-errors.log")" 0
finish
