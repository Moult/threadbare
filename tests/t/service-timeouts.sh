# A request gives up on hCaptcha or SendGrid when it doesn't answer, rather than holding a PHP worker indefinitely.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"
SILENT=$((PORT + 1))  # accepts connections and never answers, closing each after 40s
php -r '$s = stream_socket_server("tcp://127.0.0.1:" . $argv[1]); while ($c = @stream_socket_accept($s, 120)) { sleep(40); fclose($c); }' $SILENT &
trap "kill $! 2>/dev/null" EXIT
export https_proxy=http://127.0.0.1:$SILENT HTTPS_PROXY=http://127.0.0.1:$SILENT
start alice bob
cp "$ROOT/app.php" "$APP/app.php"  # the real checkCaptcha() and sendEmail() rather than the test stubs
P bob post title=Waiting content=x >/dev/null
unlimit; t=$(csrf alice login)
s=$(C -m 30 -b "$(J alice)" -c "$(J alice)" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$t" -d content=reply "$B/thread/1")
check "reply with a notification email returns despite SendGrid not answering" "$s" 303
unlimit; t=$(csrf guest reset)
s=$(C -m 30 -b "$(J guest)" -c "$(J guest)" -o /dev/null -w '%{http_code}' --data-urlencode "csrf=$t" -d email=alice@example.invalid -d h-captcha-response=x "$B/reset")
check "captcha check returns despite hCaptcha not answering" "$s" 403
finish
