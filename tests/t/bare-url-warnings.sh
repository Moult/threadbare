# A link to a bare domain (no path) renders without logging PHP warnings, which would otherwise fill the log on every view.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Links 'content=See http://example.com and https://example.org?q=1 or https://example.net/clip.mp4' >/dev/null
html=$(C $B/thread/1)
check "bare domain linked" "$(echo "$html" | grep -c 'href="http://example.com"')" 1
check "video still embedded" "$(echo "$html" | grep -c '<video')" 1
check "no warnings logged" "$(grep -c 'PHP \(Warning\|Deprecated\)' "$WORK/php-errors.log")" 0
finish
