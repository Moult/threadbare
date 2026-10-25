# A query string (e.g. ?utm_source= or ?fbclid= added to shared links) doesn't change which page is served
source "$(dirname "$0")/../lib.sh"; start alice
P alice post 'title=Hello there' 'content=op' >/dev/null
check "thread with a tracking parameter" "$(C -o /dev/null -w '%{http_code}' "$B/thread/1?utm_source=x")" 200
check "index with a tracking parameter" "$(C -o /dev/null -w '%{http_code}' "$B/?fbclid=abc")" 200
check "search still redirects" "$(C -o /dev/null -w '%{redirect_url}' "$B/search?q=hello" | grep -c 'duckduckgo.com/?q=site')" 1
finish
