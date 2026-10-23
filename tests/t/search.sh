# Members search thread titles and usernames; guests are sent to a web search; searches are rate limited
source "$(dirname "$0")/../lib.sh"; start alice bob
P alice post 'title=Hello there' 'content=op' >/dev/null
P alice post 'title=100% sure' 'content=op' >/dev/null
s() { C -b $(J alice) -G --data-urlencode "q=$1" $B/search; }
check "guests go to a web search" "$(C -o /dev/null -w '%{redirect_url}' "$B/search?q=hello" | grep -c 'duckduckgo.com')" 1
check "finds thread titles" "$(s hello | grep -c '>Hello there<')" 1
check "finds usernames" "$(s bo | grep -c 'profile/3">bob<')" 1
check "LIKE wildcards are literal" "$(s '0%' | grep -c '>100% sure<')" 1
check "underscore is literal" "$(s 'o_t' | grep -c 'Nothing found')" 1
check "hashtag search goes to the tag page" "$(C -b $(J alice) -o /dev/null -w '%{redirect_url}' "$B/search?q=%23Bim")" "$B/tag/bim"
check "search box keeps the query" "$(s hello | grep -c 'name="q" value="hello"')" 1
unlimit; for i in $(seq 10); do C -b $(J alice) -o /dev/null "$B/search?q=xx"; done
check "rate limited" "$(C -b $(J alice) -o /dev/null -w '%{http_code}' "$B/search?q=xx")" 429
finish
