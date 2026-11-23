# A session is a file. Reading the forum doesn't make one; only a page with a form does, and a visitor can only
# make so many of those. Made-up session cookies don't make one either.
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello content=x >/dev/null
files() { ls "$WORK/sessions" | wc -l; }
unlimit; before=$(files)
for i in $(seq 20); do C -o /dev/null $B/thread/1; C -o /dev/null $B/; done
check "reading without a cookie makes no sessions" "$(( $(files) - before ))" 0
for i in $(seq 20); do C -b "PHPSESSID=madeup$i" -o /dev/null $B/thread/1; done
check "nor do made-up cookies" "$(( $(files) - before ))" 0
check "pages without a session still aren't kept by the browser" "$(C -D - -o /dev/null $B/thread/1 | grep -ci '^Cache-Control: no-store')" 1

# Of the pages someone not logged in can reach, every one with a form starts a session, and the rest (but for a
# password reset link that has expired) don't
c=$(mkcode alice reset); v=$(mkcode bob verify)
for path in login reset reset/$c reset/nosuchcode verify verify/$v verify/nosuchcode email/nosuchcode tags tag/question profile/1 search thread/1/latest nosuchpage; do
    rm -f "$WORK/jar"; form=$(C -c "$WORK/jar" $B/$path | grep -c 'name="csrf"'); [ "$form" -gt 0 ] && form=1
    [ $path = reset/nosuchcode ] && form=1
    check "/$path starts a session only if it has a form" "$(grep -c PHPSESSID "$WORK/jar" 2>/dev/null)" "$form"
done
unlimit; before=$(files)

C -c "$(J kept)" -o /dev/null $B/login   # a browser that keeps its cookie
check "the login page starts a session" "$(( $(files) - before ))" 1
for i in $(seq 5); do C -b "$(J kept)" -c "$(J kept)" -o /dev/null $B/login; C -b "$(J kept)" -o /dev/null $B/thread/1; done
check "which is used again" "$(( $(files) - before ))" 1
t=$(page kept login | grep -o 'name="csrf" value="[0-9a-f]*"' | tail -1 | sed 's/.*value="//;s/"//')
C -b "$(J kept)" -c "$(J kept)" -o /dev/null --data-urlencode "csrf=$t" --data-urlencode "username=alice" --data-urlencode "password=pw-alice-long" $B/login
check "and can log in" "$(page kept notifications | grep -c 'alice')" 1

for i in $(seq 110); do last=$(C -o /dev/null -w '%{http_code}' $B/login); done
check "login pages without a cookie stop making sessions at 100" "$(( $(files) - before ))" 100
check "and say so rather than show a form that can't work" "$last" 429
check "the forum can still be read" "$(C -o /dev/null -w '%{http_code}' $B/thread/1)" 200
check "and sessions already started still work" "$(status kept notifications)" 200
finish
