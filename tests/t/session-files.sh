# Clients that never keep their session cookie (or send made-up ones) can only make so many session files.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello content=x >/dev/null
C -c "$(J kept)" -o /dev/null $B/   # a browser that keeps its cookie
files() { ls "$WORK/sessions" | wc -l; }
unlimit; before=$(files)
for i in $(seq 150); do C -o /dev/null $B/thread/1; done
check "cookieless requests stop making sessions at 100" "$(( $(files) - before ))" 100
for i in $(seq 20); do C -b "PHPSESSID=madeup$i" -o /dev/null $B/thread/1; done
check "nor do made-up cookies" "$(( $(files) - before ))" 100
check "made-up cookies aren't counted as views" "$(q 'select views from threads where id=1')" 0
C -b "$(J kept)" -c "$(J kept)" -o /dev/null $B/thread/1
check "a kept session still works" "$(q 'select views from threads where id=1')" 1
check "and logging in still works" "$(login alice; page alice notifications | grep -c 'alice')" 1
finish
