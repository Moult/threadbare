# A session remembers only the latest 200 threads it has viewed, so a crawler keeping its cookie doesn't grow it forever.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello content=x >/dev/null
C -c "$(J crawler)" -o /dev/null $B/
C -b "$(J crawler)" -o /dev/null $B/thread/1; C -b "$(J crawler)" -o /dev/null $B/thread/1
check "a view is counted once" "$(q 'select views from threads where id=1')" 1
for i in $(seq 2 500); do C -b "$(J crawler)" -o /dev/null $B/thread/$i; done
id=$(grep -o 'PHPSESSID.*' "$(J crawler)" | awk '{ print $2 }')
check "session stays small" "$(( $(stat -c %s "$WORK/sessions/sess_$id") < 9000 ))" 1
finish
