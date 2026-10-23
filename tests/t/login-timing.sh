# Logging in as an unknown account takes as long as a wrong password, so timing doesn't reveal which accounts exist
source "$(dirname "$0")/../lib.sh"; start
attempt() { unlimit; local t=$(csrf guest login); C -b "$(J guest)" -c "$(J guest)" -o /dev/null -w '%{time_total}\n' --data-urlencode "csrf=$t" --data-urlencode "username=$1" --data-urlencode password=wrong-password-x "$B/login"; }
known=$(for i in 1 2 3 4 5; do attempt alice; done | awk '{ s += $1 } END { print s }')
unknown=$(for i in 1 2 3 4 5; do attempt nobody-here; done | awk '{ s += $1 } END { print s }')
echo "  wrong password ${known}s, unknown account ${unknown}s"
check "unknown account is at least half as slow as a wrong password" "$(awk -v k="$known" -v u="$unknown" 'BEGIN { print (u * 2 >= k) ? "y" : "n" }')" y
finish
