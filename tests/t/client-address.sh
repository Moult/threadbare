# Rate limits count the visitor's address, from a proxy header when one is configured, and an IPv6 /64 as one visitor.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start
t=$(csrf g login)
# fail IP: a wrong login sent with X-Forwarded-For: IP, printing the status (429 once rate limited)
fail() { C -b "$(J g)" -c "$(J g)" -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" --data-urlencode "csrf=$t" -d username=alice -d password=wrong-password "$B/login"; }
for i in 1 2 3 4 5; do fail 192.0.2.$i >/dev/null; done
check "without clientIpHeader the header is ignored" "$(fail 192.0.2.9)" 429

unlimit
sed -i "s/'adminUsernames'/'clientIpHeader' => 'X-Forwarded-For', 'adminUsernames'/" "$APP/config.php"
for i in 1 2 3 4 5; do fail "203.0.113.1, 192.0.2.1" >/dev/null; done
check "the address the proxy added is limited" "$(fail 192.0.2.1)" 429
check "another visitor isn't" "$(fail 192.0.2.2)" 400
check "nor is one claiming the limited address first" "$(fail '192.0.2.1, 192.0.2.3')" 400
for i in 1 2 3 4 5; do fail 2001:db8::$i >/dev/null; done
check "an IPv6 /64 counts as one visitor" "$(fail 2001:db8::ffff)" 429
check "another /64 doesn't" "$(fail 2001:db8:0:1::1)" 400
check "a bad header falls back to the connection's address" "$(fail not-an-address)" 400
finish
