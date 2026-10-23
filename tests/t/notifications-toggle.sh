# Notifications change only on a CSRF-checked POST, never on a GET
source "$(dirname "$0")/../lib.sh"; start alice
check "GET /notifications renders" "$(status alice notifications)" 200
check "GET does not toggle" "$(q "select notifications from users where username='alice'")" 1
P alice notifications >/dev/null
check "POST with CSRF toggles off" "$(q "select notifications from users where username='alice'")" 0
P alice notifications >/dev/null
check "POST again toggles on" "$(q "select notifications from users where username='alice'")" 1
check "POST without CSRF refused" "$(C -b $(J alice) -o /dev/null -w '%{http_code}' -X POST $B/notifications)" 403
finish
