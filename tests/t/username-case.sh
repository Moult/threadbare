# A username can't differ from an existing one only in case
source "$(dirname "$0")/../lib.sh"; start
register() { P guest register "username=$1" "password=pw-$1-long" "password2=pw-$1-long" "email=$1@example.org" answer=black; }
check "Alice refused when alice exists" "$(register Alice)" 400
check "no Alice account" "$(q "SELECT COUNT(*) FROM users WHERE username = 'Alice'")" 0
check "a different name still registers" "$(register Alicia)" 200
finish
