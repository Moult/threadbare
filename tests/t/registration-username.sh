# Registration refuses a missing or badly formed username, with no PHP warnings or deprecations
source "$(dirname "$0")/../lib.sh"; start
check "no username" "$(P guest register 'password=pw-zed-long' 'password2=pw-zed-long' 'email=zed@example.org' answer=black)" 400
check "username with spaces" "$(P guest register 'username=ze  d' 'password=pw-zed-long' 'password2=pw-zed-long' 'email=zed@example.org' answer=black)" 400
check "no account created" "$(q 'SELECT COUNT(*) FROM users')" 4
check "no PHP warning or deprecation" "$(grep -c 'PHP Warning\|PHP Deprecated' "$WORK/php-errors.log")" 0
finish
