# Sign up, verify by email, log in and out, reset a forgotten password
source "$(dirname "$0")/../lib.sh"; start
rm -f "$(J new)"; t=$(csrf new login); unlimit
C -b "$(J new)" -c "$(J new)" -o /dev/null --data-urlencode csrf=$t -d username=newbie -d password=longenough \
    -d password2=longenough -d email=newbie@example.invalid -d answer=black "$B/register"
check "sign-up creates an unverified account" "$(q "SELECT is_verified FROM users WHERE username = 'newbie'")" 0
login newbie longenough
check "unverified account cannot log in" "$(status newbie post)" 303
code=$(lastmail verify)
check "verification link emailed" "$([ -n "$code" ] && echo yes)" yes
check "verification link works" "$(C "$B/verify/$code" | grep -c 'now verified')" 1
login newbie longenough
check "verified account can log in" "$(status newbie post)" 200
check "header greets the user" "$(page newbie '' | grep -c 'newbie</a>')" 1
P newbie logout >/dev/null
check "logged out" "$(status newbie post)" 303

login newbie wrong-password
check "wrong password refused" "$(status newbie post)" 303
check "wrong answer refused at sign-up" "$(rm -f "$(J x)"; t=$(csrf x login); unlimit; C -b "$(J x)" -c "$(J x)" -o /dev/null -w '%{http_code}' --data-urlencode csrf=$t -d username=other -d password=longenough -d password2=longenough -d email=other@example.invalid -d answer=white "$B/register")" 400

rm -f "$(J r)"; t=$(csrf r reset); unlimit
C -b "$(J r)" -c "$(J r)" -o /dev/null --data-urlencode csrf=$t -d email=newbie@example.invalid "$B/reset"
code=$(lastmail reset)
check "reset link emailed" "$([ -n "$code" ] && echo yes)" yes
t=$(csrf r reset/$code); unlimit
C -b "$(J r)" -c "$(J r)" -o /dev/null --data-urlencode csrf=$t -d password=brandnewpass -d password2=brandnewpass "$B/reset/$code"
login newbie brandnewpass
check "new password works" "$(status newbie post)" 200
finish
