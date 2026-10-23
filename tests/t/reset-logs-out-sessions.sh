# A password reset logs out the account's other sessions
source "$(dirname "$0")/../lib.sh"; start alice admin
rm -f $(J anon); t=$(csrf anon reset); C -b $(J anon) -c $(J anon) -o /dev/null --data-urlencode csrf=$t -d email=alice@example.invalid -d h-captcha-response=x $B/reset
code=$(q "select code from verifications"); [ -n "$code" ] || code=$(mkcode alice reset)
t=$(csrf anon reset/$code); C -b $(J anon) -c $(J anon) -o /dev/null --data-urlencode csrf=$t -d password=newpass-long -d password2=newpass-long $B/reset/$code
check "password changed" "$(php -r '$db=new PDO("sqlite:'$DB'"); echo (int)password_verify("newpass-long",$db->query("select password from users where username=\"alice\"")->fetchColumn());')" 1
check "old session logged out" "$(status alice post)" 303
check "anonymous resetter not logged in" "$(status anon post)" 303
login alice newpass-long; check "new password logs in" "$(status alice post)" 200
check "admin session unaffected" "$(status admin post)" 200
finish
