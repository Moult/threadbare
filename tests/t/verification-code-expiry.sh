# Codes work only for their own purpose, and only for a day; a new code replaces only one for the same purpose
source "$(dirname "$0")/../lib.sh"; start alice bob
# a real reset code, via the reset form
rm -f $(J anon); t=$(csrf anon reset); C -b $(J anon) -c $(J anon) -o /dev/null --data-urlencode csrf=$t -d email=alice@example.invalid $B/reset
code=$(lastmail reset)
check "reset mail sent with code" "$([ -n "$code" ] && echo y)" y
check "reset code opens reset form" "$(C $B/reset/$code | grep -c 'name="password2"')" 1
check "reset code rejected for profile edit" "$(C -b $(J alice) $B/profile/edit/$code | grep -c 'name=\"bio\"')" 0
rm -f $(J anon2); t=$(csrf anon2 verify); C -b $(J anon2) -c $(J anon2) -o /dev/null --data-urlencode csrf=$t -d email=alice@example.invalid $B/verify
check "verification email sent" "$(tail -1 $WORK/mail.log | grep -c 'verify/')" 1
check "reset code still works after asking for a verification email" "$(C $B/reset/$code | grep -c 'name="password2"')" 1
php -r '$db=new PDO("sqlite:'$DB'"); $db->exec("UPDATE verifications SET ts_created = ts_created - 2*86400");' 2>/dev/null
check "2-day-old code rejected" "$(C $B/reset/$code | grep -c 'name="password2"')" 0
finish
