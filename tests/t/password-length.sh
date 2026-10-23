# Passwords need at least 8 characters
source "$(dirname "$0")/../lib.sh"; start
code=$(mkcode alice reset)
rm -f $(J anon); t=$(csrf anon reset/$code); C -b $(J anon) -c $(J anon) -o /dev/null --data-urlencode csrf=$t -d password=abc -d password2=abc $B/reset/$code
check "3-char password rejected" "$(php -r '$db=new PDO("sqlite:'$DB'"); echo (int)password_verify("abc",$db->query("select password from users where username=\"alice\"")->fetchColumn());')" 0
t=$(csrf anon reset/$code); C -b $(J anon) -c $(J anon) -o /dev/null --data-urlencode csrf=$t -d password=eightchr -d password2=eightchr $B/reset/$code
check "8-char password accepted" "$(php -r '$db=new PDO("sqlite:'$DB'"); echo (int)password_verify("eightchr",$db->query("select password from users where username=\"alice\"")->fetchColumn());')" 1
finish
