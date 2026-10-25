# Deleting an account prints no debug output
source "$(dirname "$0")/../lib.sh"; start mallory
code=$(mkcode mallory profile)
t=$(csrf mallory tags); body=$(C -b $(J mallory) -c $(J mallory) --data-urlencode csrf=$t -d confirm=yes $B/profile/delete/$code)
check "no debug output" "$(echo "$body" | grep -c 'string(')" 0
check "account deleted" "$(q "select count(*) from users where username='mallory'")" 0
finish
