# A new email address is used only once confirmed, and a taken one is refused
source "$(dirname "$0")/../lib.sh"; start bob
code=$(mkcode bob profile)
check "taken address -> no 500" "$(P bob profile/edit/$code email=alice@example.invalid bio=hi)" 200
check "taken address not saved" "$(q "select email from users where username='bob'")" bob@example.invalid
P bob profile/edit/$code email=new@example.invalid bio=hello >/dev/null
check "bio saved" "$(q "select bio from users where username='bob'")" hello
check "new address not applied before confirmation" "$(q "select email from users where username='bob'")" bob@example.invalid
check "confirmation mailed to new address" "$(tail -1 $WORK/mail.log | grep -c 'new@example.invalid')" 1
link=$(tail -1 $WORK/mail.log | grep -o 'http[^ "\\]*' | head -1); path=${link#$B/}
check "confirmation link works" "$(status bob $path)" 200
check "new address applied after confirmation" "$(q "select email from users where username='bob'")" new@example.invalid
check "unchanged email needs no confirmation" "$(code2=$(mkcode bob profile); P bob profile/edit/$code2 email=new@example.invalid bio=again >/dev/null; q "select bio from users where username='bob'")" again
finish
