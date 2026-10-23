# Asking for a profile edit link only emails your own address, so it can't be used to send email to other members.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice bob
mails() { cat "$WORK/mail.log" 2>/dev/null | wc -l; }
check "another member's address looks sent" "$(P alice profile/edit email=bob@example.invalid)" 200
check "but nothing is emailed" "$(mails)" 0
check "a code isn't made for them" "$(q "select count(*) from verifications")" 0
P alice profile/edit email=alice@example.invalid >/dev/null
check "your own address is emailed" "$(tail -1 "$WORK/mail.log" | grep -c alice@example.invalid)" 1
finish
