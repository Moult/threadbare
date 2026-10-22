# Autocomplete usernames, and email the people mentioned
source "$(dirname "$0")/../lib.sh"; start alice bob
check "autocomplete by prefix" "$(page alice mention/@al)" '["alice"]'
P alice post 'title=Hello there' 'content=hi @bob' >/dev/null
check "mention rendered" "$(page alice thread/1 | grep -c 'class="usertag">@bob')" 1
check "mentioned user emailed" "$(tail -1 "$WORK/mail.log" | grep -c 'bob@example.invalid')" 1
finish
