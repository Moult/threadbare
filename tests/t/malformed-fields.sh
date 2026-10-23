# Form fields of the wrong type are a 400, not a 500
source "$(dirname "$0")/../lib.sh"; start alice
check "username[] on login" "$(P alice login 'username[]=alice' 'password=x')" 400
check "answer[] on registration" "$(P alice register 'username=zed' 'password=pw-zed-long' 'password2=pw-zed-long' 'email=zed@example.invalid' 'answer[]=black')" 400
check "title[] on a new thread" "$(P alice post 'title[]=Hello there' 'content=x')" 400
check "tags not sent as a list" "$(P alice post 'title=Hello there' 'content=x' 'tags=question')" 400
check "q[] on search" "$(C -o /dev/null -w '%{http_code}' "$B/search?q[]=x")" 400
check "tags[] still works" "$(P alice post 'title=Hello there' 'content=x' 'tags[]=question')" 303
check "nothing was posted by the bad requests" "$(q 'SELECT COUNT(*) FROM threads')" 1
finish
