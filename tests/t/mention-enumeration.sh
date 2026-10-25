# Mention autocomplete needs a login and treats _ literally
source "$(dirname "$0")/../lib.sh"; start alice
check "anonymous request refused" "$(C -o /dev/null -w '%{http_code}' $B/mention/@a)" 403
check "_ is literal, not a wildcard" "$(C -b $(J alice) $B/mention/@_)" "[]"
check "prefix search still works" "$(C -b $(J alice) $B/mention/@a)" '["admin","alice"]'
P alice post 'title=Tee' 'content=x' >/dev/null
check "thread-scoped search still works" "$(C -b $(J alice) $B/mention/1/@al)" '["alice"]'
finish
