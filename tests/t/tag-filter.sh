# Tag pages match whole tags only
source "$(dirname "$0")/../lib.sh"; start alice
P alice post 'title=Intro only' 'tags[]=intro' 'content=a' >/dev/null
P alice post 'title=Introduction only' 'tags[]=introduction' 'content=b' >/dev/null
P alice post 'title=Question and intro' 'tags[]=question' 'tags[]=intro' 'content=c' >/dev/null
l=$(C $B/tag/intro)
check "intro thread listed" "$(echo "$l" | grep -c '>Intro only<')" 1
check "multi-tag thread listed" "$(echo "$l" | grep -c '>Question and intro<')" 1
check "introduction thread not listed" "$(echo "$l" | grep -c '>Introduction only<')" 0
check "introduction tag page lists it" "$(C $B/tag/introduction | grep -c '>Introduction only<')" 1
finish
