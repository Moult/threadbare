# Hashtags in posts link to tag pages; only hashtags in recent approved posts have pages, and code, headings and URLs don't count
source "$(dirname "$0")/../lib.sh"; start admin alice bob
php -r '$db = new PDO("sqlite:" . $argv[1]);
    $db->prepare("INSERT INTO users(username, password, email, is_verified) VALUES(?, ?, ?, 1)")->execute(["newbie", password_hash("pw-newbie-long", PASSWORD_DEFAULT), "newbie@example.invalid"]);' "$DB"
login newbie
P alice post 'title=Thread A' 'content=Talking about #IfcOpenShell and (#bim) today' >/dev/null
P bob post 'title=Thread B' 'content=#heading
see http://x.example/page#frag and `inline #notatag` and &#39; 
```
x #fenced
```' >/dev/null
P bob post 'title=Curated question' 'tags[]=question' 'content=no hashtag' >/dev/null
P alice post 'title=Hashtag question' 'content=a #question too' >/dev/null
code() { C -o /dev/null -w '%{http_code}' "$B/$1"; }

l=$(C $B/tag/ifcopenshell)
check "hashtag page lists its thread" "$(echo "$l" | grep -c '>Thread A<')" 1
check "and not others" "$(echo "$l" | grep -c '>Thread B<')" 0
check "hashtag in brackets counts" "$(C $B/tag/bim | grep -c '>Thread A<')" 1
check "mixed case redirects to lower case" "$(C -o /dev/null -w '%{redirect_url}' $B/tag/IfcOpenShell)" "$B/tag/ifcopenshell"
check "post links its hashtags" "$(C $B/thread/1 | grep -c 'href="'$B'/tag/ifcopenshell" class="hashtag">#IfcOpenShell<')" 1
for t in heading frag notatag fenced nosuch; do check "no page for $t" "$(code tag/$t)" 404; done
check "no link inside code" "$(C $B/thread/2 | grep -c 'class="hashtag"')" 0
check "page past the end is missing" "$(code tag/bim/p5)" 404
q=$(C $B/tag/question)
check "curated tag page lists curated thread" "$(echo "$q" | grep -c '>Curated question<')" 1
check "and threads using it as a hashtag" "$(echo "$q" | grep -c '>Hashtag question<')" 1
check "tags page lists recent hashtags" "$(C $B/tags | grep -c '>#bim<')" 1

P bob thread/2 'content=something #fresh' >/dev/null
check "new hashtag has a page straight away" "$(code tag/fresh)" 200
P bob post/edit/5 'content=something stale' >/dev/null
check "editing the hashtag out removes its page" "$(code tag/fresh)" 404
P newbie thread/1 'content=buy #spam' >/dev/null
check "held post's hashtag has no page" "$(code tag/spam)" 404
P admin approvals/approve/5 >/dev/null
check "approving publishes it" "$(code tag/spam)" 200
check "no PHP warnings" "$(grep -c 'PHP Warning' $WORK/php-errors.log)" 0
finish
