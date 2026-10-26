# Posts are rendered once when saved, not on every view; old posts are rendered and saved when first shown; and
# Markdown that would make a huge page is refused. Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello 'content=**bold** #tagged' >/dev/null
check "HTML saved with the post" "$(q 'select html from posts where id = 1')" '<p><strong>bold</strong> #tagged</p>'
sql "UPDATE posts SET html = '<p>from the database</p>' WHERE id = 1"
check "pages show the saved HTML" "$(page alice thread/1 | grep -c 'from the database')" 1
sql "UPDATE posts SET html = NULL WHERE id = 1"
check "a post without HTML is rendered" "$(page alice thread/1 | grep -c '<strong>bold</strong>')" 1
check "and its HTML saved" "$(q 'select html is not null from posts where id = 1')" 1
check "hashtags still link" "$(page alice thread/1 | grep -c 'href="[^"]*tag/tagged"')" 1
P alice post/edit/1 'content=_edited_' >/dev/null
check "an edit saves new HTML" "$(q 'select html from posts where id = 1')" '<p><em>edited</em></p>'
check "deeply nested quotes are refused" "$(P alice thread/1 "content=$(printf '>%.0s' $(seq 5000))")" 400
check "and not saved" "$(q 'select count(*) from posts')" 1
check "a long ordinary post is fine" "$(P alice thread/1 "content=$(for i in $(seq 70); do echo -n '**Some** [text](https://example.com/page). '; done)")" 303
finish
