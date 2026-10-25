# Guests get the cached page whichever way its URL is written (extra slashes, leading zeros), so those can't bypass the cache.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Original content=x tags[]=question >/dev/null
for u in / /thread/1 /tag/question; do C -o /dev/null $B$u; done  # guests fill the cache
sql "UPDATE threads SET title = 'Changed'"                         # behind the cache's back
for u in // /p1 /p01 /p1/ /thread/01/ /thread/1/p01 /thread/001/p1 /tag/question/ /tag/question/p01; do
  check "$u is served from the cache" "$(C $B$u | grep -q Original && echo yes)" yes
done
check "a member sees the database" "$(page alice thread/1 | grep -q Changed && echo yes)" yes
finish
