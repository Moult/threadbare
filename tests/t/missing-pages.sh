# Pages past the last one (or page 0) are 404s, so guests and crawlers can't fill the cache with empty pages.
# Runs with the suite from the CI pull request (tests/run.sh).
source "$(dirname "$0")/../lib.sh"; start alice
P alice post title=Hello content=x tags[]=question >/dev/null
for u in / p1 thread/1 thread/1/p1 tag/question tag/question/p1; do check "$u" "$(status guest $u)" 200; done
for u in p0 p2 p999 thread/1/p0 thread/1/p2 thread/1/p999 tag/question/p0 tag/question/p2; do check "$u" "$(status guest $u)" 404; done
finish
