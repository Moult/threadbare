# posts and votes have their lookup indexes
source "$(dirname "$0")/../lib.sh"; start
for i in posts_thread_id posts_user_id votes_post_id; do
  check "index on ${i/_/.}" "$(q "select count(*) from sqlite_master where type='index' and name='$i' and sql like '%$(echo $i | sed 's/_/%(/;s/$/)%/')'")" 1
done
finish
