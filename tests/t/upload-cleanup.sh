# Uploads are recorded and deleted with the account
source "$(dirname "$0")/../lib.sh"; start alice
printf 'hello' > $WORK/a.txt; t=$(csrf alice upload); C -b $(J alice) -c $(J alice) -o /dev/null -F csrf=$t -F attachment=@$WORK/a.txt $B/upload
f=$(cd $APP/uploads && ls ??/??/*.txt 2>/dev/null | head -1)
check "upload stored" "$([ -n "$f" ] && echo y)" y
check "upload recorded against user" "$(q "select count(*) from uploads u join users s on s.id=u.user_id where s.username='alice'" 2>/dev/null)" 1
code=$(mkcode alice profile)
P alice profile/delete/$code confirm=yes >/dev/null
check "file removed with account" "$([ -e $APP/uploads/$f ] && echo present || echo gone)" gone
finish
