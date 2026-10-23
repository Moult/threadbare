# Upload errors render a normal page with no warnings
source "$(dirname "$0")/../lib.sh"; start alice
t=$(csrf alice upload); out=$(C -b $(J alice) -c $(J alice) --data-urlencode csrf=$t $B/upload)
check "error page has site title" "$(echo "$out" | grep -c '<title>Test Forum</title>')" 1
check "no undefined-variable warning" "$(grep -c 'Undefined variable \$data' $WORK/php-errors.log)" 0
printf '<html><body>x</body></html>' > $WORK/x.html; t=$(csrf alice upload)
check "disallowed type -> 403 page" "$(C -b $(J alice) -c $(J alice) -o /dev/null -w '%{http_code}' -F csrf=$t -F attachment=@$WORK/x.html $B/upload)" 403
check "still no warning" "$(grep -c 'Undefined variable \$data' $WORK/php-errors.log)" 0
finish
