# Attach files with and without JavaScript; reject types that aren't allowed
source "$(dirname "$0")/../lib.sh"; start alice
printf 'hello' > "$WORK/a.txt"; printf '<html><body>x</body></html>' > "$WORK/x.html"
up() { local t=$(csrf alice upload); C -b "$(J alice)" -c "$(J alice)" -F csrf=$t "$@" "$B/upload"; }
check "upload form" "$(status alice upload)" 200
check "text file accepted" "$(up -o /dev/null -w '%{http_code}' -F attachment=@"$WORK/a.txt")" 200
check "stored under uploads/" "$(find "$APP/uploads" -name '*.txt' | wc -l | tr -d ' ')" 1
url=$(up -F useJS=true -F attachment=@"$WORK/a.txt" | php -r 'echo json_decode(stream_get_contents(STDIN))->url;')
check "JavaScript upload returns a /files/ URL" "$(echo "$url" | grep -c "^$B/files/")" 1
check "HTML file refused" "$(up -o /dev/null -w '%{http_code}' -F attachment=@"$WORK/x.html")" 403
check "guests cannot upload" "$(C -o /dev/null -w '%{http_code}' "$B/upload")" 303
finish
