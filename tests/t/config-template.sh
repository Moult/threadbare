# config.php.template is valid PHP
source "$(dirname "$0")/../lib.sh"; T="$ROOT/config.php.template"
check "template parses" "$(php -l $T >/dev/null 2>&1; echo $?)" 0
check "template returns an array with blurb" "$(php -r '$c=include $argv[1]; echo is_string($c["blurb"]) ? 1 : 0;' $T)" 1
finish
