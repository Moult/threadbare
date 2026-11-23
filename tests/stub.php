<?php
// Patch the test copy of app.php (never the real one) so tests don't call other services or wait:
// sendEmail() appends each message to a log file instead of calling SendGrid, checkCaptcha()
// accepts everything instead of calling hCaptcha, isSpam() doesn't connect to Akismet, and
// passwords are hashed at a low cost. Fails loudly if any of these can't be found.
[$_, $app, $mailLog] = $argv;
$src = file_get_contents($app);

$patches = [
    'function sendEmail($config, $to, $subject, $content)' =>
        "function sendEmail(\$config, \$to, \$subject, \$content)\n"
        . "{ file_put_contents(" . var_export($mailLog, TRUE) . ", json_encode([\$to, \$subject, \$content], JSON_UNESCAPED_SLASHES) . \"\\n\", FILE_APPEND); return TRUE; }\n"
        . "function sendEmailReal(\$config, \$to, \$subject, \$content)",
    "function checkCaptcha(\$config)\n{" => "function checkCaptcha(\$config)\n{\n    return;",
    // isSpam() builds its request as usual, but can't reach Akismet
    "@fsockopen('ssl://' . \$http_host, \$port, \$errno, \$errstr, 5)" => "FALSE",
];
foreach ($patches as $from => $to) {
    if (substr_count($src, $from) !== 1) {
        fwrite(STDERR, "tests/stub.php: cannot find '" . strtok($from, "\n") . "' in app.php\n");
        exit(1);
    }
    $src = str_replace($from, $to, $src);
}
// Hash passwords cheaply, as the default cost is a fifth of a second for every sign-up and login. TEST_HASH_COST sets
// the cost for a test that needs hashing to take a while.
$src = str_replace('PASSWORD_DEFAULT)', "PASSWORD_BCRYPT, ['cost' => (int) (getenv('TEST_HASH_COST') ?: 4)])", $src, $count);
if ($count === 0) {
    fwrite(STDERR, "tests/stub.php: cannot find password_hash(..., PASSWORD_DEFAULT) in app.php\n");
    exit(1);
}
file_put_contents($app, $src);
