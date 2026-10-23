<?php
// Patch the test copy of app.php (never the real one): sendEmail() appends each message to a
// log file instead of calling SendGrid, and checkCaptcha() accepts everything instead of
// calling hCaptcha. Fails loudly if either function's signature changes.
[$_, $app, $mailLog] = $argv;
$src = file_get_contents($app);

$patches = [
    'function sendEmail($config, $to, $subject, $content)' =>
        "function sendEmail(\$config, \$to, \$subject, \$content)\n"
        . "{ file_put_contents(" . var_export($mailLog, TRUE) . ", json_encode([\$to, \$subject, \$content], JSON_UNESCAPED_SLASHES) . \"\\n\", FILE_APPEND); return TRUE; }\n"
        . "function sendEmailReal(\$config, \$to, \$subject, \$content)",
    "function checkCaptcha(\$config)\n{" => "function checkCaptcha(\$config)\n{\n    return;",
];
foreach ($patches as $from => $to) {
    if (substr_count($src, $from) !== 1) {
        fwrite(STDERR, "tests/stub.php: cannot find '" . strtok($from, "\n") . "' in app.php\n");
        exit(1);
    }
    $src = str_replace($from, $to, $src);
}
file_put_contents($app, $src);
