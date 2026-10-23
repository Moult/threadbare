<?php
// Router for PHP's built-in server: static files from www/, everything else to the app.
require __DIR__ . '/apcu_stub.php';

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/__test/clear-rate-limits') {
    foreach (apcu_cache_info()['cache_list'] ?? [] as $item) {
        if (str_starts_with($item['info'], 'ratelimit_'))
            apcu_delete($item['info']);
    }
    exit;
}
if ($path !== '/' && is_file($_SERVER['DOCUMENT_ROOT'] . $path))
    return false;
require $_SERVER['DOCUMENT_ROOT'] . '/index.php';
