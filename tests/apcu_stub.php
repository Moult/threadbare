<?php
// Stand-in for APCu when the extension is not loaded: a JSON file shared by all requests.
if (!function_exists('apcu_fetch')) {
    function apcu_stub_load()
    {
        $file = getenv('APCU_STUB_FILE');
        return is_file($file) ? (json_decode(file_get_contents($file), TRUE) ?: []) : [];
    }
    function apcu_stub_save($data)
    {
        file_put_contents(getenv('APCU_STUB_FILE'), json_encode($data), LOCK_EX);
    }
    function apcu_fetch($key)
    {
        $data = apcu_stub_load();
        return array_key_exists($key, $data) ? $data[$key] : FALSE;
    }
    function apcu_store($key, $value, $ttl = 0)
    {
        $data = apcu_stub_load();
        $data[$key] = $value;
        apcu_stub_save($data);
        return TRUE;
    }
    function apcu_add($key, $value, $ttl = 0)
    {
        $data = apcu_stub_load();
        if (array_key_exists($key, $data))
            return FALSE;
        $data[$key] = $value;
        apcu_stub_save($data);
        return TRUE;
    }
    function apcu_inc($key, $step = 1)
    {
        $data = apcu_stub_load();
        $data[$key] = ($data[$key] ?? 0) + $step;
        apcu_stub_save($data);
        return $data[$key];
    }
    function apcu_delete($key)
    {
        $data = apcu_stub_load();
        unset($data[$key]);
        apcu_stub_save($data);
        return TRUE;
    }
    function apcu_sma_info($limited = FALSE) // Memory is the size of the file, out of APCU_STUB_SHM bytes (32M)
    {
        $size = (int) (getenv('APCU_STUB_SHM') ?: 32 * 1024 * 1024);
        $file = getenv('APCU_STUB_FILE');
        return ['num_seg' => 1, 'seg_size' => $size, 'avail_mem' => $size - (is_file($file) ? filesize($file) : 0)];
    }
    function apcu_cache_info()
    {
        if (str_ends_with(debug_backtrace()[0]['file'] ?? '', '/app.php')) // Tests check the forum never lists the cache
            file_put_contents(getenv('APCU_STUB_FILE') . '.listed', "listed\n", FILE_APPEND);
        return ['cache_list' => array_map(fn($key) => ['info' => $key], array_keys(apcu_stub_load()))];
    }
}
