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
    function apcu_delete($key) // One key, an array of keys, or an APCUIterator
    {
        $data = apcu_stub_load();
        foreach (is_string($key) ? [$key] : $key as $k => $v) {
            unset($data[$key instanceof APCUIterator ? $k : $v]);
        }
        apcu_stub_save($data);
        return TRUE;
    }
    function apcu_cache_info()
    {
        if (str_ends_with(debug_backtrace()[0]['file'] ?? '', '/app.php')) // Tests check the forum doesn't list the cache
            file_put_contents(getenv('APCU_STUB_FILE') . '.listed', "listed\n", FILE_APPEND);
        return ['cache_list' => array_map(fn($key) => ['info' => $key], array_keys(apcu_stub_load()))];
    }
    define('APC_ITER_KEY', 2);
    class APCUIterator extends ArrayIterator // The entries whose keys match $search, by key
    {
        public function __construct($search = NULL, $format = APC_ITER_KEY)
        {
            $keys = array_keys(apcu_stub_load());
            parent::__construct(array_fill_keys($search === NULL ? $keys : preg_grep($search, $keys), TRUE));
        }
    }
}
