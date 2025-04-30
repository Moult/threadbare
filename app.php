<?php

$config = require_once (__DIR__ . '/config.php');
require_once (__DIR__ . '/vendor/autoload.php');

// https://www.php.net/manual/en/session.security.ini.php
ini_set('session.cookie_lifetime', 0);
ini_set('session.use_cookies', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', str_starts_with($config['baseurl'], 'https'));
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_trans_sid', 0);
ini_set('session.cache_limiter', 'nocache');
ini_set('session.save_path', $config['sessionSavePath']);

session_start();

if (empty($_SESSION['csrf']) || !is_array($_SESSION['csrf'])) {
    $_SESSION['csrf'] = [];
}

header("Content-Security-Policy: default-src 'self'; script-src 'self' https://hcaptcha.com https://*.hcaptcha.com; frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com https://www.youtube.com; style-src 'self' https://hcaptcha.com https://*.hcaptcha.com; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; img-src * data: blob:; media-src 'self' " . $config['cspUrls'] . ';');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

$baseurl = $config['baseurl'];
$perPage = 25;
$db = new \PDO('sqlite:' . __DIR__ . '/threadbare.db');
$db->exec('PRAGMA foreign_keys = ON;');
$method = $_SERVER['REQUEST_METHOD'];
$uri = trim($_SERVER['REQUEST_URI'], '/');
$mustache = new Mustache_Engine(['loader' => new Mustache_Loader_FilesystemLoader(__DIR__ . '/templates/')]);
$data = ['baseurl' => $baseurl, 'csrf' => $_SESSION['csrf'], 'captcha' => $config['hCaptchaSiteKey'], 'html_title' => $config['websiteTitle'], 'h1' => $config['websiteTitle'], 'blurb' => $config['blurb']];
if (isset($_SESSION['username'])) {
    $data['is_logged_in'] = TRUE;
    $data['username'] = $_SESSION['username'];
} else {
    $data['is_logged_in'] = FALSE;
}

function generateCsrf(&$data)
{
    $_SESSION['csrf'][] = $data['csrf'] = bin2hex(random_bytes(32));
    if (count($_SESSION['csrf']) > 50) {
        array_shift($_SESSION['csrf']);
    }
}

function checkCsrf($mustache, &$data)
{
    if (!isset($_POST['csrf']))
        render(403, '403', $mustache, $data);
    foreach ($_SESSION['csrf'] as $csrf) {
        if (hash_equals($csrf, $_POST['csrf'])) {
            generateCsrf($data);
            return;
        }
    }
    render(403, '403', $mustache, $data);
}

function checkRateLimit($config, $mustache, $data, $key = 'login', $limit = 3, $window = 300)
{
    if (isset($_SESSION['username']) && in_array($_SESSION['username'], $config['adminUsernames']))
        return;
    $now = time();
    $rateKey = 'ratelimit_' . md5($config['salt'] . $_SERVER['REMOTE_ADDR'] . $key);
    $record = apcu_fetch($rateKey);
    if (!$record) {
        $record = ['attempts' => 1, 'time' => $now];
    } elseif ($now - $record['time'] < $window) {
        $record['attempts']++;
        if ($record['attempts'] > $limit)
            render(429, '429', $mustache, $data);
    } else {
        $record = ['attempts' => 1, 'time' => $now];
    }
    apcu_store($rateKey, $record, $window);
}

function logout()
{
    unset($_SESSION['username']);
    unset($_SESSION['user_id']);
    $_SESSION['csrf'] = [];
    session_unset();
    session_destroy();
}

function getSessionToken($db)
{
    $query = $db->prepare('SELECT session_token FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id']);
    $query->execute();
    return $query->fetchColumn(0);
}

function checkSessionToken($baseurl, $db)
{
    if (isset($_SESSION['username']) && (empty($_SESSION['token']) || $_SESSION['token'] !== getSessionToken($db)))
    {
        logout();
        redirect($baseurl . 'login');
    }
}

function regenerateSessionToken($db)
{
    $token = bin2hex(random_bytes(32));
    $query = $db->prepare('UPDATE users SET session_token = :session_token WHERE id = :id');
    $query->bindValue(':id', $_SESSION['user_id']);
    $query->bindValue(':session_token', $token);
    $query->execute();
    $_SESSION['token'] = $token;
}

function checkCaptcha($mustache, $config)
{
    $data = ['secret' => $config['hCaptchaSecretKey'], 'response' => $_POST['h-captcha-response']];
    $verify = curl_init();
    curl_setopt($verify, CURLOPT_URL, 'https://hcaptcha.com/siteverify');
    curl_setopt($verify, CURLOPT_POST, true);
    curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($verify);
    $responseData = json_decode($response);
    if (!$responseData->success)
        render(403, '403', $mustache, $data);
}

function validateLogin($db)
{
    if (isset($_POST['username']) && isset($_POST['password']) && strlen($_POST['username']) <= 50) {
        $query = $db->prepare('SELECT id, username, password FROM users WHERE (username = :username OR email = :email) AND is_verified = 1');
        $query->bindParam(':username', $_POST['username']);
        $query->bindParam(':email', $_POST['username']);
        $query->execute();
        $row = $query->fetch();
        if (!$row)
            return FALSE;
        if (password_verify($_POST['password'], $row['password']))
            return $row;
    }
    return FALSE;
}

function login($db, $user)
{
    session_regenerate_id(TRUE);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['token'] = getSessionToken($db);
    if (!$_SESSION['token']) {
        regenerateSessionToken($db);
    }
}

function validatePassword()
{
    $errors = [];
    $fields = ['password', 'password2'];
    foreach ($fields as $field) {
        if (!isset($_POST[$field]) || !is_string($_POST[$field]) || strlen($_POST[$field]) < 3 || strlen($_POST[$field]) > 50) {
            $errors[] = ucfirst(trim($field, '2')) . ' needs to be at least 3-50 characters long.';
        }
    }
    if (isset($_POST['password']) && isset($_POST['password2']) && $_POST['password'] !== $_POST['password2']) {
        $errors[] = 'Passwords do not match.';
    }
    return $errors;
}

function validateRegistration($config, $db)
{
    $errors = [];
    $fields = ['username', 'password', 'password2', 'email', 'answer'];
    foreach ($fields as $field) {
        if (!isset($_POST[$field]) || !is_string($_POST[$field]) || strlen($_POST[$field]) < 3 || strlen($_POST[$field]) > 50) {
            $errors[] = ucfirst(trim($field, '2')) . ' needs to be at least 3-50 characters long.';
        }
        if (isset($_POST[$field])) {
            $_POST[$field] = str_replace(["\r", "\n"], '', $_POST[$field]);
        }
    }
    if (isset($_POST['username']) && !preg_match('/^[a-zA-Z0-9 _-]+$/', $_POST['username'])) {
        $errors[] = 'Username can only contain letters, numbers, spaces, underscores, and hyphens.';
    }
    if (preg_match('/\s{2,}/', $_POST['username']) || preg_match('/^\s|\s$/', $_POST['username'])) {
        $errors[] = 'Username cannot have leading/trailing or multiple consecutive spaces.';
    }
    if (isset($_POST['password']) && isset($_POST['password2']) && $_POST['password'] !== $_POST['password2']) {
        $errors[] = 'Passwords do not match.';
    }
    if (isset($_POST['email'])) {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $_POST['email'] = $email;
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email is not valid.';
        }
    }
    if (isset($_POST['answer']) && strtolower($_POST['answer']) != strtolower($config['iqAnswer'])) {
        $errors[] = 'The answer is wrong.';
    }
    if (isset($_POST['username']) && isset($_POST['email'])) {
        $query = $db->prepare('SELECT COUNT(id) FROM users WHERE username = :username OR email = :email');
        $query->bindParam(':username', $_POST['username']);
        $query->bindParam(':email', $_POST['email']);
        $query->execute();
        if ($query->fetchColumn() !== 0) {
            $errors[] = 'Username or email may already be registered.';
        }
    }
    return $errors;
}

function addUser($db)
{
    $query = $db->prepare('INSERT INTO users(username, password, email, is_verified) VALUES(:username, :password, :email, 0)');
    $query->bindValue(':username', $_POST['username']);
    $query->bindValue(':password', password_hash($_POST['password'], PASSWORD_DEFAULT));
    $query->bindValue(':email', $_POST['email']);
    $query->execute();
    return $db->lastInsertId();
}

function getUserByEmail($db, $email)
{
    $email = substr(trim($email), 0, 50);
    $query = $db->prepare('SELECT id, email FROM users WHERE email = :email');
    $query->bindValue(':email', $email);
    $query->execute();
    return $query->fetch();
}

function generateVerification($db, $userId)
{
    $query = $db->prepare('DELETE FROM verifications WHERE user_id = :user_id');
    $query->bindValue(':user_id', $userId);
    $query->execute();

    $code = bin2hex(random_bytes(32));
    $query = $db->prepare('INSERT INTO verifications(code, user_id) VALUES(:code, :user_id)');
    $query->bindValue(':code', $code);
    $query->bindValue(':user_id', $userId);
    $query->execute();
    return $code;
}

function sendEmail($config, $to, $subject, $content)
{
    try {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://api.sendgrid.com/v3/mail/send');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $config['sendGridKey'], 'Content-Type: application/json'
        ]);
        $data = [
            "personalizations" => $to,
            "from" => ["email" => $config['emailFrom'], "name" => $config['websiteTitle']],
            "reply_to" => ["email" => $config['emailFrom'], "name" => $config['websiteTitle']],
            "subject" => $subject,
            "content" => [["type" => "text/plain", "value" => $content]]
        ];
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        $response = curl_exec($ch);
        curl_close($ch);
        return (curl_getinfo($ch, CURLINFO_HTTP_CODE) === 202);
    } catch (Exception $e) {
        return FALSE;
    }
}

function sendVerificationEmail($config, $email, $code)
{
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $url = $config['baseurl'] . 'verify/' . $code;
    $content = "Welcome to the forums!\n\nYou've just registered a new account. If this wasn't you, ignore this email. Click this link to verify your account:\n\n" . $url;
    $to = [["to" => [["email" => $email]]]];
    return sendEmail($config, $to, 'Verify your ' . $config['websiteTitle'] . ' Account', $content);
}

function sendResetEmail($config, $email, $code)
{
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $url = $config['baseurl'] . 'reset/' . $code;
    $content = "To reset your password, click the link below. If this wasn't you, ignore this email.\n\n" . $url;
    $to = [["to" => [["email" => $email]]]];
    return sendEmail($config, $to, 'Reset ' . $config['websiteTitle'] . ' Password', $content);
}

function sendNotificationEmails($config, $db, $threadId)
{
    $emails = [];
    $query = $db->prepare('SELECT title FROM threads WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $threadId);
    $query->execute();
    $title = $query->fetchColumn(0);

    $query = $db->prepare('SELECT email FROM users WHERE id = :user_id LIMIT 1');
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->execute();
    $myEmail = $query->fetchColumn(0);

    // Mentions
    preg_match_all('/@([a-zA-Z0-9_-]{1,50})/', $_POST['content'], $matches);
    if (!empty($matches[1])) {
        $usernames = array_unique($matches[1]);
        foreach ($usernames as $username) {
            $query = $db->prepare('SELECT email FROM users WHERE LOWER(username) = LOWER(:username) AND notifications = 1 LIMIT 1');
            $query->bindValue(':username', $username, PDO::PARAM_STR);
            $query->execute();
            $email = $query->fetchColumn();
            $filteredEmail = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
            if (filter_var($filteredEmail, FILTER_VALIDATE_EMAIL) && strcasecmp($filteredEmail, $myEmail) !== 0) {
                $emails[] = $email;
            }
        }
    }

    // Those in thread
    $query = $db->prepare('SELECT DISTINCT u.email FROM posts AS p LEFT JOIN users AS u ON p.user_id = u.id WHERE p.thread_id = :thread_id AND u.notifications = 1');
    $query->bindValue(':thread_id', $threadId);
    $query->execute();
    $rawEmails = $query->fetchAll(PDO::FETCH_COLUMN, 0);

    foreach ($rawEmails as $email) {
        $filteredEmail = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        if (filter_var($filteredEmail, FILTER_VALIDATE_EMAIL) && strcasecmp($filteredEmail, $myEmail) !== 0) {
            $emails[] = $filteredEmail;
        }
    }
    if (!$emails)
        return;

    $url = $config['baseurl'] . 'thread/' . $threadId . '/latest';
    $url2 = $config['baseurl'] . 'notifications';
    $title = preg_replace('/[\x00-\x1F\x7F]/u', '', $title);
    $username = preg_replace('/[\x00-\x1F\x7F]/u', '', $_SESSION['username']);
    $content = $username . ' has posted on the thread "' . $title . '". Check it out!' . "\n\n" . $url;
    $content .= "\n\n" . "If you don't want notifications, sign in then visit this page:" . "\n\n" . $url2;
    $subject = '[' . $config['websiteTitle'] . '] ' . $_SESSION['username'] . ' commented on ' . $title;
    $to = [];
    foreach (array_unique($emails) as $email) {
        $to[] = ["to" => [["email" => $email]]];
    }
    return sendEmail($config, $to, $subject, $content);
}

function checkVerificationCode($db, $code)
{
    $query = $db->prepare('SELECT user_id FROM verifications WHERE code = :code LIMIT 1');
    $query->bindValue(':code', $code);
    $query->execute();
    $userId = $query->fetchColumn(0);
    if (!$userId)
        return FALSE;
    return $userId;
}

function updatePassword($db, $id)
{
    $query = $db->prepare('UPDATE users SET password = :password WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->bindValue(':password', password_hash($_POST['password'], PASSWORD_DEFAULT));
    $query->execute();

    $query = $db->prepare('DELETE FROM verifications WHERE user_id = :user_id');
    $query->bindValue(':user_id', $id);
    $query->execute();
}

function updatePost($db, $id)
{
    $query = $db->prepare('UPDATE posts SET content = :content, ts_updated = :ts_updated WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->bindValue(':content', $_POST['content']);
    $query->bindValue(':ts_updated', time());
    $query->execute();
}

function movePost($db, $id, $threadId)
{
    $query = $db->prepare('SELECT id FROM threads WHERE id = :thread_id LIMIT 1');
    $query->bindValue(':thread_id', $threadId);
    $query->execute();
    if (!$query->fetchColumn(0)) {
        $_POST['title'] = 'New Thread';
        $threadId = addThread($db);
    }

    $query = $db->prepare('UPDATE posts SET thread_id = :thread_id WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->bindValue(':thread_id', $threadId);
    $query->execute();

    $query = $db->prepare('
        SELECT
            (SELECT user_id FROM posts WHERE thread_id = :thread_id ORDER BY id ASC LIMIT 1) AS first_user_id,
            (SELECT user_id FROM posts WHERE thread_id = :thread_id ORDER BY id DESC LIMIT 1) AS last_user_id
    ');
    $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
    $query->execute();
    $row = $query->fetch(PDO::FETCH_ASSOC);

    $query = $db->prepare('UPDATE threads SET user_id = :user_id, last_user_id = :last_user_id WHERE id = :thread_id LIMIT 1');
    $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
    $query->bindValue(':user_id', $row['first_user_id'], PDO::PARAM_INT);
    $query->bindValue(':last_user_id', $row['last_user_id'], PDO::PARAM_INT);
    $query->execute();
}

function updateThread($db, $id)
{
    $query = $db->prepare('UPDATE threads SET title = :title WHERE id = :id');
    $query->bindValue(':title', $_POST['title']);
    $query->bindValue(':id', $id);
    $query->execute();
}

function verifyUser($db, $code)
{
    $query = $db->prepare('SELECT user_id FROM verifications WHERE code = :code LIMIT 1');
    $query->bindValue(':code', $code);
    $query->execute();
    $userId = $query->fetchColumn(0);
    if (!$userId)
        return FALSE;

    $query = $db->prepare('DELETE FROM verifications WHERE user_id = :user_id');
    $query->bindValue(':user_id', $userId);
    $query->execute();

    $query = $db->prepare('UPDATE users SET is_verified = 1 WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $userId);
    $query->execute();
    return TRUE;
}

function validateThread($config, $baseurl, &$errors)
{
    if (!isset($_POST['title']) || !is_string($_POST['title']) || strlen($_POST['title']) < 3 || strlen($_POST['title']) > 100) {
        $errors[] = 'Post title must be 3-100 characters.';
    } else if (isset($_POST['title']) && is_string($_POST['title'])) {
        $_POST['title'] = str_replace(["\r", "\n"], '', $_POST['title']);
        if (!in_array($_SESSION['username'], $config['adminUsernames']) && !in_array($_SESSION['username'], $config['trustedUsernames']) && isSpam($config, $baseurl, $_POST['title'])) {
            $errors[] = 'Thread title looks spamlike. Please reach out for help in the live chat.';
        }
    }
}

function validatePost($config, $baseurl, &$errors)
{
    if (!isset($_POST['content']) || !is_string($_POST['content']) || strlen($_POST['content']) < 1 || strlen($_POST['content']) > 5000) {
        $errors[] = 'Post content must not be blank or exceed 5000 characters.';
    } else if (!in_array($_SESSION['username'], $config['adminUsernames']) && !in_array($_SESSION['username'], $config['trustedUsernames']) && isSpam($config, $baseurl, $_POST['content'])) {
        $errors[] = 'Post body looks spamlike. Please reach out for help in the live chat.';
    }
}

function addThread($db)
{
    $query = $db->prepare('INSERT INTO threads(title, user_id, ts_created, ts_updated) VALUES(:title, :user_id, :ts_created, :ts_updated)');
    $query->bindValue(':title', $_POST['title']);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':ts_created', time());
    $query->bindValue(':ts_updated', time());
    $query->execute();
    return $db->lastInsertId();
}

function addPost($db, $threadId)
{
    $query = $db->prepare('INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated) VALUES(:thread_id, :user_id, :content, :ts_created, :ts_updated)');
    $query->bindValue(':thread_id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':content', $_POST['content']);
    $query->bindValue(':ts_created', time());
    $query->bindValue(':ts_updated', time());
    $query->execute();
    $postId = $db->lastInsertId();

    $query = $db->prepare('UPDATE threads SET last_user_id = :user_id, ts_updated = :ts_updated WHERE id = :thread_id');
    $query->bindValue(':thread_id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':ts_updated', time());
    $query->execute();
    return $postId;
}

function addVote($db, $postId, $vote)
{
    $stmt = $db->prepare('SELECT value FROM votes WHERE user_id = :user_id AND post_id = :post_id');
    $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->bindValue(':post_id', $postId, PDO::PARAM_INT);
    $stmt->execute();
    $current = $stmt->fetchColumn();

    if ($current === false) {
        $stmt = $db->prepare('INSERT INTO votes (user_id, post_id, value) VALUES (:user_id, :post_id, :value)');
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->bindValue(':post_id', $postId, PDO::PARAM_INT);
        $stmt->bindValue(':value', $vote, PDO::PARAM_INT);
        $stmt->execute();
    } elseif ((int) $current === $vote) {
        $stmt = $db->prepare('DELETE FROM votes WHERE user_id = :user_id AND post_id = :post_id');
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->bindValue(':post_id', $postId, PDO::PARAM_INT);
        $stmt->execute();
    } else {
        $stmt = $db->prepare('UPDATE votes SET value = :value WHERE user_id = :user_id AND post_id = :post_id');
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->bindValue(':post_id', $postId, PDO::PARAM_INT);
        $stmt->bindValue(':value', $vote, PDO::PARAM_INT);
        $stmt->execute();
    }
}

function redirect($url)
{
    header('Location: ' . $url, TRUE, 303);
    exit;
}

function getThreads($db, $page = 1, $perPage = 20)
{
    $results = [];
    $query = $db->prepare('
        SELECT t.id, t.title, t.views, r.last_read_at, t.user_id, u.username, lu.username AS last_username, u.email, t.ts_created, t.ts_updated, count(p.id) AS total_posts
        FROM threads AS t
        LEFT JOIN users AS u ON t.user_id = u.id
        LEFT JOIN users AS lu ON t.last_user_id = lu.id
        LEFT JOIN posts AS p ON p.thread_id = t.id
        LEFT JOIN thread_reads AS r ON r.thread_id = t.id AND r.user_id = :user_id
        GROUP BY t.id ORDER BY t.ts_updated DESC
        LIMIT :limit OFFSET :offset
    ');
    $query->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $query->bindValue(':offset', ($page - 1) * $perPage, PDO::PARAM_INT);
    if (isset($_SESSION['username'])) {
        $query->bindValue(':user_id', $_SESSION['user_id']);
    } else {
        $query->bindValue(':user_id', 0);
    }
    $query->execute();
    while ($row = $query->fetch()) {
        $results[] = [
            'id' => $row['id'],
            'title' => $row['title'],
            'username' => $row['username'],
            'last_username' => $row['last_username'],
            'views' => formatViews($row['views']),
            'total_posts' => $row['total_posts'] - 1,
            'last_page' => ceil($row['total_posts'] / $perPage),
            'is_unread' => isset($_SESSION['username']) && (!$row['last_read_at'] || $row['last_read_at'] < $row['ts_updated']),
            'ts_updated' => timeAgo($row['ts_updated']),
            'avatar' => avatar($row['username']),
            'initial' => strtoupper($row['username'][0]),
        ];
    }
    return $results;
}

function getTotalThreads($db)
{
    return (int) $db->query('SELECT COUNT(*) FROM threads')->fetchColumn();
}

function getTotalPosts($db, int $threadId): int
{
    $query = $db->prepare('SELECT COUNT(*) FROM posts WHERE thread_id = :thread_id');
    $query->bindValue(':thread_id', $threadId);
    $query->execute();
    return $query->fetchColumn(0);
}

function getPaginationPages(int $currentPage, int $totalPages): array
{
    $pages = [];
    // Always show first 3
    for ($i = 1; $i <= min(3, $totalPages); $i++) {
        $pages[] = $i;
    }
    // Pages around current
    for ($i = $currentPage - 2; $i <= $currentPage + 2; $i++) {
        if ($i > 3 && $i < $totalPages - 2) {
            $pages[] = $i;
        }
    }
    // Last 3 pages
    for ($i = max($totalPages - 2, 4); $i <= $totalPages; $i++) {
        $pages[] = $i;
    }
    $pages = array_unique($pages);
    sort($pages);

    $pagesWithGaps = [];
    $prev = 0;
    foreach ($pages as $page) {
        if ($prev && $page > $prev + 1) {
            $pagesWithGaps[] = ['page' => FALSE];
        }
        $pagesWithGaps[] = ['page' => $page, 'is_active' => $page === $currentPage];
        $prev = $page;
    }
    $pagesWithGaps[0]['is_first'] = TRUE;
    return $pagesWithGaps;
}

function formatViews($num)
{
    if ($num >= 1000000) {
        return round($num / 1000000, 1) . 'M';
    } elseif ($num >= 1000) {
        return round($num / 1000, 1) . 'k';
    }
    return (string) $num;
}

function timeAgo(int $timestamp): string
{
    $diff = time() - $timestamp;
    if ($diff < 60)
        return 'just now';
    if ($diff < 3600)
        return floor($diff / 60) . ' minute' . ($diff < 120 ? '' : 's') . ' ago';
    if ($diff < 86400)
        return floor($diff / 3600) . ' hour' . ($diff < 7200 ? '' : 's') . ' ago';
    if ($diff < 604800)
        return floor($diff / 86400) . ' day' . ($diff < 172800 ? '' : 's') . ' ago';
    if ($diff < 2419200)
        return floor($diff / 604800) . ' week' . ($diff < 1209600 ? '' : 's') . ' ago';
    if ($diff < 29030400)
        return floor($diff / 2592000) . ' month' . ($diff < 5184000 ? '' : 's') . ' ago';
    return floor($diff / 29030400) . ' year' . ($diff < 58060800 ? '' : 's') . ' ago';
}

function getThread($config, $mustache, $db, $threadId, $page, $perPage, &$data)
{
    $query = $db->prepare('
        SELECT t.id, t.title, t.user_id, u.username, t.ts_created, t.ts_updated
        FROM threads AS t LEFT JOIN users AS u ON t.user_id = u.id WHERE t.id = :id LIMIT 1');
    $query->bindValue(':id', $threadId);
    $query->execute();
    $row = $query->fetch();
    if (!$row)
        render(404, '404', $mustache, $data);
    $data['title'] = $row['title'];
    $data['can_edit'] = isset($_SESSION['user_id']) ? $row['user_id'] === $_SESSION['user_id'] || in_array($_SESSION['username'], $config['adminUsernames']) : FALSE;
    $data['posts'] = [];

    $query = $db->prepare('
        SELECT p.id, p.content, p.thread_id, p.user_id, u.username, u.email, p.ts_created, p.ts_updated,
            SUM(CASE WHEN v.value = 1 THEN 1 ELSE 0 END) AS upvotes,
            SUM(CASE WHEN v.value = -1 THEN 1 ELSE 0 END) AS downvotes,
            MAX(CASE WHEN v.user_id = :user_id THEN v.value ELSE NULL END) AS user_vote
        FROM posts AS p
        LEFT JOIN users AS u ON p.user_id = u.id
        LEFT JOIN votes AS v ON p.id = v.post_id
        WHERE p.thread_id = :id
        GROUP BY p.id
        ORDER BY p.id ASC
        LIMIT :limit OFFSET :offset
    ');
    $query->bindValue(':id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id'] ?? 0);
    $query->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $query->bindValue(':offset', ($page - 1) * $perPage, PDO::PARAM_INT);
    $query->execute();
    while ($row = $query->fetch()) {
        $Parsedown = new ForumMarkdown();
        $Parsedown->setSafeMode(true);
        $content = $row['content'];
        $content = preProcessMentions($content);
        $content = $Parsedown->text($content);
        $content = postProcessMentions($content);
        $row['can_vote'] = !empty($_SESSION['user_id']) && $_SESSION['user_id'] !== $row['user_id'];
        $row['has_votes'] = $row['upvotes'] || $row['downvotes'];
        $row['user_upvote'] = $row['user_vote'] === 1;
        $row['user_vote'] = $row['user_vote'] !== NULL;
        $row['ts_updated'] = $row['ts_updated'] > $row['ts_created'] + 5 ? date('j M Y', $row['ts_updated']) : '';
        $row['ts_created'] = date('j M Y', $row['ts_created']);
        $row['avatar'] = avatar($row['username']);
        $row['initial'] = strtoupper($row['username'][0]);
        $row['content'] = $content;
        $row['can_edit'] = isset($_SESSION['user_id']) ? $row['user_id'] === $_SESSION['user_id'] || in_array($_SESSION['username'], $config['adminUsernames']) : FALSE;
        $data['posts'][] = $row;
    }
}

function preProcessMentions($html)
{
    return preg_replace_callback('/(^|[\s(])@([a-zA-Z0-9_-]{3,50})\b/', function ($matches) {
        return $matches[1] . '**@' . $matches[2] . '**';
    }, $html);
}

function postProcessMentions($html)
{
    return preg_replace_callback('/<strong>@([a-zA-Z0-9_-]{3,50})<\/strong>/', function ($matches) {
        return '<span class="usertag">@' . htmlspecialchars($matches[1]) . '</span>';
    }, $html);
}

function getPost($config, $db, $id)
{
    if (in_array($_SESSION['username'], $config['adminUsernames'])) {
        $query = $db->prepare('SELECT content, thread_id FROM posts WHERE id = :id LIMIT 1');
    } else {
        $query = $db->prepare('SELECT content, thread_id FROM posts WHERE id = :id AND user_id = :user_id LIMIT 1');
        $query->bindValue(':user_id', $_SESSION['user_id']);
    }
    $query->bindValue(':id', $id);
    $query->execute();
    return $query->fetch();
}

function deletePost($config, $db, $id)
{
    if (in_array($_SESSION['username'], $config['adminUsernames'])) {
        $query = $db->prepare('SELECT thread_id FROM posts WHERE id = :id LIMIT 1');
    } else {
        $query = $db->prepare('SELECT thread_id FROM posts WHERE id = :id AND user_id = :user_id LIMIT 1');
        $query->bindValue(':user_id', $_SESSION['user_id']);
    }
    $query->bindValue(':id', $id);
    $query->execute();
    $threadId = $query->fetchColumn(0);

    if (!$threadId)
        return;

    $query = $db->prepare('DELETE FROM posts WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->execute();
    $query->fetch();

    $query = $db->prepare('
        SELECT 
            (SELECT user_id FROM posts WHERE thread_id = :thread_id ORDER BY id ASC LIMIT 1) AS first_user_id,
            (SELECT user_id FROM posts WHERE thread_id = :thread_id ORDER BY id DESC LIMIT 1) AS last_user_id
    ');
    $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
    $query->execute();
    $row = $query->fetch(PDO::FETCH_ASSOC);

    if ($row['first_user_id'] && $row['last_user_id']) {
        $query = $db->prepare('UPDATE threads SET user_id = :user_id, last_user_id = :last_user_id WHERE id = :thread_id LIMIT 1');
        $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
        $query->bindValue(':user_id', $row['first_user_id'], PDO::PARAM_INT);
        $query->bindValue(':last_user_id', $row['last_user_id'], PDO::PARAM_INT);
        $query->execute();
    } else {
        $query = $db->prepare('DELETE FROM threads WHERE id = :id LIMIT 1');
        $query->bindValue(':id', $threadId);
        $query->execute();
    }
}

function deleteThread($config, $db, $id)
{
    if (in_array($_SESSION['username'], $config['adminUsernames'])) {
        $query = $db->prepare('DELETE FROM threads WHERE id = :id LIMIT 1');
    } else {
        $query = $db->prepare('DELETE FROM threads WHERE id = :id AND user_id = :user_id LIMIT 1');
        $query->bindValue(':user_id', $_SESSION['user_id']);
    }
    $query->bindValue(':id', $id);
    $query->execute();
}

function handleUpload($config, $db)
{
    if (!isset($_FILES['attachment']) || $_FILES['attachment']['error'] !== UPLOAD_ERR_OK)
        render(400, '400', $mustache, $data);

    $file = $_FILES['attachment'];

    if ($file['size'] > $config['maxUploadMb'] * 1024 * 1024) {
        die('File too large.');
    }

    $allowedTypes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'application/pdf' => 'pdf',
        'text/plain' => 'txt',  // including .ifc
        'application/zip' => 'zip',
        'application/x-zip-compressed' => 'zip',
    ];

    $originalExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($file['tmp_name']);

    if ($originalExt === 'ifc' && ($mime === 'text/plain' || $mime === 'application/octet-stream')) {
        $ext = 'ifc';
    } elseif (isset($allowedTypes[$mime])) {
        $ext = $allowedTypes[$mime];
    } else {
        render(403, '403', $mustache, $data);
    }

    if ($ext === 'ifc') {
        $contents = file_get_contents($file['tmp_name']);
        if (!str_starts_with(trim($contents), 'ISO-10303-21;'))
            render(400, '400', $mustache, $data);
    }

    $filename = bin2hex(random_bytes(16)) . '.' . $ext;
    $subdir = substr($filename, 0, 2) . '/' . substr($filename, 2, 2);
    $uploadDir = realpath(__DIR__ . '/uploads') . '/' . $subdir;
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, TRUE);
    }
    if (!move_uploaded_file($file['tmp_name'], $uploadDir . DIRECTORY_SEPARATOR . $filename))
        render(500, '500', $mustache, $data);
    return $subdir . '/' . $filename;
}

function recordThreadView($db, $threadId)
{
    $key = "viewed_thread_$threadId";
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = true;
        $query = $db->prepare('UPDATE threads SET views = views + 1 WHERE id = ?');
        $query->execute([$threadId]);
    }
}

function markThreadAsRead(PDO $db, int $threadId): void
{
    $now = time();
    $query = $db->prepare('INSERT INTO thread_reads (user_id, thread_id, last_read_at)
        VALUES (:user_id, :thread_id, :now)
        ON CONFLICT(user_id, thread_id) DO UPDATE SET last_read_at = :now');
    $query->execute([
        ':user_id' => $_SESSION['user_id'],
        ':thread_id' => $threadId,
        ':now' => $now,
    ]);
}

function getThreadId(PDO $db, int $postId): int
{
    $query = $db->prepare('SELECT thread_id FROM posts WHERE id = :id');
    $query->execute([':id' => $postId]);
    return (int) $query->fetchColumn();
}

function isSpam($config, $baseurl, $content)
{
    $request = 'api_key=' . urlencode($config['akismetKey'])
        . '&blog=' . urlencode($baseurl)
        . '&user_ip=' . urlencode($_SERVER['REMOTE_ADDR'])
        . '&user_agent=' . urlencode($_SERVER['HTTP_USER_AGENT'])
        . '&referrer=' . urlencode($_SERVER['HTTP_REFERER'])
        . '&comment_type=comment'
        . '&comment_author=' . urlencode($_SESSION['username'])
        . '&comment_content=' . urlencode($content);

    $host = $http_host = 'rest.akismet.com';
    $path = '/1.1/comment-check';
    $port = 443;
    $akismet_ua = 'WordPress/4.4.1 | Akismet/3.1.7';
    $content_length = strlen($request);
    $http_request = "POST $path HTTP/1.0\r\n";
    $http_request .= "Host: $host\r\n";
    $http_request .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $http_request .= "Content-Length: {$content_length}\r\n";
    $http_request .= "User-Agent: {$akismet_ua}\r\n";
    $http_request .= "\r\n";
    $http_request .= $request;

    $response = '';
    if (false != ($fs = @fsockopen('ssl://' . $http_host, $port, $errno, $errstr, 10))) {
        fwrite($fs, $http_request);
        while (!feof($fs)) {
            $response .= fgets($fs, 1160);  // One TCP-IP packet
        }
        fclose($fs);
        $response = explode("\r\n\r\n", $response, 2);
    }
    if ('true' == $response[1])
        return true;
    return false;
}

function tryRenderFromCache($key): void
{
    if (!empty($_SESSION['user_id']))
        return;
    $html = apcu_fetch('html_' . $key . '_' . sha1($_SERVER['REQUEST_URI']));
    if ($html !== false) {
        echo $html;
        exit;
    }
}

function saveCache($key, string $html, int $ttl = 900): void
{
    apcu_store('html_' . $key . '_' . sha1($_SERVER['REQUEST_URI']), $html, $ttl);
}

function invalidateCache($keys)
{
    $cacheKeys = apcu_cache_info()['cache_list'] ?? [];
    foreach ($cacheKeys as $item) {
        foreach ($keys as $key) {
            if (str_starts_with($item['info'], 'html_' . $key)) {  // Omit _ suffix to allow wildcard
                apcu_delete($item['info']);
            }
        }
    }
}

function avatar(string $username): string
{
    $colors = ['coral', 'denim', 'amber', 'teal', 'violet', 'sage', 'maroon', 'sunflower', 'ocean', 'charcoal'];
    $index = crc32($username) % count($colors);
    return 'avatar-' . $colors[$index];
}

function render($code, $template, $mustache, $data, $cacheKey = NULL)
{
    http_response_code($code);
    $html = $mustache->render($template, $data);
    echo $html;
    if ($cacheKey && empty($_SESSION['user_id']))
        saveCache($cacheKey, $html);
    exit;
}

class ForumMarkdown extends Parsedown
{
    protected function inlineImage($excerpt)
    {
        $element = parent::inlineImage($excerpt);
        if ($element) {
            $element['element']['attributes']['loading'] = 'lazy';
        }
        return $element;
    }

    protected function inlineLink($excerpt)
    {
        $element = parent::inlineLink($excerpt);
        if ($element) {
            $element['element']['attributes']['rel'] = 'nofollow';
        }
        return $element;
    }

    protected function inlineUrl($excerpt)
    {
        $element = parent::inlineUrl($excerpt);
        if (!$element)
            return $element;
        $youtubePattern = '~(?:https?://)?(?:www\.)?(?:m\.)?(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/|youtube\.com/shorts/)([A-Za-z0-9_-]{11})~i';
        if (preg_match($youtubePattern, $element['element']['attributes']['href'], $matches)) {
            $videoId = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
            return [
                'extent' => $element['extent'],
                'position' => $element['position'],
                'element' => [
                    'name' => 'iframe',
                    'attributes' => ['src' => 'https://www.youtube.com/embed/' . $videoId, 'frameborder' => '0', 'allowfullscreen' => TRUE],
                    'handler' => 'line',
                    'text' => '',
                ],
            ];
        }
        $mime = ['mp4' => 'video/mp4', 'webm' => 'video/webm', 'ogg' => 'video/ogg'];
        $urlPath = strtolower(parse_url($element['element']['attributes']['href'])['path']);
        foreach ($mime as $ext => $mimetype) {
            if (str_ends_with($urlPath, $ext)) {
                return [
                    'extent' => $element['extent'],
                    'position' => $element['position'],
                    'element' => [
                        'name' => 'video',
                        'attributes' => ['width' => '100%', 'controls' => true],
                        'handler' => 'element',
                        'text' => [
                            'name' => 'source',
                            'attributes' => [
                                'src' => htmlspecialchars($element['element']['attributes']['href']), 'type' => $mimetype
                            ]
                        ],
                    ],
                ];
            }
        }
        $element['element']['attributes']['rel'] = 'nofollow';
        return $element;
    }
}

checkSessionToken($baseurl, $db);

$queryString = [];
if ($method === 'GET' && preg_match('/^(p[0-9]{1,3})?$/', $uri, $queryString)) {
    tryRenderFromCache('index');
    generateCsrf($data);
    $page = (count($queryString) === 2) ? (int) substr($queryString[1], 1) : 1;
    $data['threads'] = getThreads($db, $page, $perPage);
    $totalPages = ceil(getTotalThreads($db) / $perPage);
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    render(200, 'index', $mustache, $data, 'index');
} else if ($method === 'GET' && $uri === 'login') {
    generateCsrf($data);
    $data['iq_question'] = $config['iqQuestion'];
    render(200, 'login', $mustache, $data);
} else if ($method === 'POST' && $uri === 'login') {
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'login', 5, 300);
    $user = validateLogin($db);
    if ($user !== FALSE) {
        login($db, $user);
        redirect($baseurl);
    }
    $data['has_login_error'] = TRUE;
    $data['username'] = isset($_POST['username']) ? $_POST['username'] : '';
    $data['iq_question'] = $config['iqQuestion'];
    render(400, 'login', $mustache, $data);
} else if ($method === 'POST' && $uri === 'register') {
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'register', 5, 300);
    checkCaptcha($mustache, $config);
    $data['errors'] = validateRegistration($config, $db);
    if (count($data['errors']) === 0) {
        $userId = addUser($db);
        $code = generateVerification($db, $userId);
        if (sendVerificationEmail($config, $_POST['email'], $code) === FALSE)
            render(500, '500', $mustache, $data);
        $data['is_sent'] = TRUE;
        render(200, 'verify', $mustache, $data);
    }
    $data['has_register_errors'] = TRUE;
    $data['username'] = isset($_POST['username']) ? $_POST['username'] : '';
    $data['email'] = isset($_POST['email']) ? $_POST['email'] : '';
    $data['answer'] = isset($_POST['answer']) ? $_POST['answer'] : '';
    $data['iq_question'] = $config['iqQuestion'];
    render(400, 'login', $mustache, $data);
} else if ($method === 'GET' && $uri == 'reset') {
    generateCsrf($data);
    render(200, 'reset', $mustache, $data);
} else if ($method === 'POST' && $uri == 'reset') {
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'verify', 3, 300);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id']);
        if (sendResetEmail($config, $user['email'], $code) === FALSE)
            render(500, '500', $mustache, $data);
    }
    $data['is_sent'] = TRUE;
    render(200, 'reset', $mustache, $data);
} else if ($method === 'GET' && preg_match('/^reset\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    generateCsrf($data);
    $data['code'] = $queryString[1];
    $data['is_valid_code'] = (bool) checkVerificationCode($db, $queryString[1]);
    render(200, 'reset', $mustache, $data);
} else if ($method === 'POST' && preg_match('/^reset\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'reset', 3, 300);
    $data['code'] = $queryString[1];
    $userId = checkVerificationCode($db, $queryString[1]);
    $data['is_valid_code'] = (bool) $userId;
    if ($data['is_valid_code']) {
        $data['errors'] = validatePassword();
        if (count($data['errors']) === 0) {
            updatePassword($db, $userId);
            regenerateSessionToken($db);
            $data['is_success'] = TRUE;
        }
    }
    render(200, 'reset', $mustache, $data);
} else if ($method === 'GET' && $uri == 'verify') {
    generateCsrf($data);
    render(200, 'verify', $mustache, $data);
} else if ($method === 'POST' && $uri == 'verify') {
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'verify', 3, 300);
    checkCaptcha($mustache, $config);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id']);
        if (sendVerificationEmail($config, $user['email'], $code) === FALSE)
            render(500, '500', $mustache, $data);
    }
    $data['is_sent'] = TRUE;
    render(200, 'verify', $mustache, $data);
} else if ($method === 'GET' && preg_match('/^verify\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    generateCsrf($data);
    $data['code'] = $queryString[1];
    $data['is_success'] = verifyUser($db, $queryString[1]);
    render(200, 'verify', $mustache, $data);
} else if ($method === 'POST' && $uri === 'logout') {
    checkCsrf($mustache, $data);
    logout();
    redirect($baseurl);
} else if ($method === 'GET' && $uri === 'post') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    generateCsrf($data);
    render(200, 'post', $mustache, $data);
} else if ($method === 'POST' && $uri === 'post') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'post', 5, 10);
    $data['errors'] = [];
    validateThread($config, $baseurl, $data['errors']);
    validatePost($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $mustache, $data, 'post-success', 5, 300);
        $threadId = addThread($db);
        addPost($db, $threadId);
        sendNotificationEmails($config, $db, $threadId);
        invalidateCache(['index']);
        redirect($baseurl . 'thread/' . $threadId);
    }
    $data['has_error'] = TRUE;
    $data['title'] = $_POST['title'];
    $data['content'] = $_POST['content'];
    render(400, 'post', $mustache, $data);
} else if ($method === 'GET' && preg_match('/^thread\/([0-9]{1,50})\/latest$/', $uri, $queryString)) {
    $threadId = (int) $queryString[1];
    $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
    redirect($baseurl . 'thread/' . $threadId . '/p' . $totalPages);
} else if ($method === 'GET' && preg_match('/^thread\/([0-9]{1,50})(\/(p[0-9]{1,3})?)?$/', $uri, $queryString)) {
    $page = (count($queryString) === 4) ? (int) substr($queryString[3], 1) : 1;
    $threadId = (int) $queryString[1];
    $cacheKey = 'thread/' . $threadId . '/p' . $page;
    tryRenderFromCache($cacheKey);
    getThread($config, $mustache, $db, $threadId, $page, $perPage, $data);
    $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
    $data['page'] = $page;
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    recordThreadView($db, $threadId);
    if ($data['is_logged_in']) {
        markThreadAsRead($db, $threadId);
    }
    $data['id'] = $threadId;
    $data['html_title'] = $data['title'];
    generateCsrf($data);
    render(200, 'thread', $mustache, $data, $cacheKey);
} else if ($method === 'POST' && preg_match('/^thread\/([0-9]{1,50})(\/(p[0-9]{1,3})?)?$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    $page = (count($queryString) === 4) ? (int) substr($queryString[3], 1) : 1;
    $threadId = (int) $queryString[1];
    $data['errors'] = [];
    validatePost($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $mustache, $data, 'post-success', 5, 300);
        $postId = addPost($db, $threadId);
        sendNotificationEmails($config, $db, $threadId);
        $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
        invalidateCache(['index', 'thread/' . $threadId . '/p' . $totalPages]);
        redirect($baseurl . 'thread/' . $threadId . '/p' . $totalPages . '#' . $postId);
    }
    $data['has_error'] = TRUE;
    getThread($config, $mustache, $db, $threadId, $page, $perPage, $data);
    $data['id'] = $threadId;
    $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
    $data['page'] = $page;
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    $data['html_title'] = $data['title'];
    render(400, 'thread', $mustache, $data, $cacheKey);
} else if (in_array($method, ['GET', 'POST']) && preg_match('/^thread\/edit\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $threadId = (int) $queryString[1];
    $thread = getThread($config, $mustache, $db, $threadId, 1, 1, $data);
    $data['id'] = $threadId;
    if ($method === 'GET') {
        generateCsrf($data);
        render(200, 'threadedit', $mustache, $data);
    }
    $data['title'] = $_POST['title'];
    $data['errors'] = [];
    checkCsrf($mustache, $data);
    validateThread($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $mustache, $data, 'threadedit', 5, 300);
        updateThread($db, $threadId);
        invalidateCache(['index', 'thread/' . $threadId . '/p']);
        redirect($baseurl . 'thread/' . $threadId);
    }
    $data['has_error'] = TRUE;
    render(400, 'threadedit', $mustache, $data);
} else if (in_array($method, ['GET', 'POST']) && preg_match('/^post\/edit\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $postId = (int) $queryString[1];
    $post = getPost($config, $db, $postId);
    if (!$post)
        return render(404, '404', $mustache, $data);
    $data['id'] = $postId;
    $data['can_move'] = in_array($_SESSION['username'], $config['adminUsernames']);
    if ($method === 'GET') {
        generateCsrf($data);
        $data['content'] = $post['content'];
        render(200, 'postedit', $mustache, $data);
    }
    $data['content'] = $_POST['content'];
    $data['errors'] = [];
    checkCsrf($mustache, $data);
    validatePost($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $mustache, $data, 'postedit', 5, 300);
        updatePost($db, $postId);
        invalidateCache(['thread/' . $post['thread_id'] . '/p']);
        redirect($baseurl . 'thread/' . $post['thread_id']);
    }
    $data['has_error'] = TRUE;
    render(400, 'postedit', $mustache, $data);
} else if ($method === 'POST' && preg_match('/^thread\/delete\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'threaddelete', 5, 300);
    $threadId = (int) $queryString[1];
    deleteThread($config, $db, $threadId);
    invalidateCache(['index', 'thread/' . $threadId . '/p']);
    redirect($baseurl);
} else if ($method === 'POST' && preg_match('/^post\/delete\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'postdelete', 5, 300);
    $postId = (int) $queryString[1];
    $threadId = getThreadId($db, $postId);
    deletePost($config, $db, $postId);
    invalidateCache(['index', 'thread/' . $threadId . '/p']);
    redirect($baseurl . 'thread/' . $threadId . '/latest');
} else if ($method === 'POST' && preg_match('/^post\/move\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'] || !in_array($_SESSION['username'], $config['adminUsernames']))
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    $postId = (int) $queryString[1];
    $oldThreadId = getThreadId($db, $postId);
    $newThreadId = (int) $_POST['thread_id'];
    movePost($db, $postId, $newThreadId);
    invalidateCache(['index', 'thread/' . $oldThreadId . '/p']);
    redirect($baseurl);
} else if ($method === 'GET' && $uri == 'upload') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    generateCsrf($data);
    render(200, 'upload', $mustache, $data);
} else if ($method === 'POST' && $uri == 'upload') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    checkRateLimit($config, $mustache, $data, 'upload', 10, 300);
    $data['filename'] = handleUpload($config, $db);
    if (!isset($_POST['useJS']))
        render(200, 'upload', $mustache, $data);
    http_response_code(201);
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'url' => $baseurl . 'files/' . $data['filename'], 'csrf' => $data['csrf']]);
    exit;
} else if ($method === 'POST' && $uri === 'vote') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    $postId = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
    $query = $db->prepare('SELECT id FROM posts WHERE id = :id AND user_id != :user_id LIMIT 1');
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':id', $postId);
    $query->execute();
    if (!$query->fetch())
        redirect($baseurl . 'login');
    $vote = isset($_POST['vote']) ? (int) $_POST['vote'] : 0;
    $page = isset($_POST['page']) ? (int) $_POST['page'] : 1;
    if (in_array($vote, [-1, 1])) {
        addVote($db, $postId, $vote);
    }
    $threadId = getThreadId($db, $postId);
    redirect($baseurl . 'thread/' . $threadId . '/p' . $page . '#' . $postId);
} else if ($method === 'GET' && preg_match('/^mention(\/[0-9]{1,50})?\/@([A-Za-z0-9_-]{1,100})$/', $uri, $queryString)) {
    $limit = 5;
    $results = [];
    if (count($queryString) === 3) {
        // Prioritise usernames in thread
        $query = $queryString[2];
        $stmt = $db->prepare('SELECT DISTINCT u.username FROM posts AS p LEFT JOIN users AS u ON p.user_id = u.id WHERE p.thread_id = :thread_id AND u.username LIKE :query ORDER BY u.username LIMIT 5');
        $stmt->bindValue(':thread_id', substr($queryString[1], 1));
        $stmt->bindValue(':query', $query . '%');
        $stmt->execute();
        $results = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
        $limit = $limit - count($results);
        if (!$limit) {
            echo json_encode($results);
            exit;
        }
    } else {
        $query = $queryString[1];
    }
    header('Content-Type: application/json');
    $stmt = $db->prepare('SELECT username FROM users WHERE username LIKE :query ORDER BY username LIMIT :limit');
    $stmt->bindValue(':query', $query . '%');
    $stmt->bindValue(':limit', $limit);
    $stmt->execute();
    echo json_encode(array_merge($results, $stmt->fetchAll(PDO::FETCH_COLUMN, 0)));
} else if ($method === 'GET' && $uri === 'notifications') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $query = $db->prepare('UPDATE users SET notifications = NOT notifications WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id'], PDO::PARAM_INT);
    $query->execute();
    $query = $db->prepare('SELECT notifications FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id'], PDO::PARAM_INT);
    $query->execute();
    $data['is_on'] = (bool) $query->fetchColumn();
    render(200, 'notifications', $mustache, $data);
} else if ($method === 'GET' && str_starts_with($uri, 'search')) {
    redirect('https://duckduckgo.com/?q=' . urlencode('site:' . $baseurl . ' ' . trim($_GET['q'] ?? '')));
} else {
    render(404, '404', $mustache, $data);
}
