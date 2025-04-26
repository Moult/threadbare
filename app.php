<?php

session_start();

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

if (empty($_SESSION['ratelimit'])) {
    $_SESSION['ratelimit'] = ['attempts' => 0, 'time' => time()];
}

header("Content-Security-Policy: default-src 'self'; script-src 'self' https://hcaptcha.com https://*.hcaptcha.com; frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com; style-src 'self' https://hcaptcha.com https://*.hcaptcha.com; connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; img-src * data: blob:; media-src 'self' https://*.osarch.org;");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

$config = require_once (__DIR__ . '/config.php');
require_once (__DIR__ . '/vendor/autoload.php');

$baseurl = 'http://localhost/';
$perPage = 25;
$db = new \PDO('sqlite:' . __DIR__ . '/threadbare.db');
$db->exec('PRAGMA foreign_keys = ON;');
$method = $_SERVER['REQUEST_METHOD'];
$uri = trim($_SERVER['REQUEST_URI'], '/');
$mustache = new Mustache_Engine(['loader' => new Mustache_Loader_FilesystemLoader(__DIR__ . '/templates/')]);
$data = ['baseurl' => $baseurl, 'csrf' => $_SESSION['csrf'], 'captcha' => $config['hCaptchaSiteKey']];
if (isset($_SESSION['username'])) {
    $data['is_logged_in'] = TRUE;
    $data['username'] = $_SESSION['username'];
} else {
    $data['is_logged_in'] = FALSE;
}

function checkCsrf($mustache, &$data)
{
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
        var_dump($_POST['csrf']);
        var_dump($_SESSION['csrf']);
        http_response_code(403);
        echo $mustache->render('403', $data);
        exit;
    }
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    $data['csrf'] = $_SESSION['csrf'];
}

function checkRateLimit($mustache, $data, $key = 'login', $limit = 3, $window = 300)
{
    return;
    $now = time();
    if (!isset($_SESSION['ratelimit'][$key])) {
        $_SESSION['ratelimit'][$key] = ['attempts' => 0, 'time' => $now];
    }

    $record = &$_SESSION['ratelimit'][$key];

    if (($now - $record['time']) < $window) {
        $record['attempts']++;
        if ($record['attempts'] > $limit) {
            http_response_code(429);
            echo $mustache->render('429', $data);
            exit;
        }
    } else {
        $record = ['attempts' => 1, 'time' => $now];
    }
}

function checkCaptcha($mustache, $config)
{
    $data = array(
        'secret' => $config['hCaptchaSecretKey'],
        'response' => $_POST['h-captcha-response']
    );
    $verify = curl_init();
    curl_setopt($verify, CURLOPT_URL, 'https://hcaptcha.com/siteverify');
    curl_setopt($verify, CURLOPT_POST, true);
    curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($verify);
    $responseData = json_decode($response);
    if (!$responseData->success) {
        http_response_code(403);
        echo $mustache->render('403', $data);
        exit;
    }
}

function validateLogin($db)
{
    if (isset($_POST['username']) && isset($_POST['password']) && strlen($_POST['username']) <= 50) {
        $query = $db->prepare('SELECT id, password FROM users WHERE username = :username AND is_verified = 1');
        $query->bindParam(':username', $_POST['username']);
        $query->execute();
        $row = $query->fetch();
        if (!$row)
            return FALSE;
        if (password_verify($_POST['password'], $row['password']))
            return $row['id'];
    }
    return FALSE;
}

function login($userId)
{
    session_regenerate_id();
    $_SESSION['user_id'] = $userId;
    $_SESSION['username'] = $_POST['username'];
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

function validateRegistration($db)
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
    if (isset($_POST['answer']) && $_POST['answer'] != 'hcraso') {
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

function sendVerificationEmail($email, $baseurl, $code, $apiKey)
{
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $url = $baseurl . 'verify/' . $code;
    $plain = "Welcome to the OSArch Forums!\n\nYou've just registered a new account. If this wasn't you, ignore this email. Click this link to verify your account:\n\n" . $url;
    $message = new \SendGrid\Mail\Mail();
    $message->setFrom('noreply@osarch.org', 'OSArch');
    $message->setSubject('Verify your OSArch Account');
    $message->addTo($email);
    $message->addContent('text/plain', $plain);
    $sendgrid = new \SendGrid($apiKey);
    try {
        $sendgrid->send($message);
    } catch (Exception $e) {
        return FALSE;
    }
}

function sendResetEmail($email, $baseurl, $code, $apiKey)
{
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $url = $baseurl . 'reset/' . $code;
    $plain = "To reset your password for the OSArch Community, click the link below. If this wasn't you, ignore this email.\n\n" . $url;
    $message = new \SendGrid\Mail\Mail();
    $message->setFrom('noreply@osarch.org', 'OSArch');
    $message->setSubject('Reset OSArch Password');
    $message->addTo($email);
    $message->addContent('text/plain', $plain);
    $sendgrid = new \SendGrid($apiKey);
    try {
        $sendgrid->send($message);
    } catch (Exception $e) {
        return FALSE;
    }
}

function sendNotificationEmails($db, $threadId, $baseurl, $apiKey)
{
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
        $emails = [];
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

    $url = $baseurl . 'thread/' . $threadId . '/latest';
    $url2 = $baseurl . 'notifications';
    $title = preg_replace('/[\x00-\x1F\x7F]/u', '', $title);
    $username = preg_replace('/[\x00-\x1F\x7F]/u', '', $_SESSION['username']);
    $plain = $username . ' has posted on the thread "' . $title . '". Check it out!' . "\n\n" . $url;
    $plain .= "\n\n" . "If you don't want notifications, sign in then visit this page:" . "\n\n" . $url2;
    $message = new \SendGrid\Mail\Mail();
    $message->setFrom('noreply@osarch.org', 'OSArch');
    $message->setSubject('[OSArch] ' . $_SESSION['username'] . ' commented on ' . $title);
    $message->addTo('noreply@osarch.org');

    foreach (array_unique($emails) as $email) {
        $personalization = new \SendGrid\Mail\Personalization();
        $personalization->addTo(new \SendGrid\Mail\To($email));
        $message->addPersonalization($personalization);
    }

    $message->addContent('text/plain', $plain);
    $sendgrid = new \SendGrid($apiKey);
    try {
        $sendgrid->send($message);
    } catch (Exception $e) {
        return FALSE;
    }
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

function validateThread(&$errors)
{
    if (!isset($_POST['title']) || !is_string($_POST['title']) || strlen($_POST['title']) < 3 || strlen($_POST['title']) > 100) {
        $errors[] = 'Post title must be 3-100 characters.';
    }
    if (isset($_POST['title'])) {
        $_POST['title'] = str_replace(["\r", "\n"], '', $_POST['title']);
    }
}

function validatePost(&$errors)
{
    if (!isset($_POST['content']) || !is_string($_POST['content']) || strlen($_POST['content']) < 1 || strlen($_POST['content']) > 5000) {
        $errors[] = 'Post content must not be blank or exceed 5000 characters.';
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

    $query = $db->prepare('UPDATE threads SET ts_updated = :ts_updated WHERE id = :thread_id');
    $query->bindValue(':thread_id', $threadId);
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
        SELECT t.id, t.title, t.views, r.last_read_at, t.user_id, u.username, u.email, t.ts_created, t.ts_updated, count(p.id) AS total_posts
        FROM threads AS t
        LEFT JOIN users AS u ON t.user_id = u.id
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
            'views' => formatViews($row['views']),
            'total_posts' => $row['total_posts'],
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
    if (!$row) {
        http_response_code(404);
        echo $mustache->render('404', $data);
        exit;
    }
    $data['title'] = $row['title'];
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

    $query = $db->prepare('SELECT id FROM posts WHERE thread_id = :thread_id LIMIT 1');
    $query->bindValue(':thread_id', $threadId);
    $query->execute();
    $row = $query->fetch();

    if (!$row) {
        $query = $db->prepare('DELETE FROM threads WHERE id = :id LIMIT 1');
        $query->bindValue(':id', $threadId);
        $query->execute();
    }
}

function deleteThread($db, $id)
{
    $query = $db->prepare('DELETE FROM threads WHERE id = :id AND user_id = :user_id');
    $query->bindValue(':id', $id);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->execute();
}

function handleUpload($db)
{
    if (!isset($_FILES['attachment']) || $_FILES['attachment']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo $mustache->render('400', $data);
        exit;
    }

    $file = $_FILES['attachment'];

    if ($file['size'] > 5 * 1024 * 1024) {
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
        http_response_code(403);
        echo $mustache->render('403', $data);
        exit;
    }

    if ($ext === 'ifc') {
        $contents = file_get_contents($file['tmp_name']);
        if (!str_starts_with(trim($contents), 'ISO-10303-21;')) {
            http_response_code(400);
            echo $mustache->render('400', $data);
            exit;
        }
    }

    $filename = bin2hex(random_bytes(16)) . '.' . $ext;

    $uploadDir = realpath(__DIR__ . '/uploads/');
    $destination = $uploadDir . DIRECTORY_SEPARATOR . $filename;
    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        http_response_code(500);
        echo $mustache->render('500', $data);
        exit;
    }

    return $filename;
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
    invalidateCache(['index']);
}

function getThreadId(PDO $db, int $postId): int
{
    $query = $db->prepare('SELECT thread_id FROM posts WHERE id = :id');
    $query->execute([':id' => $postId]);
    return (int) $query->fetchColumn();
}

function tryRenderFromCache($key): void
{
    $cacheKey = 'html_' . ($_SESSION['user_id'] ?? '') . '_' . $key . '_' . sha1($_SERVER['REQUEST_URI']);
    $html = apcu_fetch($cacheKey);
    if ($html !== false) {
        echo $html;
        exit;
    }
}

function saveCache($key, string $html, int $ttl = 300): void
{
    $cacheKey = 'html_' . ($_SESSION['user_id'] ?? '') . '_' . $key . '_' . sha1($_SERVER['REQUEST_URI']);
    apcu_store($cacheKey, $html, $ttl);
}

function invalidateCache($keys)
{
    $userId = ($_SESSION['user_id'] ?? '');
    if (!$userId)
        return;
    $cacheKeys = apcu_cache_info()['cache_list'] ?? [];
    foreach ($cacheKeys as $item) {
        foreach ($keys as $key) {
            if (str_starts_with($item['info'], 'html_' . $userId . '_' . $key)) {  // Omit _ suffix to allow wildcard
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

class ForumMarkdown extends Parsedown
{
    protected function inlineImage($excerpt)
    {
        $element = parent::inlineImage($excerpt);
        if (isset($element)) {
            $element['element']['attributes']['loading'] = 'lazy';
            return $element;
        }
    }

    protected function inlineLink($excerpt)
    {
        $element = parent::inlineLink($excerpt);
        $mime = [
            'mp4' => 'video/mp4',
            'webm' => 'video/webm',
            'ogg' => 'video/ogg'
        ];
        if (isset($element)) {
            foreach ($mime as $ext => $mimetype) {
                if (str_ends_with($element['element']['attributes']['href'], $ext)) {
                    return array(
                        'extent' => $element['extent'] + 1,
                        'element' => array(
                            'name' => 'video',
                            'attributes' => array(
                                'width' => '100%',
                                'controls' => true,
                            ),
                            'handler' => 'element',
                            'text' => [
                                'name' => 'source',
                                'attributes' => [
                                    'src' => $element['element']['attributes']['href'],
                                    'type' => $mimetype
                                ]
                            ],
                        ),
                    );
                    var_dump($element);
                }
            }
            return $element;
        }
    }
}

$queryString = [];
if ($method === 'GET' && preg_match('/^(p[0-9]{1,3})?$/', $uri, $queryString)) {
    tryRenderFromCache('index');
    $page = 1;
    if (count($queryString) === 2) {
        $page = (int) substr($queryString[1], 1);
    }
    $data['threads'] = getThreads($db, $page, $perPage);
    $totalPages = ceil(getTotalThreads($db) / $perPage);
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    $html = $mustache->render('index', $data);
    saveCache('index', $html);
    echo $html;
} else if ($method === 'GET' && $uri === 'login') {
    echo $mustache->render('login', $data);
} else if ($method === 'POST' && $uri === 'login') {
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'login', 3, 300);
    $userId = validateLogin($db);
    if ($userId !== FALSE) {
        login($userId);
        redirect($baseurl);
    } else {
        $data['has_login_error'] = TRUE;
        $data['username'] = isset($_POST['username']) ? $_POST['username'] : '';
        echo $mustache->render('login', $data);
    }
} else if ($method === 'POST' && $uri === 'register') {
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'register', 5, 300);
    checkCaptcha($mustache, $config);
    $data['errors'] = validateRegistration($db);
    if (count($data['errors']) === 0) {
        $userId = addUser($db);
        $code = generateVerification($db, $userId);
        if (sendVerificationEmail($_POST['email'], $baseurl, $code, $config['sendGridKey']) === FALSE) {
            http_response_code(500);
            echo $mustache->render('500', $data);
            exit;
        } else {
            $data['is_sent'] = TRUE;
            echo $mustache->render('verify', $data);
        }
    } else {
        $data['has_register_errors'] = TRUE;
        $data['username'] = isset($_POST['username']) ? $_POST['username'] : '';
        $data['email'] = isset($_POST['email']) ? $_POST['email'] : '';
        $data['answer'] = isset($_POST['answer']) ? $_POST['answer'] : '';
        echo $mustache->render('login', $data);
    }
} else if ($method === 'GET' && $uri == 'reset') {
    echo $mustache->render('reset', $data);
} else if ($method === 'POST' && $uri == 'reset') {
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'verify', 3, 300);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id']);
        if (sendResetEmail($user['email'], $baseurl, $code, $config['sendGridKey']) === FALSE) {
            http_response_code(500);
            echo $mustache->render('500', $data);
            exit;
        }
    }
    $data['is_sent'] = TRUE;
    echo $mustache->render('reset', $data);
} else if ($method === 'GET' && preg_match('/^reset\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    $data['code'] = $queryString[1];
    $data['is_valid_code'] = (bool) checkVerificationCode($db, $queryString[1]);
    $data['is_valid_code'] = TRUE;
    echo $mustache->render('reset', $data);
} else if ($method === 'POST' && preg_match('/^reset\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'reset', 3, 300);
    $data['code'] = $queryString[1];
    $userId = checkVerificationCode($db, $queryString[1]);
    $data['is_valid_code'] = (bool) $userId;
    if ($data['is_valid_code']) {
        $data['errors'] = validatePassword();
        if (count($data['errors']) === 0) {
            updatePassword($db, $userId);
            $data['is_success'] = TRUE;
        }
    }
    echo $mustache->render('reset', $data);
} else if ($method === 'GET' && $uri == 'verify') {
    echo $mustache->render('verify', $data);
} else if ($method === 'POST' && $uri == 'verify') {
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'verify', 3, 300);
    checkCaptcha($mustache, $config);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id']);
        if (sendVerificationEmail($user['email'], $baseurl, $code, $config['sendGridKey']) === FALSE) {
            http_response_code(500);
            echo $mustache->render('500', $data);
            exit;
        }
    }
    $data['is_sent'] = TRUE;
    echo $mustache->render('verify', $data);
} else if ($method === 'GET' && preg_match('/^verify\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    $data['code'] = $queryString[1];
    $data['is_success'] = verifyUser($db, $queryString[1]);
    echo $mustache->render('verify', $data);
} else if ($method === 'GET' && $uri === 'logout') {
    unset($_SESSION['username']);
    session_unset();
    session_destroy();
    redirect($baseurl);
} else if ($method === 'GET' && $uri === 'post') {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    echo $mustache->render('post', $data);
} else if ($method === 'POST' && $uri === 'post') {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'post', 5, 10);
    $data['errors'] = [];
    validateThread($data['errors']);
    validatePost($data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($mustache, $data, 'post-success', 5, 300);
        $threadId = addThread($db);
        addPost($db, $threadId);
        sendNotificationEmails($db, $threadId, $baseurl, $config['sendGridKey']);
        invalidateCache(['index']);
        redirect($baseurl . 'thread/' . $threadId);
    } else {
        $data['has_error'] = TRUE;
        $data['content'] = $_POST['content'];
        echo $mustache->render('post', $data);
    }
} else if ($method === 'GET' && preg_match('/^thread\/([0-9]{1,50})\/latest$/', $uri, $queryString)) {
    $threadId = (int) $queryString[1];
    $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
    redirect($baseurl . 'thread/' . $threadId . '/p' . $totalPages);
} else if ($method === 'GET' && preg_match('/^thread\/([0-9]{1,50})(\/(p[0-9]{1,3})?)?$/', $uri, $queryString)) {
    $page = 1;
    if (count($queryString) === 4) {
        $page = (int) substr($queryString[3], 1);
    }
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
    $html = $mustache->render('thread', $data);
    saveCache($cacheKey, $html);
    echo $html;
} else if ($method === 'POST' && preg_match('/^thread\/([0-9]{1,50})(\/(p[0-9]{1,3})?)?$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    $page = 1;
    if (count($queryString) === 4) {
        $page = (int) substr($queryString[3], 1);
    }
    $threadId = (int) $queryString[1];
    $data['errors'] = [];
    validatePost($data['errors']);
    if (count($data['errors']) === 0) {
        $postId = addPost($db, $threadId);
        sendNotificationEmails($db, $threadId, $baseurl, $config['sendGridKey']);
        $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
        invalidateCache(['index', 'thread/' . $threadId . '/p']);
        redirect($baseurl . 'thread/' . $threadId . '/p' . $totalPages . '#' . $postId);
    } else {
        $data['has_error'] = TRUE;
        getThread($config, $mustache, $db, $threadId, $page, $perPage, $data);
        $data['id'] = $threadId;
        $totalPages = ceil(getTotalPosts($db, $threadId) / $perPage);
        $data['page'] = $page;
        $data['has_pagination'] = $totalPages > 1;
        $data['pages'] = getPaginationPages($page, $totalPages);
        echo $mustache->render('thread', $data);
    }
} else if ($method === 'GET' && preg_match('/^post\/edit\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    $postId = (int) $queryString[1];
    $post = getPost($config, $db, $postId);
    if (!$post) {
        http_response_code(404);
        echo $mustache->render('404', $data);
        exit;
    }
    $data['id'] = $postId;
    $data['content'] = $post['content'];
    echo $mustache->render('postedit', $data);
} else if ($method === 'POST' && preg_match('/^post\/edit\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    $postId = (int) $queryString[1];
    $post = getPost($config, $db, $postId);
    if (!$post) {
        http_response_code(404);
        echo $mustache->render('404', $data);
        exit;
    }
    $data['content'] = $_POST['content'];
    $data['errors'] = [];
    validatePost($data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($mustache, $data, 'postedit', 5, 300);
        updatePost($db, $postId);
        invalidateCache(['thread/' . $post['thread_id'] . '/p']);
        redirect($baseurl . 'thread/' . $post['thread_id']);
    } else {
        $data['has_error'] = TRUE;
        echo $mustache->render('postedit', $data);
    }
} else if ($method === 'GET' && preg_match('/^post\/delete\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    $postId = (int) $queryString[1];
    $threadId = getThreadId($db, $postId);
    deletePost($config, $db, $postId);
    invalidateCache(['index', 'thread/' . $threadId . '/p']);
    redirect($baseurl . 'thread/' . $threadId . '/latest');
} else if ($method === 'GET' && $uri == 'upload') {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    echo $mustache->render('upload', $data);
} else if ($method === 'POST' && $uri == 'upload') {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    checkRateLimit($mustache, $data, 'upload', 10, 300);
    $data['filename'] = handleUpload($db);
    if (isset($_POST['useJS'])) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'url' => $baseurl . 'files/' . $data['filename'], 'csrf' => $data['csrf']]);
        exit;
    } else {
        echo $mustache->render('upload', $data);
    }
} else if ($method === 'POST' && $uri === 'vote') {
    if (!$data['is_logged_in'])
        return redirect($baseurl . 'login');
    checkCsrf($mustache, $data);
    $postId = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
    $vote = isset($_POST['vote']) ? (int) $_POST['vote'] : 0;
    $page = isset($_POST['page']) ? (int) $_POST['page'] : 1;

    if ($postId > 0 && in_array($vote, [-1, 1])) {
        addVote($db, $postId, $vote);
    }

    $threadId = getThreadId($db, $postId);
    invalidateCache(['thread/' . $threadId . '/p']);
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
        return redirect($baseurl . 'login');
    $query = $db->prepare('UPDATE users SET notifications = NOT notifications WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id'], PDO::PARAM_INT);
    $query->execute();
    $query = $db->prepare('SELECT notifications FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id'], PDO::PARAM_INT);
    $query->execute();
    $data['is_on'] = (bool) $query->fetchColumn();
    echo $mustache->render('notifications', $data);
} else if ($method === 'GET' && str_starts_with($uri, 'search')) {
    $q = trim($_GET['q'] ?? '');
    $encoded = urlencode("site:community.osarch.org $q");
    redirect("https://duckduckgo.com/?q=$encoded");
} else {
    http_response_code(404);
    echo $mustache->render('404', $data);
    exit;
}
