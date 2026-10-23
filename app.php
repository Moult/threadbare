<?php

$config = require_once (__DIR__ . '/config.php');
require_once 'Parsedown.php';

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
$uri = trim(strtok($_SERVER['REQUEST_URI'], '?'), '/'); // Route on the path; ?utm_source= etc. must not 404
$data = ['baseurl' => $baseurl, 'csrf' => $_SESSION['csrf'], 'captcha' => $config['hCaptchaSiteKey'], 'html_title' => $config['websiteTitle'], 'h1' => $config['websiteTitle'], 'blurb' => $config['blurb']];
if (isset($_SESSION['username'])) {
    $data['is_logged_in'] = TRUE;
    $data['username'] = $_SESSION['username'];
    $data['user_id'] = $_SESSION['user_id'];
} else {
    $data['is_logged_in'] = FALSE;
}
if (isAdmin($config)) {
    $data['is_admin'] = TRUE;
    $data['pending_count'] = (int) $db->query('SELECT COUNT(*) FROM posts WHERE is_approved = 0')->fetchColumn();
    $data['flagged_count'] = (int) $db->query('SELECT COUNT(DISTINCT post_id) FROM votes WHERE value = -1')->fetchColumn();
}

function isAdmin($config)
{
    return isset($_SESSION['username']) && in_array($_SESSION['username'], $config['adminUsernames']);
}

function generateCsrf(&$data)
{
    $_SESSION['csrf'][] = $data['csrf'] = bin2hex(random_bytes(32));
    if (count($_SESSION['csrf']) > 50) {
        array_shift($_SESSION['csrf']);
    }
}

function checkCsrf(&$data)
{
    if (!isset($_POST['csrf']))
        render(403, '403', $data);
    foreach ($_SESSION['csrf'] as $csrf) {
        if (hash_equals($csrf, $_POST['csrf'])) {
            generateCsrf($data);
            return;
        }
    }
    render(403, '403', $data);
}

// The visitor's address. Behind a CDN or reverse proxy REMOTE_ADDR is the proxy's, so it comes from the header the proxy sets
function clientIp($config)
{
    $header = $config['clientIpHeader'] ?? '';
    if ($header !== '') {
        $addresses = explode(',', $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '');
        $ip = trim(end($addresses)); // The last one is the address the proxy saw; earlier ones are whatever the client sent
        if (filter_var($ip, FILTER_VALIDATE_IP))
            return $ip;
    }
    return $_SERVER['REMOTE_ADDR'];
}

// Who rate limits count: an IPv6 visitor by their /64, as one connection usually has all of it
function clientKey($config)
{
    $ip = clientIp($config);
    return str_contains($ip, ':') ? bin2hex(substr(inet_pton($ip), 0, 8)) : $ip;
}

function checkRateLimit($config, $data, $key = 'login', $limit = 3, $window = 300)
{
    if (isset($_SESSION['username']) && in_array($_SESSION['username'], $config['adminUsernames']))
        return;
    $now = time();
    $rateKey = 'ratelimit_' . md5($config['salt'] . clientKey($config) . $key);
    $record = apcu_fetch($rateKey);
    if (!$record) {
        $record = ['attempts' => 1, 'time' => $now];
    } elseif ($now - $record['time'] < $window) {
        $record['attempts']++;
        if ($record['attempts'] > $limit)
            render(429, '429', $data);
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

function regenerateSessionToken($db, $userId)
{
    $token = bin2hex(random_bytes(32));
    $query = $db->prepare('UPDATE users SET session_token = :session_token WHERE id = :id');
    $query->bindValue(':id', $userId);
    $query->bindValue(':session_token', $token);
    $query->execute();
    // Keep the current session only if it belongs to that user (e.g. not an admin editing someone else)
    if (isset($_SESSION['user_id']) && (int) $_SESSION['user_id'] === (int) $userId)
        $_SESSION['token'] = $token;
}

// Returns FALSE unless hCaptcha confirms the response, including when it can't be reached
function checkCaptcha($config)
{
    $request = ['secret' => $config['hCaptchaSecretKey'], 'response' => $_POST['h-captcha-response'] ?? ''];
    $verify = curl_init();
    curl_setopt($verify, CURLOPT_URL, 'https://hcaptcha.com/siteverify');
    curl_setopt($verify, CURLOPT_POST, true);
    curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($request));
    curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($verify);
    $responseData = json_decode($response);
    return !empty($responseData->success);
}

function validateLogin($db)
{
    if (isset($_POST['username']) && isset($_POST['password']) && strlen($_POST['username']) <= 50) {
        $query = $db->prepare('SELECT id, username, password FROM users WHERE (username = :username OR email = :email) AND is_verified = 1');
        $query->bindParam(':username', $_POST['username']);
        $query->bindParam(':email', $_POST['username']);
        $query->execute();
        $row = $query->fetch();
        if (!$row) {
            password_hash($_POST['password'], PASSWORD_DEFAULT); // As slow as a wrong password, so timing doesn't reveal which accounts exist
            return FALSE;
        }
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
        regenerateSessionToken($db, $user['id']);
    }
}

function validateProfile($config, $baseurl, $db, $userId)
{
    $errors = [];
    if (!isset($_POST['email']) || !is_string($_POST['email']) || strlen($_POST['email']) < 3 || strlen($_POST['email']) > 50) {
        $errors[] = 'Email needs to be at least 3-50 characters long.';
    }
    if (isset($_POST['email'])) {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $_POST['email'] = $email;
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email is not valid.';
        } else if (isEmailTaken($db, $email, $userId)) {
            $errors[] = 'Email is already in use.';
        }
    }
    if (!isset($_POST['bio']) || !is_string($_POST['bio']) || strlen($_POST['bio']) > 500) {
        $errors[] = 'Bio must not exceed 500 characters.';
    } else if (!in_array($_SESSION['username'], $config['adminUsernames']) && !in_array($_SESSION['username'], $config['trustedUsernames']) && isSpam($config, $baseurl, $_POST['bio'])) {
        $errors[] = 'Bio looks spamlike. Please reach out for help in the live chat.';
    }
    return $errors;
}

function validatePassword()
{
    $errors = [];
    $fields = ['password', 'password2'];
    foreach ($fields as $field) {
        if (!isset($_POST[$field]) || !is_string($_POST[$field]) || strlen($_POST[$field]) < 8 || strlen($_POST[$field]) > 50) {
            $errors[] = ucfirst(trim($field, '2')) . ' needs to be 8-50 characters long.';
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
        $min = in_array($field, ['password', 'password2']) ? 8 : 3;
        if (!isset($_POST[$field]) || !is_string($_POST[$field]) || strlen($_POST[$field]) < $min || strlen($_POST[$field]) > 50) {
            $errors[] = ucfirst(trim($field, '2')) . " needs to be $min-50 characters long.";
        }
        if (isset($_POST[$field])) {
            $_POST[$field] = str_replace(["\r", "\n"], '', $_POST[$field]);
        }
    }
    if (isset($_POST['username']) && !preg_match('/^[a-zA-Z0-9_-]+$/', $_POST['username'])) {
        $errors[] = 'Username can only contain letters, numbers, underscores, and hyphens.';
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
        // Usernames differing only in case would look alike and share @mentions
        $query = $db->prepare('SELECT COUNT(id) FROM users WHERE LOWER(username) = LOWER(:username) OR email = :email');
        $query->bindParam(':username', $_POST['username']);
        $query->bindParam(':email', $_POST['email']);
        $query->execute();
        if ($query->fetchColumn() !== 0) {
            $errors[] = 'Username or email may already be registered.';
        }
    }
    return $errors;
}

function deleteUser($db, $id)
{
    // Remove posts one by one so threads with other people's replies pass to them instead of cascading away
    $query = $db->prepare('SELECT id, thread_id FROM posts WHERE user_id = :user_id');
    $query->bindValue(':user_id', $id);
    $query->execute();
    foreach ($query->fetchAll() as $row) {
        removePost($db, $row['id'], $row['thread_id']);
    }

    // Remove the user's uploaded files; their rows go with the user
    $query = $db->prepare('SELECT path FROM uploads WHERE user_id = :user_id');
    $query->bindValue(':user_id', $id);
    $query->execute();
    foreach ($query->fetchAll(PDO::FETCH_COLUMN, 0) as $path) {
        @unlink(__DIR__ . '/uploads/' . $path);
    }

    $query = $db->prepare('DELETE FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->execute();
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

// $purpose is 'verify', 'reset' or 'profile'; a code only works for its purpose, for a day
function generateVerification($db, $userId, $purpose)
{
    // Replace only a code for the same purpose: asking for, say, a verification email mustn't cancel a reset link
    $query = $db->prepare('DELETE FROM verifications WHERE user_id = :user_id AND purpose = :purpose');
    $query->bindValue(':user_id', $userId);
    $query->bindValue(':purpose', $purpose);
    $query->execute();

    $code = bin2hex(random_bytes(32));
    $query = $db->prepare('INSERT INTO verifications(code, user_id, purpose, ts_created) VALUES(:code, :user_id, :purpose, :ts_created)');
    $query->bindValue(':code', $code);
    $query->bindValue(':user_id', $userId);
    $query->bindValue(':purpose', $purpose);
    $query->bindValue(':ts_created', time());
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

function sendProfileEmail($config, $email, $code)
{
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $url = $config['baseurl'] . 'profile/edit/' . $code;
    $content = "To edit your user profile, click the link below. If this wasn't you, ignore this email.\n\n" . $url;
    $to = [["to" => [["email" => $email]]]];
    return sendEmail($config, $to, 'Edit ' . $config['websiteTitle'] . ' Profile', $content);
}

function sendEmailChangeEmail($config, $email, $code)
{
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $url = $config['baseurl'] . 'email/' . $code;
    $content = "To use this address for your account, click the link below. If this wasn't you, ignore this email.\n\n" . $url;
    $to = [["to" => [["email" => $email]]]];
    return sendEmail($config, $to, 'Confirm your ' . $config['websiteTitle'] . ' email', $content);
}

function sendNotificationEmails($config, $db, $threadId, $userId, $poster, $postContent)
{
    $emails = [];
    $query = $db->prepare('SELECT title FROM threads WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $threadId);
    $query->execute();
    $title = $query->fetchColumn(0);

    $query = $db->prepare('SELECT email FROM users WHERE id = :user_id LIMIT 1');
    $query->bindValue(':user_id', $userId);
    $query->execute();
    $myEmail = $query->fetchColumn(0);

    // Mentions
    preg_match_all('/@([a-zA-Z0-9_-]{1,50})/', $postContent, $matches);
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
    $query = $db->prepare('SELECT DISTINCT u.email FROM posts AS p LEFT JOIN users AS u ON p.user_id = u.id WHERE p.thread_id = :thread_id AND p.is_approved = 1 AND u.notifications = 1');
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
    $poster = preg_replace('/[\x00-\x1F\x7F]/u', '', $poster);
    $content = $poster . ' has posted on the thread "' . $title . '". Check it out!' . "\n\n" . $url;
    $content .= "\n\n" . "If you don't want notifications, sign in then visit this page:" . "\n\n" . $url2;
    $subject = '[' . $config['websiteTitle'] . '] ' . $poster . ' commented on ' . $title;
    $to = [];
    foreach (array_unique($emails) as $email) {
        $to[] = ["to" => [["email" => $email]]];
    }
    return sendEmail($config, $to, $subject, $content);
}

function checkVerificationCode($config, $db, $code, $purpose)
{
    if (isset($_SESSION['user_id']) && in_array($_SESSION['username'], $config['adminUsernames'])) {
        $query = $db->prepare('SELECT id FROM users WHERE username = :code LIMIT 1');
        $query->bindValue(':code', $code);
        $query->execute();
        $userId = $query->fetchColumn(0);
        if (!$userId)
            return FALSE;
        return $userId;
    }
    $query = $db->prepare('SELECT user_id FROM verifications WHERE code = :code AND purpose = :purpose AND ts_created > :since LIMIT 1');
    $query->bindValue(':code', $code);
    $query->bindValue(':purpose', $purpose);
    $query->bindValue(':since', time() - 86400);
    $query->execute();
    $userId = $query->fetchColumn(0);
    if (!$userId)
        return FALSE;
    return $userId;
}

function isEmailTaken($db, $email, $userId)
{
    $query = $db->prepare('SELECT COUNT(id) FROM users WHERE email = :email AND id != :id');
    $query->bindValue(':email', $email);
    $query->bindValue(':id', $userId);
    $query->execute();
    return $query->fetchColumn() > 0;
}

// Saves the bio. A changed email is only held as pending; returns the code to confirm it, or NULL if unchanged.
function updateProfile($db, $id)
{
    $query = $db->prepare('UPDATE users SET bio = :bio WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->bindValue(':bio', $_POST['bio']);
    $query->execute();

    $query = $db->prepare('DELETE FROM verifications WHERE user_id = :user_id');
    $query->bindValue(':user_id', $id);
    $query->execute();

    $query = $db->prepare('SELECT email FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->execute();
    $code = $query->fetchColumn() === $_POST['email'] ? NULL : bin2hex(random_bytes(32));
    $query = $db->prepare('UPDATE users SET pending_email = :email, pending_email_code = :code, pending_email_ts = :ts WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->bindValue(':email', $code ? $_POST['email'] : NULL); // Unchanged email cancels any pending change
    $query->bindValue(':code', $code);
    $query->bindValue(':ts', $code ? time() : NULL);
    $query->execute();
    return $code;
}

function confirmEmail($db, $code)
{
    $query = $db->prepare('SELECT id, pending_email FROM users WHERE pending_email_code = :code AND pending_email_ts > :since LIMIT 1');
    $query->bindValue(':code', $code);
    $query->bindValue(':since', time() - 86400); // Like other emailed codes, it works for a day
    $query->execute();
    $row = $query->fetch();
    if (!$row || isEmailTaken($db, $row['pending_email'], $row['id']))
        return FALSE;

    $query = $db->prepare('UPDATE users SET email = pending_email, pending_email = NULL, pending_email_code = NULL WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $row['id']);
    $query->execute();
    return TRUE;
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
    expireHashtags(); // The edit may have added or removed some
}

function movePost($db, $id, $threadId)
{
    $oldThreadId = getThreadId($db, $id);
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

    // The thread goes to the first approved poster: a held post's author mustn't get it
    $query = $db->prepare('
        SELECT
            (SELECT user_id FROM posts WHERE thread_id = :thread_id ORDER BY is_approved DESC, id ASC LIMIT 1) AS first_user_id,
            (SELECT user_id FROM posts WHERE thread_id = :thread_id AND is_approved = 1 ORDER BY id DESC LIMIT 1) AS last_user_id
    ');
    $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
    $query->execute();
    $row = $query->fetch(PDO::FETCH_ASSOC);

    $query = $db->prepare('UPDATE threads SET user_id = :user_id, last_user_id = :last_user_id WHERE id = :thread_id LIMIT 1');
    $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
    $query->bindValue(':user_id', $row['first_user_id'], PDO::PARAM_INT);
    $query->bindValue(':last_user_id', $row['last_user_id'], PDO::PARAM_INT);
    $query->execute();

    // Don't leave the old thread behind with no posts
    $query = $db->prepare('DELETE FROM threads WHERE id = :id AND NOT EXISTS (SELECT 1 FROM posts WHERE thread_id = :id)');
    $query->bindValue(':id', $oldThreadId);
    $query->execute();
}

function updateThread($db, $id)
{
    $query = $db->prepare('UPDATE threads SET title = :title, tags = :tags WHERE id = :id');
    $query->bindValue(':title', $_POST['title']);
    $query->bindValue(':tags', isset($_POST['tags']) ? implode(",", $_POST['tags']) : '');
    $query->bindValue(':id', $id);
    $query->execute();
}

function verifyUser($db, $code)
{
    $query = $db->prepare('SELECT user_id FROM verifications WHERE code = :code AND purpose = :purpose AND ts_created > :since LIMIT 1');
    $query->bindValue(':code', $code);
    $query->bindValue(':purpose', 'verify');
    $query->bindValue(':since', time() - 86400);
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
    if (isset($_POST['tags'])) {
        foreach ($_POST['tags'] as $tag) {
            if (!in_array($tag, $config['tags'])) {
                $errors[] = 'Tag is invalid.';
                break;
            }
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
    $query = $db->prepare('INSERT INTO threads(title, user_id, ts_created, ts_updated, tags) VALUES(:title, :user_id, :ts_created, :ts_updated, :tags)');
    $query->bindValue(':title', $_POST['title']);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':ts_created', time());
    $query->bindValue(':ts_updated', time());
    $query->bindValue(':tags', isset($_POST['tags']) ? implode(",", $_POST['tags']) : '');
    $query->execute();
    return $db->lastInsertId();
}

function addPost($db, $threadId, $isApproved)
{
    $query = $db->prepare('INSERT INTO posts(thread_id, user_id, content, ts_created, ts_updated, is_approved) VALUES(:thread_id, :user_id, :content, :ts_created, :ts_updated, :is_approved)');
    $query->bindValue(':thread_id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':content', $_POST['content']);
    $query->bindValue(':ts_created', time());
    $query->bindValue(':ts_updated', time());
    $query->bindValue(':is_approved', $isApproved ? 1 : 0, PDO::PARAM_INT);
    $query->execute();
    $postId = $db->lastInsertId();
    if (!$isApproved)
        return $postId; // A held post doesn't bump the thread until it's approved
    if (str_contains($_POST['content'], '#'))
        expireHashtags();

    $query = $db->prepare('UPDATE threads SET last_user_id = :user_id, ts_updated = :ts_updated WHERE id = :thread_id');
    $query->bindValue(':thread_id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':ts_updated', time());
    $query->execute();
    return $postId;
}

// Admins, trusted users and users an admin has approved post straight away; everyone else's posts are held
function isApproved($config, $db)
{
    if (isAdmin($config) || in_array($_SESSION['username'], $config['trustedUsernames']))
        return TRUE;
    $query = $db->prepare('SELECT is_approved FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id']);
    $query->execute();
    return (bool) $query->fetchColumn();
}

// Tells the admins when a user's first post is held, rather than for every post after it
function sendApprovalRequestEmail($config, $db)
{
    $query = $db->prepare('SELECT COUNT(*) FROM posts WHERE user_id = :user_id AND is_approved = 0');
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->execute();
    if ($query->fetchColumn() !== 1 || !$config['adminUsernames'])
        return;

    $query = $db->prepare('SELECT email FROM users WHERE username IN (' . implode(',', array_fill(0, count($config['adminUsernames']), '?')) . ')');
    $query->execute(array_values($config['adminUsernames']));
    $to = [];
    foreach ($query->fetchAll(PDO::FETCH_COLUMN, 0) as $email) {
        $to[] = ["to" => [["email" => $email]]];
    }
    if (!$to)
        return;
    $username = preg_replace('/[\x00-\x1F\x7F]/u', '', $_SESSION['username']);
    $content = $username . " has posted for the first time. Their posts are hidden until an admin approves them:\n\n" . $config['baseurl'] . 'approvals';
    return sendEmail($config, $to, '[' . $config['websiteTitle'] . '] ' . $username . ' is awaiting approval', $content);
}

// Approves a user and publishes their held posts, bumping those threads and sending the notifications held back with them
function approveUser($config, $db, $userId)
{
    $query = $db->prepare('SELECT username FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $userId);
    $query->execute();
    $username = $query->fetchColumn();
    if (!$username)
        return;

    $query = $db->prepare('SELECT thread_id, content FROM posts WHERE user_id = :user_id AND is_approved = 0 ORDER BY id ASC');
    $query->bindValue(':user_id', $userId);
    $query->execute();
    $posts = $query->fetchAll(PDO::FETCH_ASSOC);

    $query = $db->prepare('UPDATE users SET is_approved = 1 WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $userId);
    $query->execute();
    $query = $db->prepare('UPDATE posts SET is_approved = 1 WHERE user_id = :user_id AND is_approved = 0');
    $query->bindValue(':user_id', $userId);
    $query->execute();
    expireHashtags();

    foreach (array_unique(array_column($posts, 'thread_id')) as $threadId) {
        $query = $db->prepare('UPDATE threads SET ts_updated = :ts_updated,
            last_user_id = (SELECT user_id FROM posts WHERE thread_id = :thread_id AND is_approved = 1 ORDER BY id DESC LIMIT 1)
            WHERE id = :thread_id');
        $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
        $query->bindValue(':ts_updated', time());
        $query->execute();
    }
    foreach ($posts as $post) {
        sendNotificationEmails($config, $db, $post['thread_id'], $userId, $username, $post['content']);
    }
}

// Posts people have flagged, most flagged first. Who flagged them isn't shown, not even to admins
function getFlaggedPosts($db)
{
    $query = $db->query('
        SELECT p.id, p.content, p.thread_id, p.user_id, p.ts_created, u.username, t.title, COUNT(*) AS flags
        FROM votes AS v
        JOIN posts AS p ON v.post_id = p.id
        JOIN users AS u ON p.user_id = u.id
        JOIN threads AS t ON p.thread_id = t.id
        WHERE v.value = -1
        GROUP BY p.id
        ORDER BY flags DESC, p.id DESC');
    $results = [];
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $row['ts_created'] = date('j M Y H:i', $row['ts_created']);
        $results[] = $row;
    }
    return $results;
}

function getPendingPosts($db)
{
    $query = $db->query('
        SELECT p.id, p.content, p.thread_id, p.user_id, p.ts_created, u.username, u.email, t.title
        FROM posts AS p
        JOIN users AS u ON p.user_id = u.id
        JOIN threads AS t ON p.thread_id = t.id
        WHERE p.is_approved = 0
        ORDER BY p.id ASC');
    $results = [];
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $row['ts_created'] = date('j M Y H:i', $row['ts_created']);
        $results[] = $row;
    }
    return $results;
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

function getLatestPosts($db, $userId, $perPage = 20)
{
    $results = [];
    $query = $db->prepare('
        SELECT t.id, t.title, t.views, t.user_id, u.username, p.ts_updated
        FROM posts AS p
        LEFT JOIN threads AS t ON p.thread_id = t.id
        LEFT JOIN users AS u ON t.user_id = u.id
        WHERE p.user_id = :user_id AND p.is_approved = 1
        GROUP BY p.id ORDER BY p.id DESC
        LIMIT :limit
    ');
    $query->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $query->bindValue(':user_id', $userId);
    $query->execute();
    while ($row = $query->fetch()) {
        $results[] = [
            'id' => $row['id'],
            'title' => $row['title'],
            'user_id' => $row['user_id'],
            'username' => $row['username'],
            'avatar' => avatar($row['username']),
            'initial' => strtoupper($row['username'][0]),
            'ts_updated' => timeAgo($row['ts_updated']),
        ];
    }
    return $results;
}

function getProfile($db, $id, &$data)
{
    $query = $db->prepare('SELECT username, email, bio FROM users WHERE id = :id');
    $query->bindValue(':id', $id);
    $query->execute();
    $row = $query->fetch();
    if (!$row)
        render(404, '404', $data);
    $data['profile_username'] = $row[0];
    $data['email'] = $row[1];
    $data['bio'] = $row[2] ?? '';
}

// $where is an SQL condition on the thread t, with its $params
function getThreads($db, $page = 1, $perPage = 20, $where = NULL, $params = [])
{
    $results = [];
    $sql = 'SELECT t.id, t.title, t.views, r.last_read_at, t.user_id, u.username, t.last_user_id, lu.username AS last_username, u.email, t.ts_created, t.ts_updated, count(p.id) AS total_posts, t.tags
        FROM threads AS t
        LEFT JOIN users AS u ON t.user_id = u.id
        LEFT JOIN users AS lu ON t.last_user_id = lu.id
        LEFT JOIN posts AS p ON p.thread_id = t.id AND p.is_approved = 1
        LEFT JOIN thread_reads AS r ON r.thread_id = t.id AND r.user_id = :user_id';
    if ($where !== NULL) {
        $sql .= " WHERE $where";
    }
    $sql .= ' GROUP BY t.id HAVING count(p.id) > 0 ORDER BY t.ts_updated DESC LIMIT :limit OFFSET :offset'; // A held new thread has no approved posts
    $query = $db->prepare($sql);
    foreach ($params as $name => $value) {
        $query->bindValue($name, $value, PDO::PARAM_STR);
    }
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
            'user_id' => $row['user_id'],
            'username' => $row['username'],
            'last_username' => $row['last_username'],
            'last_user_id' => $row['last_user_id'],
            'views' => formatViews($row['views']),
            'total_posts' => $row['total_posts'] - 1,
            'last_page' => ceil($row['total_posts'] / $perPage),
            'is_unread' => isset($_SESSION['username']) && (!$row['last_read_at'] || $row['last_read_at'] < $row['ts_updated']),
            'ts_updated' => timeAgo($row['ts_updated']),
            'avatar' => avatar($row['username']),
            'initial' => strtoupper($row['username'][0]),
            'tags' => implode(', ', explode(',', $row['tags'])),
        ];
    }
    return $results;
}

function getTotalThreads($db, $where = NULL, $params = [])
{
    $query = $db->prepare('SELECT COUNT(*) FROM threads AS t WHERE EXISTS (SELECT 1 FROM posts WHERE thread_id = t.id AND is_approved = 1)'
        . ($where !== NULL ? " AND ($where)" : ''));
    $query->execute($params);
    return (int) $query->fetchColumn();
}

// Threads with a curated tag, or with a recent post using it as a hashtag
function tagFilter($tag, $isCurated, $threadIds)
{
    $where = [];
    $params = [];
    if ($isCurated) {
        $where[] = "',' || t.tags || ',' LIKE :tag"; // Whole tags only: intro must not match introduction
        $params[':tag'] = '%,' . $tag . ',%';
    }
    if ($threadIds)
        $where[] = 't.id IN (' . implode(',', array_map('intval', $threadIds)) . ')';
    return [implode(' OR ', $where), $params];
}

// Posts in a thread that the viewer can see: held posts only by their author and admins
function getTotalPosts($config, $db, int $threadId): int
{
    $query = $db->prepare('SELECT COUNT(*) FROM posts WHERE thread_id = :thread_id AND (is_approved = 1 OR user_id = :user_id OR :is_admin = 1)');
    $query->bindValue(':thread_id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id'] ?? 0);
    $query->bindValue(':is_admin', isAdmin($config) ? 1 : 0, PDO::PARAM_INT);
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

function getThread($config, $db, $threadId, $page, $perPage, &$data)
{
    $query = $db->prepare('
        SELECT t.id, t.title, t.user_id, u.username, t.ts_created, t.ts_updated, t.tags
        FROM threads AS t LEFT JOIN users AS u ON t.user_id = u.id WHERE t.id = :id LIMIT 1');
    $query->bindValue(':id', $threadId);
    $query->execute();
    $row = $query->fetch();
    if (!$row || getTotalPosts($config, $db, $threadId) === 0)
        render(404, '404', $data);
    $data['title'] = $row['title'];
    $data['tags'] = explode(',', $row['tags']);
    $data['all_tags'] = [];
    foreach ($config['tags'] as $tag) {
        $data['all_tags'][] = ["tag" => $tag, "is_checked" => in_array($tag, $data['tags'])];
    }
    $data['can_edit'] = isset($_SESSION['user_id']) ? $row['user_id'] === $_SESSION['user_id'] || in_array($_SESSION['username'], $config['adminUsernames']) : FALSE;
    $data['posts'] = [];

    $query = $db->prepare('
        SELECT p.id, p.content, p.thread_id, p.user_id, u.username, u.email, p.ts_created, p.ts_updated, p.is_approved,
            SUM(CASE WHEN v.value = -1 THEN 1 ELSE 0 END) AS flags,
            MAX(CASE WHEN v.user_id = :user_id THEN v.value ELSE NULL END) AS user_vote
        FROM posts AS p
        LEFT JOIN users AS u ON p.user_id = u.id
        LEFT JOIN votes AS v ON p.id = v.post_id
        WHERE p.thread_id = :id AND (p.is_approved = 1 OR p.user_id = :user_id OR :is_admin = 1)
        GROUP BY p.id
        ORDER BY p.id ASC
        LIMIT :limit OFFSET :offset
    ');
    $query->bindValue(':id', $threadId);
    $query->bindValue(':user_id', $_SESSION['user_id'] ?? 0);
    $query->bindValue(':is_admin', isAdmin($config) ? 1 : 0, PDO::PARAM_INT);
    $query->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $query->bindValue(':offset', ($page - 1) * $perPage, PDO::PARAM_INT);
    $query->execute();
    while ($row = $query->fetch()) {
        $content = linkHashtags(renderPost($row['content']), $config['baseurl']);
        $row['can_vote'] = !empty($_SESSION['user_id']) && $_SESSION['user_id'] !== $row['user_id'] && $row['is_approved'];
        $row['is_pending'] = !$row['is_approved'];
        $row['user_vote_is_upvoted'] = $row['user_vote'] === 1;
        $row['user_vote_is_downvoted'] = $row['user_vote'] === -1;
        $row['flags'] = isAdmin($config) ? $row['flags'] : 0; // Flags are anonymous, and only admins see how many
        $row['ts_updated'] = $row['ts_updated'] > $row['ts_created'] + 5 ? date('j M Y', $row['ts_updated']) : '';
        $row['ts_created'] = date('j M Y', $row['ts_created']);
        $row['avatar'] = avatar($row['username']);
        $row['initial'] = strtoupper($row['username'][0]);
        $row['content'] = $content;
        $row['can_edit'] = isset($_SESSION['user_id']) ? $row['user_id'] === $_SESSION['user_id'] || in_array($_SESSION['username'], $config['adminUsernames']) : FALSE;
        $data['posts'][] = $row;
    }
    addReactions($db, $data['posts']);
}

// Lists who reacted to each post, in the order they reacted. Flags (down votes) are left out: they're anonymous
function addReactions($db, &$posts)
{
    $index = [];
    foreach ($posts as $i => $post) {
        $posts[$i]['reactions'] = [];
        $index[$post['id']] = $i;
    }
    if (!$index)
        return;
    $query = $db->prepare('
        SELECT v.post_id, u.id AS user_id, u.username FROM votes AS v JOIN users AS u ON v.user_id = u.id
        WHERE v.value = 1 AND v.post_id IN (' . implode(',', array_fill(0, count($index), '?')) . ') ORDER BY v.rowid');
    $query->execute(array_keys($index));
    while ($row = $query->fetch()) {
        $posts[$index[$row['post_id']]]['reactions'][] = [
            'user_id' => $row['user_id'],
            'username' => $row['username'],
            'avatar' => avatar($row['username']),
            'initial' => strtoupper($row['username'][0]),
        ];
    }
    foreach ($posts as $i => $post) {
        $posts[$i]['has_reactions'] = (bool) $post['reactions'];
    }
}

function renderPost($content)
{
    $Parsedown = new ForumMarkdown();
    $Parsedown->setSafeMode(true);
    return postProcessMentions($Parsedown->text(preProcessMentions($content)));
}

// A hashtag is a word starting with # after a space or bracket, so headings, URL fragments and entities don't count
const HASHTAG = '/(?<=[\s(])#([A-Za-z][A-Za-z0-9_]{1,49})(?![A-Za-z0-9_])/';
const HASHTAG_POSTS = 2000; // How many recent posts the list of hashtags comes from
const HASHTAG_LIMIT = 50;   // How many of the most used hashtags it keeps
const HASHTAG_TTL = 600;

// Links the hashtags in rendered post HTML, leaving alone code and existing links; collects them, lowercased, in $tags
function linkHashtags($html, $baseurl, &$tags = [])
{
    $parts = preg_split('/(<[^>]*>)/', $html, -1, PREG_SPLIT_DELIM_CAPTURE);
    $skip = 0;
    foreach ($parts as $i => $part) {
        if ($i % 2) {
            if (preg_match('/^<(\/?)(a|code|pre)\b/i', $part, $m))
                $skip = max(0, $skip + ($m[1] ? -1 : 1));
        } else if (!$skip && str_contains($part, '#')) {
            $parts[$i] = preg_replace_callback(HASHTAG, function ($m) use ($baseurl, &$tags) {
                $tags[] = $tag = strtolower($m[1]);
                return '<a href="' . $baseurl . 'tag/' . $tag . '" class="hashtag">#' . $m[1] . '</a>';
            }, $part);
        }
    }
    return implode('', $parts);
}

// The most used hashtags in recent posts, each with the threads using it. Built at most once per HASHTAG_TTL
// whatever the traffic, so tag pages never scan posts on request
function getHashtags($db, $baseurl)
{
    $cached = apcu_fetch('hashtags');
    if ($cached !== FALSE && $cached['ts'] > time() - HASHTAG_TTL)
        return $cached['tags'];
    if (!apcu_add('hashtags_lock', 1, 30)) // Another request is rebuilding it: use the old list meanwhile
        return $cached['tags'] ?? [];
    $query = $db->prepare('SELECT thread_id, content FROM posts WHERE is_approved = 1 ORDER BY id DESC LIMIT :limit');
    $query->bindValue(':limit', HASHTAG_POSTS, PDO::PARAM_INT);
    $query->execute();
    $uses = [];
    $threads = [];
    while ($row = $query->fetch()) {
        if (!str_contains($row['content'], '#'))
            continue;
        $tags = [];
        linkHashtags(renderPost($row['content']), $baseurl, $tags);
        foreach (array_unique($tags) as $tag) {
            $uses[$tag] = ($uses[$tag] ?? 0) + 1;
            $threads[$tag][$row['thread_id']] = TRUE;
        }
    }
    arsort($uses);
    $tags = [];
    foreach (array_slice(array_keys($uses), 0, HASHTAG_LIMIT) as $tag) {
        $tags[$tag] = array_keys($threads[$tag]);
    }
    apcu_store('hashtags', ['ts' => time(), 'tags' => $tags]);
    apcu_delete('hashtags_lock');
    return $tags;
}

// Rebuild the hashtag list on the next request that needs it, rather than when it times out
function expireHashtags()
{
    $cached = apcu_fetch('hashtags');
    if ($cached !== FALSE) {
        $cached['ts'] = 0;
        apcu_store('hashtags', $cached);
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
    removePost($db, $id, $threadId);
}

// Delete a post, then hand its thread to the first remaining poster, or delete the thread if it is now empty
function removePost($db, $id, $threadId)
{
    $query = $db->prepare('DELETE FROM posts WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $id);
    $query->execute();

    // The thread goes to the first approved poster: a held post's author mustn't get it
    $query = $db->prepare('
        SELECT
            (SELECT user_id FROM posts WHERE thread_id = :thread_id ORDER BY is_approved DESC, id ASC LIMIT 1) AS first_user_id,
            (SELECT user_id FROM posts WHERE thread_id = :thread_id AND is_approved = 1 ORDER BY id DESC LIMIT 1) AS last_user_id
    ');
    $query->bindValue(':thread_id', $threadId, PDO::PARAM_INT);
    $query->execute();
    $row = $query->fetch(PDO::FETCH_ASSOC);

    if ($row['first_user_id']) { // Kept even if only held posts remain, as those may yet be approved
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
        // Authors may only delete threads nobody else has replied to
        $query = $db->prepare('DELETE FROM threads WHERE id = :id AND user_id = :user_id
            AND NOT EXISTS (SELECT 1 FROM posts WHERE thread_id = :id AND user_id != :user_id) LIMIT 1');
        $query->bindValue(':user_id', $_SESSION['user_id']);
    }
    $query->bindValue(':id', $id);
    $query->execute();
    return $query->rowCount() > 0;
}

function handleUpload($config, $db, $data)
{
    if (!isset($_FILES['attachment']) || $_FILES['attachment']['error'] !== UPLOAD_ERR_OK)
        render(400, '400', $data);

    $file = $_FILES['attachment'];

    if ($file['size'] > $config['maxUploadMb'] * 1024 * 1024) {
        render(400, '400', $data);
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
        render(403, '403', $data);
    }

    if ($ext === 'ifc') {
        $contents = file_get_contents($file['tmp_name']);
        if (!str_starts_with(trim($contents), 'ISO-10303-21;'))
            render(400, '400', $data);
    }

    $filename = bin2hex(random_bytes(16)) . '.' . $ext;
    $subdir = substr($filename, 0, 2) . '/' . substr($filename, 2, 2);
    $uploadDir = realpath(__DIR__ . '/uploads') . '/' . $subdir;
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, TRUE);
    }
    if (!move_uploaded_file($file['tmp_name'], $uploadDir . DIRECTORY_SEPARATOR . $filename))
        render(500, '500', $data);

    $query = $db->prepare('INSERT INTO uploads(path, user_id, ts_created) VALUES(:path, :user_id, :ts_created)');
    $query->bindValue(':path', $subdir . '/' . $filename);
    $query->bindValue(':user_id', $_SESSION['user_id']);
    $query->bindValue(':ts_created', time());
    $query->execute();
    return $subdir . '/' . $filename;
}

function recordThreadView($db, $threadId)
{
    $key = "viewed_thread_$threadId";
    // Only count clients that send the session cookie back: one that never does (most bots) would be a new view, and a write, on every request
    if (!isset($_SESSION[$key]) && isset($_COOKIE[session_name()])) {
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
        . '&user_ip=' . urlencode(clientIp($config))
        . '&user_agent=' . urlencode($_SERVER['HTTP_USER_AGENT'] ?? '')
        . '&referrer=' . urlencode($_SERVER['HTTP_REFERER'] ?? '')
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
    if ('true' === ($response[1] ?? '')) // Unset when Akismet couldn't be reached
        return true;
    return false;
}

function tryRenderFromCache($key): void
{
    if (!empty($_SESSION['user_id']))
        return;
    $html = apcu_fetch('html_' . $key . '_' . sha1(strtok($_SERVER['REQUEST_URI'], '?')));
    if ($html !== false) {
        echo $html;
        exit;
    }
}

function saveCache($key, string $html, int $ttl = 900): void
{
    apcu_store('html_' . $key . '_' . sha1(strtok($_SERVER['REQUEST_URI'], '?')), $html, $ttl);
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

function render_template($template, $data) {
    $template = preg_replace_callback('/{{#(\w+)}}(.*?){{\/\1}}/s', function($m) use ($data) { // {{#var}}
        $value = $data[$m[1]] ?? null;
        if (is_array($value)) {
            $out = '';
            foreach ($value as $item) {
                $newData = is_array($item) ? array_replace($data, $item) : array_replace($data, ['.' => $item]);
                $out .= render_template($m[2], $newData);
            }
            return $out;
        } elseif ($value) {
            return render_template($m[2], $data);
        }
        return '';
    }, $template);
    $template = preg_replace_callback('/{{\^(\w+)}}(.*?){{\/\1}}/s', function($m) use ($data) { // {{^var}}
        return empty($data[$m[1]]) ? render_template($m[2], $data) : '';
    }, $template);
    $template = preg_replace_callback('/{{{(\w+)}}}/', function($m) use ($data) { // {{{var}}}
        return str_replace(['{{', '}}'], ['&#123;&#123;', '&#125;&#125;'], $data[$m[1]] ?? '');
    }, $template);
    $template = preg_replace_callback('/{{(\w+|.)}}/', function($m) use ($data) { // {{var}}
        $value = str_replace(['{{', '}}'], ['&#123;&#123;', '&#125;&#125;'], $data[$m[1]] ?? '');
        return htmlentities($value, ENT_QUOTES, 'UTF-8');
    }, $template);
    return $template;
}

function render($code, $template, $data, $cacheKey = NULL)
{
    http_response_code($code);
    $html = render_template(file_get_contents('templates/header.mustache', true), $data);
    $html .= render_template(file_get_contents('templates/' . $template . '.mustache', true), $data);
    $html .= render_template(file_get_contents('templates/footer.mustache', true), $data);
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

generateCsrf($data);
checkSessionToken($baseurl, $db);

// Fields are strings, except the tags[] checkboxes; anything else would hit a TypeError (500) further on
foreach ([$_GET, $_POST] as $fields) {
    foreach ($fields as $name => $value) {
        if ($name === 'tags' ? !is_array($value) : !is_string($value))
            render(400, '400', $data);
    }
}

$queryString = [];
if ($method === 'GET' && preg_match('/^(p[0-9]{1,3})?$/', $uri, $queryString)) {
    tryRenderFromCache('index');
    $page = (count($queryString) === 2) ? (int) substr($queryString[1], 1) : 1;
    $data['threads'] = getThreads($db, $page, $perPage);
    $totalPages = ceil(getTotalThreads($db) / $perPage);
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    render(200, 'index', $data, 'index');
} else if ($method === 'GET' && $uri === 'tags') {
    $data['tags'] = $config['tags'];
    $data['hashtags'] = array_keys(getHashtags($db, $baseurl));
    sort($data['hashtags']);
    $data['has_hashtags'] = (bool) $data['hashtags'];
    render(200, 'tags', $data);
} else if ($method === 'GET' && preg_match('/^tag\/([A-Za-z0-9_]{1,50})\/?(p[0-9]{1,3})?$/', $uri, $queryString)) {
    $data['tag'] = $queryString[1];
    $isCurated = in_array($data['tag'], $config['tags']);
    $threadIds = getHashtags($db, $baseurl)[strtolower($data['tag'])] ?? [];
    if (!$isCurated && !$threadIds) // Only known tags, so there's a bounded set of these pages to cache
        render(404, '404', $data);
    if (!$isCurated && $data['tag'] !== strtolower($data['tag']))
        redirect($baseurl . 'tag/' . strtolower($data['tag']) . (isset($queryString[2]) ? '/' . $queryString[2] : ''));
    tryRenderFromCache('index/tag'); // Cleared along with the front page
    [$where, $params] = tagFilter($data['tag'], $isCurated, $threadIds);
    $page = (count($queryString) === 3) ? (int) substr($queryString[2], 1) : 1;
    $data['heading'] = 'Threads tagged: ' . $data['tag'];
    $data['threads'] = getThreads($db, $page, $perPage, $where, $params);
    $totalPages = ceil(getTotalThreads($db, $where, $params) / $perPage);
    if ($page > max(1, $totalPages))
        render(404, '404', $data);
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    render(200, 'index', $data, 'index/tag');
} else if ($method === 'GET' && $uri === 'login') {
    $data['iq_question'] = $config['iqQuestion'];
    render(200, 'login', $data);
} else if ($method === 'POST' && $uri === 'login') {
    checkCsrf($data);
    checkRateLimit($config, $data, 'login', 5, 300);
    $user = validateLogin($db);
    if ($user !== FALSE) {
        login($db, $user);
        redirect($baseurl);
    }
    $data['has_login_error'] = TRUE;
    $data['username'] = isset($_POST['username']) ? $_POST['username'] : '';
    $data['iq_question'] = $config['iqQuestion'];
    render(400, 'login', $data);
} else if ($method === 'POST' && $uri === 'register') {
    checkCsrf($data);
    checkRateLimit($config, $data, 'register', 5, 300);
    if (checkCaptcha($config) === FALSE)
        render(403, '403', $data);
    $data['errors'] = validateRegistration($config, $db);
    if (count($data['errors']) === 0) {
        $userId = addUser($db);
        $code = generateVerification($db, $userId, 'verify');
        if (sendVerificationEmail($config, $_POST['email'], $code) === FALSE)
            render(500, '500', $data);
        $data['is_sent'] = TRUE;
        render(200, 'verify', $data);
    }
    $data['has_register_errors'] = TRUE;
    $data['username'] = isset($_POST['username']) ? $_POST['username'] : '';
    $data['email'] = isset($_POST['email']) ? $_POST['email'] : '';
    $data['answer'] = isset($_POST['answer']) ? $_POST['answer'] : '';
    $data['iq_question'] = $config['iqQuestion'];
    render(400, 'login', $data);
} else if ($method === 'GET' && $uri === 'reset') {
    render(200, 'reset', $data);
} else if ($method === 'POST' && $uri === 'reset') {
    checkCsrf($data);
    checkRateLimit($config, $data, 'reset', 3, 300);
    if (checkCaptcha($config) === FALSE)
        render(403, '403', $data);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id'], 'reset');
        if (sendResetEmail($config, $user['email'], $code) === FALSE)
            render(500, '500', $data);
    }
    $data['is_sent'] = TRUE;
    render(200, 'reset', $data);
} else if ($method === 'GET' && preg_match('/^reset\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    $data['code'] = $queryString[1];
    $data['is_valid_code'] = (bool) checkVerificationCode($config, $db, $queryString[1], 'reset');
    render(200, 'reset', $data);
} else if ($method === 'POST' && preg_match('/^reset\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    checkCsrf($data);
    checkRateLimit($config, $data, 'reset', 3, 300);
    $data['code'] = $queryString[1];
    $userId = checkVerificationCode($config, $db, $queryString[1], 'reset');
    $data['is_valid_code'] = (bool) $userId;
    if ($data['is_valid_code']) {
        $data['errors'] = validatePassword();
        if (count($data['errors']) === 0) {
            updatePassword($db, $userId);
            regenerateSessionToken($db, $userId);
            $data['is_success'] = TRUE;
        }
    }
    render(200, 'reset', $data);
} else if ($method === 'GET' && $uri === 'verify') {
    render(200, 'verify', $data);
} else if ($method === 'POST' && $uri === 'verify') {
    checkCsrf($data);
    checkRateLimit($config, $data, 'verify', 3, 300);
    if (checkCaptcha($config) === FALSE)
        render(403, '403', $data);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id'], 'verify');
        if (sendVerificationEmail($config, $user['email'], $code) === FALSE)
            render(500, '500', $data);
    }
    $data['is_sent'] = TRUE;
    render(200, 'verify', $data);
} else if ($method === 'GET' && preg_match('/^verify\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    $data['code'] = $queryString[1];
    $data['is_success'] = verifyUser($db, $queryString[1]);
    render(200, 'verify', $data);
} else if ($method === 'GET' && preg_match('/^email\/([A-Za-z0-9]{1,100})$/', $uri, $queryString)) {
    $data['is_success'] = confirmEmail($db, $queryString[1]);
    render(200, 'email', $data);
} else if ($method === 'GET' && preg_match('/^profile\/([0-9]{1,100})$/', $uri, $queryString)) {
    getProfile($db, $queryString[1], $data);
    $Parsedown = new ForumMarkdown();
    $Parsedown->setSafeMode(true);
    $data['bio'] = $Parsedown->text($data['bio']);
    $data['posts'] = getLatestPosts($db, $queryString[1], $perPage);
    $data['can_edit'] = isset($_SESSION['user_id']) ? (int) $queryString[1] === (int) $_SESSION['user_id'] || in_array($_SESSION['username'], $config['adminUsernames']) : FALSE;
    render(200, 'profile', $data);
} else if ($method === 'POST' && preg_match('/^profile\/delete\/([A-Za-z0-9_-]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    $userId = checkVerificationCode($config, $db, $queryString[1], 'profile');
    $data['is_valid_code'] = (bool) $userId;
    if ($data['is_valid_code'] && !empty($_POST['confirm'])) {
        deleteUser($db, $userId);
        invalidateCache(['index', 'thread/']);
        if ((int) $userId === (int) $_SESSION['user_id']) // An admin deleting someone else stays logged in
            logout();
        redirect($baseurl);
    }
    render(403, '403', $data);
} else if ($method === 'GET' && $uri === 'profile/edit') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    render(200, 'profileedit', $data);
} else if ($method === 'POST' && $uri === 'profile/edit') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'profileedit', 3, 300);
    $user = getUserByEmail($db, empty($_POST['email']) ? '' : $_POST['email']);
    if ($user) {
        $code = generateVerification($db, $user['id'], 'profile');
        if (sendProfileEmail($config, $user['email'], $code) === FALSE)
            render(500, '500', $data);
    }
    $data['is_sent'] = TRUE;
    render(200, 'profileedit', $data);
} else if ($method === 'GET' && preg_match('/^profile\/edit\/([A-Za-z0-9_-]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $data['code'] = $queryString[1];
    $userId = checkVerificationCode($config, $db, $queryString[1], 'profile');
    $data['is_valid_code'] = (bool) $userId;
    if ($data['is_valid_code']) {
        getProfile($db, $userId, $data);
    }
    render(200, 'profileedit', $data);
} else if ($method === 'POST' && preg_match('/^profile\/edit\/([A-Za-z0-9_-]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'profileedit', 3, 300);
    $data['code'] = $queryString[1];
    $userId = checkVerificationCode($config, $db, $queryString[1], 'profile');
    $data['is_valid_code'] = (bool) $userId;
    if ($data['is_valid_code']) {
        $data['email'] = $_POST['email'];
        $data['bio'] = $_POST['bio'];
        $data['errors'] = validateProfile($config, $baseurl, $db, $userId);
        if (count($data['errors']) === 0) {
            $emailCode = updateProfile($db, $userId);
            regenerateSessionToken($db, $userId);
            if ($emailCode) {
                if (sendEmailChangeEmail($config, $_POST['email'], $emailCode) === FALSE)
                    render(500, '500', $data);
                $data['is_email_pending'] = TRUE;
            }
            $data['is_success'] = TRUE;
        } else {
            $data['has_errors'] = TRUE;
        }
    }
    render(200, 'profileedit', $data);
} else if ($method === 'POST' && $uri === 'logout') {
    checkCsrf($data);
    logout();
    redirect($baseurl);
} else if ($method === 'GET' && $uri === 'post') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $data['tags'] = $config['tags'];
    render(200, 'post', $data);
} else if ($method === 'POST' && $uri === 'post') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'post', 5, 10);
    $data['tags'] = $config['tags'];
    $data['errors'] = [];
    validateThread($config, $baseurl, $data['errors']);
    validatePost($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $data, 'post-success', 5, 300);
        $threadId = addThread($db);
        if (isApproved($config, $db)) {
            addPost($db, $threadId, TRUE);
            sendNotificationEmails($config, $db, $threadId, $_SESSION['user_id'], $_SESSION['username'], $_POST['content']);
            invalidateCache(['index']);
        } else {
            addPost($db, $threadId, FALSE);
            sendApprovalRequestEmail($config, $db);
        }
        redirect($baseurl . 'thread/' . $threadId);
    }
    $data['has_errors'] = TRUE;
    $data['title'] = $_POST['title'];
    $data['content'] = $_POST['content'];
    render(400, 'post', $data);
} else if ($method === 'GET' && preg_match('/^thread\/([0-9]{1,50})\/latest$/', $uri, $queryString)) {
    $threadId = (int) $queryString[1];
    $totalPages = ceil(getTotalPosts($config, $db, $threadId) / $perPage);
    redirect($baseurl . 'thread/' . $threadId . '/p' . $totalPages);
} else if ($method === 'GET' && preg_match('/^thread\/([0-9]{1,50})(\/(p[0-9]{1,3})?)?$/', $uri, $queryString)) {
    $page = (count($queryString) === 4) ? (int) substr($queryString[3], 1) : 1;
    $threadId = (int) $queryString[1];
    $cacheKey = 'thread/' . $threadId . '/p' . $page;
    recordThreadView($db, $threadId); // Before the cache, so guests served from it are counted too
    tryRenderFromCache($cacheKey);
    getThread($config, $db, $threadId, $page, $perPage, $data);
    $totalPages = ceil(getTotalPosts($config, $db, $threadId) / $perPage);
    $data['page'] = $page;
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    if ($data['is_logged_in']) {
        markThreadAsRead($db, $threadId);
    }
    $data['id'] = $threadId;
    $data['html_title'] = $data['title'];
    render(200, 'thread', $data, $cacheKey);
} else if ($method === 'POST' && preg_match('/^thread\/([0-9]{1,50})(\/(p[0-9]{1,3})?)?$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'post', 5, 10); // Attempts too, as checking one for spam calls Akismet
    $page = (count($queryString) === 4) ? (int) substr($queryString[3], 1) : 1;
    $threadId = (int) $queryString[1];
    if (getTotalPosts($config, $db, $threadId) === 0) // Missing, or a held thread the user can't see
        render(404, '404', $data);
    $data['errors'] = [];
    validatePost($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $data, 'post-success', 5, 300);
        if (isApproved($config, $db)) {
            $postId = addPost($db, $threadId, TRUE);
            sendNotificationEmails($config, $db, $threadId, $_SESSION['user_id'], $_SESSION['username'], $_POST['content']);
            invalidateCache(['index', 'thread/' . $threadId . '/p']); // Every page, as a reply can add a page to the page links
        } else {
            $postId = addPost($db, $threadId, FALSE);
            sendApprovalRequestEmail($config, $db);
        }
        $totalPages = ceil(getTotalPosts($config, $db, $threadId) / $perPage);
        redirect($baseurl . 'thread/' . $threadId . '/p' . $totalPages . '#' . $postId);
    }
    $data['has_errors'] = TRUE;
    getThread($config, $db, $threadId, $page, $perPage, $data);
    $data['id'] = $threadId;
    $totalPages = ceil(getTotalPosts($config, $db, $threadId) / $perPage);
    $data['page'] = $page;
    $data['has_pagination'] = $totalPages > 1;
    $data['pages'] = getPaginationPages($page, $totalPages);
    $data['html_title'] = $data['title'];
    render(400, 'thread', $data);
} else if (in_array($method, ['GET', 'POST']) && preg_match('/^thread\/edit\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $threadId = (int) $queryString[1];
    getThread($config, $db, $threadId, 1, 1, $data);
    if (!$data['can_edit'])
        render(403, '403', $data);
    $data['id'] = $threadId;
    if ($method === 'GET')
        render(200, 'threadedit', $data);
    $data['title'] = $_POST['title'];
    $data['errors'] = [];
    checkCsrf($data);
    checkRateLimit($config, $data, 'post', 5, 10); // Attempts too, as checking one for spam calls Akismet
    validateThread($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $data, 'threadedit', 5, 300);
        updateThread($db, $threadId);
        invalidateCache(['index', 'thread/' . $threadId . '/p']);
        redirect($baseurl . 'thread/' . $threadId);
    }
    $data['has_errors'] = TRUE;
    render(400, 'threadedit', $data);
} else if (in_array($method, ['GET', 'POST']) && preg_match('/^post\/edit\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    $postId = (int) $queryString[1];
    $post = getPost($config, $db, $postId);
    if (!$post)
        render(404, '404', $data);
    $data['id'] = $postId;
    $data['can_move'] = in_array($_SESSION['username'], $config['adminUsernames']);
    if ($method === 'GET') {
        $data['content'] = $post['content'];
        render(200, 'postedit', $data);
    }
    $data['content'] = $_POST['content'];
    $data['errors'] = [];
    checkCsrf($data);
    checkRateLimit($config, $data, 'post', 5, 10); // Attempts too, as checking one for spam calls Akismet
    validatePost($config, $baseurl, $data['errors']);
    if (count($data['errors']) === 0) {
        checkRateLimit($config, $data, 'postedit', 5, 300);
        updatePost($db, $postId);
        invalidateCache(['thread/' . $post['thread_id'] . '/p']);
        redirect($baseurl . 'thread/' . $post['thread_id']);
    }
    $data['has_errors'] = TRUE;
    render(400, 'postedit', $data);
} else if ($method === 'POST' && preg_match('/^thread\/delete\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'threaddelete', 5, 300);
    $threadId = (int) $queryString[1];
    if (!deleteThread($config, $db, $threadId))
        render(403, '403', $data);
    invalidateCache(['index', 'thread/' . $threadId . '/p']);
    redirect($baseurl);
} else if ($method === 'POST' && preg_match('/^post\/delete\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'postdelete', 5, 300);
    $postId = (int) $queryString[1];
    $threadId = getThreadId($db, $postId);
    deletePost($config, $db, $postId);
    invalidateCache(['index', 'thread/' . $threadId . '/p']);
    redirect($baseurl . 'thread/' . $threadId . '/latest');
} else if ($method === 'POST' && preg_match('/^post\/move\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'] || !in_array($_SESSION['username'], $config['adminUsernames']))
        redirect($baseurl . 'login');
    checkCsrf($data);
    $postId = (int) $queryString[1];
    $oldThreadId = getThreadId($db, $postId);
    $newThreadId = (int) $_POST['thread_id'];
    // A held thread must stay hidden until it's approved, so nothing can be moved into it
    $query = $db->prepare('SELECT 1 FROM threads WHERE id = :id AND NOT EXISTS (SELECT 1 FROM posts WHERE thread_id = :id AND is_approved = 1)');
    $query->bindValue(':id', $newThreadId);
    $query->execute();
    if ($query->fetchColumn())
        render(400, '400', $data);
    movePost($db, $postId, $newThreadId);
    invalidateCache(['index', 'thread/' . $oldThreadId . '/p', 'thread/' . $newThreadId . '/p']);
    redirect($baseurl);
} else if ($method === 'GET' && $uri === 'approvals') {
    if (!isAdmin($config))
        render(403, '403', $data);
    $data['pending'] = getPendingPosts($db);
    $data['flagged'] = getFlaggedPosts($db);
    render(200, 'approvals', $data);
} else if ($method === 'POST' && preg_match('/^approvals\/(approve|reject-post|delete-user|dismiss-flags)\/([0-9]{1,100})$/', $uri, $queryString)) {
    if (!isAdmin($config))
        render(403, '403', $data);
    checkCsrf($data);
    $id = (int) $queryString[2];
    if ($queryString[1] === 'approve') {
        approveUser($config, $db, $id);
    } else if ($queryString[1] === 'reject-post') {
        $query = $db->prepare('SELECT thread_id FROM posts WHERE id = :id AND is_approved = 0 LIMIT 1');
        $query->bindValue(':id', $id);
        $query->execute();
        $threadId = $query->fetchColumn();
        if ($threadId)
            removePost($db, $id, $threadId);
    } else if ($queryString[1] === 'dismiss-flags') {
        $query = $db->prepare('DELETE FROM votes WHERE post_id = :id AND value = -1');
        $query->bindValue(':id', $id);
        $query->execute();
    } else {
        // Only for accounts awaiting approval: other accounts are deleted from their profile
        $query = $db->prepare('SELECT username FROM users WHERE id = :id AND is_approved = 0 LIMIT 1');
        $query->bindValue(':id', $id);
        $query->execute();
        $username = $query->fetchColumn();
        if ($username && !in_array($username, $config['adminUsernames']) && !in_array($username, $config['trustedUsernames']))
            deleteUser($db, $id);
    }
    invalidateCache(['index', 'thread/']);
    redirect($baseurl . 'approvals');
} else if ($method === 'GET' && $uri === 'upload') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    render(200, 'upload', $data);
} else if ($method === 'POST' && $uri === 'upload') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'upload', 10, 300);
    $data['filename'] = handleUpload($config, $db, $data);
    if (!isset($_POST['useJS']))
        render(200, 'upload', $data);
    http_response_code(201);
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'url' => $baseurl . 'files/' . $data['filename'], 'csrf' => $data['csrf']]);
    exit;
} else if ($method === 'POST' && $uri === 'vote') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    checkCsrf($data);
    checkRateLimit($config, $data, 'vote', 30, 60);
    $postId = isset($_POST['post_id']) ? (int) $_POST['post_id'] : 0;
    $query = $db->prepare('SELECT id FROM posts WHERE id = :id AND user_id != :user_id AND is_approved = 1 LIMIT 1');
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
    invalidateCache(['thread/' . $threadId . '/p']);
    redirect($baseurl . 'thread/' . $threadId . '/p' . $page . '#' . $postId);
} else if ($method === 'GET' && preg_match('/^mention(\/[0-9]{1,50})?\/@([A-Za-z0-9_-]{1,100})$/', $uri, $queryString)) {
    if (!$data['is_logged_in'])
        render(403, '403', $data);
    checkRateLimit($config, $data, 'mention', 60, 60); // Plenty for autocomplete as someone types
    header('Content-Type: application/json');
    $query = str_replace('_', '\_', $queryString[2]) . '%'; // _ is a LIKE wildcard but valid in usernames
    $results = [];
    if ($queryString[1] !== '') {
        // Prioritise usernames in thread
        $stmt = $db->prepare("SELECT DISTINCT u.username FROM posts AS p LEFT JOIN users AS u ON p.user_id = u.id WHERE p.thread_id = :thread_id AND p.is_approved = 1 AND u.username LIKE :query ESCAPE '\\' ORDER BY u.username LIMIT 5");
        $stmt->bindValue(':thread_id', substr($queryString[1], 1));
        $stmt->bindValue(':query', $query);
        $stmt->execute();
        $results = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }
    // Not people with posts awaiting approval, as those accounts are often spam
    $stmt = $db->prepare("SELECT username FROM users WHERE username LIKE :query ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM posts WHERE user_id = users.id AND is_approved = 0) ORDER BY username LIMIT 5");
    $stmt->bindValue(':query', $query);
    $stmt->execute();
    echo json_encode(array_slice(array_values(array_unique(array_merge($results, $stmt->fetchAll(PDO::FETCH_COLUMN, 0)))), 0, 5));
} else if (in_array($method, ['GET', 'POST']) && $uri === 'notifications') {
    if (!$data['is_logged_in'])
        redirect($baseurl . 'login');
    if ($method === 'POST') {
        checkCsrf($data);
        checkRateLimit($config, $data, 'notifications', 10, 60);
        $query = $db->prepare('UPDATE users SET notifications = NOT notifications WHERE id = :id LIMIT 1');
        $query->bindValue(':id', $_SESSION['user_id'], PDO::PARAM_INT);
        $query->execute();
        $data['is_updated'] = TRUE;
    }
    $query = $db->prepare('SELECT notifications FROM users WHERE id = :id LIMIT 1');
    $query->bindValue(':id', $_SESSION['user_id'], PDO::PARAM_INT);
    $query->execute();
    $data['is_on'] = (bool) $query->fetchColumn();
    render(200, 'notifications', $data);
} else if ($method === 'GET' && $uri === 'search') {
    $q = trim(is_string($_GET['q'] ?? NULL) ? $_GET['q'] : '');
    if (preg_match('/^#([A-Za-z0-9_]{1,50})$/', $q, $m))
        redirect($baseurl . 'tag/' . (in_array($m[1], $config['tags']) ? $m[1] : strtolower($m[1])));
    $data['web_search'] = 'https://duckduckgo.com/?q=' . urlencode('site:' . $baseurl . ' ' . $q);
    // Guests get a web search, so no page that queries the database on every request is open to crawlers
    if (!$data['is_logged_in'] || mb_strlen($q) < 2 || mb_strlen($q) > 100)
        redirect($data['web_search']);
    checkRateLimit($config, $data, 'search', 10, 60);
    $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';
    $data['heading'] = 'Search results for: ' . $q;
    $data['search'] = $q;
    $data['threads'] = getThreads($db, 1, 50, "t.title LIKE :q ESCAPE '\\'", [':q' => $like]);
    // Not people with posts awaiting approval, as those accounts are often spam
    $query = $db->prepare("SELECT id, username FROM users WHERE username LIKE :q ESCAPE '\\'
        AND NOT EXISTS (SELECT 1 FROM posts WHERE user_id = users.id AND is_approved = 0) ORDER BY username LIMIT 20");
    $query->bindValue(':q', $like);
    $query->execute();
    $data['users'] = [];
    foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $data['users'][] = $row + ['avatar' => avatar($row['username']), 'initial' => strtoupper($row['username'][0])];
    }
    $data['no_results'] = !$data['threads'] && !$data['users'];
    render(200, 'index', $data);
} else {
    render(404, '404', $data);
}
