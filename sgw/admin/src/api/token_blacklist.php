<?php
require_once __DIR__ . '/_auth.php';
require_once dirname(__DIR__) . '/lib/token_blacklist.php';
require_once dirname(__DIR__) . '/lib/request_token.php';

$method = $_SERVER['REQUEST_METHOD'];

// GET — 列出黑名单 Token + 今日各 IP 拉取统计
if ($method === 'GET') {
    $entries = token_blacklist_effective_entries();
    if (empty($entries)) {
        json_out(['ok' => true, 'entries' => []]);
    }

    $blacklistedSet = array_flip(array_column($entries, 'token'));

    // 读取今日日志，统计每个黑名单 Token 被哪些 IP 拉取及次数
    $tokenIpCount = []; // token => [ip => count]

    if (file_exists(LOG_FILE)) {
        $handle = fopen(LOG_FILE, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                if (!preg_match('/^(\S+) \[([^\]]+)\] "([^"]*)" (\d+)/', $line, $m)) continue;
                [, $ip, $time, $request, $status] = $m;
                if (!is_log_time_today($time)) continue;
                if ((int)$status !== 200) continue;
                $tok = ss_extract_token_from_request($request);
                if ($tok === '') continue;
                if (!isset($blacklistedSet[$tok])) continue;
                $tokenIpCount[$tok][$ip] = ($tokenIpCount[$tok][$ip] ?? 0) + 1;
            }
            fclose($handle);
        }
    }

    $result = array_map(function ($e) use ($tokenIpCount) {
        $tok   = $e['token'];
        $pulls = [];
        if (isset($tokenIpCount[$tok])) {
            arsort($tokenIpCount[$tok]);
            foreach ($tokenIpCount[$tok] as $ip => $cnt) {
                $pulls[] = ['ip' => $ip, 'count' => $cnt];
            }
        }
        $e['today_pulls'] = $pulls;
        $e['today_total'] = array_sum(array_column($pulls, 'count'));
        return $e;
    }, $entries);

    json_out(['ok' => true, 'entries' => $result]);
}

// POST — 添加 Token 黑名单
if ($method === 'POST') {
    $body    = json_decode(file_get_contents('php://input'), true) ?? [];
    $token   = trim($body['token'] ?? '');
    $comment = trim($body['comment'] ?? '');

    if (!$token) json_err('请输入 Token');

    $entries = token_blacklist_load_manual();
    foreach ($entries as $e) {
        if ($e['token'] === $token) json_err('该 Token 已在黑名单中');
    }

    $entries[] = ['token' => $token, 'comment' => $comment, 'added_at' => date('Y-m-d H:i')];
    if (!token_blacklist_save_manual($entries)) json_err('写入失败，请检查文件权限');
    $sync = token_blacklist_sync_map(true);
    if (!$sync['ok']) json_err('同步Token拦截规则失败，请检查文件权限');
    json_out(['ok' => true, 'nginx_reloaded' => $sync['nginx_reloaded']]);
}

// PATCH — 更新备注
if ($method === 'PATCH') {
    $body    = json_decode(file_get_contents('php://input'), true) ?? [];
    $token   = trim($body['token'] ?? '');
    $comment = trim($body['comment'] ?? '');

    if (!$token) json_err('缺少 token 参数');

    $entries = token_blacklist_load_manual();
    $found   = false;
    foreach ($entries as &$e) {
        if ($e['token'] === $token) { $e['comment'] = $comment; $found = true; break; }
    }
    unset($e);

    if ($found) {
        if (!token_blacklist_save_manual($entries)) json_err('写入失败，请检查文件权限');
        json_out(['ok' => true]);
    }

    $autoEntries = token_blacklist_load_auto();
    foreach ($autoEntries as &$e) {
        if ($e['token'] === $token) { $e['comment'] = $comment; $found = true; break; }
    }
    unset($e);

    if (!$found) json_err('未找到该Token');
    if (!token_blacklist_save_auto($autoEntries)) json_err('写入失败，请检查文件权限');
    json_out(['ok' => true]);
}

// DELETE — 移除 Token 黑名单
if ($method === 'DELETE') {
    $body  = json_decode(file_get_contents('php://input'), true) ?? [];
    $token = trim($body['token'] ?? '');

    if (!$token) json_err('缺少 token 参数');

    $manualEntries = array_values(array_filter(
        token_blacklist_load_manual(),
        static fn($e) => $e['token'] !== $token
    ));
    $autoEntries = array_values(array_filter(
        token_blacklist_load_auto(),
        static fn($e) => $e['token'] !== $token
    ));

    if (!token_blacklist_save_manual($manualEntries)) json_err('写入失败，请检查文件权限');
    if (!token_blacklist_save_auto($autoEntries)) json_err('写入失败，请检查文件权限');

    $sync = token_blacklist_sync_map(true);
    if (!$sync['ok']) json_err('同步Token拦截规则失败，请检查文件权限');
    json_out(['ok' => true, 'nginx_reloaded' => $sync['nginx_reloaded']]);
}

json_err('不支持的请求方式', 405);
