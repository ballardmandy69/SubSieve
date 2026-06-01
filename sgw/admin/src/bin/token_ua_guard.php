<?php

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/token_blacklist.php';
require_once dirname(__DIR__) . '/lib/token_ua_guard.php';

$now = time();
$detected = array_values(array_filter(
    token_ua_guard_hits($now),
    static fn(array $row) => !empty($row['should_ban'])
));
$autoEntries = token_blacklist_load_auto($now);
$autoByToken = [];
foreach ($autoEntries as $entry) {
    $autoByToken[$entry['token']] = $entry;
}

$changed = false;
foreach ($detected as $meta) {
    $token = $meta['token'];
    $existing = $autoByToken[$token] ?? [];
    $existingUntilTs = strtotime((string)($existing['blocked_until'] ?? '')) ?: 0;
    $blockedUntilTs = max($existingUntilTs, $now + (TOKEN_UA_GUARD_BAN_HOURS * 3600));
    $generatedComment = sprintf(
        '自动封禁：%d小时内检测到 %d 个不同UA（阈值>%d）',
        TOKEN_UA_GUARD_LOOKBACK_HOURS,
        $meta['ua_count'],
        TOKEN_UA_GUARD_BAN_UA
    );
    $existingComment = trim((string)($existing['comment'] ?? ''));
    $comment = ($existingComment !== '' && !str_starts_with($existingComment, '自动封禁：'))
        ? $existingComment
        : $generatedComment;

    $updatedEntry = [
        'token' => $token,
        'comment' => $comment,
        'added_at' => (string)($existing['added_at'] ?? date('Y-m-d H:i:s', $now)),
        'blocked_until' => date('Y-m-d H:i:s', $blockedUntilTs),
        'ua_count' => $meta['ua_count'],
        'ua_samples' => $meta['ua_samples'],
        'ip_count' => $meta['ip_count'],
        'ip_samples' => $meta['ip_samples'],
        'last_seen' => $meta['last_seen'],
        'reason' => 'ua_limit',
        'trigger' => sprintf(
            '%d小时内检测到 %d 个不同UA（阈值>%d）',
            TOKEN_UA_GUARD_LOOKBACK_HOURS,
            $meta['ua_count'],
            TOKEN_UA_GUARD_BAN_UA
        ),
        'source' => 'auto',
    ];

    $currentJson = json_encode($existing, JSON_UNESCAPED_UNICODE);
    $updatedJson = json_encode($updatedEntry, JSON_UNESCAPED_UNICODE);
    if ($currentJson !== $updatedJson) {
        $autoByToken[$token] = $updatedEntry;
        $changed = true;
    }
}

if ($changed && !token_blacklist_save_auto(array_values($autoByToken))) {
    guard_log('写入自动 Token 封禁文件失败');
    exit(1);
}

$sync = token_blacklist_sync_map(true, $now);
if (!$sync['ok']) {
    guard_log('同步 Token 封禁映射失败');
    exit(1);
}

if ($changed || $sync['changed']) {
    guard_log(sprintf(
        '自动封禁扫描完成：达到封禁阈值 %d 个 Token，当前生效 %d 个，nginx_reload=%s',
        count($detected),
        count($sync['tokens']),
        $sync['nginx_reloaded'] ? 'yes' : 'no'
    ));
}

function guard_log(string $message): void {
    @file_put_contents(
        TOKEN_UA_GUARD_LOG,
        '[' . date('Y-m-d H:i:s') . "] $message\n",
        FILE_APPEND | LOCK_EX
    );
}
