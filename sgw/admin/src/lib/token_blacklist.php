<?php

require_once __DIR__ . '/request_token.php';

function token_blacklist_read_file(string $path): array {
    if (!file_exists($path)) {
        return [];
    }

    $raw = @file_get_contents($path);
    if ($raw === false || trim($raw) === '') {
        return [];
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return [];
    }

    $entries = [];
    foreach ($data as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $token = trim((string)($entry['token'] ?? ''));
        if ($token === '') {
            continue;
        }
        $entry['token'] = $token;
        $entries[] = $entry;
    }

    return array_values($entries);
}

function token_blacklist_write_file(string $path, array $entries): bool {
    return file_put_contents(
        $path,
        json_encode(array_values($entries), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
        LOCK_EX
    ) !== false;
}

function token_blacklist_load_manual(): array {
    return token_blacklist_read_file(TOKEN_BLACKLIST_JSON);
}

function token_blacklist_save_manual(array $entries): bool {
    return token_blacklist_write_file(TOKEN_BLACKLIST_JSON, $entries);
}

function token_blacklist_prune_expired_auto_entries(array $entries, ?int $now = null): array {
    $now ??= time();
    $active = [];

    foreach ($entries as $entry) {
        $token = trim((string)($entry['token'] ?? ''));
        if ($token === '') {
            continue;
        }

        $untilTs = strtotime((string)($entry['blocked_until'] ?? ''));
        if ($untilTs === false || $untilTs <= $now) {
            continue;
        }

        $entry['token'] = $token;
        $entry['source'] = 'auto';
        if (empty($entry['added_at'])) {
            $entry['added_at'] = date('Y-m-d H:i:s', $now);
        }
        $active[] = $entry;
    }

    return array_values($active);
}

function token_blacklist_load_auto(?int $now = null): array {
    return token_blacklist_prune_expired_auto_entries(
        token_blacklist_read_file(TOKEN_BLACKLIST_AUTO_JSON),
        $now
    );
}

function token_blacklist_save_auto(array $entries): bool {
    return token_blacklist_write_file(TOKEN_BLACKLIST_AUTO_JSON, $entries);
}

function token_blacklist_render_map_conf(array $tokens): string {
    $tokens = array_values(array_unique(array_filter(array_map(
        static fn($token) => trim((string)$token),
        $tokens
    ))));
    sort($tokens, SORT_STRING);

    $lines = [
        '# Token blacklist map - generated automatically',
        'map $arg_token $is_token_blacklisted_arg {',
        '    default 0;',
    ];

    foreach ($tokens as $token) {
        $escaped = addcslashes($token, "\\\"");
        $lines[] = "    \"{$escaped}\" 1;";
    }

    $lines[] = '}';
    $lines[] = '';
    $lines[] = 'map $uri $is_token_blacklisted_path {';
    $lines[] = '    default 0;';
    foreach ($tokens as $token) {
        $pattern = preg_quote($token, '~');
        $lines[] = "    ~^/downloadConfig\\.js/{$pattern}(?:/|$) 1;";
    }
    $lines[] = '}';
    $lines[] = '';
    $lines[] = 'map $args $is_token_blacklisted_l {';
    $lines[] = '    default 0;';
    foreach ($tokens as $token) {
        foreach (ss_token_l_query_variants($token) as $encoded) {
            $escaped = addcslashes($encoded, "\\\"");
            $lines[] = "    \"{$escaped}\" 1;";
        }
    }
    $lines[] = '}';
    $lines[] = '';
    $lines[] = 'map "$is_token_blacklisted_arg$is_token_blacklisted_path$is_token_blacklisted_l" $is_token_blacklisted {';
    $lines[] = '    default 0;';
    $lines[] = '    ~1 1;';
    $lines[] = '}';
    return implode("\n", $lines) . "\n";
}

function token_blacklist_sync_map(bool $triggerReload = false, ?int $now = null): array {
    $now ??= time();

    $manualEntries = token_blacklist_load_manual();
    $rawAutoEntries = token_blacklist_read_file(TOKEN_BLACKLIST_AUTO_JSON);
    $activeAutoEntries = token_blacklist_prune_expired_auto_entries($rawAutoEntries, $now);

    $rawAutoJson = json_encode(array_values($rawAutoEntries), JSON_UNESCAPED_UNICODE);
    $activeAutoJson = json_encode(array_values($activeAutoEntries), JSON_UNESCAPED_UNICODE);
    $autoChanged = $rawAutoJson !== $activeAutoJson;

    if ($autoChanged && !token_blacklist_save_auto($activeAutoEntries)) {
        return ['ok' => false, 'changed' => false, 'nginx_reloaded' => false, 'tokens' => []];
    }

    $tokens = array_merge(
        array_map(static fn($entry) => $entry['token'], $manualEntries),
        array_map(static fn($entry) => $entry['token'], $activeAutoEntries)
    );

    $rendered = token_blacklist_render_map_conf($tokens);
    $current = file_exists(TOKEN_BLACKLIST_MAP_CONF) ? @file_get_contents(TOKEN_BLACKLIST_MAP_CONF) : false;
    $mapChanged = $current !== $rendered;

    if ($mapChanged && file_put_contents(TOKEN_BLACKLIST_MAP_CONF, $rendered, LOCK_EX) === false) {
        return ['ok' => false, 'changed' => false, 'nginx_reloaded' => false, 'tokens' => []];
    }

    $changed = $autoChanged || $mapChanged;
    $reloaded = false;
    if ($changed && $triggerReload) {
        $reloaded = nginx_reload();
    }

    return [
        'ok' => true,
        'changed' => $changed,
        'nginx_reloaded' => $reloaded,
        'tokens' => array_values(array_unique($tokens)),
    ];
}

function token_blacklist_effective_entries(?int $now = null): array {
    $now ??= time();

    $manualByToken = [];
    foreach (token_blacklist_load_manual() as $entry) {
        $manualByToken[$entry['token']] = $entry;
    }

    $autoByToken = [];
    foreach (token_blacklist_load_auto($now) as $entry) {
        $autoByToken[$entry['token']] = $entry;
    }

    $tokens = array_values(array_unique(array_merge(array_keys($manualByToken), array_keys($autoByToken))));
    $entries = [];

    foreach ($tokens as $token) {
        $manual = $manualByToken[$token] ?? null;
        $auto = $autoByToken[$token] ?? null;
        $manualComment = is_array($manual) ? trim((string)($manual['comment'] ?? '')) : '';
        $autoComment = is_array($auto) ? trim((string)($auto['comment'] ?? '')) : '';
        $addedAt = is_array($manual) && !empty($manual['added_at'])
            ? (string)$manual['added_at']
            : (is_array($auto) ? (string)($auto['added_at'] ?? '') : '');

        if ($manual && $auto) {
            $source = 'manual+auto';
            $sourceLabel = '手动 + 自动';
        } elseif ($manual) {
            $source = 'manual';
            $sourceLabel = '手动';
        } else {
            $source = 'auto';
            $sourceLabel = '自动';
        }

        $entries[] = [
            'token' => $token,
            'comment' => $manualComment !== '' ? $manualComment : $autoComment,
            'added_at' => $addedAt,
            'source' => $source,
            'source_label' => $sourceLabel,
            'blocked_until' => is_array($auto) ? (string)($auto['blocked_until'] ?? '') : '',
            'ua_count' => is_array($auto) ? (int)($auto['ua_count'] ?? 0) : 0,
            'ua_samples' => array_values(array_filter(
                is_array($auto) && is_array($auto['ua_samples'] ?? null) ? $auto['ua_samples'] : [],
                static fn($ua) => trim((string)$ua) !== ''
            )),
            'last_seen' => is_array($auto) ? (string)($auto['last_seen'] ?? '') : '',
            'reason' => is_array($auto) ? (string)($auto['reason'] ?? '') : '',
            'trigger' => is_array($auto) ? (string)($auto['trigger'] ?? '') : '',
        ];
    }

    usort($entries, static function(array $a, array $b): int {
        $rank = ['manual+auto' => 0, 'manual' => 1, 'auto' => 2];
        $rankA = $rank[$a['source']] ?? 9;
        $rankB = $rank[$b['source']] ?? 9;
        if ($rankA !== $rankB) {
            return $rankA <=> $rankB;
        }

        $timeA = strtotime((string)($a['blocked_until'] ?: $a['added_at'])) ?: 0;
        $timeB = strtotime((string)($b['blocked_until'] ?: $b['added_at'])) ?: 0;
        if ($timeA !== $timeB) {
            return $timeB <=> $timeA;
        }

        return strcmp($a['token'], $b['token']);
    });

    return $entries;
}
