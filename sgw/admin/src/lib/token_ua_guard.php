<?php

require_once __DIR__ . '/request_token.php';

function token_ua_guard_status(int $uaCount): string {
    if ($uaCount > TOKEN_UA_GUARD_BAN_UA) {
        return 'blocked';
    }
    if ($uaCount > TOKEN_UA_GUARD_WARN_UA) {
        return 'warning';
    }
    return '';
}

function token_ua_guard_collect(?int $now = null): array {
    $now ??= time();
    if (!file_exists(LOG_FILE)) {
        return [];
    }

    $cutoffTs = $now - (TOKEN_UA_GUARD_LOOKBACK_HOURS * 3600);
    $tokens = [];
    $handle = fopen(LOG_FILE, 'r');
    if (!$handle) {
        return [];
    }

    while (($line = fgets($handle)) !== false) {
        $line = rtrim($line);
        if ($line === '') {
            continue;
        }

        if (!preg_match('/^(\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+) "([^"]*)"$/', $line, $m)) {
            continue;
        }

        [, $ip, $time, $request, $status, , $ua] = $m;
        if ((int)$status !== 200) {
            continue;
        }

        $ua = trim($ua);
        if ($ua === '') {
            continue;
        }
        if (is_ignored_stats_ua($ua)) {
            continue;
        }

        $token = ss_extract_token_from_request($request);
        if ($token === '') {
            continue;
        }

        $ts = token_ua_guard_parse_log_timestamp($time);
        if ($ts < $cutoffTs) {
            continue;
        }

        if (!isset($tokens[$token])) {
            $tokens[$token] = [
                'token' => $token,
                'ua_map' => [],
                'ip_map' => [],
                'last_seen_ts' => 0,
            ];
        }

        $uaKey = strtolower($ua);
        $tokens[$token]['ua_map'][$uaKey] = $ua;
        $tokens[$token]['ip_map'][$ip] = $ip;
        if ($ts > $tokens[$token]['last_seen_ts']) {
            $tokens[$token]['last_seen_ts'] = $ts;
        }
    }

    fclose($handle);

    return $tokens;
}

function token_ua_guard_hits(?int $now = null): array {
    $rows = [];
    foreach (token_ua_guard_collect($now) as $entry) {
        $uaValues = array_values($entry['ua_map']);
        $ipValues = array_values($entry['ip_map']);
        $uaCount = count($uaValues);
        $status = token_ua_guard_status($uaCount);
        if ($status === '') {
            continue;
        }

        $rows[] = [
            'token' => $entry['token'],
            'ua_count' => $uaCount,
            'ua_samples' => array_slice($uaValues, -5),
            'ip_count' => count($ipValues),
            'ip_samples' => array_slice($ipValues, -5),
            'last_seen_ts' => $entry['last_seen_ts'],
            'last_seen' => $entry['last_seen_ts'] > 0 ? date('Y-m-d H:i:s', $entry['last_seen_ts']) : '',
            'status' => $status,
            'should_ban' => $status === 'blocked',
        ];
    }

    usort($rows, static function(array $a, array $b): int {
        $rank = ['blocked' => 0, 'warning' => 1];
        $rankA = $rank[$a['status']] ?? 9;
        $rankB = $rank[$b['status']] ?? 9;
        if ($rankA !== $rankB) {
            return $rankA <=> $rankB;
        }
        if ($a['ua_count'] !== $b['ua_count']) {
            return $b['ua_count'] <=> $a['ua_count'];
        }
        if ($a['ip_count'] !== $b['ip_count']) {
            return $b['ip_count'] <=> $a['ip_count'];
        }
        return $b['last_seen_ts'] <=> $a['last_seen_ts'];
    });

    return $rows;
}

function token_ua_guard_parse_log_timestamp(string $time): int {
    $dt = DateTime::createFromFormat('d/M/Y:H:i:s O', $time);
    return $dt ? $dt->getTimestamp() : 0;
}
