<?php

function ss_extract_request_target(string $requestOrTarget): string {
    $requestOrTarget = trim($requestOrTarget);
    if ($requestOrTarget === '') {
        return '';
    }

    if (preg_match('/^[A-Z]+\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/', $requestOrTarget, $m)) {
        return $m[1];
    }

    return $requestOrTarget;
}

function ss_parse_target_path(string $requestOrTarget): string {
    $target = ss_extract_request_target($requestOrTarget);
    $path = parse_url($target, PHP_URL_PATH);
    return is_string($path) ? $path : '';
}

function ss_parse_target_query(string $requestOrTarget): string {
    $target = ss_extract_request_target($requestOrTarget);
    $query = parse_url($target, PHP_URL_QUERY);
    return is_string($query) ? $query : '';
}

function ss_extract_token_from_download_config_path(string $pathOrTarget): string {
    $path = ss_parse_target_path($pathOrTarget);
    if ($path === '') {
        return '';
    }

    if (preg_match('~(?:^|/)downloadConfig\.js/([A-Za-z0-9._-]+)(?:/|$)~', $path, $m)) {
        return trim($m[1]);
    }

    return '';
}

function ss_base64_decode_loose(string $value): ?string {
    $value = rawurldecode(trim($value));
    if ($value === '') {
        return null;
    }

    $candidates = [
        $value,
        strtr($value, '-_', '+/'),
    ];

    foreach ($candidates as $candidate) {
        $padLen = (4 - (strlen($candidate) % 4)) % 4;
        $candidatePadded = $candidate . str_repeat('=', $padLen);
        $decoded = base64_decode($candidatePadded, true);
        if ($decoded !== false && $decoded !== '') {
            return $decoded;
        }
    }

    return null;
}

function ss_extract_token_from_l_query(string $requestOrTarget): string {
    $path = ss_parse_target_path($requestOrTarget);
    if ($path !== '/L' && $path !== 'L') {
        return '';
    }

    $query = ss_parse_target_query($requestOrTarget);
    if ($query === '') {
        return '';
    }

    $directToken = ss_extract_token_from_download_config_path($query);
    if ($directToken !== '') {
        return $directToken;
    }

    $decoded = ss_base64_decode_loose($query);
    if ($decoded === null) {
        return '';
    }

    return ss_extract_token_from_download_config_path($decoded);
}

function ss_extract_token_from_request(string $requestOrTarget): string {
    $target = ss_extract_request_target($requestOrTarget);
    if ($target === '') {
        return '';
    }

    if (preg_match('/(?:^|[?&])token=([^&\s"]+)/i', $target, $m)) {
        return trim($m[1]);
    }

    $pathToken = ss_extract_token_from_download_config_path($target);
    if ($pathToken !== '') {
        return $pathToken;
    }

    return ss_extract_token_from_l_query($target);
}

function ss_is_subscription_request(string $requestOrTarget): bool {
    $target = ss_extract_request_target($requestOrTarget);
    if ($target === '') {
        return false;
    }

    if (ss_extract_token_from_request($target) !== '') {
        return true;
    }

    $path = ss_parse_target_path($target);
    if ($path === '/L' || $path === 'L') {
        return true;
    }

    return str_contains($path, '/api/v1/client/subscribe');
}

function ss_token_l_query_variants(string $token): array {
    $token = trim($token);
    if ($token === '') {
        return [];
    }

    $rawVariants = [
        "downloadConfig.js/{$token}?timestamp=1",
        "/downloadConfig.js/{$token}?timestamp=1",
        "downloadConfig.js/{$token}",
        "/downloadConfig.js/{$token}",
    ];

    $encoded = [];
    foreach ($rawVariants as $raw) {
        $base64 = base64_encode($raw);
        $encoded[] = $base64;
        $encoded[] = rawurlencode($base64);
    }

    return array_values(array_unique($encoded));
}
