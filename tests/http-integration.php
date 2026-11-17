<?php
declare(strict_types=1);

/** Real loopback HTTP exercise; caller owns an isolated YOURLS and PHP server. */
$port = (int) (getenv('ACH_IT_HTTP_PORT') ?: 0);
if ($port < 1024 || $port > 65535) {
    throw new RuntimeException('Test HTTP listener port missing.');
}
$phase = $argv[1] ?? '';
if ($phase === 'ping') {
    $socket = @fsockopen('127.0.0.1', $port, $errno, $error, 1.0);
    if (!is_resource($socket)) {
        exit(1);
    }
    fclose($socket);
    exit(0);
}
if (!in_array($phase, ['verify','verify-public'], true)) {
    throw new RuntimeException('Expected ping, verify, or verify-public.');
}
$base = 'http://127.0.0.1:' . $port;
$expect = static function (bool $truth, string $message): void {
    if (!$truth) {
        throw new RuntimeException('HTTP integration: ' . $message);
    }
};
$request = static function (string $path, ?array $post = null) use ($base): array {
    $options = [
        'http' => [
            'method' => $post === null ? 'GET' : 'POST',
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => 6,
            'header' => $post === null ? '' : "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $post === null ? '' : http_build_query($post),
        ],
    ];
    $body = @file_get_contents($base . $path, false, stream_context_create($options));
    if (!is_string($body)) {
        throw new RuntimeException('Loopback HTTP request failed: ' . $path);
    }
    $headers = $http_response_header ?? [];
    if (!isset($headers[0]) || !preg_match('/\s(\d{3})\s/', $headers[0], $match)) {
        throw new RuntimeException('HTTP status line missing: ' . $path);
    }
    return [(int) $match[1], $headers, $body];
};
if ($phase === 'verify-public') {
    foreach (['/admin/plugins.php?page=ach_url_guard',
              '/admin/plugins.php?page=ach_url_guard_history'] as $url) {
        [$status,,$html] = $request($url);
        $expect($status === 403, 'Public-mode anonymous admin GET must return 403: ' . $url);
        $expect(!str_contains($html, 'Historical Link Review')
            && !str_contains($html, 'name="ach_url_guard_save"'),
            'Public mode cannot disclose plugin admin controls.');
        [$status,,$html] = $request($url, [
            'history_action'=>'delete','history_keyword'=>'yourlsblog',
            'history_confirm'=>'1','nonce'=>'anonymous'
        ]);
        $expect($status === 403, 'Public-mode anonymous admin POST must return 403: ' . $url);
    }
    // The disposable router routes / to yourls-loader.php; request the native index directly.
    [$status,,$body] = $request('/index.php');
    $expect($status === 200, 'Public shortening homepage still available when admin is protected.');
    echo 'PASS public-mode unauthenticated settings/review GET and POST denied; homepage works.' . "\n";
    exit(0);
}
$credentials = [
    'username' => 'integration',
    'password' => (string) getenv('ACH_IT_ADMIN_PASS'),
    'action' => 'shorturl',
    'format' => 'json',
    'title' => 'HTTP API integration',
];

[$httpCode, , $body] = $request('/yourls-api.php', $credentials + [
    'url' => 'https://bad.example/from-http', 'keyword' => 'http-denied',
]);
$denied = json_decode($body, true);
$expect(is_array($denied) && ($denied['status'] ?? '') === 'fail', 'Authenticated HTTP API must reject blocked domain, got HTTP ' . $httpCode);
$expect(($denied['code'] ?? '') === 'error:ach_url_guard:blocked_domain', 'Actual endpoint deny reason must match policy.');
$expect($httpCode === 403, 'Blocked API result must return HTTP 403.');

foreach ([
    ['https://example.com/casino/slot', 'http-term', 'blocked_url_term', 403],
    ['https://example.com/OFFER/2026', 'http-regex', 'blocked_url_pattern', 403],
    ['https://example.com/safe', 'reserved', 'blocked_short_keyword', 403],
    ['https://example.com/safe', 'four', 'keyword_too_short', 400],
    ['https://example.com/safe', 'abcdefghijklmnopqrstu', 'keyword_too_long', 400],
] as [$url, $keyword, $reason, $expectedHttp]) {
    [$httpCode, , $body] = $request('/yourls-api.php', $credentials + ['url' => $url, 'keyword' => $keyword]);
    $denied = json_decode($body, true);
    $expect(is_array($denied) && ($denied['code'] ?? '') === 'error:ach_url_guard:' . $reason,
        'Actual authenticated HTTP API must reject ' . $reason);
    $expect($httpCode === $expectedHttp, 'Actual HTTP status must match ' . $reason);
}

[$httpCode, , $body] = $request('/yourls-api.php', $credentials + [
    'url' => 'https://example.com/HTTP/ExactMin', 'keyword' => 'five5',
]);
$exactMin = json_decode($body, true);
$expect(is_array($exactMin) && ($exactMin['status'] ?? '') === 'success'
    && ($exactMin['url']['keyword'] ?? '') === 'five5' && $httpCode === 200,
    'Authenticated native HTTP API accepts a custom keyword exactly at minimum length.');

[$httpCode, , $body] = $request('/yourls-api.php', $credentials + [
    'url' => 'https://example.com/HTTP/CaseSensitive?abc=XYZ', 'keyword' => 'HTTP-UPPER',
]);
$allowed = json_decode($body, true);
$expect(is_array($allowed) && ($allowed['status'] ?? '') === 'success', 'Authenticated HTTP API must create allowed destination, got HTTP ' . $httpCode);
$expect(($allowed['url']['keyword'] ?? '') === 'http-upper', 'Force Lowercase must affect keyword but not target path.');
$expect($httpCode === 200, 'Allowed API request must return HTTP 200.');

[$httpCode, $headers] = $request('/yourlsblog');
$expect(in_array($httpCode, [301, 302, 307, 308], true), 'Existing short link must redirect.');
$existingLocation = '';
foreach ($headers as $header) {
    if (stripos($header, 'Location:') === 0) {
        $existingLocation = trim(substr($header, 9));
        break;
    }
}
$expect($existingLocation === 'https://blog.yourls.org/', 'Existing link redirect target must stay unchanged.');

[$httpCode, $headers] = $request('/HTTP-UPPER');
$expect(in_array($httpCode, [301, 302, 307, 308], true), 'New mixed-case alias must redirect with Force Lowercase.');
$newLocation = '';
foreach ($headers as $header) {
    if (stripos($header, 'Location:') === 0) {
        $newLocation = trim(substr($header, 9));
        break;
    }
}
$expect($newLocation === 'https://example.com/HTTP/CaseSensitive?abc=XYZ', 'Redirect destination must retain original path and query case.');

[$httpCode, , $body] = $request('/admin/plugins.php?page=ach_url_guard');
$expect(!str_contains($body, 'name="ach_url_guard_save"'), 'Unauthenticated visitor cannot access Guard settings form.');
[$httpCode, , $body] = $request('/admin/plugins.php?page=ach_url_guard', [
    'ach_url_guard_save'=>'1', 'nonce'=>'anonymous', 'mode'=>'monitor',
]);
$expect(!str_contains($body, 'Settings saved.') && !str_contains($body, 'name="ach_url_guard_save"'),
    'Private-mode anonymous settings POST cannot change policy.');


[$httpCode, , $body] = $request('/admin/plugins.php?page=ach_url_guard_history');
$expect(!str_contains($body, 'Historical Link Review'), 'Unauthenticated visitor cannot access historical review page.');
$expect(!str_contains($body, 'history_action'), 'Unauthenticated visitor cannot access review/delete forms.');
[$httpCode, , $body] = $request('/admin/plugins.php?page=ach_url_guard_history', [
    'history_action'=>'delete','history_keyword'=>'yourlsblog','history_confirm'=>'1',
    'nonce'=>'anonymous',
]);
$expect(!str_contains($body, 'Reviewed short link was deleted')
    && !str_contains($body, 'history_action'),
    'Private-mode anonymous review/delete POST cannot reach destructive forms.');



echo 'PASS loopback HTTP: authenticated API allow/deny, old/new real redirects, protected admin settings.' . "\n";
