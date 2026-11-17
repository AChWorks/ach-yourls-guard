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
if ($phase !== 'verify') {
    throw new RuntimeException('Expected ping or verify.');
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

echo 'PASS loopback HTTP: authenticated API allow/deny, old/new real redirects, protected admin settings.' . "\n";
