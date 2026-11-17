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
$request = static function (string $path, ?array $post = null, string $cookie = '') use ($base): array {
    $headers = [];
    if ($post !== null) $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    if ($cookie !== '') $headers[] = 'Cookie: ' . $cookie;
    $options = [
        'http' => [
            'method' => $post === null ? 'GET' : 'POST',
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => 6,
            'header' => implode("\r\n", $headers) . "\r\n",
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

/**
 * A real YOURLS cookie session, through the native login and admin routes.
 * No auth test filter, fake admin user, or direct BulkHistory::startDeletion
 * call is used to authorize this fixture deletion.
 */
$exerciseBulkHttp = static function (string $mode) use ($request, $expect): void {
    $jobID = (string) getenv('ACH_IT_HTTP_' . strtoupper($mode) . '_ID');
    $otherID = (string) getenv('ACH_IT_HTTP_OTHER_ID');
    $expect((bool) preg_match('/^[0-9a-f]{24}$/D', $jobID), 'HTTP job available for ' . $mode);
    $expect((bool) preg_match('/^[0-9a-f]{24}$/D', $otherID), 'Other-owner job available');

    $cookieFile = (string) getenv('ACH_IT_TEST_COOKIE_FILE');
    if ($mode === 'private') {
        // Acquire an authentic YOURLS browser cookie via native form login.
        $login = [
            'username' => 'integration',
            'password' => (string) getenv('ACH_IT_ADMIN_PASS'),
            'nonce' => (string) getenv('ACH_IT_LOGIN_NONCE'),
            'submit' => 'Login',
        ];
        [$loginStatus,$loginHeaders] = $request('/admin/plugins.php?page=ach_url_guard_history', $login);
        $cookies = [];
        foreach ($loginHeaders as $header) {
            if (preg_match('/^Set-Cookie:s*([^;,
]+)/i', $header, $match)) $cookies[] = $match[1];
        }
        $expect(in_array($loginStatus, [301,302,303], true) && count($cookies) > 0,
            'Real native private-mode login must issue an authenticated cookie');
        $cookie = implode('; ', $cookies);
        $expect($cookieFile !== '' && file_put_contents($cookieFile, $cookie) !== false,
            'Private session cookie remains private inside disposable test directory');
        chmod($cookieFile, 0600);
    } else {
        // YOURLS public mode has NO login screen. Reuse the genuine cookie
        // produced by native YOURLS private-mode login before the server
        // is restarted in public mode. No fake-user filter is injected.
        $expect($cookieFile !== '' && is_file($cookieFile), 'Private-mode login cookie available');
        $cookie = (string) file_get_contents($cookieFile);
        $expect($cookie !== '', 'A real signed session cookie is needed in public mode');
    }

    $apiPath = '/admin/admin-ajax.php?action=ach_guard_bulk_status&job=';
    [$code,$headers,$raw] = $request($apiPath . $jobID, null, $cookie);
    $state = json_decode($raw, true);
    $expect($code === 200 && is_array($state) && ($state['ok'] ?? false) === true
        && ($state['phase'] ?? '') === 'ready' && ($state['matched'] ?? 0) === 1
        && ($state['deleted'] ?? 1) === 0, 'Authenticated native AJAX status GET in ' . $mode);
    $headerText = strtolower(implode("\n", $headers));
    $expect(str_contains($headerText, 'content-type: application/json')
        && str_contains($headerText, 'cache-control:') && str_contains($headerText, 'no-store'),
        'Authenticated JSON status is correctly marked non-cacheable');
    $expect(!str_contains($raw, 'NEVER_EXPOSE_HTTP')
        && !str_contains($raw, 'bad.example')
        && !str_contains($raw, '?token='),
        'Authenticated progress never reveals destination URL, tokens or paths');

    [$otherStatus,,$otherBody] = $request($apiPath . $otherID, null, $cookie);
    $expect($otherStatus === 404 && !str_contains($otherBody, 'NEVER_EXPOSE_HTTP'),
        'Cross-owner status access refused even for authenticated administrator');
    [$badIDStatus] = $request($apiPath . 'broken', null, $cookie);
    $expect($badIDStatus === 400, 'Malformed job identifier rejected');
    [$arrayIDStatus] = $request('/admin/admin-ajax.php?action=ach_guard_bulk_status&job%5B%5D=bad',
        null, $cookie);
    $expect($arrayIDStatus === 400, 'Array-shaped job identifier rejected');
    [$methodStatus,,$methodBody] = $request($apiPath . $jobID,
        ['unexpected' => 'post'], $cookie);
    $expect($methodStatus === 405 && !str_contains($methodBody, 'snapshot matches'),
        'Authenticated status POST method rejected without side effects');

    $html = (string) ($state['html'] ?? '');
    $expect(preg_match('/name="bulk_nonce" value="([^"]+)"/', $html, $nonceMatch) === 1,
        'Real ready-state response includes native bulk POST nonce');
    $nonce = $nonceMatch[1];
    $admin = '/admin/plugins.php?page=ach_url_guard_history';
    $post = [
        'bulk_action'=>'approve','bulk_job'=>$jobID,
        'bulk_confirm_text'=>'DELETE 1','bulk_confirm'=>'1','bulk_nonce'=>$nonce,
    ];
    [$badNonce] = $request($admin, array_replace($post, ['bulk_nonce'=>'invalid']), $cookie);
    $expect($badNonce === 403, 'Invalid native admin POST nonce denied');
    [$missingBox,,$missingHtml] = $request($admin, array_diff_key($post, ['bulk_confirm'=>true]), $cookie);
    $expect($missingBox === 200 && !str_contains($missingHtml, 'Deleting — explicitly confirmed batch'),
        'Missing approval checkbox never authorizes deletion');
    [$wrongText,,$wrongHtml] = $request($admin,
        array_replace($post, ['bulk_confirm_text'=>'DELETE 1234']), $cookie);
    $expect($wrongText === 200 && !str_contains($wrongHtml, 'Deleting — explicitly confirmed batch'),
        'Inexact DELETE N text cannot authorize deletion');
    [$beforeCode,,$beforeRaw] = $request($apiPath . $jobID, null, $cookie);
    $before = json_decode($beforeRaw, true);
    $expect($beforeCode === 200 && ($before['phase'] ?? '') === 'ready'
        && ($before['deleted'] ?? 1) === 0, 'Invalid HTTP approvals left preview ready');

    [$approved,,$approvedBody] = $request($admin, $post, $cookie);
    $expect($approved === 200 && str_contains($approvedBody, 'Deleting — explicitly confirmed batch'),
        'Native admin POST with nonce/checkbox/exact text transitions ready to delete');
    [$afterCode,,$afterRaw] = $request($apiPath . $jobID, null, $cookie);
    $after = json_decode($afterRaw, true);
    $expect($afterCode === 200 && ($after['phase'] ?? '') === 'delete'
        && ($after['deleted'] ?? 1) === 0 && ($after['processed'] ?? 1) === 0,
        'HTTP authorization does not itself execute deletion or worker');
    // A valid-looking approval based on old Guard settings cannot authorize
    // deletion after the policy has changed, even with correct nonce and N.
    $staleID = (string) getenv('ACH_IT_HTTP_STALE_' . strtoupper($mode) . '_ID');
    [$staleStatus,,$staleRaw] = $request($apiPath . $staleID, null, $cookie);
    $stale = json_decode($staleRaw, true);
    $expect($staleStatus === 200 && ($stale['phase'] ?? '') === 'ready',
        'Pre-policy-change ready snapshot available to authenticated admin');
    $expect(preg_match('/name="bulk_nonce" value="([^"]+)"/',
        (string) ($stale['html'] ?? ''), $staleNonce) === 1,
        'Stale candidate exposes native nonce but no automatic delete');
    $stalePost = [
        'bulk_action'=>'approve','bulk_job'=>$staleID,
        'bulk_confirm_text'=>'DELETE 1','bulk_confirm'=>'1','bulk_nonce'=>$staleNonce[1],
    ];
    [$staleApproved,,$staleHtml] = $request($admin, $stalePost, $cookie);
    $expect($staleApproved === 200 && str_contains($staleHtml, 'Stopped — policy changed'),
        'Even valid user/nonce/DELETE N cannot approve a stale policy snapshot');
    [$staleAfter,,$staleAfterRaw] = $request($apiPath . $staleID, null, $cookie);
    $staleFinal = json_decode($staleAfterRaw, true);
    $expect($staleAfter === 200 && ($staleFinal['phase'] ?? '') === 'paused'
        && ($staleFinal['deleted'] ?? 1) === 0,
        'Stale HTTP approval pauses job without deleting any row');
    echo 'PASS genuine ' . $mode . '-mode YOURLS cookie/nonce/AJAX/DELETE N authorization and privacy.' . "\n";
};

/**
 * N1: prove owner-only cancellation for jobs older than 30 global records.
 * Both accounts authenticate via native YOURLS login/cookies. No worker is
 * executed here; the unavailable owner's approved job remains a scheduler gate.
 */
$exerciseRecoveryHttp = static function () use ($request, $expect): void {
    $owned = (string) getenv('ACH_IT_RECOVERY_INTEGRATION_ID');
    $other = (string) getenv('ACH_IT_RECOVERY_OTHER_ID');
    $missing = (string) getenv('ACH_IT_RECOVERY_MISSING_ID');
    foreach ([$owned,$other,$missing] as $id) {
        $expect((bool) preg_match('/^[a-f0-9]{24}$/D', $id),
            'All original-owner recovery job identities are available');
    }
    $currentCookie = (string) file_get_contents((string) getenv('ACH_IT_TEST_COOKIE_FILE'));
    $expect($currentCookie !== '', 'Native primary administrator cookie exists');

    // Obtain a second genuine YOURLS session. The inventory includes this
    // account explicitly, but the first account must not cancel its work.
    [$loginStatus,$loginHeaders] = $request(
        '/admin/plugins.php?page=ach_url_guard_history',
        ['username'=>'other-operator','password'=>(string)getenv('ACH_IT_OTHER_PASS'),
            'nonce'=>(string)getenv('ACH_IT_LOGIN_NONCE'),'submit'=>'Login']);
    $cookies=[];
    foreach ($loginHeaders as $header) {
        if (preg_match('/^Set-Cookie:\s*([^;,\r\n]+)/i', $header, $match))
            $cookies[]=$match[1];
    }
    $expect(in_array($loginStatus,[301,302,303],true) && $cookies!==[],
        'Other admin must log in through the real YOURLS login form');
    $otherCookie=implode('; ', $cookies);

    $base='/admin/plugins.php?page=ach_url_guard_history&bulk_job=';
    $getOwnedForm=static function (string $id, string $cookie) use ($request,$expect,$base): array {
        [$code,,$html]=$request($base.$id,null,$cookie);
        $expect($code===200 && str_contains($html,'Legacy delete-phase job:')
            && str_contains($html,'Cancel job (completed deletions remain)'),
            'Old authorized deletion is visible on exact owner-scoped job page');
        $expect(preg_match('/name="bulk_nonce" value="([^"]+)"/',$html,$found)===1,
            'Original owner can retrieve native cancellation nonce');
        return [$found[1],$html];
    };
    [$nonceOwn,$ownPage]=$getOwnedForm($owned,$currentCookie);
    [$nonceOther,$otherPage]=$getOwnedForm($other,$otherCookie);
    $expect(str_contains($ownPage,'Previously approved deletion jobs')
        && str_contains($ownPage,$owned)
        && !str_contains($ownPage,$other),
        'First admin sees old owned delete job but no other-owner job');
    $expect(str_contains($otherPage,'Previously approved deletion jobs')
        && str_contains($otherPage,$other)
        && !str_contains($otherPage,$owned),
        'Second admin sees old owned delete job but no first-owner job');

    [$denied,,$foreignHtml]=$request($base.$other,null,$currentCookie);
    $expect($denied===200 && str_contains($foreignHtml,'No accessible job with this ID.')
        && !str_contains($foreignHtml,'Legacy delete-phase job:'),
        'Cross-owner GET of an exact job ID is denied');
    [$orphanDenied,,$orphanHtml]=$request($base.$missing,null,$currentCookie);
    $expect($orphanDenied===200 && str_contains($orphanHtml,'No accessible job with this ID.')
        && !str_contains($orphanHtml,'Legacy delete-phase job:'),
        'Unavailable-owner job cannot be opened by any available admin');

    $cancel=static fn(string $id,string $nonce): array => [
        'bulk_action'=>'cancel','bulk_job'=>$id,'bulk_nonce'=>$nonce
    ];
    [$wrongCancel,,$wrongBody]=$request(
        '/admin/plugins.php?page=ach_url_guard_history',
        $cancel($other,$nonceOwn), $currentCookie);
    $expect($wrongCancel===200
        && str_contains($wrongBody,'Could not complete the requested operation')
        && !str_contains($wrongBody,'Cancelled. No further deletion'),
        'Authenticated user cannot cancel another owner job with a valid own nonce');
    [$verifyOther,,$otherAfterUnauthorized]=$request($base.$other,null,$otherCookie);
    $expect($verifyOther===200 && str_contains($otherAfterUnauthorized,'Legacy delete-phase job:')
        && str_contains($otherAfterUnauthorized,'Deleting — explicitly confirmed batch')
        && !str_contains($otherAfterUnauthorized,'Cancelled. No further deletion'),
        'Cross-owner cancellation POST leaves the original owner job actively unchanged');
    // Missing-owner job cannot be cancelled through either real account.
    [$orphanCancel,,$orphanBody]=$request(
        '/admin/plugins.php?page=ach_url_guard_history',
        $cancel($missing,$nonceOther), $otherCookie);
    $expect($orphanCancel===200
        && str_contains($orphanBody,'Could not complete the requested operation'),
        'Other admin cannot act on unavailable owner job');

    foreach ([[$owned,$nonceOwn,$currentCookie],[$other,$nonceOther,$otherCookie]] as $item) {
        [$id,$nonce,$cookie]=$item;
        [$cancelCode,,$cancelHtml]=$request(
            '/admin/plugins.php?page=ach_url_guard_history',
            $cancel($id,$nonce),$cookie);
        $expect($cancelCode===200
            && str_contains($cancelHtml,'Cancelled. No further deletion')
            && !str_contains($cancelHtml,'Deleting — explicitly confirmed batch'),
            'Original owner cancels previous delete job with valid YOURLS session+nonce');
        [$checkCode,,$checkBody]=$request($base.$id,null,$cookie);
        $expect($checkCode===200 && str_contains($checkBody,'Cancelled. No further deletion'),
            'Cancelled report persists and remains navigable to its original owner');
    }
    echo "PASS genuine multi-admin HTTP job recovery after 30 global records,"
        . " owner-only cancellation, orphan gate and no deletion.\n";
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
    // Public YOURLS does not protect native admin-ajax.php by itself. Guard
    // must reject its read-only job status API before returning any metadata.
    [$status,,$body] = $request('/admin/admin-ajax.php?action=ach_guard_bulk_status&job=123456789012345678901234');
    $expect($status === 403 && !str_contains($body, 'snapshot matches')
        && !str_contains($body, '"scanned"'), 'Public-mode anonymous worker status denied by Guard');
    [$status,,$body] = $request('/admin/admin-ajax.php?action=ach_guard_bulk_status&job=123456789012345678901234',
        ['unexpected'=>'post']);
    $expect($status === 403 && !str_contains($body, '"scanned"'),
        'Public-mode anonymous status POST denied even before method validation');
    // The disposable router routes / to yourls-loader.php; request the native index directly.
    [$status,,$body] = $request('/index.php');
    $expect($status === 200, 'Public shortening homepage still available when admin is protected.');
    $exerciseBulkHttp('public');
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
    'url' => 'https://example.com/HTTP/UppercaseMinimum', 'keyword' => 'QWERT',
]);
$upperMinimum = json_decode($body, true);
$expect(is_array($upperMinimum) && ($upperMinimum['status'] ?? '') === 'success'
    && ($upperMinimum['url']['keyword'] ?? '') === 'qwert' && $httpCode === 200,
    'Force Lowercase normalizes an all-uppercase five-character alias even before core keyword hooks.');

[$httpCode, , $body] = $request('/yourls-api.php', $credentials + [
    'url' => 'https://example.com/HTTP/CaseSensitive?abc=XYZ', 'keyword' => 'HTTP-UPPER',
]);
$allowed = json_decode($body, true);
$expect(is_array($allowed) && ($allowed['status'] ?? '') === 'success',
    'Authenticated HTTP API must create allowed destination, got HTTP ' . $httpCode
    . ', API code ' . (string) ($allowed['code'] ?? 'missing'));
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


[$status,,$anonymousAjax] = $request(
    '/admin/admin-ajax.php?action=ach_guard_bulk_status&job=123456789012345678901234');
$expect(!str_contains($anonymousAjax, '"scanned"')
    && !str_contains($anonymousAjax, 'snapshot matches'),
    'Private-mode anonymous status cannot read job metadata');

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



$exerciseBulkHttp('private');
$exerciseRecoveryHttp();
echo 'PASS loopback HTTP: authenticated API allow/deny, old/new real redirects, protected admin settings.' . "\n";
