<?php
declare(strict_types=1);

/**
 * Companion to db-integration.sh. The wrapper creates a unique, disposable
 * database and an isolated YOURLS source copy. Never point this at production.
 */
$phase = $argv[1] ?? '';
if (!in_array($phase, ['ping', 'create', 'install', 'verify', 'snapshot', 'drop', 'gate'], true)) {
    fwrite(STDERR, "Expected ping|create|install|verify|snapshot|drop.\n");
    exit(2);
}
$host = getenv('ACH_IT_DB_HOST') ?: '';
$socket = getenv('ACH_IT_DB_SOCKET') ?: '';
$dbName = getenv('ACH_IT_DB_NAME') ?: '';
$site = getenv('ACH_IT_SITE') ?: '';
if (!in_array($host, ['localhost', '127.0.0.1'], true) ||
    !preg_match('/^ach_guard_it_[0-9a-f]{8}$/D', $dbName)) {
    throw new RuntimeException('Refusing any database other than a unique local test database.');
}
$dsn = $socket !== ''
    ? 'mysql:unix_socket=' . $socket . ';charset=utf8mb4'
    : 'mysql:host=' . $host . ';port=' . (int) (getenv('ACH_IT_DB_PORT') ?: '3306') . ';charset=utf8mb4';
$dbUser = getenv('ACH_IT_DB_USER') ?: '';
$dbPass = getenv('ACH_IT_DB_PASS') ?: '';
$pdo = new PDO($dsn, $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 3]);
if ($phase === 'ping') {
    exit(0);
}
if ($phase === 'create') {
    $pdo->exec('CREATE DATABASE ' . chr(96) . $dbName . chr(96) . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_bin');
    exit(0);
}
if ($phase === 'drop') {
    $pdo->exec('DROP DATABASE IF EXISTS ' . chr(96) . $dbName . chr(96));
    exit(0);
}
if (!is_file($site . '/includes/load-yourls.php') || !is_file($site . '/user/config.php')) {
    throw new RuntimeException('Missing the disposable YOURLS site.');
}

$pdo->exec('USE ' . chr(96) . $dbName . chr(96));
if ($phase === 'snapshot') {
    $urls = $pdo->query('SELECT keyword,url,title,timestamp,ip,clicks FROM yourls_url ORDER BY keyword')->fetchAll(PDO::FETCH_ASSOC);
    $options = $pdo->query('SELECT option_name,option_value FROM yourls_options ORDER BY option_name,option_id')->fetchAll(PDO::FETCH_ASSOC);
    echo hash('sha256', serialize([$urls, $options])) . "\n";
    exit(0);
}
$table = static function () use ($pdo): array {
    return $pdo->query('SELECT keyword, url, clicks FROM yourls_url ORDER BY keyword')->fetchAll(PDO::FETCH_ASSOC);
};
$expect = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException('Database integration: ' . $message);
    }
};
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_HOST'] = '127.0.0.1';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
$_SERVER['SERVER_NAME'] = '127.0.0.1';

if ($phase === 'install') {
    define('YOURLS_INSTALLING', true);
    require $site . '/includes/load-yourls.php';
    $install = yourls_create_sql_tables();
    $expect(($install['error'] ?? []) === [], 'YOURLS must install real tables and default records.');
    $expect(count($table()) >= 3, 'YOURLS installer must create sample rows.');
    $plugins = [
        'random-shorturls/plugin.php',
        'hyphens-in-urls/plugin.php',
        'force-lowercase/plugin.php',
        'ach-url-guard/plugin.php',
    ];
    $expect(yourls_update_option('active_plugins', $plugins), 'Must persist all four active plugin entries.');
    echo "PASS YOURLS 1.10.6 installed in unique disposable MariaDB database.\n";
    exit(0);
}

require $site . '/includes/load-yourls.php';
$expect(defined('YOURLS_VERSION') && YOURLS_VERSION === '1.10.6', 'Expected exact targeted YOURLS 1.10.6.');
$expect(class_exists(\ACh\Yourls\UrlGuard\Guard::class), 'ACh URL Guard must load via actual plugin activation.');
$active = (array) yourls_get_option('active_plugins', []);
$expect(count($active) === 4, 'All four plugins must remain active.');
$expect(function_exists('ozh_random_shorturl'), 'Random ShortURLs loaded.');
$expect(function_exists('ozh_hyphen_in_charset'), 'Allow Hyphens loaded.');
$expect(function_exists('ozh_break_the_web_lowercase'), 'Force Lowercase loaded.');

// This phase runs as three independent CLI processes against one disposable
// YOURLS database. Native flood delay is enabled only for this focused probe.
if ($phase === 'gate') {
    $expect(yourls_get_flood_delay() === 15, 'Must use normal native 15-second flood policy.');
    $expect(yourls_is_private(), 'Fixture should have native private mode.');
    $expect(yourls_is_valid_user() !== true, 'This test is not a logged-in privileged admin.');
    $mode = (string) getenv('ACH_IT_GATE_CASE');
    $expect(in_array($mode, ['first', 'repeat', 'different'], true), 'Expected one gate phase.');
    $verifyCount = 0;
    $work = static function () use (&$verifyCount): array {
        $verifyCount++;
        return ['status' => 'deny', 'reason' => 'http_not_found', 'host' => 'example.com'];
    };
    $url = $mode === 'different' ? 'https://example.com/other' : 'https://example.com/rejected';
    $guardSettings = \ACh\Yourls\UrlGuard\Policy::settings(['reachability_enabled' => true]);
    $result = \ACh\Yourls\UrlGuard\WorkGate::evaluate(
        $url, $guardSettings, '', $work, '203.0.113.250', null, false, $site . '/.work-admission-fixture'
    );
    if ($mode === 'different') {
        $expect(($result['reason'] ?? '') === 'work_deferred', 'Fresh URL must defer extra costly work.');
        $expect($verifyCount === 0, 'New URL during native delay must not execute costly probe.');
    } else {
        $expect(($result['reason'] ?? '') === 'http_not_found', 'Must preserve initial deny verdict.');
        $expect($verifyCount === ($mode === 'first' ? 1 : 0),
            'Repeated rejected request must reuse result across PHP processes.');
    }
    echo "PASS real YOURLS native-delay work admission ($mode), expensive executions=$verifyCount.\n";
    exit(0);
}

$knownBefore = $pdo->query("SELECT url FROM yourls_url WHERE keyword='yourlsblog'")->fetchColumn();
$expect(is_string($knownBefore) && $knownBefore !== '', 'Pre-existing link is present.');

$allowed = yourls_add_new_link('https://example.com/MiXeD/Path?token=secret', 'UPPER-LINK', 'Integration allowed');
$expect(($allowed['status'] ?? '') === 'success', 'Monitor must allow normal creation.');
$expect(($allowed['url']['keyword'] ?? '') === 'upper-link', 'Force Lowercase and Allow Hyphens keep custom keyword working.');
$stored = $pdo->query("SELECT url FROM yourls_url WHERE keyword='upper-link'")->fetchColumn();
$expect($stored === 'https://example.com/MiXeD/Path?token=secret', 'Destination path and query case unchanged.');
$overlongAlias = yourls_add_new_link('https://example.com/Allowed/LongAlias', '123456789012345678901', 'Rejected in Monitor');
$expect(($overlongAlias['code'] ?? '') === 'error:ach_url_guard:keyword_too_long',
    'Custom alias over 20 characters must be rejected even in Monitor.');
$expect(($overlongAlias['errorCode'] ?? '') === '400', 'Alias length reject is a bad request, not a service failure.');
$exactAlias = yourls_add_new_link('https://example.com/Allowed/ExactAlias', '12345678901234567890', '20-character alias');
$expect(($exactAlias['status'] ?? '') === 'success', 'Exactly 20-character alias succeeds in Monitor.');

$monitor = yourls_add_new_link('https://example.com/?sensitive=not-for-logs', 'monitor-root', 'Monitor root');
$expect(($monitor['status'] ?? '') === 'success', 'Monitor must not prevent a root destination.');
$events = yourls_get_option('ach_url_guard_events', []);
$expect(is_array($events) && count($events) > 0, 'Real database must contain sampled monitoring event.');
$expect(($events[0]['reason'] ?? '') === 'root_url', 'Root destination reason recorded.');
$expect(!str_contains(serialize($events), 'not-for-logs'), 'No URL query tokens persist in event payload.');
$chainedInMonitor = yourls_add_new_link('https://bit.ly/retarget', 'monitor-chain', 'Monitor proposed shortener block');
$expect(($chainedInMonitor['status'] ?? '') === 'success',
    'Starter domain list is observed but does not block in Monitor.');
$expect((yourls_get_option('ach_url_guard_events', [])[0]['reason'] ?? '') === 'blocked_domain',
    'Starter shortener domain is reported.');

$settings = \ACh\Yourls\UrlGuard\Policy::settings([
    'mode' => 'enforce',
    'block_root_urls' => true,
    'blocked_domains' => ['bad.example', '.bad-parent.example', '*.bad-children.example'],
    'root_exceptions' => ['trusted.example'],
    'blocked_url_terms' => ['casino'],
    'blocked_url_patterns' => ['~/(?:offer|sale)(?:/|$)~i'],
    'blocked_short_keywords' => ['reserved'],
    'max_custom_keyword_length' => 20,
]);
$expect(yourls_update_option('ach_url_guard_settings', $settings), 'Must save enforce settings to real DB.');
$rowsBeforeDenials = count($table());
$try = static function (string $url, string $keyword) use ($expect): array {
    $result = yourls_add_new_link($url, $keyword, 'Integration');
    $expect(is_array($result), 'Native YOURLS link result is an array.');
    return $result;
};
foreach ([
    ['https://example.com/?token=denied', 'deny-root', 'root_url'],
    ['https://bad.example/path', 'deny-apex', 'blocked_domain'],
    ['https://sub.bad-parent.example/path', 'deny-child', 'blocked_domain'],
    ['https://sub.bad-children.example/path', 'deny-wildcard', 'blocked_domain'],
    ['https://127.0.0.1/private', 'deny-local', 'private_address'],
    ['https://example.com/p/CaSiNo-2026', 'deny-term', 'blocked_url_term'],
    ['https://example.com/OFFER/123', 'deny-regex', 'blocked_url_pattern'],
    ['https://example.com/valid-page', 'reserved', 'blocked_short_keyword'],
    ['https://example.com/valid-page', 'abcdefghijklmnopqrstu', 'keyword_too_long'],
] as [$url, $keyword, $reason]) {
    $result = $try($url, $keyword);
    $expect(($result['status'] ?? '') === 'fail', 'Must deny ' . $reason);
    $expect(($result['code'] ?? '') === 'error:ach_url_guard:' . $reason, 'Must identify reason ' . $reason);
    $expect(($result['errorCode'] ?? '') === ($reason === 'keyword_too_long' ? '400' : '403'),
        'Must use correct status for ' . $reason);
}
$expect(count($table()) === $rowsBeforeDenials, 'Denied creates must never persist rows.');

foreach ([
    ['https://trusted.example/', 'allowed-exception'],
    ['https://sub.bad.example/Page', 'allowed-child-exact'],
    ['https://bad-children.example/Page', 'allowed-apex-wild'],
] as [$url, $keyword]) {
    $result = $try($url, $keyword);
    $expect(($result['status'] ?? '') === 'success', 'Rule exceptions and exact semantics must permit ' . $keyword);
}

$_REQUEST = [
    'url' => 'https://bad.example/api', 'keyword' => 'deny-api', 'title' => 'API path',
];
$apiDenied = yourls_api_action_shorturl();
$expect(($apiDenied['status'] ?? '') === 'fail', 'Native YOURLS API action must apply the same deny policy.');
$_REQUEST = [
    'url' => 'https://example.com/CaSeSensitive', 'keyword' => 'API-ALLOWED', 'title' => 'API path',
];
$apiAllowed = yourls_api_action_shorturl();
$expect(($apiAllowed['status'] ?? '') === 'success', 'Native YOURLS API action must permit valid URL.');
$expect(($apiAllowed['url']['keyword'] ?? '') === 'api-allowed', 'API custom keyword lowercased only.');
$expect($pdo->query("SELECT url FROM yourls_url WHERE keyword='api-allowed'")->fetchColumn() ===
    'https://example.com/CaSeSensitive', 'API must preserve destination path case.');

$expect($pdo->query("SELECT url FROM yourls_url WHERE keyword='yourlsblog'")->fetchColumn() === $knownBefore,
    'Previously stored redirect must remain unchanged.');
$expect($pdo->query("SELECT COUNT(*) FROM yourls_url WHERE keyword LIKE 'deny-%'")->fetchColumn() == 0,
    'Denied keywords must not exist.');

ob_start();
ach_url_guard_admin_page();
$adminHtml = ob_get_clean();
$expect(str_contains($adminHtml, 'ACh URL Guard'), 'Native-registered admin callback must render.');
$expect(str_contains($adminHtml, 'value="enforce" selected'), 'Admin settings reflect real database mode.');
$expect(!str_contains($adminHtml, 'not-for-logs'), 'Admin event display must not expose query tokens.');

// Exercise the real settings callback and its built-in nonce and domain-rule validation.
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = [
    'ach_url_guard_save' => '1',
    'nonce' => yourls_create_nonce('ach_url_guard_settings'),
    'mode' => 'enforce',
    'unknown_action' => 'allow',
    'block_root_urls' => '1',
    'blocked_domains' => "bad.example\ninvalid domain rule",
    'root_exceptions' => 'trusted.example',
    'dnsbl_zones' => '',
];
ob_start();
ach_url_guard_admin_page();
$invalidHtml = ob_get_clean();
$expect(str_contains($invalidHtml, 'Invalid settings'), 'Invalid admin rules must not save.');
$expect(yourls_get_option('ach_url_guard_settings', []) === $settings, 'Invalid form must preserve existing settings.');
$_POST['blocked_domains'] = "bad.example\n.bad-parent.example\n*.bad-children.example";
$_POST['blocked_url_patterns'] = '/[broken/';
ob_start();
ach_url_guard_admin_page();
$invalidRegexHtml = ob_get_clean();
$expect(str_contains($invalidRegexHtml, 'blocked_url_patterns'), 'Invalid PCRE must be reported to admin.');
$expect(yourls_get_option('ach_url_guard_settings', []) === $settings, 'Invalid regex cannot partially save settings.');
$_POST['blocked_url_patterns'] = '~/(?:offer|sale)(?:/|$)~i';
$_POST['blocked_url_terms'] = 'casino';
$_POST['blocked_short_keywords'] = 'reserved';
$_POST['max_custom_keyword_length'] = '20';
ob_start();
ach_url_guard_admin_page();
$validHtml = ob_get_clean();
$expect(str_contains($validHtml, 'Settings saved.'), 'Valid admin POST with actual nonce must save.');
$expect((yourls_get_option('ach_url_guard_settings', [])['mode'] ?? '') === 'enforce', 'Saved mode persists.');
$saved = yourls_get_option('ach_url_guard_settings', []);
$expect(($saved['max_custom_keyword_length'] ?? null) === 20, 'Custom keyword cap persists.');
$expect(($saved['blocked_url_terms'] ?? null) === ['casino'], 'Literal URL terms persist.');
$expect(($saved['blocked_url_patterns'] ?? null) === ['~/(?:offer|sale)(?:/|$)~i'], 'PCRE patterns persist.');
$expect(($saved['blocked_short_keywords'] ?? null) === ['reserved'], 'Custom reserved aliases persist.');
$_POST = [];
$_GET = [];
$_SERVER['REQUEST_METHOD'] = 'GET';

// Real YOURLS/MySQL historical review: read-only browsing followed by an
// intentional deletion of only a disposable, test-owned link. The native
// deletion/cache/hooks path runs inside the plugin's locked transaction.
$historyDB = yourls_get_db('read-history_integration');
$historyPolicy = \ACh\Yourls\UrlGuard\Policy::settings(
    yourls_get_option('ach_url_guard_settings', [])
);
$baselineHistory = $pdo->query('SELECT keyword,url,title FROM yourls_url ORDER BY keyword')->fetchAll(PDO::FETCH_ASSOC);
$historyPage = \ACh\Yourls\UrlGuard\HistoricalReview::page($historyDB, '', 25);
$expect(count($historyPage['rows']) > 0, 'Historical browser must return real YOURLS URL rows.');
ob_start();
ach_url_guard_history_page();
$historyHtml = ob_get_clean();
$expect(str_contains($historyHtml, 'Historical Link Review'), 'Actual plugin review UI renders.');
$expect(str_contains($historyHtml, 'Check HTTP'), 'Healthy records offer manual HTTP checks.');
$expect(!str_contains($historyHtml, 'not-for-logs'), 'Historical UI never leaks private query tokens.');
$expect($pdo->query('SELECT keyword,url,title FROM yourls_url ORDER BY keyword')->fetchAll(PDO::FETCH_ASSOC)
    === $baselineHistory, 'Historical UI and page scanning cannot modify existing URLs.');

$historyName = 'history-delete-fixture';
$expect(yourls_insert_link_in_db('https://bad.example/private?token=DO_NOT_RENDER',
    $historyName, 'History-only test record'), 'A flagged test-owned record must be inserted.');
$marked = \ACh\Yourls\UrlGuard\HistoricalReview::find($historyDB, $historyName);
$expect($marked !== null, 'Historical lookup retrieves the exact fixture row.');
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::inspect($marked, $historyPolicy)['reason']
    === 'blocked_domain', 'Current local Guard policy flags fixture row.');
$reviewProof = \ACh\Yourls\UrlGuard\HistoricalReview::proof($marked, $historyPolicy);
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = [
    'history_action' => 'review', 'history_keyword' => $historyName,
    'nonce' => yourls_create_nonce('ach_url_guard_history_review'),
];
ob_start(); ach_url_guard_history_page(); $confirmationHTML = ob_get_clean();
$expect(str_contains($confirmationHTML, 'Delete this short link permanently'),
    'Real YOURLS nonce and admin review render a confirmation form.');
$expect(!str_contains($confirmationHTML, 'DO_NOT_RENDER'),
    'Review confirmation hides URL query tokens.');
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::find($historyDB, $historyName) !== null,
    'Review form must not delete a link.');

$originalTitle = 'History-only test record';
$updateHistory = $pdo->prepare('UPDATE yourls_url SET title = ? WHERE keyword = ?');
$updateHistory->execute(['Changed after preview', $historyName]);
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::delete($historyDB, $historyName,
    $reviewProof, 'blocked_domain', false, $historyPolicy) === 'stale',
    'Native DB row edit invalidates the original approval.');
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::find($historyDB, $historyName) !== null,
    'Stale deletion cannot remove modified link.');
$updateHistory->execute([$originalTitle, $historyName]);
$marked = \ACh\Yourls\UrlGuard\HistoricalReview::find($historyDB, $historyName);
$reviewProof = \ACh\Yourls\UrlGuard\HistoricalReview::proof($marked, $historyPolicy);

// A concurrent admin policy save can outlive this PHP request's cached option.
// Change only the disposable database's policy option and verify fresh SQL
// inside the locked delete transaction rejects an obsolete approval.
$policyUpdate = $pdo->prepare('UPDATE yourls_options SET option_value = ? WHERE option_name = ?');
$modifiedPolicy = $saved;
$modifiedPolicy['blocked_domains'] = [];
$policyUpdate->execute([serialize($modifiedPolicy), 'ach_url_guard_settings']);
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::delete($historyDB, $historyName,
    $reviewProof, 'blocked_domain', false, $historyPolicy) === 'stale',
    'Concurrent stored policy change must cancel cached-policy deletion.');
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::find($historyDB, $historyName) !== null,
    'Link survives concurrent policy changes.');
$policyUpdate->execute([serialize($saved), 'ach_url_guard_settings']);

$cleanPolicy = $historyPolicy;
$cleanPolicy['blocked_domains'] = [];
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::delete($historyDB, $historyName,
    \ACh\Yourls\UrlGuard\HistoricalReview::proof($marked, $cleanPolicy),
    'blocked_domain', false, $cleanPolicy) === 'no_longer_flagged',
    'Policy no longer flagging link prevents deletion.');

$_POST = [
    'history_action' => 'delete', 'history_keyword' => $historyName,
    'history_proof' => $reviewProof, 'history_reason' => 'blocked_domain',
    'history_scope' => 'local', 'history_confirm' => '1',
    'nonce' => yourls_create_nonce('ach_url_guard_history_delete'),
];
ob_start(); ach_url_guard_history_page(); $deletedHTML = ob_get_clean();
$expect(str_contains($deletedHTML, 'Reviewed short link was deleted'),
    'Explicit YOURLS admin confirmation deletes only tested fixture.');
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::find($historyDB, $historyName) === null,
    'Native deletion removed the test-owned row.');
$expect(yourls_get_keyword_infos($historyName, false) === false,
    'Native YOURLS keyword lookup observes deleted record.');
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::delete($historyDB, $historyName,
    $reviewProof, 'blocked_domain', false, $historyPolicy) === 'stale',
    'A repeated delete cannot alter any other row.');
$expect($pdo->query("SELECT url FROM yourls_url WHERE keyword='yourlsblog'")->fetchColumn()
    === $knownBefore, 'Pre-existing YOURLS redirect stays intact after reviewed deletion.');
$_POST = [];
$_GET = [];
$_SERVER['REQUEST_METHOD'] = 'GET';

echo 'PASS real DB integration: active plugins, monitor, enforce, API, admin callback, old links, data privacy.' . "\n";
