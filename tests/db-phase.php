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
    'min_custom_keyword_length' => 5,
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
    ['https://example.com/valid-page', 'four', 'keyword_too_short'],
    ['https://example.com/valid-page', 'abcdefghijklmnopqrstu', 'keyword_too_long'],
] as [$url, $keyword, $reason]) {
    $result = $try($url, $keyword);
    $expect(($result['status'] ?? '') === 'fail', 'Must deny ' . $reason);
    $expect(($result['code'] ?? '') === 'error:ach_url_guard:' . $reason, 'Must identify reason ' . $reason);
    $expect(($result['errorCode'] ?? '') === (
        in_array($reason, ['keyword_too_short', 'keyword_too_long'], true) ? '400' : '403'
    ), 'Must use correct status for ' . $reason);
}
$expect(count($table()) === $rowsBeforeDenials, 'Denied creates must never persist rows.');
$exactMinimum = $try('https://example.com/custom-keyword-five-test', 'abcde');
$expect(($exactMinimum['status'] ?? '') === 'success',
    'A five-character custom keyword succeeds in native YOURLS when minimum is five.');
$expect($pdo->query("SELECT COUNT(*) FROM yourls_url WHERE keyword='abcde'")->fetchColumn() == 1,
    'Exactly-minimum custom keyword is stored without unexpected rewriting.');

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

// These CLI acceptance calls deliberately simulate a logged-in administrator.
// HTTP integration below separately tests anonymous real routes in both modes.
yourls_set_user('integration');
yourls_add_filter('shunt_is_valid_user', static fn() => true);

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
$_POST['min_custom_keyword_length'] = '5';
$_POST['max_custom_keyword_length'] = '20';
ob_start();
ach_url_guard_admin_page();
$validHtml = ob_get_clean();
$expect(str_contains($validHtml, 'Settings saved.'), 'Valid admin POST with actual nonce must save.');
$expect((yourls_get_option('ach_url_guard_settings', [])['mode'] ?? '') === 'enforce', 'Saved mode persists.');
$saved = yourls_get_option('ach_url_guard_settings', []);
$expect(($saved['min_custom_keyword_length'] ?? null) === 5, 'Custom keyword minimum persists.');
$expect(($saved['max_custom_keyword_length'] ?? null) === 20, 'Custom keyword cap persists.');
$expect(($saved['blocked_url_terms'] ?? null) === ['casino'], 'Literal URL terms persist.');
$expect(($saved['blocked_url_patterns'] ?? null) === ['~/(?:offer|sale)(?:/|$)~i'], 'PCRE patterns persist.');
$expect(($saved['blocked_short_keywords'] ?? null) === ['reserved'], 'Custom reserved aliases persist.');

// Verify malformed authenticated POST inputs are rejected by the real YOURLS
// settings callback and never write even one byte of the stored policy option.
$validSettingsPost = $_POST;
$storedSettingsBefore = $pdo->query(
    "SELECT option_value FROM yourls_options WHERE option_name='ach_url_guard_settings'"
)->fetchColumn();
$expect(is_string($storedSettingsBefore), 'Guard settings are persisted in real MariaDB options.');
$malformedSettingsCases = [
    'minimum array' => ['min_custom_keyword_length', ['5'], false],
    'maximum array' => ['max_custom_keyword_length', ['20'], false],
    'missing minimum' => ['min_custom_keyword_length', null, true],
    'missing maximum' => ['max_custom_keyword_length', null, true],
    'empty minimum' => ['min_custom_keyword_length', '', false],
    'noninteger maximum' => ['max_custom_keyword_length', 'oops', false],
    'negative minimum' => ['min_custom_keyword_length', '-1', false],
    'oversized maximum' => ['max_custom_keyword_length', '99999999999999999999999999999', false],
    'minimum above maximum' => ['min_custom_keyword_length', '21', false],
];
foreach ($malformedSettingsCases as $name => [$field, $value, $missing]) {
    $_POST = $validSettingsPost;
    $_POST['mode'] = 'monitor'; // Would otherwise change the saved policy.
    if ($missing) {
        unset($_POST[$field]);
    } else {
        $_POST[$field] = $value;
    }
    ob_start();
    ach_url_guard_admin_page();
    $invalidBoundsHtml = ob_get_clean();
    $expect(str_contains($invalidBoundsHtml, 'Invalid settings, nothing saved:'),
        $name . ': invalid settings must report an explicit error');
    $expect(str_contains($invalidBoundsHtml, $field . ':'),
        $name . ': error must identify the malformed bound');
    $expect(yourls_get_option('ach_url_guard_settings', []) === $saved,
        $name . ': entire settings object must remain strictly unchanged');
    $expect($pdo->query(
        "SELECT option_value FROM yourls_options WHERE option_name='ach_url_guard_settings'"
    )->fetchColumn() === $storedSettingsBefore,
        $name . ': persisted database option must remain byte-for-byte unchanged');
}
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
$expect(\ACh\Yourls\UrlGuard\HistoricalReview::inspect([
    'keyword' => 'abc', 'url' => 'https://example.com/valid-page',
    'timestamp' => '2026-01-01 00:00:00', 'clicks' => 0, 'title' => ''
], $historyPolicy)['status'] === 'allow',
    'Existing three-character keyword is not condemned by new-link-only minimum.');
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
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = ['keyword' => $historyName];
ob_start(); ach_url_guard_history_page(); $exactListHtml = ob_get_clean();
$expect(str_contains($exactListHtml, $historyName) && !str_contains($exactListHtml, 'DO_NOT_RENDER'),
    'Exact-keyword GET review list hides destination query tokens before individual review.');
$_GET = [];
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
$expect(str_contains($confirmationHTML,
    'data-copy-url="https://bad.example/private?token=DO_NOT_RENDER"'),
    'Exact, authenticated confirmation exposes full original destination only for Copy.');
$expect(str_contains($confirmationHTML,
    'data-copy-url="' . ach_url_guard_esc(yourls_link($historyName)) . '"'),
    'Exact, authenticated confirmation offers the native full short URL for Copy.');
$expect(!str_contains($confirmationHTML, 'href="https://bad.example/')
    && !str_contains($confirmationHTML, 'src="https://bad.example/'),
    'Destination remains inert text with no outbound fetch or auto-navigation.');
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

// Bulk review on real MySQL/InnoDB: create the indexed candidate table, scan
// across a disposable job, delete only fixture-owned matches, and preserve
// healthy, stale, or subsequently created records.
$bulkDB = yourls_get_db('read-bulk_integration');
$bulkAllowed = yourls_insert_link_in_db('https://example.com/safe-page',
    'bulk-safe-fixture', 'Keep this link');
$bulkMarked1 = yourls_insert_link_in_db('https://bad.example/unwanted',
    'bulk-flagged-a', 'Flagged fixture A');
$bulkMarked2 = yourls_insert_link_in_db('https://bad.example/unwanted2',
    'bulk-flagged-b', 'Flagged fixture B');
$expect($bulkAllowed && $bulkMarked1 && $bulkMarked2, 'Bulk fixture inserts succeed.');
$bulkJob = \ACh\Yourls\UrlGuard\BulkHistory::create($bulkDB, 'integration', 'page',
    \ACh\Yourls\UrlGuard\BulkHistory::filter(['reason' => 'blocked_domain']),
    ['bulk-safe-fixture','bulk-flagged-a','bulk-flagged-b']);
$bulkJob = \ACh\Yourls\UrlGuard\BulkHistory::scanStep($bulkDB, $bulkJob['id'], 'integration');
$expect($bulkJob['phase'] === 'ready' && $bulkJob['matched'] === 2,
    'Native MariaDB dry-run flags exactly two fixture URLs.');
$expect((string) $pdo->query("SELECT url FROM yourls_url WHERE keyword='bulk-safe-fixture'")->fetchColumn()
    === 'https://example.com/safe-page', 'Dry-run does not touch URLs.');
$bulkJob = \ACh\Yourls\UrlGuard\BulkHistory::startDeletion($bulkDB, $bulkJob['id'],
    'integration', 'DELETE 2', true);
$bulkJob = \ACh\Yourls\UrlGuard\BulkHistory::deleteStep($bulkDB, $bulkJob['id'], 'integration');
$expect($bulkJob['phase'] === 'done' && $bulkJob['deleted'] === 2 && $bulkJob['skipped'] === 0,
    'Exact two flagged fixture URLs deleted using native YOURLS function.');
$expect($pdo->query("SELECT COUNT(*) FROM yourls_url WHERE keyword LIKE 'bulk-%'")->fetchColumn() == 1,
    'Healthy fixture remains and only approved candidates deleted.');
$expect($pdo->query("SELECT url FROM yourls_url WHERE keyword='yourlsblog'")->fetchColumn()
    === $knownBefore, 'Bulk deletion did not damage unrelated historical links.');
\ACh\Yourls\UrlGuard\BulkHistory::clear($bulkDB, $bulkJob['id'], 'integration');

// Real MariaDB/InnoDB B1: a redirect can increment click count *after*
// a network probe starts but before deleteStep takes the URL row lock.
// The proof deliberately omits clicks, so the locked metadata check must
// independently skip this now-active zero-click candidate.
foreach (['bulk-net-active','bulk-net-stable','bulk-net-already-clicked'] as $key) {
    $expect(yourls_insert_link_in_db('https://example.com/' . $key, $key, 'Network bulk fixture'),
        'Can insert disposable network bulk link ' . $key);
}
$pdo->prepare('UPDATE yourls_url SET clicks = 1 WHERE keyword = ?')
    ->execute(['bulk-net-already-clicked']);
$networkClickJob = \ACh\Yourls\UrlGuard\BulkHistory::create($bulkDB, 'integration', 'page',
    \ACh\Yourls\UrlGuard\BulkHistory::filter([
        'reason'=>'http_not_found', 'clicks'=>'zero', 'host'=>'example.com',
        'prefix'=>'bulk-net-', 'before'=>'2099-12-31',
    ]),
    ['bulk-net-active','bulk-net-stable','bulk-net-already-clicked']);
$networkCalls = [];
$networkProbe = static function (string $url, array $cfg) use ($pdo, $bulkDB, &$networkCalls, $expect): array {
    $expect(!$bulkDB->inTransaction(), 'HTTP probe must run outside MariaDB transaction and row locks.');
    $key = basename((string) parse_url($url, PHP_URL_PATH));
    $networkCalls[$key] = ($networkCalls[$key] ?? 0) + 1;
    if ($key === 'bulk-net-active' && $networkCalls[$key] === 2) {
        // Simulate another request recording a click while the HTTP check
        // is in progress, before the deletion request acquires a row lock.
        $pdo->prepare('UPDATE yourls_url SET clicks=clicks+1 WHERE keyword=?')
            ->execute(['bulk-net-active']);
    }
    return ['status'=>'deny','reason'=>'http_not_found'];
};
$steps = 0;
while ($networkClickJob['phase'] === 'scan') {
    $networkClickJob = \ACh\Yourls\UrlGuard\BulkHistory::scanStep($bulkDB,
        $networkClickJob['id'], 'integration', $networkProbe);
    $expect(++$steps < 10, 'Bounded network scan must complete.');
}
$expect($networkClickJob['matched'] === 2, 'Zero-click dry-run includes two definite HTTP candidates.');
$networkClickJob = \ACh\Yourls\UrlGuard\BulkHistory::startDeletion($bulkDB,
    $networkClickJob['id'], 'integration', 'DELETE 2', true);
$steps = 0;
while ($networkClickJob['phase'] === 'delete') {
    $networkClickJob = \ACh\Yourls\UrlGuard\BulkHistory::deleteStep($bulkDB,
        $networkClickJob['id'], 'integration', $networkProbe);
    $expect(++$steps < 10, 'Bounded network deletion must complete.');
}
$expect($networkClickJob['phase'] === 'done' && $networkClickJob['processed'] === 2
    && $networkClickJob['deleted'] === 1 && $networkClickJob['skipped'] === 1,
    'Locked MariaDB metadata check skips newly-clicked HTTP 404 and deletes stable zero-click link.');
$expect($networkCalls['bulk-net-active'] === 2 && $networkCalls['bulk-net-stable'] === 2,
    'Each previewed candidate has a separate pre-lock network recheck.');
$expect((int)$pdo->query("SELECT clicks FROM yourls_url WHERE keyword='bulk-net-active'")->fetchColumn() === 1
    && \ACh\Yourls\UrlGuard\HistoricalReview::find($bulkDB, 'bulk-net-stable') === null
    && \ACh\Yourls\UrlGuard\HistoricalReview::find($bulkDB, 'bulk-net-already-clicked') !== null,
    'Real database preserves newly clicked and already clicked links; stable candidate removed.');
$expect(\ACh\Yourls\UrlGuard\BulkHistory::deleteStep($bulkDB,
    $networkClickJob['id'], 'integration')['deleted'] === 1,
    'Repeated completed MariaDB network deletion is inert.');
$candidateStatuses = $bulkDB->fetchAll(
    'SELECT keyword,result FROM yourls_ach_guard_candidates WHERE job_id = :id ORDER BY keyword',
    ['id' => $networkClickJob['id']]
);
$expect($candidateStatuses === [
    ['keyword'=>'bulk-net-active','result'=>'skipped'],
    ['keyword'=>'bulk-net-stable','result'=>'deleted'],
], 'Real MariaDB snapshot stores exact skipped/deleted reason outcomes.');
\ACh\Yourls\UrlGuard\BulkHistory::clear($bulkDB, $networkClickJob['id'], 'integration');

// B2: first-party admin must require explicit consent for every advertised
// network-derived reason (not just HTTP 404/410).
foreach (\ACh\Yourls\UrlGuard\BulkHistory::networkReasons() as $reason) {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = [
        'bulk_action'=>'create','bulk_nonce'=>yourls_create_nonce('ach_url_guard_bulk'),
        'bulk_mode'=>'page','bulk_filter'=>['reason'=>$reason],
        'bulk_keywords'=>['bulk-net-active'],
    ];
    [$refusedJob,$refusal] = ach_url_guard_bulk_request($bulkDB);
    $expect($refusedJob === null && str_contains($refusal, 'Confirm HTTP/DNS network scanning'),
        'Missing explicit network consent refuses admin job for '.$reason);
}
$_SERVER['REQUEST_METHOD'] = 'GET';
$_POST = [];

// Exercise actual DNS/redirect transport policies through injectable resolver
// and requester, never a live external provider or unsafe outbound HTTP request.
$unsafeDnsRequests = 0;
$privateDnsProbe = new \ACh\Yourls\UrlGuard\HttpProbe(
    static fn(string $host): array => ['8.8.8.8','127.0.0.1'],
    static function () use (&$unsafeDnsRequests): array {
        $unsafeDnsRequests++;
        return ['http_code'=>200];
    }
);
$badRedirectRequests = 0;
$badRedirectProbe = new \ACh\Yourls\UrlGuard\HttpProbe(
    static fn(string $host): array => ['8.8.8.8'],
    static function () use (&$badRedirectRequests): array {
        $badRedirectRequests++;
        return ['http_code'=>302,'location'=>"/bad\nlocation"];
    }
);
foreach ([
    'private_dns_address'=>['bulk-dns-fixture','https://example.com/dns-fixture',$privateDnsProbe],
    'invalid_redirect'=>['bulk-redirect-fixture','https://example.com/redirect-fixture',$badRedirectProbe],
] as $reason=>[$keyword,$url,$httpProbe]) {
    $expect(\ACh\Yourls\UrlGuard\BulkHistory::networkMode(
        \ACh\Yourls\UrlGuard\BulkHistory::filter(['reason'=>$reason])),
        'Network scan explicitly enabled for advertised '.$reason);
    $expect(yourls_insert_link_in_db($url,$keyword,'Network reason fixture'),
        'Insert disposable network-reason URL '.$reason);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = [
        'bulk_action'=>'create','bulk_nonce'=>yourls_create_nonce('ach_url_guard_bulk'),
        'bulk_mode'=>'page','bulk_filter'=>['reason'=>$reason],
        'bulk_keywords'=>[$keyword], 'bulk_http_ack'=>'1',
    ];
    [$createdJob,$creationError] = ach_url_guard_bulk_request($bulkDB);
    $expect($createdJob !== null && $creationError === '',
        'Confirmed admin opt-in starts network reason job '.$reason);
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_POST = [];
    $callback = static fn(string $target, array $cfg): array => $httpProbe->check($target,$cfg);
    $createdJob = \ACh\Yourls\UrlGuard\BulkHistory::scanStep($bulkDB,
        $createdJob['id'], 'integration', $callback);
    $expect($createdJob['phase']==='ready' && $createdJob['matched']===1,
        'Native MariaDB scan materializes network-only reason '.$reason);
    $createdJob = \ACh\Yourls\UrlGuard\BulkHistory::startDeletion($bulkDB,
        $createdJob['id'], 'integration', 'DELETE 1', true);
    $createdJob = \ACh\Yourls\UrlGuard\BulkHistory::deleteStep($bulkDB,
        $createdJob['id'], 'integration', $callback);
    $expect($createdJob['phase']==='done' && $createdJob['deleted']===1
        && \ACh\Yourls\UrlGuard\HistoricalReview::find($bulkDB,$keyword)===null,
        'Native MariaDB deletion revalidates network reason '.$reason);
    \ACh\Yourls\UrlGuard\BulkHistory::clear($bulkDB, $createdJob['id'], 'integration');
}
$expect($unsafeDnsRequests === 0,
    'Private DNS addresses never trigger HTTP transport (real HttpProbe injected resolver).');
$expect($badRedirectRequests === 2,
    'Invalid redirects only fetch the original safe host, once during preview and recheck.');
$_POST = [];
$_SERVER['REQUEST_METHOD'] = 'GET';

// Network-only historical deletion with deterministic injection and no
// external traffic. Includes healthy, ambiguous, and confirmed missing URLs.
$networkCases = [
    ['net-missing-404', 'https://example.com/missing-404', 'deny', 'http_not_found'],
    ['net-missing-410', 'https://example.com/missing-410', 'deny', 'http_not_found'],
    ['net-healthy', 'https://example.com/healthy', 'allow', 'checks_passed'],
    ['net-timeout', 'https://example.com/timeout', 'unknown', 'connection_error'],
    ['net-unavailable', 'https://example.com/403', 'unknown', 'http_inconclusive'],
];
$fakeProbe = static function (string $url): array {
    if (str_contains($url, 'missing-404') || str_contains($url, 'missing-410')) {
        return ['status' => 'deny', 'reason' => 'http_not_found'];
    }
    if (str_contains($url, 'timeout')) return ['status' => 'unknown', 'reason' => 'connection_error'];
    if (str_contains($url, '/403')) return ['status' => 'unknown', 'reason' => 'http_inconclusive'];
    return ['status' => 'allow', 'reason' => 'checks_passed'];
};
foreach ($networkCases as [$key,$url,$status,$reason]) {
    $expect(yourls_insert_link_in_db($url,$key,'Network fixture'), 'Fixture inserted: '.$key);
    $row = \ACh\Yourls\UrlGuard\HistoricalReview::find($bulkDB,$key);
    $result = \ACh\Yourls\UrlGuard\HistoricalReview::inspect($row, $historyPolicy, true, $fakeProbe);
    $expect($result['status'] === $status && $result['reason'] === $reason,
        'Controlled network verdict matches '.$key);
    $proof = \ACh\Yourls\UrlGuard\HistoricalReview::proof($row,$historyPolicy);
    $attempt = \ACh\Yourls\UrlGuard\HistoricalReview::delete($bulkDB,$key,$proof,
        $reason,true,$historyPolicy,$fakeProbe);
    $expect($attempt === ($status === 'deny' ? 'deleted' : 'no_longer_flagged'),
        'Destructive network gate preserves all non-definite links '.$key);
    $remaining = \ACh\Yourls\UrlGuard\HistoricalReview::find($bulkDB,$key);
    $expect(($remaining===null) === ($status==='deny'), 'Network delete row state '.$key);
}

$_POST = [];
$_GET = [];
$_SERVER['REQUEST_METHOD'] = 'GET';

echo 'PASS real DB integration: active plugins, monitor, enforce, API, admin callback, old links, data privacy.' . "\n";
