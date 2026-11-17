<?php
declare(strict_types=1);

// Standalone, dependency-free historical-admin and deletion gate regressions.
// No credentials, external network calls, or real YOURLS database are used.
define('YOURLS_ABSPATH', __DIR__);
define('YOURLS_DB_TABLE_URL', 'yourls_url');
define('YOURLS_DB_TABLE_OPTIONS', 'yourls_options');
define('YOURLS_COOKIEKEY', 'history-review-local-test-secret');
define('YOURLS_USER', 'fixture-admin');
define('YOURLS_DB_PREFIX', 'yourls_');

final class FakeHistoryDB
{
    public array $rows = [];
    private array $snapshot = [];
    private bool $transaction = false;
    public int $deletes = 0;
    public ?array $settingsRaw = ['mode' => 'enforce'];

    public function fetchAll(string $query, array $binds): array
    {
        if (array_key_exists('prefix', $binds)) return [];
        if (array_key_exists('name', $binds) && $binds['name'] === 'ach_url_guard_settings') {
            return $this->settingsRaw === null ? [] : [['option_value' => serialize($this->settingsRaw)]];
        }
        if (strpos($query, 'ORDER BY keyword ASC LIMIT ') === false
            || !preg_match('/LIMIT ([0-9]+)$/D', $query, $match)) {
            throw new RuntimeException('Unexpected scan query');
        }
        $cursor = (string) $binds['cursor'];
        $sorted = array_values($this->rows);
        usort($sorted, static fn(array $a, array $b): int => strcmp($a['keyword'], $b['keyword']));
        return array_slice(array_values(array_filter($sorted, static fn(array $r): bool =>
            strcmp($r['keyword'], $cursor) > 0)), 0, (int) $match[1]);
    }

    public function fetchObject(string $query, array $binds): object|false
    {
        $keyword = (string) $binds['keyword'];
        return isset($this->rows[$keyword]) ? (object) $this->rows[$keyword] : false;
    }

    public function beginTransaction(): bool
    {
        if ($this->transaction) throw new RuntimeException('Nested transaction');
        $this->snapshot = $this->rows;
        return $this->transaction = true;
    }

    public function inTransaction(): bool { return $this->transaction; }

    public function rollBack(): bool
    {
        if (!$this->transaction) throw new RuntimeException('No transaction');
        $this->rows = $this->snapshot;
        $this->transaction = false;
        return true;
    }

    public function commit(): bool
    {
        if (!$this->transaction) throw new RuntimeException('No transaction');
        $this->transaction = false;
        return true;
    }
}

$db = new FakeHistoryDB();
$options = ['ach_url_guard_settings' => ['mode' => 'enforce']];
$nonceActions = [];
$pageSlugs = [];
function yourls_add_filter($name, $cb, $priority = 10, $argc = 1): void {}
function yourls_add_action($name, $cb): void {}
function yourls_register_plugin_page($slug, $title, $cb): void {
    global $pageSlugs;
    $pageSlugs[$slug] = $cb;
}
function yourls_sanitize_keyword($value): string { return strtolower((string) $value); }
function yourls_get_db($context = ''): FakeHistoryDB { global $db; return $db; }
function yourls_get_option($name, $fallback = false) {
    global $options;
    return $options[$name] ?? $fallback;
}
function yourls_create_nonce($action): string {return 'test-nonce-' . $action;}
function yourls_verify_nonce($action, $nonce = false): bool {
    global $nonceActions;
    $nonceActions[] = $action;
    if (!is_string($nonce) || !hash_equals(yourls_create_nonce($action), $nonce)) {
        throw new RuntimeException('Rejected invalid admin nonce');
    }
    return true;
}
function yourls_admin_url($path = ''): string {return 'https://short.example/admin/' . $path;}
function yourls_link($keyword = ''): string {return 'https://short.example/' . rawurlencode((string) $keyword);}
$historyAuthenticated = true;
function yourls_is_valid_user(): bool { global $historyAuthenticated; return $historyAuthenticated; }
function yourls_die($message, $title = '', $status = 403): void { throw new RuntimeException('Authentication denied (' . $status . ')'); }
function yourls_maybe_unserialize($value) {return @unserialize((string) $value, ['allowed_classes' => false]);}
function yourls_delete_link_by_keyword($keyword): int {
    global $db;
    if (!isset($db->rows[$keyword])) return 0;
    unset($db->rows[$keyword]);
    $db->deletes++;
    return 1;
}

require dirname(__DIR__) . '/plugin.php';
ach_url_guard_register_page(); // Simulate the native plugins_loaded hook.
use ACh\Yourls\UrlGuard\HistoricalReview;
use ACh\Yourls\UrlGuard\Policy;
function check(bool $ok, string $description): void {
    global $assertions;
    $assertions++;
    if (!$ok) throw new RuntimeException('FAIL ' . $description);
}
$assertions = 0;
$makeRow = static fn(string $keyword, string $url, string $title = ''): array => [
    'keyword' => $keyword,
    'url' => $url,
    'title' => $title,
    'timestamp' => '2026-11-01 12:34:56',
    'clicks' => 0,
];
$db->rows = [
    'bad' => $makeRow('bad', 'https://bit.ly/private?api_key=NEVER_SHOW', 'Known nesting'),
    'long-generated-name-1234567890' => $makeRow(
        'long-generated-name-1234567890', 'https://example.com/valid-page'),
    'safe' => $makeRow('safe', 'https://example.com/valid-page?session=DO_NOT_EXPOSE'),
    'home' => $makeRow('home', 'https://example.net/?auth=NO_EXPOSE'),
];
$settings = Policy::settings($options['ach_url_guard_settings']);
check(isset($pageSlugs['ach_url_guard_history']), 'history page registered by plugin');
$historyAuthenticated = false;
$anonymousDenied = false;
try { ob_start(); ach_url_guard_history_page(); ob_end_clean(); }
catch (RuntimeException $e) { $anonymousDenied = str_contains($e->getMessage(), 'Authentication denied'); ob_end_clean(); }
check($anonymousDenied, 'anonymous history page denied independent of YOURLS_PRIVATE');
$anonymousDeleteDenied = false;
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['history_action' => 'delete', 'history_confirm' => '1', 'history_keyword' => 'bad'];
try { ob_start(); ach_url_guard_history_page(); ob_end_clean(); }
catch (RuntimeException $e) { $anonymousDeleteDenied = true; ob_end_clean(); }
check($anonymousDeleteDenied && $db->deletes === 0, 'anonymous delete POST denied before any operation');
$anonymousSettingsDenied = false;
try { ob_start(); ach_url_guard_admin_page(); ob_end_clean(); }
catch (RuntimeException $e) { $anonymousSettingsDenied = true; ob_end_clean(); }
check($anonymousSettingsDenied, 'neighboring Guard settings page is also restricted');
$historyAuthenticated = true;
$_SERVER['REQUEST_METHOD'] = 'GET'; $_POST = [];

check(HistoricalReview::inspect($db->rows['bad'], $settings)['reason'] === 'blocked_domain', 'blocked domain flagged');
check(HistoricalReview::inspect($db->rows['home'], $settings)['reason'] === 'root_url', 'homepage-only flagged');
check(HistoricalReview::inspect($db->rows['safe'], $settings)['status'] === 'allow', 'safe path allowed');
$strictUnknown = Policy::settings(['unknown_action' => 'deny',
    'blocked_url_patterns' => ['~example\\.com~']]);
$overBudget = $makeRow('expensive-url', 'https://example.com/long/' . str_repeat('a', 70000));
check(HistoricalReview::inspect($overBudget, $strictUnknown)['status'] === 'unknown',
    'uncertain regex budget is never treated as definite historical deletion evidence');
check(HistoricalReview::inspect($overBudget, $strictUnknown)['reason'] === 'regex_unavailable',
    'unknown review preserves diagnostic reason even in strict deny mode');
check(HistoricalReview::inspect($db->rows['long-generated-name-1234567890'], $settings)['status'] === 'allow',
    'historical generated/unknown-length alias not condemned by custom cap');
$display = ach_url_guard_history_compact('https://example.org/start/'
    . str_repeat('x', 140) . '/finish?key=LAST', 64);
check(str_starts_with($display, 'https://example.org/') && str_contains($display, '[...]')
    && str_ends_with($display, 'LAST') && strlen($display) === 64,
    'long URL shows start and end with middle omission');
$bracketUrl = 'https://example.org/[...]?q=' . str_repeat('a', 180) . '&end=TAIL';
$bracketHtml = ach_url_guard_history_compact_html($bracketUrl, 55);
check(substr_count($bracketHtml, 'class="ach-history-marker"') === 1
    && str_contains($bracketHtml, 'ach-history-suffix')
    && str_contains($bracketHtml, 'TAIL'),
    'pre-existing literal [...] does not confuse or hide the actual omission marker');
$mobileParts = ach_url_guard_history_compact_parts(str_repeat('z', 500), 80);
check($mobileParts['truncated'] && strlen($mobileParts['tail']) <= 10
    && strlen($mobileParts['head']) > 0,
    'narrow mobile value keeps a compact exact suffix and visible start');
$mediumValue = 'https://example.org/' . str_repeat('abcde', 10);
$mediumCode = ach_url_guard_history_code($mediumValue, 80);
check(strlen($mediumValue) < 80
    && str_contains($mediumCode, 'class="ach-history-one-line"')
    && str_contains($mediumCode, 'class="ach-history-compact" aria-hidden="true"')
    && str_contains($mediumCode, 'class="ach-history-marker"'),
    'medium-length value has a hidden compact alternative for width-dependent overflow');
$unicodeValue = 'https://example.org/' . str_repeat('路径', 10);
$unicodeCode = ach_url_guard_history_code($unicodeValue);
check(str_contains($unicodeCode, 'ach-history-original')
    && str_contains($unicodeCode, 'ach-history-compact')
    && str_contains($unicodeCode, 'middle omitted'),
    'Unicode text has both original and accessible abbreviated alternatives');
ob_start();
ach_url_guard_history_responsive_script();
$responsiveScript = ob_get_clean();
check(str_contains($responsiveScript, 'getBoundingClientRect().width > code.clientWidth')
    && str_contains($responsiveScript, 'ResizeObserver')
    && str_contains($responsiveScript, 'Intl.Segmenter'),
    'rendered-width and grapheme-aware abbreviation is initialized with resize observation');
check(str_contains($responsiveScript, 'original.setAttribute')
    && str_contains($responsiveScript, 'compact.setAttribute')
    && str_contains($responsiveScript, 'suffix.textContent'),
    'accessible compact state and exact untrusted suffix use safe text assignment');
check(ach_url_guard_history_compact('https://example.org/') === 'https://example.org/',
    'short URL remains unchanged in display');
check(str_contains(ach_url_guard_history_compact(str_repeat('مسیر', 40), 22), '[...]'),
    'UTF-8 multibyte labels abbreviate without breaking a character');
ob_start();
ach_url_guard_history_url_field('Full destination URL', 'https://example.org/?x="><img src=x onerror=alert(1)>&secret=a');
$unsafeField = ob_get_clean();
check(!str_contains($unsafeField, '<img') && !str_contains($unsafeField, 'onerror=alert(1)>')
    && str_contains($unsafeField, '&quot;') && str_contains($unsafeField, '&amp;secret=a'),
    'copy attribute and visible URL label escape attacker-controlled text');
check(HistoricalReview::hostLabel($db->rows['bad']['url']) === 'bit.ly', 'host summary only');
check(HistoricalReview::hostLabel('not a url') === '[invalid destination]', 'invalid host redacted');
check(HistoricalReview::pageSize('1000') === 50, 'unbounded batch sizes reset to documented default');
check(HistoricalReview::pageSize('25') === 25, 'configurable scan batch size');
check(count(HistoricalReview::page($db, '', 25)['rows']) === 4, 'scan reads all rows');
check(HistoricalReview::page($db, 'home', 25)['rows'][0]['keyword'] === 'long-generated-name-1234567890',
    'keyset page follows selected cursor');
$original = $db->rows;
$_SERVER['REQUEST_METHOD'] = 'GET';
$_GET = [];
$_POST = [];
ob_start();ach_url_guard_history_page();$html = ob_get_clean();
check(str_contains($html, 'Review deletion'), 'definitely flagged rows provide review');
check(str_contains($html, 'ach-history-original')
    && str_contains($html, 'ach-history-compact')
    && str_contains($html, 'getBoundingClientRect().width > code.clientWidth'),
    'normal admin page includes responsive abbreviation markup and working resize script');

check(str_contains($html, 'ach-history-table') && str_contains($html, 'white-space:nowrap')
    && str_contains($html, 'text-overflow:ellipsis'),
    'list retains single-line compact values and bounded responsive columns');
check(!str_contains($html, 'data-copy-url='),
    'default review table never embeds a full destination for copying');
check(str_contains($html, 'Select all visible'), 'visible-page Select All checkbox rendered');
check(str_contains($html, 'Select All Matching Filters across every page'),
    'cross-page filtered selection clearly labeled');
check(str_contains($html, 'name="bulk_keywords[]"'), 'table row checkbox attached to filter form');
check(str_contains($html, 'name="bulk_filter[reason]"'), 'reason filter visible');
check(str_contains($html, 'name="bulk_filter[clicks]"'), 'clicks filter visible');

check(str_contains($html, 'Check HTTP'), 'clean old rows can receive a manual HTTP check');
check(!str_contains($html, 'NEVER_SHOW') && !str_contains($html, 'DO_NOT_EXPOSE')
    && !str_contains($html, 'NO_EXPOSE'), 'admin page never embeds private query tokens');
check(!str_contains($html, 'api_key='), 'full URL query not rendered');
check($db->rows === $original && $db->deletes === 0, 'opening/previewing admin never deletes');

// B2: every advertised network-derived filter requires explicit consent,
 // even for manual current-page selections; no URL rows change.
foreach (\ACh\Yourls\UrlGuard\BulkHistory::networkReasons() as $networkReason) {
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_POST = [
        'bulk_action' => 'create', 'bulk_nonce' => yourls_create_nonce('ach_url_guard_bulk'),
        'bulk_mode' => 'page', 'bulk_keywords' => ['bad'],
        'bulk_filter' => ['reason' => $networkReason],
    ];
    [$unconfirmedJob, $consentError] = ach_url_guard_bulk_request($db);
    check($unconfirmedJob === null && str_contains($consentError, 'Confirm HTTP/DNS network scanning'),
        'network reason ' . $networkReason . ' requires consent before any candidate scan');
    check($db->deletes === 0, 'missing network consent causes no deletion');
    $_POST['bulk_http_ack'] = '0';
    [$invalidAckJob, $invalidAckError] = ach_url_guard_bulk_request($db);
    check($invalidAckJob === null && str_contains($invalidAckError, 'Confirm HTTP/DNS'),
        'network consent requires explicit checked value for ' . $networkReason);
}
$_SERVER['REQUEST_METHOD'] = 'GET';
$_POST = [];

// Prove an unconfirmed or stale confirmation is inert.
$bad = $db->rows['bad'];
$proof = HistoricalReview::proof($bad, $settings);
check(strlen($proof) === 64, 'review fingerprint is a bounded HMAC digest');
check(HistoricalReview::delete($db, 'bad', 'ffff', 'blocked_domain', false, $settings) === 'invalid_request',
    'short/tampered proof rejected');
check(HistoricalReview::delete($db, 'bad', str_repeat('f', 64), 'blocked_domain', false, $settings) === 'stale',
    'mismatched proof cannot delete');
$changed = $settings;
$changed['blocked_domains'] = [];
check(HistoricalReview::delete($db, 'bad', $proof, 'blocked_domain', false, $changed) === 'stale',
    'rule change invalidates old proof');
check(HistoricalReview::delete($db, 'bad', HistoricalReview::proof($bad, $changed),
    'blocked_domain', false, $changed) === 'no_longer_flagged', 'clean URL cannot be removed by history review');
$db->rows['bad']['clicks'] = 30;
check(hash_equals($proof, HistoricalReview::proof($db->rows['bad'], $settings)),
    'ordinary click counter change does not invalidate snapshot identity');
$db->rows['bad']['url'] = 'https://example.com/safe-path';
check(HistoricalReview::delete($db, 'bad', $proof, 'blocked_domain', false, $settings) === 'stale',
    'destination changed after preview prevents deletion');
$db->rows['bad'] = $bad;
$db->settingsRaw = ['mode' => 'enforce', 'blocked_domains' => []];
check(HistoricalReview::delete($db, 'bad', $proof, 'blocked_domain', false, $settings) === 'stale',
    'current stored policy change cancels deletion even when request had cached old rules');
check(isset($db->rows['bad']), 'concurrent policy update preserves historical link');
$db->settingsRaw = ['mode' => 'enforce'];

$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = [
    'history_action' => 'review', 'history_keyword' => 'bad',
    'nonce' => yourls_create_nonce('ach_url_guard_history_review'),
];
ob_start();ach_url_guard_history_page();$reviewHtml=ob_get_clean();
check(str_contains($reviewHtml, 'Delete this short link permanently'), 'two-step confirmation rendered');
check(str_contains($reviewHtml, 'Full short URL')
    && str_contains($reviewHtml, 'data-copy-url="https://short.example/bad"')
    && str_contains($reviewHtml, 'Full destination URL'),
    'exact reviewed link and original destination presented before deletion');
check(str_contains($reviewHtml, 'data-copy-url="https://bit.ly/private?api_key=NEVER_SHOW"'),
    'explicit single-link confirmation offers full destination to Copy');
check(!str_contains($reviewHtml, 'href="https://bit.ly/')
    && !str_contains($reviewHtml, 'src="https://bit.ly/')
    && !str_contains($reviewHtml, 'href="https://short.example/bad"'),
    'untrusted destination is text/copy only, not a navigable or fetched resource');
check(str_contains(ach_url_guard_history_compact_html(str_repeat('a', 180), 40),
    'class="ach-history-marker"') && str_contains($reviewHtml, 'ach-history-copy'),
    'abbreviation marker remains an explicit fixed-size element');
check(!str_contains($reviewHtml, 'aria-label="Full destination URL: '),
    'private full destination is not duplicated in assistive labels');
check(str_contains($reviewHtml, 'navigator.clipboard.writeText')
    && str_contains($reviewHtml, 'document.execCommand'),
    'copy implementation supports secure Clipboard API and browser fallback');
check($db->deletes === 0, 'review action is not deletion');

$_POST = [
    'history_action' => 'delete', 'history_keyword' => 'bad',
    'history_proof' => $proof, 'history_reason' => 'blocked_domain',
    'history_scope' => 'local', 'nonce' => yourls_create_nonce('ach_url_guard_history_delete'),
];
ob_start();ach_url_guard_history_page();$withoutConfirm=ob_get_clean();
check(str_contains($withoutConfirm, 'Explicit confirmation is required'), 'unchecked confirmation rejected');
check(isset($db->rows['bad']), 'unchecked confirmation does not delete');
$_POST['history_confirm'] = '1';
$_POST['nonce'] = 'invalid';
$nonceRejected = false;
try {ob_start();ach_url_guard_history_page();ob_end_clean();}
catch (RuntimeException $e) {$nonceRejected = true; ob_end_clean();}
check($nonceRejected && isset($db->rows['bad']), 'invalid action nonce blocks deletion');

$_POST['nonce'] = yourls_create_nonce('ach_url_guard_history_delete');
ob_start();ach_url_guard_history_page();$deletedHtml=ob_get_clean();
check(str_contains($deletedHtml, 'Reviewed short link was deleted'), 'successful delete feedback');
check(!isset($db->rows['bad']) && $db->deletes === 1, 'exact flagged link deleted once');
check(isset($db->rows['home']) && isset($db->rows['safe']), 'unrelated old links remain unchanged');
check(HistoricalReview::delete($db, 'bad', $proof, 'blocked_domain', false, $settings) === 'stale',
    'repeated operation is idempotently inert');
check($db->deletes === 1, 'no second delete');

// Destructive HTTP path: deterministic injectable fake transport, no internet.
$probeNetwork = static function (string $url, array $cfg): array {
    if (str_contains($url, '/missing-404') || str_contains($url, '/missing-410')) {
        return ['status' => 'deny', 'reason' => 'http_not_found', 'host' => 'example.com'];
    }
    if (str_contains($url, '/unsafe-redirect')) {
        return ['status' => 'deny', 'reason' => 'private_dns_address', 'host' => 'example.com'];
    }
    if (str_contains($url, '/blocked-403') || str_contains($url, '/rate-429')
        || str_contains($url, '/server-503') || str_contains($url, '/timeout')) {
        return ['status' => 'unknown', 'reason' => 'http_inconclusive', 'host' => 'example.com'];
    }
    return ['status' => 'allow', 'reason' => 'checks_passed', 'host' => 'example.com'];
};
$noNetworkRequests = 0;
$blockedPrivate = $makeRow('private-untrusted', 'http://127.0.0.1/missing-404');
check(HistoricalReview::inspect($blockedPrivate, $settings, true,
    static function () use (&$noNetworkRequests): array { $noNetworkRequests++; throw new RuntimeException('Should not fetch'); })
    ['reason'] === 'private_address' && $noNetworkRequests === 0,
    'private IP rejected before any HTTP request');
foreach (['missing-404','missing-410','healthy-200','blocked-403','rate-429','server-503','timeout'] as $case) {
    $key = 'network-' . $case;
    $db->rows[$key] = $makeRow($key, 'https://example.com/' . $case);
    $result = HistoricalReview::inspect($db->rows[$key], $settings, true, $probeNetwork);
    $expected = str_starts_with($case, 'missing-') ? 'deny'
        : (str_starts_with($case, 'healthy-') ? 'allow' : 'unknown');
    check($result['status'] === $expected, 'network ' . $case . ' classified correctly');
    $policyNow = $settings;
    $policyNow['unknown_action'] = 'deny';
    if ($expected === 'unknown') {
        check(HistoricalReview::inspect($db->rows[$key], $policyNow, true, $probeNetwork)
            ['status'] === 'unknown', 'strict unknown does not convert inconclusive HTTP into deletion');
    }
    $proof = HistoricalReview::proof($db->rows[$key], $settings);
    if ($expected !== 'deny') {
        check(HistoricalReview::delete($db, $key, $proof, 'http_not_found', true,
            $settings, $probeNetwork) === 'no_longer_flagged',
            'HTTP ' . $case . ' never authorizes deletion');
        check(isset($db->rows[$key]), 'no deletion for HTTP ' . $case);
    } else {
        $savedRow = $db->rows[$key];
        $db->rows[$key]['url'] = 'https://example.com/healthy-200';
        check(HistoricalReview::delete($db, $key, $proof, 'http_not_found', true,
            $settings, $probeNetwork) === 'stale', 'changed URL cancels network delete ' . $case);
        $db->rows[$key] = $savedRow;
        $old = $db->settingsRaw;
        $db->settingsRaw = ['mode' => 'enforce', 'blocked_domains' => []];
        check(HistoricalReview::delete($db, $key, $proof, 'http_not_found', true,
            $settings, $probeNetwork) === 'stale', 'stored-policy change cancels network delete ' . $case);
        $db->settingsRaw = $old;
        check(HistoricalReview::delete($db, $key, $proof, 'http_not_found', true,
            $settings, $probeNetwork) === 'deleted',
            'confirmed network-only failure deleted once ' . $case);
        check(HistoricalReview::delete($db, $key, $proof, 'http_not_found', true,
            $settings, $probeNetwork) === 'stale', 'repeat network delete inert ' . $case);
    }
}

check(in_array('ach_url_guard_history_delete', $nonceActions, true), 'delete nonce checked');

$_POST = []; $_GET = []; $_SERVER['REQUEST_METHOD'] = 'GET';
echo 'PASS ' . $assertions . ' historical admin, pagination, preview, privacy and deletion-safety assertions (fake DB)' . PHP_EOL;
