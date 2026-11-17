<?php
declare(strict_types=1);

// Standalone, dependency-free historical-admin and deletion gate regressions.
// No credentials, external network calls, or real YOURLS database are used.
define('YOURLS_ABSPATH', __DIR__);
define('YOURLS_DB_TABLE_URL', 'yourls_url');
define('YOURLS_COOKIEKEY', 'history-review-local-test-secret');

final class FakeHistoryDB
{
    public array $rows = [];
    private array $snapshot = [];
    private bool $transaction = false;
    public int $deletes = 0;

    public function fetchAll(string $query, array $binds): array
    {
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
check(str_contains($html, 'Check HTTP'), 'clean old rows can receive a manual HTTP check');
check(!str_contains($html, 'NEVER_SHOW') && !str_contains($html, 'DO_NOT_EXPOSE')
    && !str_contains($html, 'NO_EXPOSE'), 'admin page never embeds private query tokens');
check(!str_contains($html, 'api_key='), 'full URL query not rendered');
check($db->rows === $original && $db->deletes === 0, 'opening/previewing admin never deletes');

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

$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = [
    'history_action' => 'review', 'history_keyword' => 'bad',
    'nonce' => yourls_create_nonce('ach_url_guard_history_review'),
];
ob_start();ach_url_guard_history_page();$reviewHtml=ob_get_clean();
check(str_contains($reviewHtml, 'Delete this short link permanently'), 'two-step confirmation rendered');
check(!str_contains($reviewHtml, 'NEVER_SHOW'), 'confirmation does not reveal query token');
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
check(in_array('ach_url_guard_history_delete', $nonceActions, true), 'delete nonce checked');

$_POST = []; $_GET = []; $_SERVER['REQUEST_METHOD'] = 'GET';
echo 'PASS ' . $assertions . ' historical admin, pagination, preview, privacy and deletion-safety assertions (fake DB)' . PHP_EOL;
