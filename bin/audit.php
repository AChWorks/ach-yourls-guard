<?php
declare(strict_types=1);

/**
 * Read-only operator scan of existing YOURLS URLs.
 * php bin/audit.php --limit=200 --after=last_keyword [--network] [--reputation]
 * Does not delete, block, mark, or update any existing short link.
 * Export only to a private file: full destination URLs can contain sensitive tokens.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}
require_once dirname(__DIR__) . '/src/Policy.php';
require_once dirname(__DIR__) . '/src/HttpProbe.php';
require_once dirname(__DIR__) . '/src/Reputation.php';
require_once dirname(__DIR__) . '/src/Guard.php';

use ACh\Yourls\UrlGuard\Policy;
use ACh\Yourls\UrlGuard\Guard;

$options = getopt('', ['site:', 'limit:', 'after:', 'network', 'reputation', 'help']);
if (isset($options['help'])) {
    fwrite(STDOUT, "Usage: php bin/audit.php --site=/path/to/yourls --limit=200 --after=KEYWORD [--network] [--reputation]\n");
    exit(0);
}
$site = isset($options['site']) && is_string($options['site']) ? $options['site'] : dirname(__DIR__, 4);
$site = realpath($site);
if ($site === false || !is_file($site . '/user/config.php') || !is_file($site . '/includes/version.php')) {
    fwrite(STDERR, "Invalid YOURLS installation path.\n");
    exit(2);
}
$limit = filter_var($options['limit'] ?? 200, FILTER_VALIDATE_INT);
if ($limit === false || $limit < 1) {
    fwrite(STDERR, "--limit must be a positive integer.\n");
    exit(2);
}
$cursor = (string) ($options['after'] ?? '');
require $site . '/user/config.php';
$prefix = (string) YOURLS_DB_PREFIX;
if (!preg_match('/^[a-zA-Z0-9_]+$/D', $prefix)) {
    fwrite(STDERR, "Invalid database table prefix.\n");
    exit(2);
}
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$db = new mysqli(YOURLS_DB_HOST, YOURLS_DB_USER, YOURLS_DB_PASS, YOURLS_DB_NAME);
$optionQuery = $db->prepare('SELECT option_value FROM ' . $prefix . 'options WHERE option_name = ?');
$optionName = 'ach_url_guard_settings';
$optionQuery->bind_param('s', $optionName);
$optionQuery->execute();
$record = $optionQuery->get_result()->fetch_assoc();
$stored = $record ? @unserialize($record['option_value'], ['allowed_classes' => false]) : [];
$settings = Policy::settings(is_array($stored) ? $stored : []);
$settings['reachability_enabled'] = isset($options['network']);
$settings['web_risk_enabled'] = isset($options['reputation']);
$settings['dnsbl_enabled'] = false;
$key = defined('ACH_URL_GUARD_WEB_RISK_KEY') ? (string) ACH_URL_GUARD_WEB_RISK_KEY : '';
if ($settings['web_risk_enabled'] && $key === '') {
    fwrite(STDERR, "Web Risk API key missing; no reputation scan was run.\n");
    exit(2);
}
$query = $db->prepare('SELECT keyword,url FROM ' . $prefix . 'url WHERE keyword > ? ORDER BY keyword LIMIT ?');
$query->bind_param('si', $cursor, $limit);
$query->execute();
$rows = $query->get_result();
$guard = new Guard();
$scanned = 0;
$flagged = 0;
fputcsv(STDOUT, ['keyword', 'status', 'reason', 'destination'], ',', '"', '');
while ($row = $rows->fetch_assoc()) {
    $scanned++;
    $cursor = (string) $row['keyword'];
    $result = $guard->evaluate((string) $row['url'], $settings, $key);
    if ($result['status'] !== 'allow') {
        $flagged++;
        fputcsv(STDOUT, [$cursor, $result['status'], $result['reason'], $row['url']], ',', '"', '');
    }
}
fwrite(STDERR, sprintf("Scanned: %d, flagged: %d, next cursor: %s\n", $scanned, $flagged, $cursor));
