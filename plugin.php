<?php
/*
Plugin Name: ACh URL Guard
Plugin URI: https://github.com/AChWorks/ach-yourls-guard
Description: Safe new-link policy enforcement and an optional admin-only manual review of historical short links.
Version: 0.2.1
Author: ACh
*/

if (!defined('YOURLS_ABSPATH')) {
    exit;
}

require_once __DIR__ . '/src/Policy.php';
require_once __DIR__ . '/src/HttpProbe.php';
require_once __DIR__ . '/src/Reputation.php';
require_once __DIR__ . '/src/Guard.php';
require_once __DIR__ . '/src/WorkGate.php';
require_once __DIR__ . '/src/HistoricalReview.php';
require_once __DIR__ . '/src/HistoryAdmin.php';
require_once __DIR__ . '/src/BulkHistory.php';
require_once __DIR__ . '/src/HistoryBulkAdmin.php';

use ACh\Yourls\UrlGuard\Policy;
use ACh\Yourls\UrlGuard\Guard;
use ACh\Yourls\UrlGuard\WorkGate;

// Admin is responsible for turning on enforcement; new installs start in monitor mode.
yourls_add_filter('shunt_add_new_link', 'ach_url_guard_on_create', 10, 4);
yourls_add_action('plugins_loaded', 'ach_url_guard_register_page');
yourls_add_action('load-ach_url_guard', 'ach_url_guard_require_admin');
yourls_add_action('load-ach_url_guard_history', 'ach_url_guard_require_admin');

function ach_url_guard_on_create($original, $url, $keyword = '', $title = '')
{
    $settings = Policy::settings(yourls_get_option('ach_url_guard_settings', []));
    $normalizedUrl = yourls_sanitize_url((string) $url);
    $secret = defined('ACH_URL_GUARD_WEB_RISK_KEY') ? (string) ACH_URL_GUARD_WEB_RISK_KEY : '';
    try {
        // Only custom short keywords are user-provided; YOURLS generates normal
        // aliases separately. Use the core sanitizer to count what would be saved.
        $normalizedKeyword = is_scalar($keyword) ? (string) $keyword : '';
        if ($normalizedKeyword !== '') {
            $normalizedKeyword = yourls_sanitize_keyword($normalizedKeyword, true);
        }
        $keywordPolicy = Policy::inspectKeyword($normalizedKeyword, $settings);
        if ($keywordPolicy['reason'] === 'keyword_too_long') {
            // Deterministic input limit is independent of URL safety Monitor mode.
            $result = $keywordPolicy;
        } else {
            // Deterministic local denies remain enforceable even when costly
            // validation is deferred by native-compatible work admission.
            $quick = Policy::inspect($normalizedUrl, $settings, false);
            if ($quick['status'] !== 'allow') {
                $result = $quick;
            } elseif ($keywordPolicy['status'] === 'deny') {
                $result = $keywordPolicy;
            } else {
                $result = WorkGate::evaluate($normalizedUrl, $settings, $secret,
                    static fn(): array => (new Guard())->evaluate($normalizedUrl, $settings, $secret));
            }
        }
    } catch (\Throwable $error) {
        // A plugin crash must not cause a fatal on the public shortener.
        // Never leak URL, API keys, exception messages or backend internals.
        error_log('ACh URL Guard unexpected error [' . get_class($error) . ']');
        $result = [
            'status' => $settings['unknown_action'] === 'deny' ? 'deny' : 'unknown',
            'reason' => 'guard_unavailable',
            'host' => '',
        ];
    }
    if ($result['status'] !== 'allow') {
        ach_url_guard_record_event($normalizedUrl, $result, $settings);
    }
    if (($result['reason'] ?? '') !== 'keyword_too_long' &&
        ($settings['mode'] !== 'enforce' || $result['status'] !== 'deny')) {
        // Identity return is essential: YOURLS shunts on *any* other value.
        return $original;
    }
    $messages = [
        'root_url' => 'Homepage-only URLs cannot be shortened. Please provide a page path.',
        'blocked_domain' => 'This domain is not allowed.',
        'blocked_url_term' => 'This destination contains a prohibited phrase.',
        'blocked_url_pattern' => 'This destination matches a prohibited URL rule.',
        'blocked_short_keyword' => 'This custom short keyword is reserved.',
        'keyword_too_long' => 'Custom short keyword exceeds the configured maximum of ' .
            $settings['max_custom_keyword_length'] . ' characters.',
        'regex_unavailable' => 'A URL rule could not be evaluated.',
        'work_control_unavailable' => 'Destination validation is temporarily unavailable.',
        'work_deferred' => 'Destination validation was deferred due to repeated requests.',
        'web_risk_threat' => 'This destination is flagged as unsafe.',
        'dnsbl_listed' => 'This destination is flagged by a spam list.',
        'http_not_found' => 'The requested destination was not found (HTTP 404/410).',
        'private_dns_address' => 'This destination resolves to a private or reserved address.',
        'private_address' => 'Private destinations cannot be shortened.',
        'unverifiable_destination' => 'The destination could not be verified at this time.',
        'guard_unavailable' => 'Destination verification is temporarily unavailable.',
    ];
    $reason = (string) ($result['reason'] ?? 'invalid_url');
    $isTransient = in_array($reason, ['unverifiable_destination', 'guard_unavailable', 'regex_unavailable',
        'work_control_unavailable', 'work_deferred'], true);
    $code = $reason === 'keyword_too_long' ? '400' : ($isTransient ? '503' : '403');
    return [
        'status' => 'fail',
        'code' => 'error:ach_url_guard:' . $reason,
        'message' => $messages[$reason] ?? 'This URL is invalid or prohibited by the link policy.',
        'errorCode' => $code,
        'statusCode' => $code,
    ];
}

/** Log only host/reason/hash. URL paths and credentials remain out of event logs. */
function ach_url_guard_record_event(string $url, array $result, array $settings): void
{
    $limit = (int) $settings['recent_event_count'];
    $host = (string) ($result['host'] ?? '');
    $reason = (string) ($result['reason'] ?? 'unknown');
    if ($limit === 0) {
        return;
    }
    try {
        $events = yourls_get_option('ach_url_guard_events', []);
        if (!is_array($events)) {
            $events = [];
        }
        $now = gmdate('c');
        // This shunt runs before YOURLS's native IP flood check. Repeated
        // violations must not update a serialized DB option on every hit.
        // Keep one representative event per reason/mode/second, across hosts;
        // this is a best-effort sample, not a complete audit ledger.
        $second = substr($now, 0, 19);
        foreach ($events as $previous) {
            if (!is_array($previous) || substr((string) ($previous['time'] ?? ''), 0, 19) !== $second) {
                break;
            }
            if (($previous['mode'] ?? null) === $settings['mode'] && ($previous['reason'] ?? null) === $reason) {
                return;
            }
        }
        array_unshift($events, [
            'time' => $now,
            'mode' => $settings['mode'],
            'result' => (string) ($result['status'] ?? 'unknown'),
            'reason' => $reason,
            'host' => $host,
            'url_hash' => substr(hash('sha256', $url), 0, 16),
        ]);
        yourls_update_option('ach_url_guard_events', array_slice($events, 0, $limit));
    } catch (\Throwable $error) {
        error_log('ACh URL Guard failed to record event [' . get_class($error) . ']');
    }
}

/**
 * YOURLS only calls its normal admin auth gate when YOURLS_PRIVATE=true.
 * Plugin settings and destructive history actions require a real logged-in
 * user even for public shorteners. Nonces never replace authentication.
 */
function ach_url_guard_require_admin(): void
{
    if (yourls_is_valid_user() !== true) {
        yourls_die('Admin login required to manage ACh URL Guard.', 'Access denied', 403);
        exit;
    }
    // The historical confirmation can contain query credentials. Set the
    // admin-only cache policy at the pre-render load hook, before page output.
    if (!headers_sent()) {
        header('Cache-Control: private, no-store, max-age=0', true);
    }
}

function ach_url_guard_register_page(): void
{
    yourls_register_plugin_page('ach_url_guard', 'ACh URL Guard', 'ach_url_guard_admin_page');
    yourls_register_plugin_page('ach_url_guard_history', 'ACh URL Guard — Historical Review', 'ach_url_guard_history_page');
}

function ach_url_guard_esc($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ach_url_guard_admin_page(): void
{
    ach_url_guard_require_admin();
    $settings = Policy::settings(yourls_get_option('ach_url_guard_settings', []));
    $feedback = '';
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['ach_url_guard_save'])) {
        yourls_verify_nonce('ach_url_guard_settings', isset($_POST['nonce']) && is_string($_POST['nonce']) ? $_POST['nonce'] : '');
        $raw = [];
        foreach (['mode', 'unknown_action', 'connect_timeout_seconds', 'request_timeout_seconds', 'max_redirects', 'recent_event_count', 'max_custom_keyword_length'] as $name) {
            if (isset($_POST[$name]) && is_scalar($_POST[$name])) {
                $raw[$name] = $_POST[$name];
            }
        }
        foreach (['block_root_urls', 'reachability_enabled', 'web_risk_enabled', 'dnsbl_enabled'] as $name) {
            $raw[$name] = isset($_POST[$name]) ? '1' : '0';
        }
        foreach (['blocked_domains', 'root_exceptions', 'dnsbl_zones', 'blocked_url_terms', 'blocked_url_patterns', 'blocked_short_keywords'] as $name) {
            $raw[$name] = isset($_POST[$name]) && is_string($_POST[$name]) ? $_POST[$name] : '';
        }
        $errors = [];
        foreach (['blocked_domains', 'root_exceptions', 'dnsbl_zones'] as $field) {
            $lines = preg_split('/\r\n|\r|\n/', (string) $raw[$field]);
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') {
                    continue;
                }
                $parsed = Policy::domainLines($line);
                if ($parsed === [] || ($field === 'dnsbl_zones' && substr($parsed[0], 0, 1) === '.')) {
                    $errors[] = $field . ': ' . $line;
                } elseif ($field === 'dnsbl_zones' && substr($parsed[0], 0, 2) === '*.') {
                    $errors[] = $field . ': ' . $line;
                }
            }
        }
        foreach (Policy::invalidPatterns($raw['blocked_url_patterns']) as $pattern) {
            $errors[] = 'blocked_url_patterns: ' . $pattern;
        }
        foreach (Policy::textLines($raw['blocked_short_keywords']) as $shortKeyword) {
            if (strcasecmp($shortKeyword, yourls_sanitize_keyword($shortKeyword, true)) !== 0) {
                $errors[] = 'blocked_short_keywords: ' . $shortKeyword;
            }
        }
        if (isset($raw['max_custom_keyword_length']) &&
            (filter_var($raw['max_custom_keyword_length'], FILTER_VALIDATE_INT) === false ||
                (int) $raw['max_custom_keyword_length'] < 0)) {
            $errors[] = 'max_custom_keyword_length: must be a nonnegative integer';
        }
        if ($errors !== []) {
            $feedback = 'Invalid settings, nothing saved: ' . implode('; ', $errors);
        } else {
            $settings = Policy::settings($raw);
            yourls_update_option('ach_url_guard_settings', $settings);
            $feedback = 'Settings saved.';
        }
    }

    echo '<main role="main" style="max-width:850px;margin:2em auto;">';
    echo '<h2>ACh URL Guard</h2>';
    echo '<p>Automatic rules apply to new links only; existing redirects remain unchanged unless an admin explicitly reviews and deletes an individual historical link.</p>';
    echo '<p><a href="' . ach_url_guard_esc(yourls_admin_url('plugins.php?page=ach_url_guard_history')) . '">Review existing links (manual deletion only)</a></p>';
    if ($feedback !== '') {
        echo '<p class="' . (strpos($feedback, 'Invalid') === 0 ? 'error' : 'success') . '">' . ach_url_guard_esc($feedback) . '</p>';
    }
    $hasKey = defined('ACH_URL_GUARD_WEB_RISK_KEY') && ACH_URL_GUARD_WEB_RISK_KEY !== '';
    echo '<p><strong>Google Web Risk API key:</strong> ' . ($hasKey ? 'configured' : 'not configured') . '. Never store this secret in the plugin directory or a public repository.</p>';
    if (!$hasKey && $settings['web_risk_enabled']) {
        echo '<p class="error">Web Risk was enabled without an API key. Threat checks are inconclusive.</p>';
    }
    echo '<form method="post">';
    echo '<input type="hidden" name="ach_url_guard_save" value="1" />';
    echo '<input type="hidden" name="nonce" value="' . ach_url_guard_esc(yourls_create_nonce('ach_url_guard_settings')) . '" />';
    echo '<p><label><strong>Mode:</strong> <select name="mode">';
    foreach (['monitor' => 'Monitor only (no new blocking)', 'enforce' => 'Enforce: reject definite violations'] as $value => $label) {
        echo '<option value="' . $value . '"' . ($settings['mode'] === $value ? ' selected' : '') . '>' . ach_url_guard_esc($label) . '</option>';
    }
    echo '</select></label></p>';
    echo '<p><small>Monitor reports destination safety decisions without blocking them. The custom short keyword length limit applies in both modes.</small></p>';
    echo '<p><label><strong>Maximum custom short keyword characters:</strong> ';
    echo '<input type="number" name="max_custom_keyword_length" min="0" value="' .
        ach_url_guard_esc($settings['max_custom_keyword_length']) . '" /></label>';
    echo '<br /><small>20 by default. 0 disables this limit; excludes domain, destination URL and generated aliases.</small></p>';
    foreach ([
        'block_root_urls' => 'Disallow homepage-only destinations (including /?query=...)',
        'reachability_enabled' => 'Check destination HTTP status and each redirect hop',
        'dnsbl_enabled' => 'Use configured DNS domain spam lists (only new links)',
        'web_risk_enabled' => 'Use Google Web Risk (requires API key + billing-enabled Google Cloud project)',
    ] as $name => $label) {
        echo '<p><label><input type="checkbox" name="' . $name . '" value="1"' . ($settings[$name] ? ' checked' : '') . ' /> ' . ach_url_guard_esc($label) . '</label></p>';
    }
    echo '<p><label><strong>Unknown/unverifiable destination:</strong> <select name="unknown_action">';
    foreach (['allow' => 'Allow but record (fewer false positives)', 'deny' => 'Reject until verified (strict)'] as $value => $label) {
        echo '<option value="' . $value . '"' . ($settings['unknown_action'] === $value ? ' selected' : '') . '>' . ach_url_guard_esc($label) . '</option>';
    }
    echo '</select></label></p>';
    foreach ([
        'blocked_domains' => ['Blocked domains, one per line', 'Editable starter set blocks nesting known shorteners (such as bit.ly and tinyurl.com) only in Enforce. example.com = apex; .example.com = apex and subdomains; *.example.com = subdomains only.'],
        'blocked_url_terms' => ['Blocked phrases within destination URLs', 'One literal phrase per line; ASCII case-insensitive, matches host, path and query, including percent-encoded text.'],
        'blocked_url_patterns' => ['Blocked destination URL patterns (Regex)', 'One complete PCRE regex per line, including delimiters and optional flags, e.g. ~^https?://[^/]+/offer~i. Invalid patterns are rejected on save.'],
        'blocked_short_keywords' => ['Reserved custom short keywords', 'One exact short alias per line, case-insensitive. URL safety mode controls enforcement of this list.'],
        'root_exceptions' => ['Homepage-only URL exceptions, one domain per line', 'Accept homepage-only links only for approved hosts.'],
        'dnsbl_zones' => ['DNSBL zones, one per line', 'Domain-oriented DNSBL providers require their own usage terms and functioning resolver. Empty = no DNSBL lookups.'],
    ] as $name => $spec) {
        echo '<p><label><strong>' . ach_url_guard_esc($spec[0]) . '</strong><br />';
        echo '<textarea name="' . $name . '" rows="5" style="width:min(100%,620px)">' . ach_url_guard_esc(implode("\n", $settings[$name])) . '</textarea>';
        echo '</label><br /><small>' . ach_url_guard_esc($spec[1]) . '</small></p>';
    }
    foreach ([
        'connect_timeout_seconds' => 'Connection timeout (seconds)',
        'request_timeout_seconds' => 'Total per-hop request timeout (seconds)',
        'max_redirects' => 'Maximum redirect hops',
        'recent_event_count' => 'Recent monitored/rejected events retained (0 disables)',
    ] as $name => $label) {
        echo '<p><label><strong>' . ach_url_guard_esc($label) . ':</strong> ';
        echo '<input name="' . $name . '" type="number" min="0" value="' . ach_url_guard_esc($settings[$name]) . '" /></label></p>';
    }
    echo '<p><button type="submit" class="button primary">Save settings</button></p>';
    echo '</form>';

    $events = yourls_get_option('ach_url_guard_events', []);
    if (is_array($events) && $events !== []) {
        echo '<h3>Recent sampled decisions (no full URLs or query tokens stored)</h3>';
        echo '<table class="tbl" style="width:100%"><thead><tr><th>UTC</th><th>Mode</th><th>Result</th><th>Reason</th><th>Host</th><th>URL hash</th></tr></thead><tbody>';
        foreach (array_slice($events, 0, (int) $settings['recent_event_count']) as $event) {
            echo '<tr>';
            foreach (['time', 'mode', 'result', 'reason', 'host', 'url_hash'] as $key) {
                echo '<td>' . ach_url_guard_esc($event[$key] ?? '') . '</td>';
            }
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
    echo '</main>';
}
