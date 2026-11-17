<?php
declare(strict_types=1);

use ACh\Yourls\UrlGuard\HistoricalReview;
use ACh\Yourls\UrlGuard\Policy;

function ach_url_guard_history_hidden(string $name, string $value): string
{
    return '<input type="hidden" name="' . ach_url_guard_esc($name) . '" value="'
        . ach_url_guard_esc($value) . '" />';
}

function ach_url_guard_history_message(string $message, bool $success = false): void
{
    echo '<p class="' . ($success ? 'success' : 'error') . '" role="status">'
        . ach_url_guard_esc($message) . '</p>';
}

/** Human-facing reasons; preserve the machine reason for verification and logs. */
function ach_url_guard_history_reason_label(string $reason): string
{
    $labels = [
        'policy_pass' => 'No definite local violation',
        'root_url' => 'Homepage-only destination',
        'blocked_domain' => 'Blocked domain',
        'blocked_url_term' => 'Blocked URL phrase',
        'blocked_url_pattern' => 'Blocked URL Regex',
        'blocked_short_keyword' => 'Reserved short keyword',
        'invalid_url' => 'Invalid destination URL',
        'invalid_hostname' => 'Invalid hostname',
        'unsupported_scheme' => 'Unsupported URL scheme',
        'private_address' => 'Private or local address',
        'private_dns_address' => 'Domain resolved to a private address',
        'ambiguous_ip' => 'Ambiguous numeric IP',
        'url_credentials_disallowed' => 'Credentials embedded in URL',
        'invalid_redirect' => 'Invalid redirect target',
        'http_not_found' => 'HTTP 404/410 not found',
        'regex_unavailable' => 'Regex evaluation inconclusive',
        'unverifiable_destination' => 'Destination verification inconclusive',
    ];
    return $labels[$reason] ?? ucwords(str_replace('_', ' ', $reason));
}

/** Show an explicit irreversible-action confirmation, but do not delete yet. */
function ach_url_guard_history_confirmation(
    array $row,
    array $verdict,
    string $scope,
    array $settings
): void {
    echo '<section aria-label="Review link deletion" style="border:1px solid #ccc;padding:1em;margin:1em 0;">';
    echo '<h3>Review before permanent deletion</h3>';
    echo '<p>Short keyword: <strong>' . ach_url_guard_esc($row['keyword']) . '</strong></p>';
    echo '<p>Destination host: <strong>'
        . ach_url_guard_esc(HistoricalReview::hostLabel((string) $row['url'])) . '</strong></p>';
    echo '<p>Reason: <strong>' . ach_url_guard_esc(ach_url_guard_history_reason_label((string) $verdict['reason']))
        . '</strong> <small>(' . ach_url_guard_esc($verdict['reason']) . ')</small>'
        . ($scope === 'network' ? ' (verified again before deletion)' : ' (current local rule)') . '</p>';
    echo '<p>Created: ' . ach_url_guard_esc((string) $row['timestamp'])
        . '; recorded clicks: ' . (int) $row['clicks'] . '</p>';
    echo '<p><strong>Permanent action.</strong> Deletion removes this short link using YOURLS native deletion.'
        . ' Its redirect will stop working. Existing click logs follow normal YOURLS behavior.'
        . ' Only this reviewed keyword is targeted; no automatic or bulk deletion occurs.</p>';
    echo '<form method="post">';
    echo ach_url_guard_history_hidden('history_action', 'delete');
    echo ach_url_guard_history_hidden('history_keyword', (string) $row['keyword']);
    echo ach_url_guard_history_hidden('history_scope', $scope);
    echo ach_url_guard_history_hidden('history_reason', (string) $verdict['reason']);
    echo ach_url_guard_history_hidden('history_proof', HistoricalReview::proof($row, $settings));
    echo ach_url_guard_history_hidden('nonce', yourls_create_nonce('ach_url_guard_history_delete'));
    echo '<p><label><input type="checkbox" name="history_confirm" value="1" required /> '
        . 'I reviewed this exact link and authorize its permanent deletion.</label></p>';
    echo '<p><button type="submit" class="button">Delete this short link permanently</button> '
        . '<a href="' . ach_url_guard_esc(yourls_admin_url('plugins.php?page=ach_url_guard_history'))
        . '">Cancel</a></p>';
    echo '</form></section>';
}

/** Registered by YOURLS under /admin/plugins.php?page=ach_url_guard_history. */
function ach_url_guard_history_page(): void
{
    ach_url_guard_require_admin();
    $settings = Policy::settings(yourls_get_option('ach_url_guard_settings', []));
    $db = yourls_get_db('read-ach_guard_history');
    $size = HistoricalReview::pageSize($_GET['limit'] ?? 50);
    $cursor = isset($_GET['after']) && is_string($_GET['after']) ? $_GET['after'] : '';
    $lookup = isset($_GET['keyword']) && is_string($_GET['keyword']) ? trim($_GET['keyword']) : '';
    $feedback = null;
    $confirm = null;
    $page = null;
    [$bulkJob, $bulkError] = ach_url_guard_bulk_request($db);

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && isset($_POST['history_action'])) {
        $post = static function (string $key): string {
            return isset($_POST[$key]) && is_string($_POST[$key]) ? $_POST[$key] : '';
        };
        $action = $post('history_action');
        if (!in_array($action, ['review', 'probe', 'delete'], true)) {
            $feedback = 'Unrecognized review action; no links were changed.';
        } else {
            // YOURLS admin route has already authenticated the operator.
            $nonceAction = $action === 'delete' ? 'ach_url_guard_history_delete'
                : 'ach_url_guard_history_review';
            yourls_verify_nonce($nonceAction, $post('nonce'));
            $keyword = $post('history_keyword');
            if ($action === 'delete') {
                if ($post('history_confirm') !== '1') {
                    $feedback = 'Explicit confirmation is required. Nothing was deleted.';
                } else {
                    $result = HistoricalReview::delete(
                        $db, $keyword, $post('history_proof'),
                        $post('history_reason'), $post('history_scope') === 'network',
                        $settings
                    );
                    $messages = [
                        'deleted' => 'Reviewed short link was deleted through YOURLS.',
                        'stale' => 'The link or rules changed since review. No deletion occurred; review again.',
                        'no_longer_flagged' => 'The link is not definitely flagged under the current check. No deletion occurred.',
                        'invalid_request' => 'The deletion request is invalid. No deletion occurred.',
                        'error' => 'Deletion failed. No confirmed deletion; inspect the server log and retry carefully.',
                    ];
                    $feedback = $messages[$result] ?? 'Deletion was not confirmed.';
                    $feedbackSuccess = $result === 'deleted';
                }
            } else {
                $row = HistoricalReview::find($db, $keyword);
                if ($row === null) {
                    $feedback = 'That exact short keyword was not found.';
                } else {
                    $scope = $action === 'probe' ? 'network' : 'local';
                    $verdict = HistoricalReview::inspect($row, $settings, $scope === 'network');
                    if ($verdict['status'] === 'deny') {
                        $confirm = [$row, $verdict, $scope];
                    } else {
                        $feedback = $scope === 'network'
                            ? ($verdict['status'] === 'unknown'
                                ? 'HTTP check inconclusive (' . $verdict['reason']
                                    . '); deletion is not offered.'
                                : 'No definite problem found by this HTTP check; deletion is not offered.')
                            : 'Current local policies do not definitely flag this link. No deletion offered.';
                    }
                }
            }
        }
    }

    echo '<main role="main" style="max-width:1050px;margin:2em auto;">';
    echo '<h2>ACh URL Guard — Historical Link Review</h2>';
    echo '<p><a href="' . ach_url_guard_esc(yourls_admin_url('plugins.php?page=ach_url_guard'))
        . '">Guard settings</a></p>';
    echo '<p>Existing redirects are unchanged by this page. Local policy preview is read-only.'
        . ' A matched rule is <strong>not proof of malicious intent</strong>.'
        . ' Review individuals or explicitly confirm a filter-based batch; no autonomous deletion.</p>';
    echo '<p>HTTP checks are <strong>opt-in per link</strong>, can be slow and make outbound'
        . ' requests. DNSBL and Web Risk are never invoked by this review UI.'
        . ' To audit large sets with network requests, use the documented private CLI audit.</p>';
    if ($feedback !== null) {
        ach_url_guard_history_message($feedback, isset($feedbackSuccess) && $feedbackSuccess);
    }
    if ($confirm !== null) {
        ach_url_guard_history_confirmation($confirm[0], $confirm[1], $confirm[2], $settings);
    }

    if ($bulkError !== '') ach_url_guard_history_message($bulkError);
    if ($bulkJob !== null) ach_url_guard_bulk_job($bulkJob);
    ach_url_guard_bulk_filter_form();
    ach_url_guard_bulk_recent_jobs($db);

    echo '<form method="get"><input type="hidden" name="page" value="ach_url_guard_history" />';
    echo '<p><label>Find exact short keyword: <input type="text" name="keyword" value="'
        . ach_url_guard_esc($lookup) . '" /></label> ';
    echo '<button type="submit" class="button">Find</button></p></form>';
    echo '<form method="get"><input type="hidden" name="page" value="ach_url_guard_history" />';
    echo '<p><label>Rows per page: <select name="limit">';
    foreach ([25, 50, 100] as $value) {
        echo '<option value="' . $value . '"' . ($size === $value ? ' selected' : '')
            . '>' . $value . '</option>';
    }
    echo '</select></label> <button type="submit" class="button">Start review</button></p></form>';

    try {
        if ($lookup !== '') {
            $row = HistoricalReview::find($db, $lookup);
            $page = ['rows' => $row === null ? [] : [$row], 'has_more' => false, 'next_cursor' => ''];
            if ($row === null) {
                ach_url_guard_history_message('No existing link matched this exact keyword.');
            }
        } else {
            $page = HistoricalReview::page($db, $cursor, $size);
        }
    } catch (\Throwable $error) {
        error_log('ACh URL Guard history page failed [' . get_class($error) . ']');
        ach_url_guard_history_message('Could not read the review page. No links were changed.');
    }

    if ($page !== null) {
        echo '<p>Showing ' . count($page['rows']) . ' existing links in this batch.'
            . ' All rows are displayed so links without a local-policy match can be HTTP-checked individually.'
            . '</p>';
        echo '<div style="overflow-x:auto"><table class="tbl" style="width:100%;">';
        echo '<thead><tr><th><label><input type="checkbox" id="ach-history-select-all" />' . ' Select all visible</label></th><th>Short keyword</th><th>Destination host</th>'
            . '<th>Local policy result</th><th>Clicks</th><th>Action</th></tr></thead><tbody>';
        foreach ($page['rows'] as $row) {
            $verdict = HistoricalReview::inspect($row, $settings);
            $flagged = $verdict['status'] === 'deny';
            echo '<tr><td><input type="checkbox" class="ach-history-select"' . ' name="bulk_keywords[]" form="ach-bulk-create" value="' . ach_url_guard_esc((string) $row['keyword']) . '" aria-label="Select ' . ach_url_guard_esc((string) $row['keyword']) . '" />' . '</td><td><code>' . ach_url_guard_esc((string) $row['keyword']) . '</code></td>';
            echo '<td>' . ach_url_guard_esc(HistoricalReview::hostLabel((string) $row['url'])) . '</td>';
            echo '<td>' . ach_url_guard_esc(ach_url_guard_history_reason_label((string) $verdict['reason']));
            if ($flagged) {
                echo ' <strong>(review)</strong>';
            } elseif ($verdict['status'] === 'unknown') {
                echo ' <strong>(uncertain)</strong>';
            }
            echo '</td><td>' . (int) $row['clicks'] . '</td><td>';
            echo '<form method="post">';
            echo ach_url_guard_history_hidden('history_action', $flagged ? 'review' : 'probe');
            echo ach_url_guard_history_hidden('history_keyword', (string) $row['keyword']);
            echo ach_url_guard_history_hidden('nonce', yourls_create_nonce('ach_url_guard_history_review'));
            echo '<button type="submit" class="button" aria-label="'
                . ach_url_guard_esc(($flagged ? 'Review deletion for ' : 'Check HTTP for ')
                    . (string) $row['keyword']) . '">'
                . ($flagged ? 'Review deletion' : 'Check HTTP') . '</button></form></td></tr>';
        }
        echo '</tbody></table></div>';
        echo '<script>(function(){var a=document.getElementById("ach-history-select-all");'
            . 'if(a)a.addEventListener("change",function(){document.querySelectorAll(".ach-history-select")'
            . '.forEach(function(e){e.checked=a.checked;});});})();</script>';
        if ($page['has_more'] && $lookup === '') {
            echo '<p><a href="' . ach_url_guard_esc(
                yourls_admin_url('plugins.php?page=ach_url_guard_history')
                . '&limit=' . $size . '&after=' . rawurlencode($page['next_cursor'])
            ) . '">Next batch</a></p>';
        }
    }
    echo '</main>';
}
