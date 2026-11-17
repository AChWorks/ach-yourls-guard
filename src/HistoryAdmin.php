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

/** Abbreviate only the visible label; the Copy control keeps the exact value. */
function ach_url_guard_history_compact_parts(string $value, int $max = 80, bool $force = false): array
{
    $max = max(16, $max);
    if (!$force && strlen($value) <= $max) {
        return ['truncated' => false, 'head' => $value, 'tail' => ''];
    }
    $chars = preg_split('//u', $value, -1, PREG_SPLIT_NO_EMPTY);
    // Invalid legacy UTF-8 must not break the review page.
    if ($chars === false) {
        $chars = str_split($value);
    }
    $count = count($chars);
    if (($count <= $max && !$force) || $count < 3) {
        return ['truncated' => false, 'head' => $value, 'tail' => ''];
    }
    // The compact alternative is prebuilt even for medium-length values.
    // JavaScript chooses it only if the ORIGINAL rendered width exceeds its
    // actual container; no fixed character count decides visible overflow.
    $tail = min(10, max(1, (int) floor($count * 0.3)), $count - 2);
    $head = min($count - $tail - 1, max(1, $max - strlen('[...]') - $tail));
    return [
        'truncated' => true,
        'head' => implode('', array_slice($chars, 0, $head)),
        'tail' => implode('', array_slice($chars, -$tail)),
    ];
}

function ach_url_guard_history_compact(string $value, int $max = 80): string
{
    $parts = ach_url_guard_history_compact_parts($value, $max);
    return $parts['truncated'] ? $parts['head'] . '[...]' . $parts['tail'] : $value;
}

/** Keep [...] and the suffix visible even when a narrow column clips the prefix. */
function ach_url_guard_history_compact_html(string $value, int $max = 80, bool $force = false): string
{
    $parts = ach_url_guard_history_compact_parts($value, $max, $force);
    if (!$parts['truncated']) {
        return ach_url_guard_esc($value);
    }
    return '<span class="ach-history-prefix">' . ach_url_guard_esc($parts['head']) . '</span>'
        . '<span class="ach-history-marker">'
        . '<span aria-hidden="true">[...]</span>'
        . '<span class="ach-history-sr-only">middle omitted</span></span>'
        . '<span class="ach-history-suffix">' . ach_url_guard_esc($parts['tail']) . '</span>';
}

/**
 * Always retain a measurable exact-value span. The alternate compact label is
 * exposed only when the original text is wider than the available CSS box.
 * The input value stays inert and is never fetched or used as a link.
 */
function ach_url_guard_history_code(string $value, int $max = 80): string
{
    $truncated = ach_url_guard_history_compact_parts($value, $max)['truncated'];
    $class = 'ach-history-one-line' . ($truncated ? ' ach-history-abbreviated' : '');
    return '<code class="' . $class . '" dir="ltr" title="' . ach_url_guard_esc($value) . '">'
        . '<span class="ach-history-original" aria-hidden="' . ($truncated ? 'true' : 'false') . '">'
        . ach_url_guard_esc($value) . '</span>'
        . '<span class="ach-history-compact" aria-hidden="' . ($truncated ? 'false' : 'true') . '">'
        . ach_url_guard_history_compact_html($value, $max, true)
        . '</span></code>';
}

/**
 * Recalculate when the actual code box or font metrics change. In contrast to
 * a fixed PHP length limit, this catches a 70-character or Unicode URL that
 * fits desktop but overflows a narrow mobile viewport.
 */
function ach_url_guard_history_responsive_script(): void
{
    echo <<<'HTML'
<script>
(function () {
    var codes = Array.prototype.slice.call(document.querySelectorAll('.ach-history-one-line'));
    if (!codes.length) return;
    var segmenter = typeof Intl !== 'undefined' && Intl.Segmenter
        ? new Intl.Segmenter(undefined, {granularity: 'grapheme'}) : null;
    function characters(value) {
        // Preserve emoji sequences and combining marks when available.
        return segmenter ? Array.from(segmenter.segment(value), function (item) {
            return item.segment;
        }) : Array.from(value);
    }
    function update(code) {
        var original = code.querySelector('.ach-history-original');
        var compact = code.querySelector('.ach-history-compact');
        if (!original || !compact) return;
        var overflow = original.getBoundingClientRect().width > code.clientWidth + 1;
        code.classList.toggle('ach-history-abbreviated', overflow);
        original.setAttribute('aria-hidden', overflow ? 'true' : 'false');
        compact.setAttribute('aria-hidden', overflow ? 'false' : 'true');
        if (!overflow) return;

        var prefix = compact.querySelector('.ach-history-prefix');
        var suffix = compact.querySelector('.ach-history-suffix');
        var marker = compact.querySelector('.ach-history-marker');
        if (!prefix || !suffix || !marker) return;

        var parts = characters(original.textContent);
        if (parts.length < 3) return;
        var measure = document.createElement('span');
        measure.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;width:max-content';
        measure.setAttribute('aria-hidden', 'true');
        code.appendChild(measure);

        // Reserve space for a real visible first grapheme and the [...] marker.
        measure.textContent = parts[0];
        var prefixWidth = measure.getBoundingClientRect().width;
        var budget = Math.max(0, code.clientWidth
            - marker.getBoundingClientRect().width - prefixWidth - 1);
        var tailCount = Math.min(10, parts.length - 2);
        do {
            measure.textContent = parts.slice(-tailCount).join('');
            if (measure.getBoundingClientRect().width <= budget || tailCount === 1) break;
            tailCount--;
        } while (tailCount > 1);
        measure.remove();

        prefix.textContent = parts.slice(0, parts.length - tailCount - 1).join('');
        suffix.textContent = parts.slice(-tailCount).join('');
    }
    var observer = typeof ResizeObserver === 'function'
        ? new ResizeObserver(function (entries) {
            entries.forEach(function (entry) {
                var code = entry.target.classList.contains('ach-history-original')
                    ? entry.target.parentElement : entry.target;
                update(code);
            });
        }) : null;
    codes.forEach(function (code) {
        update(code);
        if (observer) {
            observer.observe(code);
            observer.observe(code.querySelector('.ach-history-original'));
        }
    });
    if (!observer) {
        window.addEventListener('resize', function () {
            codes.forEach(update);
        });
    }
    if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(function () { codes.forEach(update); });
    }
})();
</script>
HTML;
}

/**
 * A full URL is intentionally available only after the exact authenticated
 * individual review. Keep the value inert: no anchor, fetch, navigation or log.
 */
function ach_url_guard_history_url_field(string $label, string $value): void
{
    echo '<div class="ach-history-url-field">';
    echo '<strong>' . ach_url_guard_esc($label) . '</strong>';
    echo ach_url_guard_history_code($value);
    echo '<button type="button" class="button ach-history-copy" data-copy-url="'
        . ach_url_guard_esc($value) . '" aria-label="Copy ' . ach_url_guard_esc($label)
        . '">Copy</button></div>';
}

function ach_url_guard_history_copy_script(): void
{
    echo <<<'HTML'
<script>
(function () {
    var status = document.getElementById('ach-history-copy-status');
    function legacyCopy(value) {
        var field = document.createElement('textarea');
        field.value = value;
        field.readOnly = true;
        field.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
        document.body.appendChild(field);
        var previousFocus = document.activeElement;
        field.focus();
        field.select();
        var success = false;
        try { success = document.execCommand('copy'); }
        catch (e) { success = false; }
        field.remove();
        if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus();
        return success;
    }
    document.querySelectorAll('.ach-history-copy').forEach(function (button) {
        button.addEventListener('click', function () {
            var value = button.getAttribute('data-copy-url');
            var label = button.getAttribute('aria-label').replace(/^Copy /, '');
            function report(success) {
                if (status) status.textContent = success
                    ? label + ' copied.'
                    : 'Copy unavailable. Inspect this link in YOURLS link management.';
            }
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(value).then(
                    function () { report(true); },
                    function () { report(legacyCopy(value)); }
                );
            } else {
                report(legacyCopy(value));
            }
        });
    });
})();
</script>
HTML;
}

/** Show an explicit irreversible-action confirmation, but do not delete yet. */
function ach_url_guard_history_confirmation(
    array $row,
    array $verdict,
    string $scope,
    array $settings
): void {
    echo '<section class="ach-history-confirm" aria-label="Review link deletion">';
    echo '<h3>Review before permanent deletion</h3>';
    echo '<p>Short keyword: ' . ach_url_guard_history_code((string) $row['keyword'], 66) . '</p>';
    ach_url_guard_history_url_field('Full short URL', yourls_link((string) $row['keyword']));
    ach_url_guard_history_url_field('Full destination URL', (string) $row['url']);
    echo '<p id="ach-history-copy-status" role="status" aria-live="polite"></p>';
    echo '<p><small>Full URLs are shown only for this individually reviewed link.'
        . ' Destination URLs may contain private query tokens. Copy to inspect;'
        . ' neither address is opened by this page.</small></p>';
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
    ach_url_guard_history_copy_script();
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
    echo <<<'HTML'
<style>
.ach-history-confirm { box-sizing:border-box;max-width:100%;overflow:hidden;border:1px solid #ccc;padding:1em;margin:1em 0; }
.ach-history-url-field { display:grid;grid-template-columns:9rem minmax(0,1fr) auto;align-items:center;gap:.5em 1em;margin:.6em 0;min-width:0; }
.ach-history-one-line { position:relative;display:inline-flex;box-sizing:border-box;width:100%;max-width:100%;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle;unicode-bidi:isolate; }
.ach-history-original { flex:0 0 auto;white-space:nowrap; }
.ach-history-compact { display:none;min-width:0;width:100%; }
.ach-history-abbreviated .ach-history-original { position:absolute;visibility:hidden;width:max-content;max-width:none; }
.ach-history-abbreviated .ach-history-compact { display:inline-flex; }
.ach-history-prefix { flex:1 1 auto;min-width:0;overflow:hidden;white-space:nowrap; }
.ach-history-marker,.ach-history-suffix { flex:0 0 auto;white-space:nowrap; }
.ach-history-sr-only { position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap; }
.ach-history-copy { white-space:nowrap; }
.ach-history-table { width:100%;min-width:760px;table-layout:fixed; }
.ach-history-table th,.ach-history-table td { vertical-align:top; }
.ach-history-keyword { min-width:0;overflow:hidden; }
@media (max-width:650px) {
    .ach-history-url-field { grid-template-columns:minmax(0,1fr) auto; }
    .ach-history-url-field strong { grid-column:1 / -1; }
}
</style>
HTML;

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
    if ($bulkJob !== null) {
        echo '<div id="ach-bulk-live">';
        ach_url_guard_bulk_job($bulkJob);
        echo '</div><p role="status" id="ach-bulk-poll-message"></p>';
        if (in_array($bulkJob['phase'], ['scan', 'delete'], true)) {
            ach_url_guard_bulk_poll_script((string) $bulkJob['id']);
        }
    }
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
        echo '<div style="overflow-x:auto;max-width:100%"><table class="tbl ach-history-table">';
        echo '<colgroup><col style="width:8%"><col style="width:36%"><col style="width:17%">'
            . '<col style="width:23%"><col style="width:6%"><col style="width:10%"></colgroup>';
        echo '<thead><tr><th><label><input type="checkbox" id="ach-history-select-all" />' . ' Select all visible</label></th><th>Short keyword</th><th>Destination host</th>'
            . '<th>Local policy result</th><th>Clicks</th><th>Action</th></tr></thead><tbody>';
        foreach ($page['rows'] as $row) {
            $verdict = HistoricalReview::inspect($row, $settings);
            $flagged = $verdict['status'] === 'deny';
            echo '<tr><td><input type="checkbox" class="ach-history-select"' . ' name="bulk_keywords[]" form="ach-bulk-create" value="' . ach_url_guard_esc((string) $row['keyword']) . '" aria-label="Select ' . ach_url_guard_esc((string) $row['keyword']) . '" />'
                . '</td><td class="ach-history-keyword">'
                . ach_url_guard_history_code((string) $row['keyword'], 46) . '</td>';
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
    ach_url_guard_history_responsive_script();
    echo '</main>';
}
