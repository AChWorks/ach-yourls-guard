<?php
declare(strict_types=1);

use ACh\Yourls\UrlGuard\BulkHistory;
use ACh\Yourls\UrlGuard\HistoricalReview;

function ach_url_guard_bulk_post(string $key): string
{
    return isset($_POST[$key]) && is_string($_POST[$key]) ? $_POST[$key] : '';
}

/** Handle authenticated POSTs only; never mutate the URL table on GET. */
function ach_url_guard_bulk_request($db): array
{
    $job = null;
    $error = '';
    try {
        $owner = BulkHistory::actor();
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && isset($_POST['bulk_action'])) {
            $action = ach_url_guard_bulk_post('bulk_action');
            yourls_verify_nonce('ach_url_guard_bulk', ach_url_guard_bulk_post('bulk_nonce'));
            if ($action === 'create') {
                $selected = $_POST['bulk_keywords'] ?? [];
                if (!is_array($selected)) throw new InvalidArgumentException('Invalid page selection');
                $filters = $_POST['bulk_filter'] ?? [];
                if (!is_array($filters)) throw new InvalidArgumentException('Invalid filters');
                $filter = BulkHistory::filter($filters);
                if (BulkHistory::networkMode($filter)
                    && ach_url_guard_bulk_post('bulk_http_ack') !== '1') {
                    throw new InvalidArgumentException('Confirm HTTP/DNS network scanning before starting');
                }
                $job = BulkHistory::create($db, $owner, ach_url_guard_bulk_post('bulk_mode'),
                    $filter, $selected);
            } else {
                $id = ach_url_guard_bulk_post('bulk_job');
                if ($action === 'step') {
                    $current = BulkHistory::load($db, $id, $owner);
                    if ($current === null) throw new RuntimeException('Review job not found');
                    $job = match ($current['phase']) {
                        'scan' => BulkHistory::scanStep($db, $id, $owner),
                        'delete' => BulkHistory::deleteStep($db, $id, $owner),
                        default => $current,
                    };
                } elseif ($action === 'approve') {
                    $job = BulkHistory::startDeletion($db, $id, $owner,
                        ach_url_guard_bulk_post('bulk_confirm_text'),
                        ach_url_guard_bulk_post('bulk_confirm') === '1');
                } elseif ($action === 'retry') {
                    $job = BulkHistory::retry($db, $id, $owner);
                } elseif ($action === 'cancel') {
                    $job = BulkHistory::cancel($db, $id, $owner);
                } elseif ($action === 'clear') {
                    BulkHistory::clear($db, $id, $owner);
                } else {
                    throw new InvalidArgumentException('Unrecognized bulk action');
                }
            }
        } elseif (isset($_GET['bulk_job']) && is_string($_GET['bulk_job'])) {
            $job = BulkHistory::load($db, $_GET['bulk_job'], $owner);
            if ($job === null) $error = 'No accessible job with this ID.';
        }
    } catch (Throwable $e) {
        error_log('ACh URL Guard bulk operation failed [' . get_class($e) . ']');
        $error = $e instanceof InvalidArgumentException ? $e->getMessage()
            : 'Could not complete the requested operation. The server log has the error class.';
    }
    return [$job, $error];
}

function ach_url_guard_bulk_action_form(string $action, string $id, string $text): void
{
    echo '<form method="post" style="display:inline-block;margin:.25em .5em .25em 0;">';
    echo ach_url_guard_history_hidden('bulk_action', $action);
    echo ach_url_guard_history_hidden('bulk_job', $id);
    echo ach_url_guard_history_hidden('bulk_nonce', yourls_create_nonce('ach_url_guard_bulk'));
    echo '<button type="submit" class="button">' . ach_url_guard_esc($text) . '</button></form>';
}

function ach_url_guard_bulk_job(array $job): void
{
    $phase = (string) $job['phase'];
    $id = (string) $job['id'];
    echo '<section aria-label="Historical bulk review progress" style="border:1px solid #ccc;padding:1em;margin:1em 0;">';
    echo '<h3>Bulk review job</h3>';
    $states = [
        'scan' => 'Scanning — read-only preview',
        'ready' => 'Ready — preview complete',
        'delete' => 'Deleting — explicitly confirmed batch',
        'done' => 'Completed',
        'error' => 'Worker error — manual retry required',
        'paused' => 'Stopped — policy changed',
        'cancelled' => 'Cancelled',
    ];
    echo '<p><strong>Status: ' . ach_url_guard_esc($states[$phase] ?? $phase) . '</strong></p>';
    echo '<p><strong>' . (int) $job['scanned'] . '</strong> links scanned; '
        . '<strong>' . (int) $job['matched'] . '</strong> snapshot matches; '
        . '<strong>' . (int) $job['processed'] . '</strong> processed; '
        . '<strong>' . (int) $job['deleted'] . '</strong> deleted; '
        . '<strong>' . (int) $job['skipped'] . '</strong> skipped.</p>';
    echo '<p>Scope: ' . ($job['mode'] === 'all' ? 'All matching rows across all pages'
        : 'Selected keywords from the starting page') . '.</p>';
    $filters = $job['filter'];
    echo '<p>Filter: reason <code>' . ach_url_guard_esc($filters['reason'])
        . '</code>, clicks <code>' . ach_url_guard_esc($filters['clicks'])
        . '</code>, host <code>' . ach_url_guard_esc($filters['host'] ?: '(any)')
        . '</code>, prefix <code>' . ach_url_guard_esc($filters['prefix'] ?: '(any)')
        . '</code>, created on/before <code>' . ach_url_guard_esc($filters['before'] ?: '(any)')
        . '</code>.</p>';
    $bookmark = yourls_admin_url('plugins.php?page=ach_url_guard_history&bulk_job=' . rawurlencode($id));
    echo '<p><a href="' . ach_url_guard_esc($bookmark)
        . '">Bookmark / reopen this job at any time</a></p>';
    if (in_array($phase, ['scan', 'delete'], true)) {
        $last = strtotime((string) ($job['updated_at'] ?? '')) ?: 0;
        echo '<p>Work is performed by the server background worker, not this browser.'
            . ' You can navigate away and return using the bookmarked link.'
            . ' This page updates progress in place, without full-page refresh.</p>';
        if ($phase === 'scan') {
            echo '<p><strong>No short links are deleted during scanning.</strong>'
                . ' The destructive confirmation becomes available only after all rows have been previewed.</p>';
        } else {
            echo '<p>Previously confirmed deletion is in progress. Cancel stops subsequent batches,'
                . ' but cannot restore links already deleted.</p>';
            if (empty($job['updated_at'])) {
                echo '<p role="status"><strong>Legacy delete-phase job:</strong> This approval'
                    . ' predates the background worker. Enabling the scheduler will resume'
                    . ' already-confirmed deletion. Cancel this job first if it should not resume.</p>';
            }
        }
        if ($last === 0 || time() - $last > 120) {
            echo '<p role="status" class="error"><strong>Worker not recently active.</strong>'
                . ' Have the site operator verify the scheduled CLI worker.'
                . ' The saved job can be resumed without restarting its scan.</p>';
        } else {
            echo '<p role="status">Last saved progress: ' . ach_url_guard_esc(gmdate('Y-m-d H:i:s', $last))
                . ' UTC. Waiting for the next scheduled worker run.</p>';
        }
        $label = $phase === 'scan' ? 'Run one scan batch manually' : 'Run one deletion batch manually';
        ach_url_guard_bulk_action_form('step', $id, $label);
        ach_url_guard_bulk_action_form('cancel', $id, 'Cancel job (completed deletions remain)');
    } elseif ($phase === 'ready') {
        echo '<p><strong>Dry-run complete.</strong>'
            . ' No links were removed by the preview.'
            . ' A definite match is not proof that a destination is malicious.</p>';
        if ((int) $job['matched'] === 0) {
            echo '<p>No definite matching candidates were found. No links will be deleted.</p>';
        } else {
            echo '<p>There are <strong>' . (int) $job['matched']
                . '</strong> exact snapshotted candidates. Permanent deletion breaks those short links.'
                . ' Rows changed since scanning will be skipped, not replaced by new matches.'
                . ' Before proceeding, verify a recoverable full-site/database backup.'
                . ' This action has <strong>no undo</strong>.</p>';
            echo '<form method="post">';
            echo ach_url_guard_history_hidden('bulk_action', 'approve');
            echo ach_url_guard_history_hidden('bulk_job', $id);
            echo ach_url_guard_history_hidden('bulk_nonce', yourls_create_nonce('ach_url_guard_bulk'));
            echo '<p><label>Type <code>DELETE ' . (int) $job['matched']
                . '</code> to authorize this exact candidate set: '
                . '<input name="bulk_confirm_text" type="text" autocomplete="off" required /></label></p>';
            echo '<p><label><input name="bulk_confirm" type="checkbox" value="1" required /> '
                . 'I authorize permanent deletion of every still-valid candidate matching this filter,'
                . ' without individual manual review.</label></p>';
            echo '<p><button class="button" type="submit">Start confirmed background deletion</button></p></form>';
        }
        ach_url_guard_bulk_action_form('cancel', $id, 'Cancel without deleting');
    } elseif ($phase === 'error') {
        $info = is_array($job['error_info'] ?? null) ? $job['error_info'] : [];
        echo '<p>Failed stage: <code>' . ach_url_guard_esc((string) ($info['stage'] ?? 'job_step'))
            . '</code>; UTC: <code>' . ach_url_guard_esc((string) ($info['occurred_at'] ?? 'unknown'))
            . '</code>; code: <code>' . ach_url_guard_esc((string) ($info['code'] ?? 'unknown'))
            . '</code>; log reference: <code>' . ach_url_guard_esc((string) ($info['ref'] ?? 'unavailable'))
            . '</code>.</p>';
        echo '<p role="alert">The server worker stopped after an error ('
            . ach_url_guard_esc($job['error_class'] ?? 'unavailable')
            . '). No background processing will continue until an admin retries.'
            . ' Inspect the server log before retrying; the saved cursor remains intact.</p>';
        ach_url_guard_bulk_action_form('retry', $id, 'Retry background processing');
        ach_url_guard_bulk_action_form('cancel', $id, 'Cancel job');
    } elseif ($phase === 'paused') {
        echo '<p>Stopped: the Guard policy changed during scanning or deletion.'
            . ' Start a new dry-run with the latest rules. Already deleted links are not restored.</p>';
    } elseif ($phase === 'done') {
        echo '<p>Completed. ' . (int) $job['deleted'] . ' deleted and '
            . (int) $job['skipped'] . ' skipped. Unrelated links were not in the candidate set.</p>';
    } elseif ($phase === 'cancelled') {
        echo '<p>Cancelled. No further deletion will be initiated from this job.'
            . ' Any already completed deletions cannot be undone by cancellation.</p>';
    }
    if (in_array($phase, ['done', 'cancelled', 'paused'], true)) {
        ach_url_guard_bulk_action_form('clear', $id, 'Clear this job report (not short links)');
    }
    echo '</section>';
}

/**
 * YOURLS native admin-ajax.php handles cookie authentication in private mode.
 * Guard repeats its own login gate for public-mode YOURLS installations.
 * This endpoint is read-only, never steps a job, and never exposes URLs.
 */
function ach_url_guard_bulk_ajax_status(): void
{
    ach_url_guard_require_admin();
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        http_response_code(405);
        echo json_encode(['ok' => false, 'error' => 'GET required']);
        return;
    }
    $id = $_GET['job'] ?? '';
    if (!is_string($id) || !preg_match('/^[0-9a-f]{24}$/D', $id)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid job identifier']);
        return;
    }
    try {
        $db = yourls_get_db('read-ach_guard_bulk_ajax');
        $job = BulkHistory::load($db, $id, BulkHistory::actor());
        if ($job === null) {
            http_response_code(404);
            echo json_encode(['ok' => false, 'error' => 'No accessible job']);
            return;
        }
        ob_start();
        ach_url_guard_bulk_job($job);
        $html = ob_get_clean();
        echo json_encode([
            'ok' => true, 'id' => $id, 'phase' => $job['phase'],
            'updated' => (string) ($job['updated_at'] ?? ''),
            'stale' => (strtotime((string) ($job['updated_at'] ?? '')) ?: 0) < time() - 120,
            'scanned' => (int) $job['scanned'], 'matched' => (int) $job['matched'],
            'processed' => (int) $job['processed'], 'deleted' => (int) $job['deleted'],
            'skipped' => (int) $job['skipped'], 'html' => $html,
        ], JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Throwable $error) {
        error_log('ACh URL Guard bulk progress failed [' . get_class($error) . ']');
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' => 'Progress temporarily unavailable']);
    }
}

/** Render progress without reloading. If controls have keyboard focus,
 * preserve the focused DOM and display a terminal result in a sibling card;
 * never make the ready/error/done state invisible due to deferred replacement.
 */
function ach_url_guard_bulk_poll_script(string $id): void
{
    $endpoint = yourls_admin_url('admin-ajax.php?action=ach_guard_bulk_status&job='
        . rawurlencode($id));
    echo '<script>(function () { const endpoint = '
        . json_encode($endpoint, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_QUOT | JSON_HEX_APOS)
        . ';' . "\n";
    echo <<<'SCRIPT'
    const box = document.getElementById("ach-bulk-live");
    const pending = document.getElementById("ach-bulk-pending");
    const message = document.getElementById("ach-bulk-poll-message");
    if (!box || !pending) return;
    let rendered = "", deferred = null, stopped = false, failures = 0;
    const terminal = phase => !["scan", "delete"].includes(phase);
    const containsFocus = element => element.contains(document.activeElement);
    const announce = text => { if (message) message.textContent = text; };

    function afterFocusLeaves() {
        setTimeout(() => {
            if (containsFocus(box)) return;
            if (!pending.hidden) {
                // The new terminal card is already visible. Never replace it:
                // it may contain a filled DELETE N form or focused controls.
                box.hidden = true;
            } else if (deferred !== null) {
                box.innerHTML = deferred.html;
                rendered = deferred.signature;
                deferred = null;
            }
        }, 0);
    }
    box.addEventListener("focusout", afterFocusLeaves);

    function draw(data) {
        const signature = [data.phase, data.updated, data.stale,
            data.scanned, data.matched, data.processed, data.deleted,
            data.skipped].join("|");
        if (signature === rendered) return;
        const isTerminal = terminal(data.phase);
        if (containsFocus(box)) {
            if (isTerminal) {
                // A focused old control must not block delivery of READY,
                // ERROR, PAUSED or DONE. Display the complete new state now.
                pending.innerHTML = data.html;
                pending.hidden = false;
                deferred = null;
                announce("Job status changed to " + data.phase
                    + ". Updated controls are visible below.");
            } else {
                // Keep the focused control stable and update read-only counts.
                deferred = {html: data.html, signature};
                announce(data.phase + ": " + data.scanned + " scanned, "
                    + data.matched + " matched, " + data.deleted + " deleted.");
            }
        } else if (pending.hidden) {
            box.innerHTML = data.html;
            rendered = signature;
            deferred = null;
            announce("");
        }
    }

    function again(delay = 3000) {
        if (!stopped) setTimeout(poll, delay);
    }
    async function poll() {
        if (stopped) return;
        try {
            const response = await fetch(endpoint, {
                credentials: "same-origin", cache: "no-store",
                headers: {"Accept": "application/json"}
            });
            const contentType = response.headers.get("content-type") || "";
            if ([401, 403].includes(response.status) || response.redirected
                || (response.ok && !contentType.includes("json"))) {
                stopped = true;
                announce("Login expired. Sign in to YOURLS and reopen the saved job.");
                return;
            }
            if (response.status === 404) {
                stopped = true;
                announce("This job is no longer accessible. Open Recent saved jobs.");
                return;
            }
            if (!response.ok) throw new Error("status " + response.status);
            const data = await response.json();
            if (!data.ok || typeof data.html !== "string") throw new Error("invalid status");
            failures = 0;
            draw(data);
            if (!terminal(data.phase)) again();
        } catch (_) {
            failures++;
            announce("Live progress is unavailable; reconnecting automatically. "
                + "The server job remains saved.");
            again(Math.min(30000, 3000 * Math.pow(2, Math.min(failures, 4))));
        }
    }
    poll();
})();
</script>
SCRIPT;
}

function ach_url_guard_bulk_recent_jobs($db): void
{
    try {
        $jobs = BulkHistory::recentJobs($db, BulkHistory::actor());
        if ($jobs === []) return;
        echo '<section aria-label="Resume prior bulk review jobs"><h3>Recent saved jobs</h3><ul>';
        foreach ($jobs as $job) {
            $url = yourls_admin_url('plugins.php?page=ach_url_guard_history&bulk_job='
                . rawurlencode($job['id']));
            echo '<li><a href="' . ach_url_guard_esc($url) . '">'
                . ach_url_guard_esc($job['phase']) . ' — '
                . (int) $job['matched'] . ' matched, ' . (int) $job['deleted']
                . ' deleted</a></li>';
        }
        echo '</ul></section>';
    } catch (Throwable $error) {
        error_log('ACh URL Guard recent job list failed [' . get_class($error) . ']');
    }
}

/** Form fields are associated with table-row checkboxes using form= attribute. */
function ach_url_guard_bulk_filter_form(): void
{
    echo '<section aria-label="Select historical links for bulk review">';
    echo '<h3>Filter and select existing links</h3>';
    echo '<p>Opening this page is read-only. Dry-run scans can store the exact candidate'
        . ' fingerprints in a private database table, without deleting URLs or storing query tokens.'
        . ' A separate approval is required before any deletion.</p>';
    echo '<form method="post" id="ach-bulk-create">';
    echo ach_url_guard_history_hidden('bulk_action', 'create');
    echo ach_url_guard_history_hidden('bulk_nonce', yourls_create_nonce('ach_url_guard_bulk'));
    echo '<p><label><input type="radio" name="bulk_mode" value="page" checked /> '
        . 'Only checked rows on this page</label> ';
    echo '<label><input type="radio" name="bulk_mode" value="all" /> '
        . '<strong>Select All Matching Filters across every page</strong></label></p>';
    echo '<p><label>Definite reason: <select name="bulk_filter[reason]">';
    echo '<option value="any">All definite local policy violations</option>';
    foreach (HistoricalReview::definiteReasons() as $reason) {
        echo '<option value="' . ach_url_guard_esc($reason) . '">'
            . ach_url_guard_esc(ach_url_guard_history_reason_label($reason)) . '</option>';
    }
    echo '</select></label> <label>Clicks: <select name="bulk_filter[clicks]">'
        . '<option value="any">Any</option><option value="zero">Zero</option>'
        . '<option value="positive">At least one</option></select></label></p>';
    echo '<p><label>Destination host (exact): <input type="text" name="bulk_filter[host]" /></label> '
        . '<label>Keyword prefix: <input type="text" name="bulk_filter[prefix]" /></label> '
        . '<label>Created on or before: <input type="date" name="bulk_filter[before]" /></label></p>';
    echo '<p><label><input type="checkbox" name="bulk_http_ack" value="1" /> '
        . 'For network filters only: I approve outbound HTTP/DNS checks when selecting HTTP 404/410,'
        . ' Private DNS address, or Invalid redirect.'
        . ' This runs one checked link per request and can be costly/slow for large sets.'
        . ' DNSBL/Google Web Risk are never used. This is not deletion approval.</label></p>';
    echo '<p><button type="submit" class="button primary">Preview selected/filter-matching links (no deletion)</button></p>';
    echo '</form></section>';
}
