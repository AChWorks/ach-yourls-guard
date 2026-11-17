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
                if (($filters['reason'] ?? '') === 'http_not_found' && !isset($_POST['bulk_http_ack'])) {
                    throw new InvalidArgumentException('Confirm HTTP network scanning before starting');
                }
                $job = BulkHistory::create($db, $owner, ach_url_guard_bulk_post('bulk_mode'),
                    $filters, $selected);
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
    echo '<h3>Filtered selection job</h3>';
    echo '<p>Progress: <strong>' . ach_url_guard_esc($phase) . '</strong> — '
        . (int) $job['scanned'] . ' scanned, ' . (int) $job['matched']
        . ' exactly snapshotted candidates; ' . (int) $job['processed'] . ' processed, '
        . (int) $job['deleted'] . ' deleted, ' . (int) $job['skipped'] . ' skipped.</p>';
    echo '<p>Scope: ' . ($job['mode'] === 'all' ? 'All matching rows across all pages'
        : 'Selected keywords from the starting page') . '.</p>';
    $filters = $job['filter'];
    echo '<p>Filter: reason <code>' . ach_url_guard_esc($filters['reason'])
        . '</code>, clicks <code>' . ach_url_guard_esc($filters['clicks'])
        . '</code>, host <code>' . ach_url_guard_esc($filters['host'] ?: '(any)')
        . '</code>, prefix <code>' . ach_url_guard_esc($filters['prefix'] ?: '(any)')
        . '</code>, created on/before <code>' . ach_url_guard_esc($filters['before'] ?: '(any)')
        . '</code>.</p>';
    echo '<p><a href="' . ach_url_guard_esc(yourls_admin_url(
        'plugins.php?page=ach_url_guard_history&bulk_job=' . rawurlencode($id)
    )) . '">Bookmark this job to resume after closing the browser</a></p>';
    if (in_array($phase, ['scan', 'delete'], true)) {
        $label = $phase === 'scan' ? 'Continue scanning' : 'Continue deletion';
        echo '<p>Work proceeds in bounded batches while this browser is open.'
            . ' Closing it pauses further requests; progress is saved.</p>';
        echo '<form method="post" id="ach-bulk-step">';
        echo ach_url_guard_history_hidden('bulk_action', 'step');
        echo ach_url_guard_history_hidden('bulk_job', $id);
        echo ach_url_guard_history_hidden('bulk_nonce', yourls_create_nonce('ach_url_guard_bulk'));
        echo '<button type="submit" class="button primary">' . $label . '</button></form>';
        ach_url_guard_bulk_action_form('cancel', $id, 'Stop and keep progress');
        echo '<button type="button" id="ach-bulk-pause-browser" class="button">Pause automatic continuation</button>';
        echo '<script>(function(){var form=document.getElementById("ach-bulk-step");'
            . 'var pause=document.getElementById("ach-bulk-pause-browser");'
            . 'var t=setTimeout(function(){if(form)form.submit()},600);'
            . 'if(pause)pause.addEventListener("click",function(){clearTimeout(t);'
            . 'pause.disabled=true;pause.textContent="Automatic continuation paused";});})();</script>';
    } elseif ($phase === 'ready') {
        if ((int) $job['matched'] === 0) {
            echo '<p>No definite matching candidates were found. No links will be deleted.</p>';
        } else {
            echo '<p><strong>Dry-run complete.</strong> A current policy match is not proof'
                . ' of abuse. Your selection contains ' . (int) $job['matched']
                . ' snapshotted links. Deletion permanently breaks their redirects.'
                . ' Rows changed since scanning will be skipped, not replaced by new matches.'
                . ' Restore requires your independent site backup.</p>';
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
            echo '<p><button class="button" type="submit">Start confirmed batch deletion</button></p></form>';
        }
        ach_url_guard_bulk_action_form('cancel', $id, 'Cancel without deleting');
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
        . 'I approve outbound HTTP checks if selecting HTTP 404/410.'
        . ' This runs one checked link per request and can be costly/slow for large sets.'
        . ' DNSBL/Google Web Risk are never used.</label></p>';
    echo '<p><button type="submit" class="button primary">Preview selected/filter-matching links (no deletion)</button></p>';
    echo '</form></section>';
}
