<?php
declare(strict_types=1);

/**
 * Synthetic, in-memory-only HTML for Playwright Chromium acceptance.
 * It uses the real production poll-script renderer, never a live YOURLS site.
 */
function yourls_admin_url(string $path): string
{
    return 'https://guard-bulk.test/admin/' . $path;
}

require dirname(__DIR__) . '/src/HistoryBulkAdmin.php';
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Guard bulk progress focus regression</title></head>
<body>
<div id="ach-bulk-live">
  <section><h3>Scanning — read-only preview</h3>
    <button type="button" id="focus-action">Focused action</button>
  </section>
</div>
<div id="ach-bulk-pending" hidden></div>
<p id="ach-bulk-poll-message" role="status" aria-live="polite"></p>
<?php ach_url_guard_bulk_poll_script(str_repeat('a',24)); ?>
</body></html>
