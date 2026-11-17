<?php
declare(strict_types=1);

/**
 * Synthetic, disposable visual fixture using actual HistoricalReview PHP
 * renderers and styles. CLI only; never uses Production or network.
 *
 *   php -d log_errors=0 tests/history-layout-fixture.php > /tmp/guard-layout.html
 */
if (PHP_SAPI !== 'cli') {
    exit(1);
}
ob_start();
require __DIR__ . '/history-review.php';
ob_end_clean();
if (!preg_match('~<style>.*?</style>~s', $html, $styles)) {
    throw new RuntimeException('Expected actual HistoryAdmin CSS from test renderer.');
}

$cases = [
    'short' => 'https://example.test/ok',
    'medium' => 'https://example.test/' . str_repeat('abcde', 10),
    'unicode' => 'https://example.test/' . str_repeat('📄路径🙂', 10),
    'graphemes' => 'https://example.test/' . str_repeat('👩‍💻é', 12),
    'very-long' => 'https://example.test/' . str_repeat('longpath/', 80) . '?token=SYNTHETIC&ending=ORIGINAL-END',
    'brackets' => 'https://example.test/[...]middle/' . str_repeat('part', 20) . '?end=FINAL',
    'markup' => 'https://example.test/?payload="><img src=x onerror=alert(1)>&token=TEST',
];

echo '<!doctype html><html lang="en"><meta charset="utf-8">'
    . '<meta name="viewport" content="width=device-width,initial-scale=1">'
    . '<title>ACh URL Guard visual fixture (synthetic data)</title>'
    . '<main style="max-width:1050px;margin:2em auto">';
echo $styles[0];
echo '<p id="ach-history-copy-status" role="status" aria-live="polite"></p>';
foreach ($cases as $name => $destination) {
    echo '<section class="ach-history-confirm" data-case="' . ach_url_guard_esc($name) . '">'
        . '<h3>' . ach_url_guard_esc($name) . '</h3>';
    ach_url_guard_history_url_field('Full destination URL', $destination);
    echo '</section>';
}

echo '<div data-case="table-medium" style="overflow-x:auto;max-width:100%">'
    . '<table class="tbl ach-history-table">'
    . '<colgroup><col style="width:8%"><col style="width:36%"><col style="width:17%">'
    . '<col style="width:23%"><col style="width:6%"><col style="width:10%"></colgroup>'
    . '<tbody><tr><td></td><td class="ach-history-keyword">'
    . ach_url_guard_history_code('medium-' . str_repeat('xy', 38), 46)
    . '</td><td>example.test</td><td>review</td><td>0</td><td>Review</td>'
    . '</tr></tbody></table></div>';
ach_url_guard_history_copy_script();
ach_url_guard_history_responsive_script();
echo '</main></html>';
