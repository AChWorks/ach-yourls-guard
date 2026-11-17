<?php
declare(strict_types=1);

/**
 * Explicit opt-in CLI worker for already-created YOURLS bulk jobs.
 * Recommended cron: * * * * * /usr/bin/php /path/to/yourls/user/plugins/ach-url-guard/bin/bulk-worker.php --seconds=45
 *
 * No web entry point, no automatic scheduler installation, no job creation,
 * and no deletion unless an authenticated admin has separately authorized
 * that job's exact DELETE N confirmation.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

$options = getopt('', ['site:', 'seconds:', 'help']);
if (isset($options['help'])) {
    fwrite(STDOUT, "Usage: php bin/bulk-worker.php [--site=/path/to/yourls] [--seconds=45]\n");
    exit(0);
}
$site = realpath($options['site'] ?? dirname(__DIR__, 4));
if (!is_string($site) || !is_file($site . '/includes/load-yourls.php')
    || !is_file($site . '/user/config.php')
    || realpath(dirname(__DIR__)) !== realpath($site . '/user/plugins/ach-url-guard')) {
    fwrite(STDERR, "Worker cannot locate its own canonical YOURLS installation.\n");
    exit(2);
}
$seconds = filter_var($options['seconds'] ?? '45', FILTER_VALIDATE_INT);
if (!is_int($seconds) || $seconds < 1) {
    fwrite(STDERR, "--seconds must be a positive integer.\n");
    exit(2);
}

define('YOURLS_CONFIGFILE', $site . '/user/config.php');
require_once $site . '/includes/load-yourls.php';

use ACh\Yourls\UrlGuard\HistoryWorker;

if (!function_exists('yourls_is_active_plugin')
    || !yourls_is_active_plugin('ach-url-guard/plugin.php')) {
    fwrite(STDERR, "ACh URL Guard plugin is not active; no jobs were processed.\n");
    exit(2);
}

try {
    $db = yourls_get_db('write-ach_guard_bulk_worker');
    // MariaDB/MySQL advisory lock is connection-scoped, survives transactions,
    // and is automatically released on worker failure. Multiple cron invocations
    // or hosts must never process a deletion job concurrently.
    $lockName = 'ach_guard_bulk_' . substr(hash('sha256', $site), 0, 40);
    $lock = $db->fetchOne('SELECT GET_LOCK(:name, 0) AS acquired', ['name' => $lockName]);
    if (!is_array($lock) || (int) ($lock['acquired'] ?? 0) !== 1) {
        // Another scheduler invocation is already running; do not enqueue a duplicate.
        exit(0);
    }
    $workerFailed = false;
    try {
        $result = HistoryWorker::run($db, $seconds);
        if ($result['steps'] !== 0 || $result['failures'] !== 0) {
            fwrite(STDOUT, sprintf("Bulk worker: %d steps, %d job steps, %d failures\n",
                $result['steps'], $result['jobs'], $result['failures']));
        }
        $workerFailed = $result['failures'] !== 0;
    } finally {
        $db->fetchOne('SELECT RELEASE_LOCK(:name) AS released', ['name' => $lockName]);
    }
    if ($workerFailed) exit(3);
} catch (Throwable $error) {
    fwrite(STDERR, "Bulk worker unavailable [" . get_class($error) . "]. Check private server logs.\n");
    exit(3);
}
