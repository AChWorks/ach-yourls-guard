<?php
declare(strict_types=1);

// Test-only, read-only advisory-lock holder. Never accepts a production DB.
$dbName = (string) getenv('ACH_IT_DB_NAME');
$socket = (string) getenv('ACH_IT_DB_SOCKET');
$site = (string) getenv('ACH_IT_SITE');
$ready = $argv[1] ?? '';
if (!preg_match('/^ach_guard_it_[0-9a-f]{8}$/D', $dbName)
    || !is_file($site . '/user/plugins/ach-url-guard/src/HistoryWorker.php')
    || !is_string($ready) || !str_starts_with($ready, (string) getenv('TMPDIR') . '/')) {
    exit(2);
}
require_once $site . '/user/plugins/ach-url-guard/src/HistoryWorker.php';
$dsn = $socket !== '' ? 'mysql:unix_socket=' . $socket . ';charset=utf8mb4'
    : 'mysql:host=127.0.0.1;port=' . (int) getenv('ACH_IT_DB_PORT') . ';charset=utf8mb4';
$pdo = new PDO($dsn, (string) getenv('ACH_IT_DB_USER'), (string) getenv('ACH_IT_DB_PASS'),
    [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT=>3]);
$name = \ACh\Yourls\UrlGuard\HistoryWorker::lockName($dbName, 'yourls_');
$statement = $pdo->prepare('SELECT GET_LOCK(:lock, 0)');
$statement->execute(['lock'=>$name]);
if ((int) $statement->fetchColumn() !== 1) exit(3);
file_put_contents($ready, 'locked');
try {
    sleep(12); // Test harness terminates earlier and verifies release-on-disconnect.
} finally {
    $statement = $pdo->prepare('SELECT RELEASE_LOCK(:lock)');
    $statement->execute(['lock'=>$name]);
}
