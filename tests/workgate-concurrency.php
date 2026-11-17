<?php
declare(strict_types=1);

/**
 * Deterministic overlapping expensive checks, with no network or database.
 * Fibers pause within the expensive callback while WorkGate's file locks are
 * released. No sleeps or scheduler timing assumptions are required.
 */
require dirname(__DIR__) . '/src/Policy.php';
require dirname(__DIR__) . '/src/WorkGate.php';

use ACh\Yourls\UrlGuard\Policy;
use ACh\Yourls\UrlGuard\WorkGate;

define('YOURLS_ABSPATH', __DIR__);
define('YOURLS_COOKIEKEY', 'isolated-test-cookie-secret');

$assertions = 0;
$nativeChecks = 0;

function yourls_check_IP_flood(string $ip = ''): bool
{
    global $nativeChecks;
    $nativeChecks++;
    return true;
}

function verify(bool $condition, string $description): void
{
    global $assertions;
    $assertions++;
    if (!$condition) {
        throw new RuntimeException('WorkGate overlap: ' . $description);
    }
}

/** Create one small private test directory; clean only this test's files. */
function testDirectory(): string
{
    $dir = rtrim(sys_get_temp_dir(), '/') . '/ach-workgate-overlap-' . bin2hex(random_bytes(8));
    if (!mkdir($dir, 0700)) {
        throw new RuntimeException('Unable to create isolated workgate directory');
    }
    return $dir;
}

function cleanupTestDirectory(string $dir): void
{
    foreach (glob($dir . '/b-*') ?: [] as $file) {
        unlink($file);
    }
    rmdir($dir);
}

/** Read only this unique test directory's current admission marker. */
function admissionSnapshot(string $dir): array
{
    $files = glob($dir . '/b-*') ?: [];
    if (count($files) !== 1) {
        throw new RuntimeException('Expected one private admission bucket');
    }
    $items = json_decode((string) file_get_contents($files[0]), true);
    if (!is_array($items) || count($items) !== 1) {
        throw new RuntimeException('Expected one admission entry');
    }
    return array_values($items)[0];
}

$settings = Policy::settings(['reachability_enabled' => true, 'blocked_domains' => []]);
$ip = '203.0.113.62';
$secret = 'fake-secret-for-test';

/**
 * A starts at t=0 and pauses. B starts after the native 15 s delay at t=16,
 * with either the same or a different fingerprint, and also pauses.
 * A completes after B's admission but before B completes.
 *
 * This must never publish A's result as B's result.
 */
function overlapCase(
    string $label,
    string $firstUrl,
    string $secondUrl,
    array $firstVerdict,
    array $secondVerdict,
    bool $newerCompletesFirst = false
): void {
    global $settings, $ip, $secret;
    $dir = testDirectory();
    try {
        $executions = 0;
        $create = static function (string $url, float $start) use (
            &$executions, $settings, $ip, $secret, $dir
        ): Fiber {
            return new Fiber(static function () use (
                $url, $start, &$executions, $settings, $ip, $secret, $dir
            ): array {
                return WorkGate::evaluate(
                    $url, $settings, $secret,
                    static function () use (&$executions): array {
                        $executions++;
                        return Fiber::suspend('active');
                    },
                    $ip, 15, false, $dir, $start
                );
            });
        };

        $a = $create($firstUrl, 0.0);
        verify($a->start() === 'active', $label . ': A is active');
        verify($a->isSuspended(), $label . ': A remains in flight');
        $generationA = admissionSnapshot($dir)['generation'] ?? null;
        verify(is_string($generationA) && strlen($generationA) === 32,
            $label . ': A has a unique admission generation');

        $b = $create($secondUrl, 16.0);
        verify($b->start() === 'active', $label . ': B admitted after expiry');
        verify($b->isSuspended(), $label . ': B remains in flight');
        verify($executions === 2, $label . ': both generations actually started');
        $generationB = admissionSnapshot($dir)['generation'] ?? null;
        verify(is_string($generationB) && strlen($generationB) === 32 &&
            $generationB !== $generationA, $label . ': newer admission has a distinct generation');

        $unexpectedRuns = 0;
        if ($newerCompletesFirst) {
            $b->resume($secondVerdict);
            verify($b->isTerminated(), $label . ': B completed first');
            verify($b->getReturn() === $secondVerdict, $label . ': B caller keeps its result');
            $bDone = admissionSnapshot($dir);
            verify(($bDone['generation'] ?? null) === $generationB &&
                ($bDone['state'] ?? null) === 'done',
                $label . ': B owns its completed result');

            $a->resume($firstVerdict);
            verify($a->isTerminated(), $label . ': stale A then completes');
            verify($a->getReturn() === $firstVerdict, $label . ': A caller keeps its result');
            $afterA = admissionSnapshot($dir);
            verify(($afterA['generation'] ?? null) === $generationB &&
                ($afterA['state'] ?? null) === 'done' &&
                ($afterA['verdict']['reason'] ?? null) === $secondVerdict['reason'],
                $label . ': A cannot change the completed B result');
        } else {
            $a->resume($firstVerdict);
            verify($a->isTerminated(), $label . ': A completed');
            verify($a->getReturn() === $firstVerdict, $label . ': A caller retains original result');
            $afterStaleA = admissionSnapshot($dir);
            verify(($afterStaleA['generation'] ?? null) === $generationB &&
                ($afterStaleA['state'] ?? null) === 'working',
                $label . ': older completion cannot mutate newer working state');

            $between = WorkGate::evaluate(
                $secondUrl, $settings, $secret,
                static function () use (&$unexpectedRuns): array {
                    $unexpectedRuns++;
                    return ['status' => 'deny', 'reason' => 'unexpected_execution', 'host' => ''];
                },
                $ip, 15, false, $dir, 17.0
            );
            verify($between['reason'] === 'work_deferred',
                $label . ': A completion cannot prematurely mark B done');
            verify($unexpectedRuns === 0, $label . ': no extra expensive work');
            verify($b->isSuspended(), $label . ': B is still working');

            $b->resume($secondVerdict);
            verify($b->isTerminated(), $label . ': B completed');
            verify($b->getReturn() === $secondVerdict, $label . ': B caller retains original result');
            $afterB = admissionSnapshot($dir);
            verify(($afterB['generation'] ?? null) === $generationB &&
                ($afterB['state'] ?? null) === 'done',
                $label . ': newer generation owns its completed verdict');
        }

        $cached = WorkGate::evaluate(
            $secondUrl, $settings, $secret,
            static function () use (&$unexpectedRuns): array {
                $unexpectedRuns++;
                return ['status' => 'deny', 'reason' => 'unexpected_execution', 'host' => ''];
            },
            $ip, 15, false, $dir, 18.0
        );
        verify($cached['status'] === $secondVerdict['status'],
            $label . ': cache has newer status, not stale A status');
        verify($cached['reason'] === $secondVerdict['reason'],
            $label . ': cache has newer verdict, not stale A verdict');
        verify($unexpectedRuns === 0, $label . ': cached result avoids expensive work');
    } finally {
        cleanupTestDirectory($dir);
    }
}

$allowed = ['status' => 'allow', 'reason' => 'checks_passed', 'host' => 'example.com'];
$blocked = ['status' => 'deny', 'reason' => 'blocked_domain', 'host' => 'example.com'];

overlapCase('same URL: stale allow versus newer deny',
    'https://example.com/X', 'https://example.com/X', $allowed, $blocked);

overlapCase('same URL: stale deny versus newer allow',
    'https://example.com/X', 'https://example.com/X', $blocked, $allowed);

overlapCase('different fingerprint: older allow versus newer deny',
    'https://example.com/X', 'https://example.com/Y', $allowed, $blocked);

overlapCase('different fingerprint: older deny versus newer allow',
    'https://example.com/X', 'https://example.com/Y', $blocked, $allowed);

overlapCase('older deny after newer allow already completed',
    'https://example.com/X', 'https://example.com/X', $blocked, $allowed, true);

$dir = testDirectory();
try {
    $executions = 0;
    $first = WorkGate::evaluate(
        'https://example.com/Z', $settings, $secret,
        static function () use (&$executions, $allowed): array {
            $executions++;
            return $allowed;
        },
        $ip, 15, false, $dir, 100.0
    );
    verify($first === $allowed, 'single admission returns full original result');
    $cached = WorkGate::evaluate(
        'https://example.com/Z', $settings, $secret,
        static function () use (&$executions, $blocked): array {
            $executions++;
            return $blocked;
        },
        $ip, 15, false, $dir, 101.0
    );
    verify($cached['reason'] === 'checks_passed', 'same-generation completion cached normally');
    verify($executions === 1, 'same-generation cached response avoided repeated work');
    $expired = WorkGate::evaluate(
        'https://example.com/Z', $settings, $secret,
        static function () use (&$executions, $blocked): array {
            $executions++;
            return $blocked;
        },
        $ip, 15, false, $dir, 116.0
    );
    verify($expired === $blocked, 'new generation admitted after native expiry');
    verify($executions === 2, 'expiry triggers only one new evaluation');
} finally {
    cleanupTestDirectory($dir);
}

verify($nativeChecks >= 19, 'native YOURLS flood entry still invoked before the work gate');

echo "PASS $assertions deterministic WorkGate overlap assertions; no network, no DB, private state removed.\n";
