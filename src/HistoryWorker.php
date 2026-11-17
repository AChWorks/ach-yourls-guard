<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Host-local, scheduled background processing. Never creates jobs and never
 * authorizes deletion: only a valid admin-confirmed 'delete' phase is runnable.
 */
final class HistoryWorker
{
    public static function run($db, int $seconds = 45): array
    {
        if ($seconds < 1) throw new \InvalidArgumentException('Worker seconds must be positive');
        $deadline = microtime(true) + $seconds;
        $result = ['steps' => 0, 'jobs' => 0, 'failures' => 0];
        $seen = [];
        do {
            $active = BulkHistory::runnableJobs($db);
            if ($active === []) break;
            $progressed = false;
            foreach ($active as $entry) {
                if (microtime(true) >= $deadline && $result['steps'] > 0) break 2;
                try {
                    $job = $entry['phase'] === 'scan'
                        ? BulkHistory::scanStep($db, $entry['id'], $entry['owner'])
                        : BulkHistory::deleteStep($db, $entry['id'], $entry['owner']);
                    $result['steps']++;
                    $seen[$entry['id']] = true;
                    $progressed = true;
                } catch (\Throwable $error) {
                    $result['failures']++;
                    $seen[$entry['id']] = true;
                    // Preserve the error class (never URL data or SQL text);
                    // stop this job until the owner explicitly retries it.
                    BulkHistory::fail($db, $entry['id'], $entry['owner'], get_class($error));
                }
            }
        } while ($progressed && microtime(true) < $deadline);
        $result['jobs'] = count($seen);
        return $result;
    }
}
