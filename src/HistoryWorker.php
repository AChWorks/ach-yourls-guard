<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Host-local, scheduled background processing. Never creates jobs and never
 * authorizes deletion: only a valid admin-confirmed 'delete' phase is runnable.
 */
final class HistoryWorker
{
    /** MySQL advisory locks are scoped to the database SERVER, not a host's
     * filesystem. All workers on the same schema/table namespace use this name.
     */
    public static function lockName(string $databaseName, string $prefix): string
    {
        if ($databaseName === '' || $prefix === '') {
            throw new \InvalidArgumentException('Worker database identity is incomplete');
        }
        return 'ach_guard_bulk_' . substr(hash('sha256', $databaseName . "\0" . $prefix), 0, 40);
    }

    /** Diagnostic context may be logged only to private server logs; avoid
     * exception messages, SQL parameter values, URLs and credentials.
     */
    public static function failureRecord(array $entry, string $stage, \Throwable $error): array
    {
        $code = preg_replace('/[^a-zA-Z0-9_-]/', '', (string) $error->getCode());
        return [
            'event' => 'job_failed',
            'job_id' => $entry['id'],
            'phase' => $entry['phase'],
            'stage' => $stage,
            'occurred_at' => gmdate('c'),
            'category' => get_class($error),
            'code' => substr((string) $code, 0, 32),
            'ref' => bin2hex(random_bytes(8)),
        ];
    }

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
                $stage = $entry['phase'] === 'scan' ? 'scan_step' : 'delete_step';
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
                    $diagnostic = self::failureRecord($entry, $stage, $error);
                    error_log('ACh URL Guard bulk worker '
                        . json_encode($diagnostic, JSON_UNESCAPED_SLASHES));
                    // Each failure is stopped; a worker restart cannot
                    // quietly repeat a destructive attempt.
                    BulkHistory::fail($db, $entry['id'], $entry['owner'],
                        $diagnostic['category'], $diagnostic);
                }
            }
        } while ($progressed && microtime(true) < $deadline);
        $result['jobs'] = count($seen);
        return $result;
    }
}
