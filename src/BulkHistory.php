<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Explicitly approved, resumable historical cleanup.
 * Dry-run materializes exact candidate row proofs (never full destinations)
 * in an indexed InnoDB table. No automatic deletion, cron, or vendor calls.
 */
final class BulkHistory
{
    private const OPTION_PREFIX = 'ach_url_guard_bulk_';
    private const CANDIDATE_SUFFIX = 'ach_guard_candidates';

    private static function table(string $name): string
    {
        if (strlen($name) > 64 || !preg_match('/^[a-zA-Z0-9_]+$/D', $name)) {
            throw new \RuntimeException('Invalid YOURLS SQL table identifier');
        }
        return chr(96) . $name . chr(96);
    }

    private static function optionsTable(): string
    {
        return self::table((string) YOURLS_DB_TABLE_OPTIONS);
    }

    private static function candidatesTable(): string
    {
        return self::table((string) YOURLS_DB_PREFIX . self::CANDIDATE_SUFFIX);
    }

    private static function optionName(string $id): string
    {
        if (!preg_match('/^[0-9a-f]{24}$/D', $id)) {
            throw new \InvalidArgumentException('Invalid job ID');
        }
        return self::OPTION_PREFIX . $id;
    }

    public static function actor(): string
    {
        if (!defined('YOURLS_USER') || !is_string(YOURLS_USER) || YOURLS_USER === '') {
            throw new \RuntimeException('No authenticated YOURLS user identity');
        }
        return YOURLS_USER;
    }

    public static function filter($raw): array
    {
        if (!is_array($raw)) throw new \InvalidArgumentException('Missing bulk filters');
        $scalar = static function (string $key) use ($raw): string {
            if (!isset($raw[$key])) return '';
            if (!is_string($raw[$key])) throw new \InvalidArgumentException('Invalid filter field');
            return trim($raw[$key]);
        };
        $reason = $scalar('reason') ?: 'any';
        if (!in_array($reason, array_merge(['any'], HistoricalReview::definiteReasons()), true)) {
            throw new \InvalidArgumentException('Unsupported reason filter');
        }
        $clicks = $scalar('clicks') ?: 'any';
        if (!in_array($clicks, ['any', 'zero', 'positive'], true)) {
            throw new \InvalidArgumentException('Unsupported clicks filter');
        }
        $host = strtolower(rtrim($scalar('host'), '.'));
        if ($host !== '' && !Policy::validDomain($host) && !filter_var($host, FILTER_VALIDATE_IP)) {
            throw new \InvalidArgumentException('Invalid destination host filter');
        }
        $prefix = $scalar('prefix');
        if (strlen($prefix) > 100 || str_contains($prefix, "\0")) {
            throw new \InvalidArgumentException('Invalid keyword prefix');
        }
        $before = $scalar('before');
        if ($before !== '') {
            $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $before);
            if ($d === false || $d->format('Y-m-d') !== $before) {
                throw new \InvalidArgumentException('Invalid date filter');
            }
        }
        return compact('reason', 'clicks', 'host', 'prefix', 'before');
    }

    public static function networkMode(array $filter): bool
    {
        return $filter['reason'] === 'http_not_found';
    }

    private static function policyHash(array $settings): string
    {
        return hash('sha256', serialize(Policy::settings($settings)));
    }

    public static function ensureSchema($db): void
    {
        $db->exec('CREATE TABLE IF NOT EXISTS ' . self::candidatesTable() . ' (
            job_id CHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            keyword VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
            row_proof CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            reason VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            result VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT \'pending\',
            PRIMARY KEY (job_id, keyword)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin');
    }

    public static function create($db, string $owner, string $mode, array $filterInput, array $selected): array
    {
        if ($owner === '' || !in_array($mode, ['page', 'all'], true)) {
            throw new \InvalidArgumentException('Select current page or all filtered matches');
        }
        $filter = self::filter($filterInput);
        if ($mode === 'page') {
            if ($selected === [] || count($selected) > 100) {
                throw new \InvalidArgumentException('Select 1–100 page rows');
            }
            foreach ($selected as $keyword) {
                if (!is_string($keyword) || $keyword === '' || strlen($keyword) > 100
                    || $keyword !== yourls_sanitize_keyword($keyword)) {
                    throw new \InvalidArgumentException('Invalid short keyword selection');
                }
            }
            $selected = array_values(array_unique($selected));
            sort($selected, SORT_STRING);
        } else {
            $selected = [];
        }
        self::ensureSchema($db);
        $settings = HistoricalReview::storedSettings($db);
        $high = $db->fetchOne('SELECT keyword FROM ' . HistoricalReview::urlTable()
            . ' ORDER BY keyword DESC LIMIT 1');
        $clock = $db->fetchOne('SELECT NOW() AS started');
        $id = bin2hex(random_bytes(12));
        $state = [
            'id' => $id, 'owner' => $owner, 'mode' => $mode, 'phase' => 'scan',
            'filter' => $filter, 'selected' => $selected,
            'policy_hash' => self::policyHash($settings),
            'started' => (string) ($clock['started'] ?? date('Y-m-d H:i:s')),
            'ceiling' => (string) ($high['keyword'] ?? ''), 'cursor' => '',
            'scanned' => 0, 'matched' => 0, 'processed' => 0,
            'deleted' => 0, 'skipped' => 0, 'reason_counts' => [],
        ];
        $n = $db->fetchAffected('INSERT INTO ' . self::optionsTable()
            . ' (option_name, option_value) VALUES (:name, :value)',
            ['name' => self::optionName($id), 'value' => serialize($state)]);
        if ((int) $n !== 1) throw new \RuntimeException('Could not create review job');
        return $state;
    }

    public static function load($db, string $id, string $owner, bool $lock = false): ?array
    {
        $rows = $db->fetchAll('SELECT option_value FROM ' . self::optionsTable()
            . ' WHERE option_name = :name' . ($lock ? ' FOR UPDATE' : ''),
            ['name' => self::optionName($id)]);
        if (count($rows) !== 1) return null;
        $job = yourls_maybe_unserialize((string) $rows[0]['option_value']);
        if (!is_array($job) || ($job['id'] ?? '') !== $id || ($job['owner'] ?? '') !== $owner) {
            return null;
        }
        return $job;
    }

    private static function save($db, array $job): void
    {
        $n = $db->fetchAffected('UPDATE ' . self::optionsTable()
            . ' SET option_value = :value WHERE option_name = :name',
            ['value' => serialize($job), 'name' => self::optionName((string) $job['id'])]);
        if ((int) $n !== 1) throw new \RuntimeException('Could not save review progress');
    }

    /** Recovery links for the authenticated owner's recent saved jobs. */
    public static function recentJobs($db, string $owner): array
    {
        $rows = $db->fetchAll('SELECT option_name, option_value FROM ' . self::optionsTable()
            . ' WHERE option_name LIKE :prefix ORDER BY option_id DESC LIMIT 30',
            ['prefix' => self::OPTION_PREFIX . '%']);
        $jobs = [];
        foreach ($rows as $row) {
            $name = (string) ($row['option_name'] ?? '');
            if (!str_starts_with($name, self::OPTION_PREFIX)) continue;
            $id = substr($name, strlen(self::OPTION_PREFIX));
            if (!preg_match('/^[0-9a-f]{24}$/D', $id)) continue;
            $job = yourls_maybe_unserialize((string) ($row['option_value'] ?? ''));
            if (!is_array($job) || ($job['owner'] ?? '') !== $owner || ($job['id'] ?? '') !== $id) {
                continue;
            }
            $jobs[] = [
                'id' => $id, 'phase' => (string) ($job['phase'] ?? 'unknown'),
                'matched' => (int) ($job['matched'] ?? 0),
                'deleted' => (int) ($job['deleted'] ?? 0),
            ];
        }
        return $jobs;
    }

    /** Bounded keyset scan; never serializes an unbounded keyword list. */
    private static function sourcePage($db, array $job): array
    {
        $size = self::networkMode($job['filter']) ? 1 : 50;
        if ($job['mode'] === 'page') {
            $keys = array_values(array_filter($job['selected'],
                static fn(string $key): bool => strcmp($key, (string) $job['cursor']) > 0));
            $batch = array_slice($keys, 0, $size);
            $rows = [];
            foreach ($batch as $keyword) {
                $rows[] = ['keyword' => $keyword, 'row' => HistoricalReview::find($db, $keyword)];
            }
            return [$rows, count($keys) > $size];
        }
        if ($job['ceiling'] === '') return [[], false];
        $raw = $db->fetchAll('SELECT keyword,url,title,timestamp,clicks FROM '
            . HistoricalReview::urlTable()
            . ' WHERE keyword > :cursor AND keyword <= :ceiling AND timestamp <= :started'
            . ' ORDER BY keyword ASC LIMIT ' . (int) ($size + 1),
            ['cursor' => $job['cursor'], 'ceiling' => $job['ceiling'], 'started' => $job['started']]);
        $more = count($raw) > $size;
        return [array_map(static fn(array $row): array =>
            ['keyword' => (string) $row['keyword'], 'row' => $row],
            array_slice($raw, 0, $size)), $more];
    }

    /** Select only definite violations of the *current* policy and filters. */
    public static function matches(array $row, array $settings, array $filter, ?callable $probe = null): ?array
    {
        if ($filter['clicks'] === 'zero' && (int) $row['clicks'] !== 0) return null;
        if ($filter['clicks'] === 'positive' && (int) $row['clicks'] === 0) return null;
        if ($filter['before'] !== '' && substr((string) $row['timestamp'], 0, 10) > $filter['before']) {
            return null;
        }
        if ($filter['prefix'] !== '' && !str_starts_with((string) $row['keyword'], $filter['prefix'])) {
            return null;
        }
        if ($filter['host'] !== '' && strtolower(HistoricalReview::hostLabel((string) $row['url']))
            !== $filter['host']) return null;
        $network = self::networkMode($filter);
        $decision = HistoricalReview::inspect($row, $settings, $network, $probe);
        if (($decision['status'] ?? '') !== 'deny') return null;
        if ($filter['reason'] !== 'any' && ($decision['reason'] ?? '') !== $filter['reason']) return null;
        return $decision;
    }

    /** Dry-run step: saves an exact snapshot of each approved candidate. */
    public static function scanStep($db, string $id, string $owner, ?callable $probe = null): array
    {
        $job = self::load($db, $id, $owner);
        if ($job === null) throw new \RuntimeException('Review job not found');
        if ($job['phase'] !== 'scan') return $job;
        $settings = HistoricalReview::storedSettings($db);
        if (!hash_equals($job['policy_hash'], self::policyHash($settings))) {
            return self::pause($db, $id, $owner);
        }
        [$items, $more] = self::sourcePage($db, $job);
        $candidates = [];
        foreach ($items as $item) {
            if ($item['row'] === null) continue;
            $decision = self::matches($item['row'], $settings, $job['filter'], $probe);
            if ($decision === null) continue;
            $candidates[] = [
                'keyword' => $item['keyword'],
                'proof' => HistoricalReview::proof($item['row'], $settings),
                'reason' => (string) $decision['reason'],
            ];
        }
        $db->beginTransaction();
        try {
            $locked = self::load($db, $id, $owner, true);
            if ($locked === null) throw new \RuntimeException('Review job vanished');
            if ($locked['phase'] !== 'scan' || $locked['cursor'] !== $job['cursor']) {
                $db->rollBack();
                return $locked;
            }
            $current = HistoricalReview::storedSettings($db, true);
            if (!hash_equals($job['policy_hash'], self::policyHash($current))) {
                $locked['phase'] = 'paused';
            } else {
                foreach ($candidates as $candidate) {
                    $n = $db->fetchAffected('INSERT INTO ' . self::candidatesTable()
                        . ' (job_id, keyword, row_proof, reason)'
                        . ' VALUES (:id, :keyword, :proof, :reason)',
                        ['id' => $id, 'keyword' => $candidate['keyword'],
                            'proof' => $candidate['proof'], 'reason' => $candidate['reason']]);
                    if ((int) $n !== 1) throw new \RuntimeException('Candidate insert failed');
                    $locked['matched']++;
                    $reason = $candidate['reason'];
                    $locked['reason_counts'][$reason] = ($locked['reason_counts'][$reason] ?? 0) + 1;
                }
                $locked['scanned'] += count($items);
                if ($items !== []) $locked['cursor'] = end($items)['keyword'];
                if (!$more) $locked['phase'] = 'ready';
            }
            self::save($db, $locked);
            $db->commit();
            return $locked;
        } catch (\Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }

    private static function pause($db, string $id, string $owner): array
    {
        $db->beginTransaction();
        try {
            $job = self::load($db, $id, $owner, true);
            if ($job === null) throw new \RuntimeException('Review job vanished');
            if (in_array($job['phase'], ['scan', 'delete'], true)) {
                $job['phase'] = 'paused';
                self::save($db, $job);
            }
            $db->commit();
            return $job;
        } catch (\Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }

    /** A complete preview is necessary before any multi-link deletion. */
    public static function startDeletion($db, string $id, string $owner, string $typed, bool $confirmed): array
    {
        $db->beginTransaction();
        try {
            $job = self::load($db, $id, $owner, true);
            if ($job === null || $job['phase'] !== 'ready') {
                throw new \RuntimeException('Finish the preview before approval');
            }
            if (!$confirmed || $job['matched'] === 0 || $typed !== 'DELETE ' . $job['matched']) {
                throw new \InvalidArgumentException('Type DELETE and the exact match count');
            }
            $settings = HistoricalReview::storedSettings($db, true);
            if (!hash_equals($job['policy_hash'], self::policyHash($settings))) {
                $job['phase'] = 'paused';
            } else {
                $job['phase'] = 'delete';
                $job['cursor'] = '';
            }
            self::save($db, $job);
            $db->commit();
            return $job;
        } catch (\Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }

    /** Delete only pre-materialized candidates, comparing policy and row proof. */
    public static function deleteStep($db, string $id, string $owner, ?callable $probe = null): array
    {
        $job = self::load($db, $id, $owner);
        if ($job === null) throw new \RuntimeException('Deletion job not found');
        if ($job['phase'] !== 'delete') return $job;
        $settings = HistoricalReview::storedSettings($db);
        if (!hash_equals($job['policy_hash'], self::policyHash($settings))) {
            return self::pause($db, $id, $owner);
        }
        $size = self::networkMode($job['filter']) ? 1 : 25;
        $rows = $db->fetchAll('SELECT keyword,row_proof,reason FROM '
            . self::candidatesTable()
            . ' WHERE job_id = :id AND keyword > :cursor ORDER BY keyword ASC LIMIT ' . (int) ($size + 1),
            ['id' => $id, 'cursor' => $job['cursor']]);
        $more = count($rows) > $size;
        $batch = array_slice($rows, 0, $size);

        // External GETs run before the job or URL rows are locked.
        $checks = [];
        foreach ($batch as $candidate) {
            $keyword = (string) $candidate['keyword'];
            $row = HistoricalReview::find($db, $keyword);
            $decision = $row === null ? null : self::matches($row, $settings, $job['filter'], $probe);
            $checks[$keyword] = [
                'row' => $row, 'decision' => $decision,
                'proof' => $row === null ? '' : HistoricalReview::proof($row, $settings),
            ];
        }

        $db->beginTransaction();
        try {
            $locked = self::load($db, $id, $owner, true);
            if ($locked === null) throw new \RuntimeException('Deletion job vanished');
            if ($locked['phase'] !== 'delete' || $locked['cursor'] !== $job['cursor']) {
                $db->rollBack();
                return $locked;
            }
            $current = HistoricalReview::storedSettings($db, true);
            if (!hash_equals($job['policy_hash'], self::policyHash($current))) {
                $locked['phase'] = 'paused';
                self::save($db, $locked);
                $db->commit();
                return $locked;
            }
            foreach ($batch as $candidate) {
                $keyword = (string) $candidate['keyword'];
                $check = $checks[$keyword];
                $latest = HistoricalReview::find($db, $keyword, true);
                $reason = (string) $candidate['reason'];
                $approved = $latest !== null && $check['row'] !== null
                    && $check['decision'] !== null
                    && ($check['decision']['reason'] ?? '') === $reason
                    && hash_equals((string) $candidate['row_proof'], $check['proof'])
                    && hash_equals((string) $candidate['row_proof'],
                        HistoricalReview::proof($latest, $current));
                if ($approved && !self::networkMode($job['filter'])) {
                    $final = self::matches($latest, $current, $job['filter']);
                    $approved = $final !== null && $final['reason'] === $reason;
                }
                if ($approved) {
                    $affected = yourls_delete_link_by_keyword($keyword);
                    if ((int) $affected !== 1 || HistoricalReview::find($db, $keyword, true) !== null) {
                        throw new \RuntimeException('Native deletion could not verify the exact row');
                    }
                    $locked['deleted']++;
                    $status = 'deleted';
                } else {
                    $locked['skipped']++;
                    $status = 'skipped';
                }
                $db->fetchAffected('UPDATE ' . self::candidatesTable()
                    . ' SET result = :result WHERE job_id = :id AND keyword = :keyword',
                    ['result' => $status, 'id' => $id, 'keyword' => $keyword]);
                $locked['processed']++;
                $locked['cursor'] = $keyword;
            }
            if (!$more) $locked['phase'] = 'done';
            self::save($db, $locked);
            $db->commit();
            return $locked;
        } catch (\Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }

    public static function cancel($db, string $id, string $owner): array
    {
        $db->beginTransaction();
        try {
            $job = self::load($db, $id, $owner, true);
            if ($job === null) throw new \RuntimeException('Review job unavailable');
            if (in_array($job['phase'], ['scan', 'ready', 'delete'], true)) {
                $job['phase'] = 'cancelled';
                self::save($db, $job);
            }
            $db->commit();
            return $job;
        } catch (\Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }

    /** Clear only completed/cancelled metadata. This never deletes short URLs. */
    public static function clear($db, string $id, string $owner): void
    {
        $db->beginTransaction();
        try {
            $job = self::load($db, $id, $owner, true);
            if ($job === null || !in_array($job['phase'], ['cancelled', 'done', 'paused'], true)) {
                throw new \RuntimeException('Only inactive reports can be cleared');
            }
            $db->fetchAffected('DELETE FROM ' . self::candidatesTable() . ' WHERE job_id = :id',
                ['id' => $id]);
            $db->fetchAffected('DELETE FROM ' . self::optionsTable() . ' WHERE option_name = :name',
                ['name' => self::optionName($id)]);
            $db->commit();
        } catch (\Throwable $error) {
            if ($db->inTransaction()) $db->rollBack();
            throw $error;
        }
    }
}
