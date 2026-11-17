<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Admin-only, explicitly requested review of existing links. Opening/scanning
 * never mutates URL rows or makes outbound requests. Deletion is a separate
 * human-confirmed transaction through YOURLS's native delete function.
 */
final class HistoricalReview
{
    public static function pageSize($value): int
    {
        $parsed = filter_var($value, FILTER_VALIDATE_INT);
        return in_array($parsed, [25, 50, 100], true) ? (int) $parsed : 50;
    }

    private static function table(): string
    {
        $name = (string) YOURLS_DB_TABLE_URL;
        if (!preg_match('/^[a-zA-Z0-9_]+$/D', $name)) {
            throw new \RuntimeException('Invalid YOURLS URL table identifier');
        }
        return $name;
    }

    /** @return array{rows:array,has_more:bool,next_cursor:string} */
    public static function page($db, string $cursor, int $size): array
    {
        if (strlen($cursor) > 512) {
            throw new \InvalidArgumentException('Invalid review cursor');
        }
        $size = self::pageSize($size);
        $limit = $size + 1;
        $rows = $db->fetchAll(
            'SELECT keyword, url, title, timestamp, clicks FROM ' . self::table()
            . ' WHERE keyword > :cursor ORDER BY keyword ASC LIMIT ' . $limit,
            ['cursor' => $cursor]
        );
        $more = count($rows) > $size;
        $rows = array_slice($rows, 0, $size);
        $end = $rows !== [] ? (string) $rows[array_key_last($rows)]['keyword'] : $cursor;
        return ['rows' => $rows, 'has_more' => $more, 'next_cursor' => $end];
    }

    public static function find($db, string $keyword, bool $lock = false): ?array
    {
        if ($keyword === '' || strlen($keyword) > 512) {
            return null;
        }
        $row = $db->fetchObject(
            'SELECT keyword, url, title, timestamp, clicks FROM ' . self::table()
            . ' WHERE keyword = :keyword' . ($lock ? ' FOR UPDATE' : ''),
            ['keyword' => $keyword]
        );
        if ($row === false || $row === null) {
            return null;
        }
        $item = (array) $row;
        // A case-insensitive database collation must never select another alias.
        return hash_equals((string) $item['keyword'], $keyword) ? $item : null;
    }

    /**
     * The custom alias cap applies to new *custom* aliases, not historical
     * generated aliases. Deliberately ignore that cap for old-link review.
     * Network checks are opt-in and never contact reputation vendors.
     */
    public static function inspect(array $row, array $settings, bool $network = false): array
    {
        $settings = Policy::settings($settings);
        $local = Policy::inspect((string) $row['url'], $settings);
        if ($local['status'] === 'deny'
            && self::isDefiniteReason((string) $local['reason'])) {
            return $local;
        }
        $aliasSettings = $settings;
        $aliasSettings['max_custom_keyword_length'] = 0;
        $alias = Policy::inspectKeyword((string) $row['keyword'], $aliasSettings);
        if ($alias['status'] === 'deny') {
            return $alias;
        }
        if ($local['status'] !== 'allow') {
            return self::conservative($local);
        }
        if (!$network) {
            return $local;
        }
        $settings['reachability_enabled'] = true;
        $settings['web_risk_enabled'] = false;
        $settings['dnsbl_enabled'] = false;
        return self::conservative((new Guard())->evaluate((string) $row['url'], $settings, ''));
    }

    /**
     * "Reject unknown" is a new-link availability policy, not proof an old
     * customer URL is malicious or missing. Treat only already understood,
     * definite policy violations as candidates for irreversible deletion.
     * New verdict reasons require deliberate review before enabling deletion.
     */
    private static function isDefiniteReason(string $reason): bool
    {
        return in_array($reason, [
            'invalid_url', 'unsupported_scheme', 'url_credentials_disallowed',
            'private_address', 'ambiguous_ip', 'invalid_hostname',
            'blocked_domain', 'blocked_url_term', 'blocked_url_pattern',
            'blocked_short_keyword', 'root_url',
            'http_not_found', 'private_dns_address', 'invalid_redirect',
        ], true);
    }

    private static function conservative(array $verdict): array
    {
        if (($verdict['status'] ?? '') === 'deny'
            && !self::isDefiniteReason((string) ($verdict['reason'] ?? ''))) {
            $verdict['status'] = 'unknown';
        }
        return $verdict;
    }

    /**
     * Proof binds the operator's reviewed snapshot to both the URL identity
     * and the current effective rules. Mutable click counts do not invalidate
     * it. Never display or persist the raw URL outside the authorized form.
     */
    public static function proof(array $row, array $settings): string
    {
        $identity = [
            'keyword' => (string) ($row['keyword'] ?? ''),
            'url' => (string) ($row['url'] ?? ''),
            'title' => (string) ($row['title'] ?? ''),
            'timestamp' => (string) ($row['timestamp'] ?? ''),
            'policy' => Policy::settings($settings),
        ];
        return hash_hmac('sha256', serialize($identity), (string) YOURLS_COOKIEKEY);
    }

    /** Keep URL paths, credentials and query parameters out of the review UI. */
    public static function hostLabel(string $url): string
    {
        $parts = parse_url($url);
        $host = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
        return $host !== '' ? $host : '[invalid destination]';
    }

    /**
     * A local or a manually network-verified definite violation is required.
     * Lock and re-read the exact row before native YOURLS deletion so edits
     * between scan and confirmation cannot delete a different destination.
     */
    public static function delete(
        $db,
        string $keyword,
        string $expectedProof,
        string $expectedReason,
        bool $network,
        array $settings
    ): string {
        if (!preg_match('/^[a-f0-9]{64}$/D', $expectedProof)
            || $expectedReason === ''
            || $keyword === ''
            || $keyword !== yourls_sanitize_keyword($keyword)) {
            return 'invalid_request';
        }
        // For slow HTTP checks, do the GET before taking a database row lock.
        try {
            $row = self::find($db, $keyword);
            if ($row === null || !hash_equals(self::proof($row, $settings), $expectedProof)) {
                return 'stale';
            }
            $result = self::inspect($row, $settings, $network);
            if ($result['status'] !== 'deny' || $result['reason'] !== $expectedReason) {
                return 'no_longer_flagged';
            }

            $db->beginTransaction();
            try {
                $locked = self::find($db, $keyword, true);
                if ($locked === null || !hash_equals(self::proof($locked, $settings), $expectedProof)) {
                    $db->rollBack();
                    return 'stale';
                }
                // Fast local policies can be verified while the row is locked.
                // Network results were rechecked immediately before the lock.
                $local = self::inspect($locked, $settings, false);
                if (!$network && ($local['status'] !== 'deny' || $local['reason'] !== $expectedReason)) {
                    $db->rollBack();
                    return 'no_longer_flagged';
                }

                // The native function clears cache and dispatches delete_link
                // hooks; the explicit transaction protects the checked row.
                $affected = yourls_delete_link_by_keyword($keyword);
                if ((int) $affected !== 1 || self::find($db, $keyword, true) !== null) {
                    throw new \RuntimeException('Native deletion did not remove the checked row');
                }
                $db->commit();
                return 'deleted';
            } catch (\Throwable $error) {
                if ($db->inTransaction()) {
                    $db->rollBack();
                }
                throw $error;
            }
        } catch (\Throwable $error) {
            error_log('ACh URL Guard reviewed history deletion failed [' . get_class($error) . ']');
            return 'error';
        }
    }
}
