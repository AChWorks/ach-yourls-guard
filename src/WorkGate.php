<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Bounded shared admission for optional expensive work before YOURLS's native
 * link-insertion flood check. Reuses its configured delay and exemptions.
 *
 * Private temporary bucket files contain hashed IP/request identities and only
 * a minimal verdict. Never store destination URLs, query strings or API keys.
 * All files are outside the served YOURLS tree. No schema or cron.
 */
final class WorkGate
{
    private const ENTRIES_PER_BUCKET = 32;

    public static function needed(array $settings): bool
    {
        return !empty($settings['blocked_url_patterns']) ||
            !empty($settings['reachability_enabled']) ||
            !empty($settings['web_risk_enabled']) ||
            (!empty($settings['dnsbl_enabled']) && !empty($settings['dnsbl_zones']));
    }

    /**
     * $clientIp/$delay/$exempt/$directory/$now may be injected in isolated tests.
     * In production all defaults come from YOURLS and the PHP runtime.
     */
    public static function evaluate(
        string $url,
        array $settings,
        string $secret,
        callable $work,
        ?string $clientIp = null,
        ?int $delay = null,
        ?bool $exempt = null,
        ?string $directory = null,
        ?float $now = null
    ): array {
        if (!self::needed($settings)) {
            return $work();
        }

        $clientIp = $clientIp ?? yourls_get_IP();

        // Respect any native flood shunt, policy or IP whitelist before even
        // attempting a PCRE or billable/outbound lookup. This check is naturally
        // repeated by YOURLS after this shunt, for accepted creations.
        yourls_check_IP_flood($clientIp);

        $delay = $delay ?? yourls_get_flood_delay();
        if ($delay <= 0) {
            // YOURLS flood control is intentionally disabled by the operator
            // (or by isolated fixtures); do not invent another rate ceiling.
            return $work();
        }

        if ($exempt === null) {
            $exempt = (yourls_is_private() && yourls_is_valid_user() === true) ||
                in_array($clientIp, yourls_get_flood_ip_whitelist(), true);
        }
        if ($exempt) {
            // Match YOURLS: authenticated private admins and configured
            // whitelist clients are exempt, never blocked by the work gate.
            return $work();
        }

        $now = $now ?? microtime(true);
        $directory = $directory ?? (rtrim(sys_get_temp_dir(), '/') . '/ach-yourls-work-' .
            substr(hash('sha256', (string) YOURLS_ABSPATH), 0, 24));
        $ipHash = hash_hmac('sha256', $clientIp, defined('YOURLS_COOKIEKEY') ? (string) YOURLS_COOKIEKEY : (string) YOURLS_ABSPATH);
        $fingerprint = hash('sha256', $url . "\0" . serialize($settings) . "\0" . hash('sha256', $secret));
        // A fingerprint identifies the request, not the execution. The same
        // request can be admitted again after expiry while an earlier attempt
        // is still running; completion must belong to the exact admission.
        $generation = bin2hex(random_bytes(16));
        $take = self::transaction($directory, $ipHash, $now, $delay,
            static function (array &$items) use ($ipHash, $fingerprint, $generation, $now, $delay): array {
                $prior = $items[$ipHash] ?? null;
                if (is_array($prior) && $now - (float) ($prior['at'] ?? 0) < $delay) {
                    if (($prior['fingerprint'] ?? '') === $fingerprint &&
                        ($prior['state'] ?? '') === 'done' &&
                        is_array($prior['verdict'] ?? null)) {
                        return ['kind' => 'cached', 'verdict' => $prior['verdict']];
                    }
                    return ['kind' => 'deferred'];
                }
                $items[$ipHash] = [
                    'at' => $now,
                    'fingerprint' => $fingerprint,
                    'generation' => $generation,
                    'state' => 'working',
                ];
                return ['kind' => 'admitted', 'changed' => true];
            }
        );
        if (!is_array($take)) {
            return self::uncertain($settings, 'work_control_unavailable');
        }
        if ($take['kind'] === 'cached') {
            return $take['verdict'];
        }
        if ($take['kind'] === 'deferred') {
            return self::uncertain($settings, 'work_deferred');
        }

        try {
            $result = $work();
        } catch (\Throwable $error) {
            // Retain the short-lived admission marker on failures rather than
            // repeatedly performing expensive work after a crashed request.
            throw $error;
        }
        $compact = [
            'status' => (string) ($result['status'] ?? 'unknown'),
            'reason' => (string) ($result['reason'] ?? 'unknown'),
            'host' => (string) ($result['host'] ?? ''),
        ];
        // A concurrent request may have replaced an expired marker with a
        // new admission of the *same* URL and fingerprint. The random
        // generation identifies this exact attempt and prevents an old
        // completion from publishing over any newer working/completed result.
        self::transaction($directory, $ipHash, $now, $delay,
            static function (array &$items) use ($ipHash, $fingerprint, $generation, $compact): array {
                if (($items[$ipHash]['fingerprint'] ?? '') !== $fingerprint ||
                    ($items[$ipHash]['generation'] ?? null) !== $generation ||
                    ($items[$ipHash]['state'] ?? '') !== 'working') {
                    return ['kind' => 'stale'];
                }
                $items[$ipHash]['state'] = 'done';
                $items[$ipHash]['verdict'] = $compact;
                return ['kind' => 'stored', 'changed' => true];
            }
        );
        return $result;
    }

    private static function uncertain(array $settings, string $reason): array
    {
        return [
            'status' => ($settings['unknown_action'] ?? 'allow') === 'deny' ? 'deny' : 'unknown',
            'reason' => $reason,
            'host' => '',
        ];
    }

    /**
     * One 0700 site directory, 256 hashed buckets, 32 short-lived identities
     * per bucket. Lock time covers only tiny JSON state transitions, never
     * DNS, regex or HTTP work. Contention/unwritable storage is uncertainty.
     */
    private static function transaction(
        string $directory,
        string $ipHash,
        float $now,
        int $delay,
        callable $operation
    ): ?array {
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            return null;
        }
        if (is_link($directory) || !is_dir($directory) || !is_writable($directory) ||
            ((@fileperms($directory) & 0077) !== 0)) {
            return null;
        }
        $file = $directory . '/b-' . substr($ipHash, 0, 2);
        if (is_link($file)) {
            return null;
        }
        $handle = @fopen($file, 'c+b');
        if (!is_resource($handle)) {
            return null;
        }
        try {
            if (!@flock($handle, LOCK_EX | LOCK_NB)) {
                return null;
            }
            $json = stream_get_contents($handle, 65536);
            $items = json_decode(is_string($json) ? $json : '', true);
            if (!is_array($items)) {
                $items = [];
            }
            foreach ($items as $key => $item) {
                if (!is_array($item) || $now - (float) ($item['at'] ?? 0) >= $delay) {
                    unset($items[$key]);
                }
            }
            $answer = $operation($items);
            if (!empty($answer['changed'])) {
                if (count($items) > self::ENTRIES_PER_BUCKET) {
                    uasort($items, static fn($a, $b) => ($a['at'] ?? 0) <=> ($b['at'] ?? 0));
                    $items = array_slice($items, -self::ENTRIES_PER_BUCKET, null, true);
                }
                $encoded = json_encode($items, JSON_UNESCAPED_SLASHES);
                if (!is_string($encoded) || !rewind($handle) || !ftruncate($handle, 0) ||
                    fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                    return null;
                }
            }
            return $answer;
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
