<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/** Official Google Web Risk Lookup API; key only comes from protected site configuration. */
final class WebRisk
{
    /** @var callable */
    private $transport;

    public function __construct(?callable $transport = null)
    {
        $this->transport = $transport ?? [self::class, 'transport'];
    }

    public function lookup(string $url, string $key, int $timeout): array
    {
        if ($key === '') {
            return ['status' => 'unknown', 'reason' => 'web_risk_not_configured'];
        }
        // Google REST v1 Lookup. Only these upstream-supported types are meaningful.
        $request = 'https://webrisk.googleapis.com/v1/uris:search?' . http_build_query([
            'uri' => $url,
            'key' => $key,
        ], '', '&', PHP_QUERY_RFC3986);
        foreach (['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'] as $threat) {
            $request .= '&threatTypes=' . $threat;
        }
        $response = ($this->transport)($request, $timeout);
        if (($response['http_code'] ?? 0) !== 200 || !is_string($response['body'] ?? null)) {
            return ['status' => 'unknown', 'reason' => 'web_risk_unavailable'];
        }
        $data = json_decode($response['body'], true);
        if (!is_array($data)) {
            return ['status' => 'unknown', 'reason' => 'web_risk_invalid_reply'];
        }
        if (isset($data['threat']) && !empty($data['threat']['threatTypes'])) {
            return ['status' => 'deny', 'reason' => 'web_risk_threat', 'threat_types' => $data['threat']['threatTypes']];
        }
        // An empty successful response means not on the queried lists, not guaranteed safe.
        if (isset($data['threat']) || $data === []) {
            return ['status' => 'allow', 'reason' => 'web_risk_not_listed'];
        }
        return ['status' => 'unknown', 'reason' => 'web_risk_unexpected_reply'];
    }

    public static function transport(string $request, int $timeout): array
    {
        if (!function_exists('curl_init')) {
            return ['http_code' => 0, 'body' => ''];
        }
        $ch = curl_init($request);
        if ($ch === false) {
            return ['http_code' => 0, 'body' => ''];
        }
        try {
            if (!curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROXY => '',
                CURLOPT_NOPROXY => '*',
                CURLOPT_CONNECTTIMEOUT => min(5, $timeout),
                CURLOPT_TIMEOUT => $timeout,
                CURLOPT_HTTPHEADER => ['Accept: application/json'],
                CURLOPT_USERAGENT => 'ACh-LinkGuard/0.1',
            ])) {
                return ['http_code' => 0, 'body' => ''];
            }
            $body = curl_exec($ch);
            return ['http_code' => (int) curl_getinfo($ch, CURLINFO_HTTP_CODE), 'body' => $body !== false ? (string) $body : ''];
        } finally {
            unset($ch); // CurlHandle cleanup without deprecated curl_close()
        }
    }
}

/** Optional, domain-oriented DNSBL. Supports the positive codes from SURBL-like providers. */
final class DomainDnsbl
{
    /** @var callable */
    private $resolver;

    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver ?? static function (string $name): array {
            $records = @dns_get_record($name, DNS_A);
            $out = [];
            foreach (is_array($records) ? $records : [] as $record) {
                if (!empty($record['ip'])) {
                    $out[] = (string) $record['ip'];
                }
            }
            return $out;
        };
    }

    public function lookup(string $host, array $zones): array
    {
        $host = strtolower(preg_replace('/^www\.(?=.+\.)/i', '', $host));
        foreach ($zones as $zone) {
            $zone = strtolower(trim((string) $zone));
            if (!Policy::validDomain($zone)) {
                continue;
            }
            // DNSBLs must never list the reserved 'invalid' test name (RFC 5782).
            if ($this->listed('invalid.' . $zone)) {
                continue;
            }
            if ($this->listed($host . '.' . $zone)) {
                return ['status' => 'deny', 'reason' => 'dnsbl_listed', 'provider' => $zone];
            }
        }
        return ['status' => 'allow', 'reason' => 'dnsbl_not_listed'];
    }

    private function listed(string $name): bool
    {
        foreach (($this->resolver)($name) as $ip) {
            if (
                is_string($ip) &&
                substr($ip, 0, 4) === '127.' &&
                $ip !== '127.0.0.1' &&
                substr($ip, 0, 12) !== '127.255.255.'
            ) {
                return true;
            }
        }
        return false;
    }
}
