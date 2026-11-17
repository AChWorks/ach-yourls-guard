<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Non-invasive HTTP status checker. All redirect hops get independent DNS checks.
 * Reject any private/reserved DNS response before pinning public IPs to cURL.
 * Never follows redirects automatically, never uses HTTP proxies, never downloads
 * a full response body, and always verifies HTTPS certificates.
 */
final class HttpProbe
{
    /** @var callable */
    private $resolver;
    /** @var callable */
    private $requester;

    public function __construct(?callable $resolver = null, ?callable $requester = null)
    {
        $this->resolver = $resolver ?? [self::class, 'resolveAddresses'];
        $this->requester = $requester ?? [self::class, 'requestOnce'];
    }

    public function check(string $url, array $settings): array
    {
        $settings = Policy::settings($settings);
        $visited = [];
        for ($hop = 0; $hop <= $settings['max_redirects']; $hop++) {
            $policy = Policy::inspect($url, $settings);
            if ($policy['status'] !== 'allow') {
                // Local PCRE budget exhaustion is an explicit unknown, not a
                // definite bad destination; preserve the operator's policy.
                return self::withChain(['status' => $policy['status'], 'reason' => $policy['reason'], 'final_url' => $url, 'hops' => $hop], $visited);
            }
            if (isset($visited[$url])) {
                return self::withChain(['status' => 'unknown', 'reason' => 'redirect_loop', 'final_url' => $url], $visited);
            }
            $visited[$url] = true;
            $ips = ($this->resolver)($policy['host']);
            if (!is_array($ips) || $ips === []) {
                return self::withChain(['status' => 'unknown', 'reason' => 'dns_unresolved', 'final_url' => $url], $visited);
            }
            $valid = [];
            foreach ($ips as $ip) {
                if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
                    return self::withChain(['status' => 'unknown', 'reason' => 'dns_invalid', 'final_url' => $url], $visited);
                }
                if (!self::isPublicIp($ip)) {
                    return self::withChain(['status' => 'deny', 'reason' => 'private_dns_address', 'final_url' => $url], $visited);
                }
                $valid[] = $ip;
            }
            $valid = array_values(array_unique($valid));
            // Real link navigation uses GET. A HEAD 200 can conceal a GET-only
            // redirect to a prohibited or private destination. Bounded GET
            // observes the actual redirect route and needs no fallback request.
            $response = ($this->requester)($url, $valid, 'GET', $settings);
            $code = (int) ($response['http_code'] ?? 0);
            if ($code >= 300 && $code < 400) {
                if (empty($response['location'])) {
                    return self::withChain(['status' => 'unknown', 'reason' => 'redirect_without_location', 'final_url' => $url], $visited);
                }
                $next = self::resolveLocation($url, (string) $response['location']);
                if ($next === '') {
                    return self::withChain(['status' => 'deny', 'reason' => 'invalid_redirect', 'final_url' => $url], $visited);
                }
                $url = $next;
                continue;
            }
            if ($code >= 200 && $code < 300) {
                return self::withChain(['status' => 'allow', 'reason' => 'http_success', 'final_url' => $url, 'http_code' => $code], $visited);
            }
            if ($code === 404 || $code === 410) {
                return self::withChain(['status' => 'deny', 'reason' => 'http_not_found', 'final_url' => $url, 'http_code' => $code], $visited);
            }
            if ($code > 0) {
                return self::withChain(['status' => 'unknown', 'reason' => 'http_inconclusive', 'final_url' => $url, 'http_code' => $code], $visited);
            }
            return self::withChain(['status' => 'unknown', 'reason' => 'connection_error', 'final_url' => $url], $visited);
        }
        return self::withChain(['status' => 'unknown', 'reason' => 'too_many_redirects', 'final_url' => $url], $visited);
    }

    private static function withChain(array $result, array $visited): array
    {
        $result['chain'] = array_keys($visited);
        return $result;
    }

    /** IANA special-use ranges not comprehensively excluded by PHP FILTER_FLAG_NO_RES_RANGE. */
    public static function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        // These IANA special-purpose networks are not globally reachable, or can
        // tunnel/translate requests to internal destinations. See README sources.
        $deny = [
            '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
            '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
            '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
            '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
            '224.0.0.0/4', '240.0.0.0/4',
            '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48',
            '100::/64', '100:0:0:1::/64', '2001::/32', '2001:2::/48',
            '2001:10::/28', '2001:20::/28', '2001:30::/28',
            '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16',
            'fc00::/7', 'fe80::/10', 'ff00::/8',
        ];
        // IANA explicitly marks these two hosts as globally reachable anycast.
        if ($ip === '192.0.0.9' || $ip === '192.0.0.10') {
            return true;
        }
        foreach ($deny as $cidr) {
            if (self::matchesCidr($ip, $cidr)) {
                return false;
            }
        }
        return true;
    }

    public static function matchesCidr(string $ip, string $cidr): bool
    {
        [$network, $bits] = explode('/', $cidr, 2);
        $ipBinary = @inet_pton($ip);
        $networkBinary = @inet_pton($network);
        if ($ipBinary === false || $networkBinary === false || strlen($ipBinary) !== strlen($networkBinary)) {
            return false;
        }
        $bits = (int) $bits;
        if ($bits < 0 || $bits > 8 * strlen($ipBinary)) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        if (substr($ipBinary, 0, $bytes) !== substr($networkBinary, 0, $bytes)) {
            return false;
        }
        $remaining = $bits % 8;
        if ($remaining === 0) {
            return true;
        }
        $mask = (0xff << (8 - $remaining)) & 0xff;
        return (ord($ipBinary[$bytes]) & $mask) === (ord($networkBinary[$bytes]) & $mask);
    }

    public static function resolveAddresses(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        $ips = [];
        foreach (is_array($records) ? $records : [] as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }
        return array_values(array_unique($ips));
    }

    public static function resolveLocation(string $from, string $location): string
    {
        $location = trim($location);
        if ($location === '' || preg_match('/[\x00-\x1F\x7F]/', $location)) {
            return '';
        }
        if (preg_match('/^[a-z][a-z0-9+.-]*:/i', $location)) {
            return $location;
        }
        $p = parse_url($from);
        if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) {
            return '';
        }
        if (substr($location, 0, 2) === '//') {
            return $p['scheme'] . ':' . $location;
        }
        $base = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        if ($location[0] === '#') {
            return preg_replace('/#.*$/', '', $from) . $location;
        }
        if ($location[0] === '?') {
            return $base . ($p['path'] ?? '/') . $location;
        }
        if ($location[0] !== '/') {
            $path = (string) ($p['path'] ?? '/');
            $location = substr($path, 0, (int) strrpos($path, '/') + 1) . $location;
        }
        $suffix = '';
        if (preg_match('/[?#]/', $location, $m, PREG_OFFSET_CAPTURE)) {
            $offset = $m[0][1];
            $suffix = substr($location, $offset);
            $location = substr($location, 0, $offset);
        }
        $path = [];
        foreach (explode('/', $location) as $segment) {
            if ($segment === '..') {
                array_pop($path);
            } elseif ($segment !== '.') {
                $path[] = $segment;
            }
        }
        $normalized = implode('/', $path);
        return $base . ($normalized !== '' && $normalized[0] === '/' ? '' : '/') . $normalized . $suffix;
    }

    /** Live transport (unit tests inject their own request function). */
    public static function requestOnce(string $url, array $ips, string $method, array $settings): array
    {
        if (!function_exists('curl_init')) {
            return ['http_code' => 0, 'error' => 'curl_extension_missing'];
        }
        $p = parse_url($url);
        if (!is_array($p) || empty($p['host'])) {
            return ['http_code' => 0, 'error' => 'invalid_url'];
        }
        $host = trim((string) $p['host'], '[]');
        $port = (int) ($p['port'] ?? (strtolower((string) $p['scheme']) === 'https' ? 443 : 80));
        $ip = $ips[0];
        if (strpos($ip, ':') !== false) {
            $ip = '[' . $ip . ']';
        }
        $ch = curl_init($url);
        if ($ch === false) {
            return ['http_code' => 0, 'error' => 'curl_init_failed'];
        }
        $location = '';
        $received = 0;
        try {
            // Every cURL safety setting must be applied before making a request.
            // In particular, a failed CURLOPT_RESOLVE must never fall back to
            // unpinned DNS, since it could turn the validation into an SSRF.
            if (!curl_setopt_array($ch, [
                CURLOPT_NOBODY => $method === 'HEAD',
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROXY => '',
                CURLOPT_NOPROXY => '*',
                CURLOPT_CONNECTTIMEOUT => $settings['connect_timeout_seconds'],
                CURLOPT_TIMEOUT => $settings['request_timeout_seconds'],
                CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $ip],
                CURLOPT_USERAGENT => 'ACh-LinkGuard/0.1',
                CURLOPT_HEADERFUNCTION => static function ($unused, string $line) use (&$location): int {
                    if (stripos($line, 'Location:') === 0) {
                        $location = trim(substr($line, 9));
                    }
                    return strlen($line);
                },
                CURLOPT_WRITEFUNCTION => static function ($unused, string $chunk) use (&$received): int {
                    $received += strlen($chunk);
                    return $received > 16384 ? 0 : strlen($chunk);
                },
            ])) {
                return ['http_code' => 0, 'error' => 'curl_configuration_failed'];
            }
            if (defined('CURLOPT_PROTOCOLS_STR')) {
                $protocolsConfigured = curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'http,https');
            } else {
                $protocolsConfigured = curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            }
            if (!$protocolsConfigured) {
                return ['http_code' => 0, 'error' => 'curl_protocol_configuration_failed'];
            }
            $response = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = $response === false ? 'curl_error_' . curl_errno($ch) : '';
            return ['http_code' => $code, 'location' => $location, 'error' => $error];
        } finally {
            unset($ch); // CurlHandle cleanup without deprecated curl_close()
        }
    }
}
