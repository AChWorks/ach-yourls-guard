<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/** Side-effect-free host, path and operator denylist policy. */
final class Policy
{
    public static function defaults(): array
    {
        return [
            'mode' => 'monitor',
            'block_root_urls' => true,
            'root_exceptions' => [],
            // Editable anti-chaining starter set; new installations remain Monitor.
            'blocked_domains' => ['.bit.ly', '.tinyurl.com', '.cutt.ly', '.is.gd'],
            'blocked_url_terms' => [],
            'blocked_url_patterns' => [],
            'blocked_short_keywords' => [],
            // 0 explicitly disables the custom-alias cap.
            'max_custom_keyword_length' => 20,
            'reachability_enabled' => false,
            'unknown_action' => 'allow',
            'dnsbl_enabled' => false,
            'dnsbl_zones' => [],
            'web_risk_enabled' => false,
            'connect_timeout_seconds' => 3,
            'request_timeout_seconds' => 6,
            'max_redirects' => 5,
            'recent_event_count' => 200,
        ];
    }

    public static function settings($raw): array
    {
        $raw = is_array($raw) ? $raw : [];
        $result = self::defaults();
        foreach ($result as $key => $default) {
            if (!array_key_exists($key, $raw)) {
                continue;
            }
            $value = $raw[$key];
            if (is_bool($default)) {
                $result[$key] = $value === true || $value === 1 || $value === '1';
            } elseif (is_int($default)) {
                $n = filter_var($value, FILTER_VALIDATE_INT);
                $result[$key] = $n !== false ? $n : $default;
            } elseif (is_array($default)) {
                $result[$key] = in_array($key, ['blocked_domains', 'root_exceptions', 'dnsbl_zones'], true)
                    ? self::domainLines($value) : self::textLines($value);
            } elseif (is_string($value)) {
                $result[$key] = $value;
            }
        }
        if (!in_array($result['mode'], ['monitor', 'enforce'], true)) {
            $result['mode'] = 'monitor';
        }
        if (!in_array($result['unknown_action'], ['allow', 'deny'], true)) {
            $result['unknown_action'] = 'allow';
        }
        $result['connect_timeout_seconds'] = max(1, min(20, $result['connect_timeout_seconds']));
        $result['request_timeout_seconds'] = max($result['connect_timeout_seconds'], min(60, $result['request_timeout_seconds']));
        $result['max_redirects'] = max(0, min(12, $result['max_redirects']));
        $result['recent_event_count'] = max(0, min(2000, $result['recent_event_count']));
        $result['max_custom_keyword_length'] = max(0, $result['max_custom_keyword_length']);
        return $result;
    }

    /** Exact domain, .domain (apex and children), *.domain (children only). */
    public static function domainLines($input): array
    {
        $lines = is_array($input) ? $input : preg_split('/\r\n|\r|\n/', (string) $input);
        $valid = [];
        foreach ($lines as $line) {
            if (!is_scalar($line)) {
                continue;
            }
            $line = strtolower(trim((string) $line));
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $prefix = '';
            if (substr($line, 0, 2) === '*.') {
                $prefix = '*.';
                $line = substr($line, 2);
            } elseif ($line[0] === '.') {
                $prefix = '.';
                $line = substr($line, 1);
            }
            $line = rtrim($line, '.');
            if (!self::validDomain($line)) {
                continue;
            }
            $valid[$prefix . $line] = $prefix . $line;
        }
        return array_values($valid);
    }

    /** Plain, deduplicated operator lines; no execution or hidden matching syntax. */
    public static function textLines($input): array
    {
        $lines = is_array($input) ? $input : preg_split('/\r\n|\r|\n/', (string) $input);
        $valid = [];
        foreach ($lines as $line) {
            if (!is_scalar($line)) {
                continue;
            }
            $line = trim((string) $line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $valid[$line] = $line;
        }
        return array_values($valid);
    }

    /** Reject invalid PCRE syntax when the admin saves; never silently drop a rule. */
    public static function invalidPatterns($input): array
    {
        $invalid = [];
        foreach (self::textLines($input) as $pattern) {
            if (@preg_match($pattern, '') === false) {
                $invalid[] = $pattern;
            }
        }
        return $invalid;
    }

    /** YOURLS sanitizes custom aliases before saving; count characters, not URL bytes. */
    public static function inspectKeyword(string $keyword, array $settings): array
    {
        if ($keyword === '') {
            return self::verdict('allow', 'keyword_pass');
        }
        $length = preg_match_all('/./us', $keyword);
        $length = $length === false ? strlen($keyword) : $length;
        $limit = (int) ($settings['max_custom_keyword_length'] ?? 0);
        if ($limit > 0 && $length > $limit) {
            return self::verdict('deny', 'keyword_too_long');
        }
        foreach ($settings['blocked_short_keywords'] ?? [] as $term) {
            if (strcasecmp($keyword, (string) $term) === 0) {
                return self::verdict('deny', 'blocked_short_keyword');
            }
        }
        return self::verdict('allow', 'keyword_pass');
    }

    public static function validDomain(string $host): bool
    {
        if (strlen($host) > 253 || strpos($host, '.') === false || strpos($host, '..') !== false) {
            return false;
        }
        foreach (explode('.', $host) as $label) {
            if (strlen($label) > 63 || !preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/D', $label)) {
                return false;
            }
        }
        return true;
    }

    public static function matchedDomain(string $host, array $rules): ?string
    {
        $host = strtolower(rtrim($host, '.'));
        foreach ($rules as $rule) {
            $rule = strtolower(trim((string) $rule));
            if (substr($rule, 0, 2) === '*.') {
                $suffix = substr($rule, 1);
                if (strlen($host) > strlen($suffix) && substr($host, -strlen($suffix)) === $suffix) {
                    return $rule;
                }
            } elseif (substr($rule, 0, 1) === '.') {
                $apex = substr($rule, 1);
                if ($host === $apex || (strlen($host) > strlen($rule) && substr($host, -strlen($rule)) === $rule)) {
                    return $rule;
                }
            } elseif ($host === $rule) {
                return $rule;
            }
        }
        return null;
    }

    public static function inspect(string $input, array $settings): array
    {
        $url = trim($input);
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return self::verdict('deny', 'invalid_url');
        }
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return self::verdict('deny', 'invalid_url');
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return self::verdict('deny', 'unsupported_scheme');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            return self::verdict('deny', 'url_credentials_disallowed');
        }
        $host = strtolower(rtrim((string) $parts['host'], '.'));
        $host = trim($host, '[]');
        if (
            $host === 'localhost' ||
            substr($host, -10) === '.localhost' ||
            substr($host, -6) === '.local' ||
            substr($host, -9) === '.internal'
        ) {
            return self::verdict('deny', 'private_address', $host);
        }
        // Numeric and legacy non-canonical IPv4 notations can resolve to local IPs.
        // Such ambiguous hostnames should never bypass the literal-IP check.
        if (preg_match('/^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$/iD', $host)) {
            if (!filter_var($host, FILTER_VALIDATE_IP)) {
                return self::verdict('deny', 'ambiguous_ip', $host);
            }
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (!HttpProbe::isPublicIp($host)) {
                return self::verdict('deny', 'private_address', $host);
            }
        } elseif (!self::validDomain($host)) {
            return self::verdict('deny', 'invalid_hostname');
        }
        $matched = self::matchedDomain($host, $settings['blocked_domains'] ?? []);
        if ($matched !== null) {
            return self::verdict('deny', 'blocked_domain', $host, $matched);
        }
        // Optional operator-owned substring/regex rules. Match both visible and
        // once-percent-decoded URLs; no outbound providers or URL data retention.
        $decoded = rawurldecode($url);
        foreach ($settings['blocked_url_terms'] ?? [] as $term) {
            if ($term !== '' && (stripos($url, (string) $term) !== false ||
                stripos($decoded, (string) $term) !== false)) {
                return self::verdict('deny', 'blocked_url_term', $host);
            }
        }
        foreach ($settings['blocked_url_patterns'] ?? [] as $pattern) {
            $rawMatch = @preg_match((string) $pattern, $url);
            if ($rawMatch === false) {
                return self::verdict(
                    ($settings['unknown_action'] ?? 'allow') === 'deny' ? 'deny' : 'unknown',
                    'regex_unavailable',
                    $host
                );
            }
            if ($rawMatch === 1) {
                return self::verdict('deny', 'blocked_url_pattern', $host);
            }
            if ($decoded !== $url) {
                $decodedMatch = @preg_match((string) $pattern, $decoded);
                if ($decodedMatch === false) {
                    return self::verdict(
                        ($settings['unknown_action'] ?? 'allow') === 'deny' ? 'deny' : 'unknown',
                        'regex_unavailable',
                        $host
                    );
                }
                if ($decodedMatch === 1) {
                    return self::verdict('deny', 'blocked_url_pattern', $host);
                }
            }
        }
        $path = (string) ($parts['path'] ?? '');
        $segments = [];
        foreach (explode('/', rawurldecode($path)) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }
        if (
            ($settings['block_root_urls'] ?? false) &&
            $segments === [] &&
            self::matchedDomain($host, $settings['root_exceptions'] ?? []) === null
        ) {
            return self::verdict('deny', 'root_url', $host);
        }
        return self::verdict('allow', 'policy_pass', $host);
    }

    public static function verdict(string $status, string $reason, string $host = '', string $rule = ''): array
    {
        return ['status' => $status, 'reason' => $reason, 'host' => $host, 'rule' => $rule];
    }
}
