<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Policy.php';
require_once dirname(__DIR__) . '/src/HttpProbe.php';
require_once dirname(__DIR__) . '/src/Reputation.php';
require_once dirname(__DIR__) . '/src/Guard.php';

use ACh\Yourls\UrlGuard\Policy;
use ACh\Yourls\UrlGuard\HttpProbe;
use ACh\Yourls\UrlGuard\WebRisk;
use ACh\Yourls\UrlGuard\DomainDnsbl;
use ACh\Yourls\UrlGuard\Guard;

$tests = 0;
function eq($expected, $actual, string $what): void
{
    global $tests;
    $tests++;
    if ($expected !== $actual) {
        throw new RuntimeException("FAIL $what: expected " . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}
function status(string $url, array $settings): string
{
    return Policy::inspect($url, $settings)['reason'];
}
$settings = Policy::settings([]);
eq('monitor', $settings['mode'], 'default mode must not block');
eq('root_url', status('https://example.com', $settings), 'empty root');
eq('root_url', status('https://example.com/?q=foo', $settings), 'query root');
eq('root_url', status('https://example.com/', $settings), 'slash root');
eq('root_url', status('https://example.com/./', $settings), 'dot-segment root');
eq('root_url', status('https://example.com/%2e/', $settings), 'encoded dot-segment root');
eq('root_url', status('https://example.com////', $settings), 'multi-slash root');
eq('policy_pass', status('https://example.com/page', $settings), 'page path accepted');
eq('policy_pass', status('HTTPS://Example.com/SomePage', $settings), 'uppercase scheme accepted');
eq('private_address', status('https://127.0.0.1/private', $settings), 'loopback forbidden');
eq('private_address', status('https://10.1.2.3/private', $settings), 'private IPv4 forbidden');
eq('private_address', status('https://[::1]/x', $settings), 'IPv6 loopback forbidden');
eq('private_address', status('http://service.localhost/x', $settings), 'local TLD forbidden');
eq('ambiguous_ip', status('http://0177.0.0.1/x', $settings), 'octal numeric IP alias forbidden');
eq('ambiguous_ip', status('http://2130706433/x', $settings), 'integer IPv4 alias forbidden');
eq('url_credentials_disallowed', status('https://user:pass@example.com/x', $settings), 'URL credentials forbidden');
eq('unsupported_scheme', status('ftp://example.com/file', $settings), 'FTP blocked');
eq('invalid_hostname', status('http://intranet/x', $settings), 'single-label hosts rejected');
eq('invalid_url', status('not a url', $settings), 'malformed URL');

$settings['blocked_domains'] = Policy::domainLines("bad.example\n.bad-domain.example\n*.only-children.example\n# comment\nINVALID RULE\n");
eq(['bad.example', '.bad-domain.example', '*.only-children.example'], $settings['blocked_domains'], 'valid deny rules');
eq('blocked_domain', status('https://bad.example/news', $settings), 'exact bad domain');
eq('policy_pass', status('https://sub.bad.example/news', $settings), 'exact does not block subdomains');
eq('policy_pass', status('https://notbad.example/news', $settings), 'not arbitrary substring');
eq('blocked_domain', status('https://bad-domain.example/news', $settings), 'leading-dot apex');
eq('blocked_domain', status('https://a.bad-domain.example/news', $settings), 'leading-dot subdomain');
eq('blocked_domain', status('https://shop.only-children.example/news', $settings), 'wildcard subdomain');
eq('policy_pass', status('https://only-children.example/news', $settings), 'wildcard excludes apex');
eq('policy_pass', status('https://bad-domain.example.evil.com/news', $settings), 'not arbitrary suffix');
$settings['root_exceptions'] = ['.trusted.example'];
eq('policy_pass', status('https://www.trusted.example', $settings), 'root exception wildcard');
eq('root_url', status('https://not-trusted.example', $settings), 'root rule still active');
$settings['block_root_urls'] = false;
eq('policy_pass', status('https://example.com/', $settings), 'root rule configurable');
$settings['block_root_urls'] = true;

eq('https://example.com/a/new', HttpProbe::resolveLocation('https://example.com/a/page', 'new'), 'relative redirect');
eq('https://example.com/new', HttpProbe::resolveLocation('https://example.com/a/page', '../new'), 'parent redirect');
eq('http://other.example/path', HttpProbe::resolveLocation('http://example.com/a', '//other.example/path'), 'protocol relative scheme logic');
eq('https://example.com/p?q=1', HttpProbe::resolveLocation('https://example.com/p', '?q=1'), 'query redirect');
eq('', HttpProbe::resolveLocation('https://example.com/p', "http://evil.com/\r\nHeader: x"), 'CRLF redirect rejected');

eq(false, HttpProbe::isPublicIp('127.0.0.1'), 'loopback IPv4');
eq(false, HttpProbe::isPublicIp('169.254.169.254'), 'metadata IP');
eq(false, HttpProbe::isPublicIp('172.16.0.2'), 'private IPv4');
eq(false, HttpProbe::isPublicIp('::1'), 'loopback IPv6');
eq(false, HttpProbe::isPublicIp('fc00::1'), 'private IPv6');
eq(false, HttpProbe::isPublicIp('2001:db8::1'), 'IANA documentation IPv6');
eq(false, HttpProbe::isPublicIp('100.64.0.1'), 'IANA shared address IPv4');
eq(false, HttpProbe::isPublicIp('64:ff9b::7f00:1'), 'NAT64-mapped localhost');
eq(false, HttpProbe::isPublicIp('2002:c0a8:101::1'), '6to4 mapped private');
eq(false, HttpProbe::isPublicIp('198.18.0.1'), 'benchmark IPv4');
eq(false, HttpProbe::isPublicIp('3fff::1'), 'IANA documentation IPv6 2024');

eq(true, HttpProbe::isPublicIp('8.8.8.8'), 'public IPv4');
eq(true, HttpProbe::isPublicIp('2001:4860:4860::8888'), 'public IPv6');

$requests = [];
$resolver = static function (string $host): array {return $host === 'internal.example' ? ['10.0.0.1', '8.8.8.8'] : ['8.8.8.8'];};
$respond = static function (string $url, array $ips, string $method, array $cfg) use (&$requests): array {
    $requests[] = [$url, $ips, $method];
    if (str_contains($url, '/not-found')) return ['http_code' => 404];
    if (str_contains($url, '/gone')) return ['http_code' => 410];
    if (str_contains($url, '/head-false-404')) return ['http_code' => $method === 'HEAD' ? 404 : 200];
    if (str_contains($url, '/head-get-error')) return $method === 'HEAD' ? ['http_code' => 404] : ['http_code' => 0, 'error' => 'curl_error_28'];
    if (str_contains($url, '/blocked')) return ['http_code' => 403];
    if (str_contains($url, '/rate-limited')) return ['http_code' => 429];
    if (str_contains($url, '/server-error')) return ['http_code' => 503];
    if (str_contains($url, '/head-not-allowed')) return ['http_code' => $method === 'HEAD' ? 405 : 200];
    if (str_contains($url, '/to-private')) return ['http_code' => 302, 'location' => 'http://127.0.0.1/admin'];
    if (str_contains($url, '/to-root')) return ['http_code' => 301, 'location' => '/'];
    if (str_contains($url, '/to-page')) return ['http_code' => 301, 'location' => '/somewhere'];
    if (str_contains($url, '/to-intermediate')) return ['http_code' => 302, 'location' => 'https://unsafe.example/intermediate'];
    if (str_contains($url, '/intermediate')) return ['http_code' => 302, 'location' => 'https://good.example/final'];
    if (str_contains($url, '/to-loop')) return ['http_code' => 302, 'location' => '/to-loop'];
    return ['http_code' => 200];
};
$probe = new HttpProbe($resolver, $respond);
eq('http_success', $probe->check('https://example.com/exists', $settings)['reason'], 'probe 200');
eq('http_not_found', $probe->check('https://example.com/not-found', $settings)['reason'], 'probe 404');
eq('http_not_found', $probe->check('https://example.com/gone', $settings)['reason'], 'probe 410');
eq('http_success', $probe->check('https://example.com/head-false-404', $settings)['reason'], 'HEAD 404 with GET 200 passes');
eq('get_fallback_failed', $probe->check('https://example.com/head-get-error', $settings)['reason'], 'HEAD 404 is not definitive if GET transport fails');
eq('http_inconclusive', $probe->check('https://example.com/blocked', $settings)['reason'], '403 inconclusive');
eq('http_inconclusive', $probe->check('https://example.com/rate-limited', $settings)['reason'], '429 inconclusive');
eq('http_inconclusive', $probe->check('https://example.com/server-error', $settings)['reason'], '503 inconclusive');
eq('http_success', $probe->check('https://example.com/head-not-allowed', $settings)['reason'], 'fallback to GET');
eq('private_address', $probe->check('https://example.com/to-private', $settings)['reason'], 'no redirect to localhost');
eq('root_url', $probe->check('https://example.com/to-root', $settings)['reason'], 'root policy on final redirect');
eq('http_success', $probe->check('https://example.com/to-page', $settings)['reason'], 'relative redirect followed safely');
eq('redirect_loop', $probe->check('https://example.com/to-loop', $settings)['reason'], 'redirect loop');
$before = count($requests);
eq('private_dns_address', $probe->check('https://internal.example/data', $settings)['reason'], 'reject mixed public/private DNS');
eq($before, count($requests), 'no request to private DNS');
$rebindingResolutions = 0;
$rebindingRequests = 0;
$rebindProbe = new HttpProbe(
    static function (string $host) use (&$rebindingResolutions): array {
        $rebindingResolutions++;
        return $rebindingResolutions === 1 ? ['8.8.8.8'] : ['127.0.0.1'];
    },
    static function (string $url, array $ips, string $method, array $cfg) use (&$rebindingRequests): array {
        $rebindingRequests++;
        return ['http_code' => 302, 'location' => '/second'];
    }
);
eq('private_dns_address', $rebindProbe->check('https://changing.example/first', $settings)['reason'], 'DNS rebinding between hops rejected');
eq(1, $rebindingRequests, 'No second request to private rebinding IP');

$risk = new WebRisk(static function (string $url, int $timeout): array {
    if (str_contains($url, 'unsafe.example')) {
        return ['http_code' => 200, 'body' => '{"threat":{"threatTypes":["SOCIAL_ENGINEERING"]}}'];
    }
    if (str_contains($url, 'network-error.example')) {
        return ['http_code' => 503, 'body' => ''];
    }
    return ['http_code' => 200, 'body' => '{}'];
});
eq('web_risk_threat', $risk->lookup('https://unsafe.example/x', 'test-key', 3)['reason'], 'Web Risk malicious');
eq('web_risk_not_listed', $risk->lookup('https://good.example/x', 'test-key', 3)['reason'], 'Web Risk unlisted');
eq('web_risk_unavailable', $risk->lookup('https://network-error.example/x', 'test-key', 3)['reason'], 'Web Risk outage');
eq('web_risk_not_configured', $risk->lookup('https://good.example/x', '', 3)['reason'], 'Web Risk no key');

$dns = new DomainDnsbl(static function (string $fqdn): array {
    if ($fqdn === 'unsafe.example.surbl.example') return ['127.0.0.2'];
    if ($fqdn === 'invalid.broken.example') return ['127.0.0.2'];
    if ($fqdn === 'innocent.example.broken.example') return ['127.0.0.2'];
    return [];
});
eq('dnsbl_listed', $dns->lookup('unsafe.example', ['surbl.example'])['reason'], 'positive DNSBL');
eq('dnsbl_not_listed', $dns->lookup('innocent.example', ['broken.example'])['reason'], 'broken list ignored');

$settings['reachability_enabled'] = true;
$settings['web_risk_enabled'] = true;
$settings['dnsbl_enabled'] = false;
$guard = new Guard($probe, $risk, $dns);
eq('web_risk_threat', $guard->evaluate('https://unsafe.example/x', $settings, 'test-key')['reason'], 'combined risk denial');
eq('web_risk_threat', $guard->evaluate('https://good.example/to-intermediate', $settings, 'test-key')['reason'], 'intermediate redirect reputation checked');
eq('http_not_found', $guard->evaluate('https://normal.example/not-found', $settings, 'test-key')['reason'], 'combined reachability');
eq('uncertain_destination', $guard->evaluate('https://normal.example/blocked', $settings, 'test-key')['reason'], 'unknown allowed by default');
$settings['unknown_action'] = 'deny';
eq('unverifiable_destination', $guard->evaluate('https://normal.example/blocked', $settings, 'test-key')['reason'], 'strict unknown denial');

// Test real hook wiring with minimal YOURLS stubs. This must not mutate any URL table.
define('YOURLS_ABSPATH', dirname(__DIR__));
$hooks = [];
$fakeOptions = ['ach_url_guard_settings' => ['mode' => 'monitor', 'block_root_urls' => true]];
$eventWrites = 0;
function yourls_add_filter($name, $callable, $priority = 10, $argc = 1): void {global $hooks;$hooks[] = [$name, $callable, $priority, $argc];}
function yourls_add_action($name, $callable): void {global $hooks;$hooks[] = [$name, $callable];}
function yourls_get_option($name, $default = false) {global $fakeOptions;return $fakeOptions[$name] ?? $default;}
function yourls_update_option($name, $value): void {global $fakeOptions, $eventWrites;$fakeOptions[$name] = $value;if ($name === 'ach_url_guard_events') $eventWrites++;}
function yourls_sanitize_url($url): string {return $url;}
function yourls_create_nonce($action): string {return 'fake-test-nonce';}
function yourls_verify_nonce($action, $nonce = false): void {global $lastNonce; $lastNonce = $nonce;}
function yourls_register_plugin_page($slug, $title, $function): void {}
require dirname(__DIR__) . '/plugin.php';
eq('shunt_add_new_link', $hooks[0][0], 'guard uses official shunt hook');
eq(4, $hooks[0][3], 'hook receives all input parameters');
$sentinel = new stdClass();
eq($sentinel, ach_url_guard_on_create($sentinel, 'https://example.com/'), 'monitor mode never changes shunt default');
$fakeOptions['ach_url_guard_settings']['mode'] = 'enforce';
$decision = ach_url_guard_on_create($sentinel, 'https://example.com/');
eq('fail', $decision['status'], 'enforcement rejects root');
eq('error:ach_url_guard:root_url', $decision['code'], 'enforcement descriptive code');
eq(2, count($fakeOptions['ach_url_guard_events']), 'observability ring stores separate monitor/enforce decisions');
for ($attempt = 0; $attempt < 100; $attempt++) {
    ach_url_guard_on_create($sentinel, 'https://unique' . $attempt . '.example.com/');
}
eq(2, count($fakeOptions['ach_url_guard_events']), 'monitoring samples repeated same-second decisions');
eq(2, $eventWrites, 'repeated abusive decisions do not amplify DB writes');
$_SERVER['REQUEST_METHOD'] = 'GET';
ob_start();
ach_url_guard_admin_page();
$adminHtml = ob_get_clean();
eq(true, strpos($adminHtml, 'Monitor only') !== false, 'admin has monitor setting');
eq(true, strpos($adminHtml, 'Enforce: reject definite violations') !== false, 'admin has enforcement setting');
eq(true, strpos($adminHtml, 'Web Risk API key:') !== false, 'admin displays key readiness');
eq(true, strpos($adminHtml, 'Recent sampled decisions') !== false, 'admin shows audit evidence');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['ach_url_guard_save' => '1', 'mode' => 'enforce', 'blocked_domains' => 'invalid domain', 'root_exceptions' => '', 'dnsbl_zones' => ''];
ob_start(); ach_url_guard_admin_page(); $badHtml = ob_get_clean();
eq(true, strpos($badHtml, 'Invalid domain rule(s)') !== false, 'invalid rule is visible to operator');
eq('enforce', $fakeOptions['ach_url_guard_settings']['mode'], 'enforce mode unchanged by invalid input');
$_POST = ['ach_url_guard_save' => '1', 'nonce' => 'fake-test-nonce', 'mode' => 'monitor', 'blocked_domains' => '.Bad.Example', 'root_exceptions' => '', 'dnsbl_zones' => ''];
ob_start(); ach_url_guard_admin_page(); $okHtml = ob_get_clean();
eq(true, strpos($okHtml, 'Settings saved') !== false, 'admin saves valid rules');
eq('fake-test-nonce', $lastNonce, 'admin passes explicit POST nonce to YOURLS verifier');
eq(['.bad.example'], $fakeOptions['ach_url_guard_settings']['blocked_domains'], 'stored rule canonicalized');

printf("PASS %d assertions, offline, no live data altered\n", $tests);
