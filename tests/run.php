<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Policy.php';
require_once dirname(__DIR__) . '/src/HttpProbe.php';
require_once dirname(__DIR__) . '/src/Reputation.php';
require_once dirname(__DIR__) . '/src/Guard.php';
require_once dirname(__DIR__) . '/src/WorkGate.php';

use ACh\Yourls\UrlGuard\Policy;
use ACh\Yourls\UrlGuard\HttpProbe;
use ACh\Yourls\UrlGuard\WebRisk;
use ACh\Yourls\UrlGuard\DomainDnsbl;
use ACh\Yourls\UrlGuard\Guard;
use ACh\Yourls\UrlGuard\WorkGate;

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
eq('monitor', $settings['mode'], 'default mode must not block URL policies');
eq(20, $settings['max_custom_keyword_length'], 'default custom short keyword cap');
eq(['.bit.ly', '.tinyurl.com', '.cutt.ly', '.is.gd'], $settings['blocked_domains'], 'editable shortener-chain starter list');
eq('blocked_domain', status('https://sub.bit.ly/path', $settings), 'starter list matches an existing shortening service');
eq('policy_pass', status('https://example.com/page', $settings), 'starter list does not block ordinary domains');
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

$filters = Policy::settings([
    'block_root_urls' => false,
    'blocked_domains' => [],
    'blocked_url_terms' => "casino\n# comment\nBad Offer\ncasino",
    'blocked_url_patterns' => ['~/(?:sale|offer)(?:/|$)~i'],
    'blocked_short_keywords' => "admin\nSupport",
]);
eq(['casino', 'Bad Offer'], $filters['blocked_url_terms'], 'plain URL terms parsed, deduplicated and comment-free');
eq('blocked_url_term', status('https://example.com/sAFE/CaSiNo/shop', $filters), 'case-insensitive term in path');
eq('blocked_url_term', status('https://example.com/ok?q=bad%20offer', $filters), 'decoded term in query');
eq('blocked_url_pattern', status('https://example.com/OFFER/123', $filters), 'operator PCRE matches full URL');
eq('policy_pass', status('https://example.com/safepage', $filters), 'nonmatching phrase and regex allowed');
eq(['~/(?:sale|offer)(?:/|$)~i'], $filters['blocked_url_patterns'], 'regex line preserved intact');
eq(['/[broken/'], Policy::invalidPatterns('/[broken/'), 'invalid PCRE rejected on admin save');
eq([], Policy::invalidPatterns('~/(?:sale|offer)(?:/|$)~i'), 'valid PCRE accepted');
eq('keyword_too_long', Policy::inspectKeyword('abcdefghijklmnopqrstu', $filters)['reason'], '21-character custom alias rejected');
eq('keyword_pass', Policy::inspectKeyword('abcdefghijklmnopqrst', $filters)['reason'], '20-character alias accepted');
eq('blocked_short_keyword', Policy::inspectKeyword('SUPPORT', $filters)['reason'], 'reserved alias exact insensitive match');
eq('keyword_pass', Policy::inspectKeyword('supporter', $filters)['reason'], 'reserved alias does not block substrings');
eq('keyword_too_long', Policy::inspectKeyword(str_repeat('ژ', 21), $filters)['reason'], 'UTF-8 characters counted, not bytes');
$filters['max_custom_keyword_length'] = 0;
eq('keyword_pass', Policy::inspectKeyword('abcdefghijklmnopqrstu', $filters)['reason'], 'operator disables cap with 0');
$broken = Policy::settings(['block_root_urls' => false, 'blocked_domains' => [], 'blocked_url_patterns' => '/[broken/']);
eq('regex_unavailable', status('https://example.com/p', $broken), 'corrupted stored regex is visible as unknown');
$broken['unknown_action'] = 'deny';
eq('deny', Policy::inspect('https://example.com/p', $broken)['status'], 'strict unknown policy applies to untestable regex');

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
eq('http_success', $probe->check('https://example.com/head-false-404', $settings)['reason'], 'Real GET 200 is sufficient even if HEAD differs');
eq('connection_error', $probe->check('https://example.com/head-get-error', $settings)['reason'], 'GET transport failure is inconclusive');
eq('http_inconclusive', $probe->check('https://example.com/blocked', $settings)['reason'], '403 inconclusive');
eq('http_inconclusive', $probe->check('https://example.com/rate-limited', $settings)['reason'], '429 inconclusive');
eq('http_inconclusive', $probe->check('https://example.com/server-error', $settings)['reason'], '503 inconclusive');
eq('http_success', $probe->check('https://example.com/head-not-allowed', $settings)['reason'], 'GET succeeds when HEAD is disabled');
eq('private_address', $probe->check('https://example.com/to-private', $settings)['reason'], 'no redirect to localhost');
eq('root_url', $probe->check('https://example.com/to-root', $settings)['reason'], 'root policy on final redirect');
eq('http_success', $probe->check('https://example.com/to-page', $settings)['reason'], 'relative redirect followed safely');
eq('redirect_loop', $probe->check('https://example.com/to-loop', $settings)['reason'], 'redirect loop');
$redirectRules = $settings;
$redirectRules['blocked_url_terms'] = ['unsafe.example'];
eq('blocked_url_term', $probe->check('https://example.com/to-intermediate', $redirectRules)['reason'],
    'local content rules must also prevent redirect hops reaching forbidden destinations');

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

// A HEAD 200 must never hide the actual GET redirect chain.
$getCalls = [];
$getRedirect = new HttpProbe(
    static fn(string $host): array => ['8.8.8.8'],
    static function (string $url, array $ips, string $method, array $cfg) use (&$getCalls): array {
        $getCalls[] = [$url, $method];
        if ($method === 'HEAD') return ['http_code' => 200];
        if (str_contains($url, '/get-to-good')) {
            return ['http_code' => 302, 'location' => 'https://good.example/done'];
        }
        if (str_contains($url, '/get-to-blocked')) {
            return ['http_code' => 302, 'location' => 'https://bad.example/x'];
        }
        if (str_contains($url, '/get-to-private')) {
            return ['http_code' => 302, 'location' => 'http://127.0.0.1/secret'];
        }
        if (str_contains($url, '/get-to-loop')) {
            return ['http_code' => 302, 'location' => '/get-to-loop'];
        }
        return ['http_code' => 200];
    }
);
$getRules = Policy::settings(['blocked_domains' => ['bad.example'], 'block_root_urls' => false]);
eq('http_success', $getRedirect->check('https://example.com/get-to-good', $getRules)['reason'],
    'GET-only allowed redirect chain is followed');
eq('blocked_domain', $getRedirect->check('https://example.com/get-to-blocked', $getRules)['reason'],
    'GET-only blocked redirect is rejected');
eq('private_address', $getRedirect->check('https://example.com/get-to-private', $getRules)['reason'],
    'GET-only private redirect is rejected before outbound requests');
eq('redirect_loop', $getRedirect->check('https://example.com/get-to-loop', $getRules)['reason'],
    'GET-only redirect loop terminates');
eq(true, !array_filter($getCalls, static fn(array $call): bool => $call[1] === 'HEAD'),
    'Actual reachability always uses GET, never HEAD');
eq(true, !array_filter($getCalls, static fn(array $call): bool => str_contains($call[0], '127.0.0.1')),
    'No request reaches a private redirect destination');

$oldBacktrack = ini_get('pcre.backtrack_limit');
$oldRecursion = ini_get('pcre.recursion_limit');
$oldJit = ini_get('pcre.jit');
$evilPattern = '~^https://example[.]com/(a+)+$~';
$evilInput = 'https://example.com/' . str_repeat('a', 600) . '!';
eq(null, Policy::boundedPatternMatch($evilPattern, $evilInput),
    'Expensive valid operator PCRE returns inconclusive under bounded budget');
eq(null, Policy::boundedPatternMatch('~example~', 'https://example.com/' . str_repeat('a', 70000)),
    'Long input consumes no unbounded operator PCRE work');

eq($oldBacktrack, ini_get('pcre.backtrack_limit'), 'PCRE backtrack setting restored');
eq($oldRecursion, ini_get('pcre.recursion_limit'), 'PCRE recursion setting restored');
eq($oldJit, ini_get('pcre.jit'), 'PCRE JIT setting restored');
eq(false, Policy::boundedPatternMatch('~[.]example[.]com/never~', $evilInput),
    'Normal regex nonmatch works');
eq(true, Policy::boundedPatternMatch('~^https://example[.]com/~', $evilInput),
    'Normal regex match works');
$regexSettings = Policy::settings([
    'block_root_urls' => false, 'blocked_domains' => [],
    'blocked_url_patterns' => [$evilPattern],
]);
eq('regex_unavailable', Policy::inspect($evilInput, $regexSettings)['reason'],
    'Monitor reports the PCRE resource failure instead of a clean allow');
eq('unknown', Policy::inspect($evilInput, $regexSettings)['status'],
    'Monitor keeps PCRE uncertainty visible');
$longRegexUrl = 'https://example.com/' . str_repeat('x', 70000);
eq('regex_unavailable', Policy::inspect($longRegexUrl, $regexSettings)['reason'],
    'Large destination URL yields explicit regex uncertainty, not a hidden allow');
eq('policy_pass', Policy::inspect($longRegexUrl, $regexSettings, false)['reason'],
    'No general maximum is imposed on a long destination URL without PCRE evaluation');

$regexSettings['unknown_action'] = 'deny';
eq('deny', Policy::inspect($evilInput, $regexSettings)['status'],
    'Strict operator unknown policy denies PCRE failure');
eq('policy_pass', Policy::inspect($evilInput, $regexSettings, false)['reason'],
    'Cheap local policy can bypass regex for work admission');
$regexProbeCalls = 0;
$budgetProbe = new HttpProbe(
    static fn(string $host): array => ['8.8.8.8'],
    static function () use (&$regexProbeCalls): array {
        $regexProbeCalls++;
        return ['http_code' => 200];
    }
);
$monitorRegex = $regexSettings;
$monitorRegex['unknown_action'] = 'allow';
eq('unknown', $budgetProbe->check($evilInput, $monitorRegex)['status'],
    'Redirect/network probe must preserve PCRE budget uncertainty');
eq(0, $regexProbeCalls, 'PCRE exhaustion prevents outbound network requests');
eq('deny', $budgetProbe->check($evilInput, $regexSettings)['status'],
    'Strict unknown policy denies before network requests');


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
function yourls_sanitize_keyword($keyword, $restrict = false): string {
    return $restrict ? strtolower(preg_replace('/[^a-zA-Z0-9-]/', '', (string) $keyword)) : (string) $keyword;
}
function yourls_create_nonce($action): string {return 'fake-test-nonce';}
function yourls_verify_nonce($action, $nonce = false): void {global $lastNonce; $lastNonce = $nonce;}
function yourls_register_plugin_page($slug, $title, $function): void {}
function yourls_admin_url($path = ''): string { return 'https://local.example/admin/' . $path; }
$nativeFloodChecks = 0;
function yourls_check_IP_flood(string $ip = ''): bool {
    global $nativeFloodChecks;
    $nativeFloodChecks++;
    if ($ip === 'blocked-by-native') {
        throw new RuntimeException('native_flood_denied');
    }
    return true;
}
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
$fakeOptions['ach_url_guard_settings'] = ['mode' => 'monitor', 'block_root_urls' => false, 'blocked_domains' => []];
$limitFail = ach_url_guard_on_create($sentinel, 'https://example.com/valid-page', 'abcdefghijklmnopqrstu');
eq('error:ach_url_guard:keyword_too_long', $limitFail['code'], 'length cap enforced in Monitor');
eq('400', $limitFail['errorCode'], 'alias length failure uses HTTP 400');
eq($sentinel, ach_url_guard_on_create($sentinel, 'https://example.com/valid-page', 'abcdefghijklmnopqrst'), 'exactly 20 characters allowed');
$fakeOptions['ach_url_guard_settings']['blocked_short_keywords'] = ['support'];
eq($sentinel, ach_url_guard_on_create($sentinel, 'https://example.com/valid-page', 'SUPPORT'), 'Monitor does not block reserved alias');
$fakeOptions['ach_url_guard_settings']['mode'] = 'enforce';
$blockedShort = ach_url_guard_on_create($sentinel, 'https://example.com/valid-page', 'SUPPORT');
eq('error:ach_url_guard:blocked_short_keyword', $blockedShort['code'], 'Enforce rejects reserved alias');
$fakeOptions['ach_url_guard_settings']['max_custom_keyword_length'] = 0;
eq($sentinel, ach_url_guard_on_create($sentinel, 'https://example.com/valid-page', 'abcdefghijklmnopqrstu'), '0 turns off the alias cap');
$_SERVER['REQUEST_METHOD'] = 'GET';
ob_start();
ach_url_guard_admin_page();
$adminHtml = ob_get_clean();
eq(true, strpos($adminHtml, 'Monitor only') !== false, 'admin has monitor setting');
eq(true, strpos($adminHtml, 'name="max_custom_keyword_length"') !== false,
    'alias length cap visibly configurable in admin settings');
eq(true, strpos($adminHtml, 'Enforce: reject definite violations') !== false, 'admin has enforcement setting');
eq(true, strpos($adminHtml, 'Web Risk API key:') !== false, 'admin displays key readiness');
eq(true, strpos($adminHtml, 'Recent sampled decisions') !== false, 'admin shows audit evidence');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['ach_url_guard_save' => '1', 'mode' => 'enforce', 'blocked_domains' => 'invalid domain', 'root_exceptions' => '', 'dnsbl_zones' => ''];
ob_start(); ach_url_guard_admin_page(); $badHtml = ob_get_clean();
eq(true, strpos($badHtml, 'Invalid settings') !== false, 'invalid rule is visible to operator');
eq('enforce', $fakeOptions['ach_url_guard_settings']['mode'], 'enforce mode unchanged by invalid input');
$_POST = ['ach_url_guard_save' => '1', 'nonce' => 'fake-test-nonce', 'mode' => 'enforce',
    'blocked_domains' => '.Bad.Example', 'root_exceptions' => '', 'dnsbl_zones' => '',
    'blocked_url_patterns' => '/[broken/'];
ob_start(); ach_url_guard_admin_page(); $badPatternHtml = ob_get_clean();
eq(true, strpos($badPatternHtml, 'blocked_url_patterns') !== false, 'invalid regex shown, no settings saved');
eq('enforce', $fakeOptions['ach_url_guard_settings']['mode'], 'invalid regex preserves previous settings');
$_POST = ['ach_url_guard_save' => '1', 'nonce' => 'fake-test-nonce', 'mode' => 'monitor',
    'blocked_domains' => '.Bad.Example', 'root_exceptions' => '', 'dnsbl_zones' => '',
    'blocked_url_terms' => 'casino', 'blocked_url_patterns' => '~/(?:sale|offer)~i',
    'blocked_short_keywords' => 'SUPPORT', 'max_custom_keyword_length' => '25'];
ob_start(); ach_url_guard_admin_page(); $okHtml = ob_get_clean();
eq(true, strpos($okHtml, 'Settings saved') !== false, 'admin saves valid rules');
eq('fake-test-nonce', $lastNonce, 'admin passes explicit POST nonce to YOURLS verifier');
eq(['.bad.example'], $fakeOptions['ach_url_guard_settings']['blocked_domains'], 'stored rule canonicalized');
eq(25, $fakeOptions['ach_url_guard_settings']['max_custom_keyword_length'], 'max alias length saved from admin');
eq(['casino'], $fakeOptions['ach_url_guard_settings']['blocked_url_terms'], 'URL phrases saved from admin');
eq(['~/(?:sale|offer)~i'], $fakeOptions['ach_url_guard_settings']['blocked_url_patterns'], 'PCRE patterns saved from admin');
eq(['SUPPORT'], $fakeOptions['ach_url_guard_settings']['blocked_short_keywords'], 'reserved aliases saved from admin');


// WorkGate shares a small anonymous file state across requests for optional
// expensive checks. No customer URL or source IP may appear in those files.
$gateDir = rtrim(sys_get_temp_dir(), '/') . '/ach-yourls-work-test-' . bin2hex(random_bytes(5));
$gateSettings = Policy::settings(['reachability_enabled' => true, 'blocked_domains' => []]);
$workCount = 0;
$work = static function () use (&$workCount): array {
    $workCount++;
    return ['status' => 'deny', 'reason' => 'http_not_found', 'host' => 'test.example'];
};
$client = '203.0.113.171';
$first = WorkGate::evaluate('https://example.com/a?secret=NO_LEAK', $gateSettings, 'test-secret',
    $work, $client, 15, false, $gateDir, 1000);
eq('http_not_found', $first['reason'], 'First expensive URL validation is admitted');
eq(1, $workCount, 'First expensive evaluation executed once');
$cached = WorkGate::evaluate('https://example.com/a?secret=NO_LEAK', $gateSettings, 'test-secret',
    $work, $client, 15, false, $gateDir, 1001);
eq('http_not_found', $cached['reason'], 'Rejected URL is coalesced from a cached verdict');
eq(1, $workCount, 'Repeated denied URL does not repeat external work');
$deferred = WorkGate::evaluate('https://example.com/b', $gateSettings, 'test-secret',
    $work, $client, 15, false, $gateDir, 1002);
eq('work_deferred', $deferred['reason'], 'Changing URL within native flood delay defers cost');
eq('unknown', $deferred['status'], 'Default policy does not introduce a hard user block');
eq(1, $workCount, 'Different rejected URL cannot amplify paid work');
$strict = $gateSettings;
$strict['unknown_action'] = 'deny';
$strictDecision = WorkGate::evaluate('https://example.com/c', $strict, 'test-secret',
    $work, $client, 15, false, $gateDir, 1003);
eq('deny', $strictDecision['status'], 'Strict unknown policy applies to deferred work');
$adm = WorkGate::evaluate('https://example.com/c', $strict, 'test-secret',
    $work, $client, 15, true, $gateDir, 1003);
eq('http_not_found', $adm['reason'], 'Privileged client exempt from admission deferral');
eq(2, $workCount, 'Admin can execute costly checks during non-admin busy period');
$anotherClient = WorkGate::evaluate('https://example.com/b', $gateSettings, 'test-secret',
    $work, '203.0.113.172', 15, false, $gateDir, 1004);
eq('http_not_found', $anotherClient['reason'], 'Distinct client can work independently');
eq(3, $workCount, 'Independent IP gets a fresh evaluation');
$expired = WorkGate::evaluate('https://example.com/b', $gateSettings, 'test-secret',
    $work, $client, 15, false, $gateDir, 1016);
eq('http_not_found', $expired['reason'], 'Expiry follows native configured flood delay');
eq(4, $workCount, 'Expired admission permits work');
$unavailable = WorkGate::evaluate('https://example.com/d', $gateSettings, 'test-secret',
    $work, $client, 15, false, __FILE__, 1017);
eq('work_control_unavailable', $unavailable['reason'], 'Unwritable admission path is uncertainty');
eq(4, $workCount, 'Unwritable admission path never causes unlimited paid calls');
try {
    WorkGate::evaluate('https://example.com/new', $gateSettings, 'test-secret',
        $work, 'blocked-by-native', 15, false, $gateDir, 1018);
    throw new RuntimeException('Native flood guard was bypassed');
} catch (RuntimeException $exception) {
    eq('native_flood_denied', $exception->getMessage(),
        'Original YOURLS flood admission executes before expensive work');
}
eq(4, $workCount, 'Native rejection prevents expensive work');
$gateFiles = glob($gateDir . '/b-*') ?: [];
eq(true, $gateFiles !== [], 'Bounded private bucket files exist');
foreach ($gateFiles as $file) {
    $savedGate = (string) file_get_contents($file);
    eq(false, str_contains($savedGate, 'NO_LEAK'), 'No URL token stored in work-control file');
    eq(false, str_contains($savedGate, $client), 'No raw client IP stored in work-control file');
    unlink($file);
}
rmdir($gateDir);
eq(true, $nativeFloodChecks >= 9, 'Preflight reused the native flood function');

printf("PASS %d assertions, offline, no live data altered\n", $tests);
