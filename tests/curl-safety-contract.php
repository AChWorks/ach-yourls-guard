<?php
declare(strict_types=1);

/**
 * Safety contract for the real HttpProbe/WebRisk transport code without
 * connecting to any host. Namespace function overrides intercept cURL.
 */
namespace ACh\Yourls\UrlGuard {
    $curlChecks = [
        'fail_array' => false,
        'fail_protocols' => false,
        'executed' => 0,
        'options' => [],
        'protocols' => [],
    ];
    function curl_init($url) { return (object) ['url' => $url]; }
    function curl_setopt_array($ch, array $opts) {
        global $curlChecks;
        $curlChecks['options'] = $opts;
        return !$curlChecks['fail_array'];
    }
    function curl_setopt($ch, $option, $value) {
        global $curlChecks;
        $curlChecks['protocols'][$option] = $value;
        return !$curlChecks['fail_protocols'];
    }
    function curl_exec($ch) {
        global $curlChecks;
        $curlChecks['executed']++;
        return 'OK';
    }
    function curl_getinfo($ch, $option) { return 200; }
    function curl_errno($ch) { return 0; }
}

namespace {
    require dirname(__DIR__) . '/src/Policy.php';
    require dirname(__DIR__) . '/src/HttpProbe.php';
    require dirname(__DIR__) . '/src/Reputation.php';

    use ACh\Yourls\UrlGuard\HttpProbe;
    use ACh\Yourls\UrlGuard\WebRisk;

    $asserts = 0;
    function ok($condition, string $message): void {
        global $asserts;
        $asserts++;
        if (!$condition) throw new \RuntimeException($message);
    }

    $settings = ['connect_timeout_seconds' => 2, 'request_timeout_seconds' => 5];
    $GLOBALS['curlChecks']['fail_array'] = true;
    $failure = HttpProbe::requestOnce('https://example.com/path', ['8.8.8.8'], 'HEAD', $settings);
    ok($failure['error'] === 'curl_configuration_failed', 'Failed CURLOPT_RESOLVE must fail closed.');
    ok($GLOBALS['curlChecks']['executed'] === 0, 'No request on failed cURL options.');
    $GLOBALS['curlChecks']['fail_array'] = false;
    $GLOBALS['curlChecks']['fail_protocols'] = true;
    $failure = HttpProbe::requestOnce('https://example.com/path', ['8.8.8.8'], 'HEAD', $settings);
    ok($failure['error'] === 'curl_protocol_configuration_failed', 'Failed scheme restriction must fail closed.');
    ok($GLOBALS['curlChecks']['executed'] === 0, 'No request when protocol restriction is refused.');
    $GLOBALS['curlChecks']['fail_protocols'] = false;
    $response = HttpProbe::requestOnce('https://example.com/path', ['8.8.8.8'], 'GET', $settings);
    ok($response['http_code'] === 200, 'Working cURL path remains usable.');
    ok($GLOBALS['curlChecks']['executed'] === 1, 'A configured request executes.');
    ok($GLOBALS['curlChecks']['options'][CURLOPT_RESOLVE] === ['example.com:443:8.8.8.8'], 'Public IP is pinned.');
    ok($GLOBALS['curlChecks']['options'][CURLOPT_FOLLOWLOCATION] === false, 'Automatic redirects disabled.');
    ok($GLOBALS['curlChecks']['options'][CURLOPT_SSL_VERIFYPEER] === true, 'TLS certificate chain verified.');
    ok($GLOBALS['curlChecks']['options'][CURLOPT_SSL_VERIFYHOST] === 2, 'TLS hostname verified.');
    ok($GLOBALS['curlChecks']['options'][CURLOPT_PROXY] === '', 'Proxy override disabled.');
    ok($GLOBALS['curlChecks']['options'][CURLOPT_NOPROXY] === '*', 'Environment proxies bypassed.');
    ok($GLOBALS['curlChecks']['protocols'] !== [], 'HTTP(S) protocols explicitly constrained.');

    // Optional Web Risk is currently disabled by product policy, but if it is
    // ever enabled, TLS/proxy option failure must not trigger unsafe network.
    $GLOBALS['curlChecks']['fail_array'] = true;
    $before = $GLOBALS['curlChecks']['executed'];
    $risk = WebRisk::transport('https://webrisk.googleapis.com/v1/uris:search', 5);
    ok($risk['http_code'] === 0, 'Web Risk fails closed on cURL configuration error.');
    ok($before === $GLOBALS['curlChecks']['executed'], 'No Web Risk request without security options.');
    echo "PASS $asserts cURL security contract assertions (no network)\n";
}
