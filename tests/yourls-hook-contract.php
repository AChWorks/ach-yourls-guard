<?php
declare(strict_types=1);

/**
 * Exercises the actual YOURLS 1.10.6 filter dispatcher and add-link shunt.
 * No database, network, credentials, or existing URL records are touched.
 */
$source = getenv('YOURLS_SOURCE') ?: dirname(__DIR__, 2) . '/upstream-yourls';
$source = realpath($source);
if ($source === false || !is_file($source . '/includes/functions-shorturls.php')) {
    fwrite(STDERR, "Set YOURLS_SOURCE to a YOURLS 1.10.6 source tree.\n");
    exit(2);
}
define('YOURLS_ABSPATH', $source);
require $source . '/includes/functions-plugins.php';
require $source . '/includes/functions-shorturls.php';

$options = ['ach_url_guard_settings' => ['mode' => 'monitor', 'block_root_urls' => true]];
$pages = [];
function yourls_get_option($name, $default = false) { global $options; return $options[$name] ?? $default; }
function yourls_update_option($name, $value) { global $options; $options[$name] = $value; }
class FakeDb { public function add_plugin_page($slug, $title, $fn) { global $pages; $pages[$slug] = [$title, $fn]; } }
function yourls_get_db($context = '') { return new FakeDb(); }
function yourls_sanitize_url($url) { return $url; }
function yourls_get_IP() { throw new RuntimeException('reached_native_pipeline'); }

require dirname(__DIR__) . '/plugin.php';
yourls_do_action('plugins_loaded');
$expect = function ($condition, $message) {
    if (!$condition) throw new RuntimeException($message);
};
$expect(isset($pages['ach_url_guard']) && $pages['ach_url_guard'][1] === 'ach_url_guard_admin_page', 'Real hook must register plugin page.');
try {
    yourls_add_new_link('https://example.com/?only=query', 'MiXeD-key', 'A title');
    throw new RuntimeException('Monitor mode shunted native creation.');
} catch (RuntimeException $error) {
    $expect($error->getMessage() === 'reached_native_pipeline', 'Monitor must return actual native shunt sentinel.');
}
$expect(count($options['ach_url_guard_events'] ?? []) === 1, 'Monitor should record the root violation.');
$options['ach_url_guard_settings']['mode'] = 'enforce';
$blocked = yourls_add_new_link('https://example.com/?only=query', 'MiXeD-key', 'A title');
$expect(is_array($blocked) && $blocked['status'] === 'fail', 'Real shunt must return fail payload.');
$expect($blocked['code'] === 'error:ach_url_guard:root_url', 'Fail code must identify root violation.');
$expect($blocked['statusCode'] === '403', 'Enforce must return expected HTTP status.');
$expect(count($options['ach_url_guard_events'] ?? []) === 2, 'Enforce must record the decision.');
$options['ach_url_guard_settings']['mode'] = 'monitor';
try {
    yourls_add_new_link('https://example.com/SomeCaseSensitivePath', 'MiXeD-key', 'A title');
    throw new RuntimeException('Allowed creation was shunted.');
} catch (RuntimeException $error) {
    $expect($error->getMessage() === 'reached_native_pipeline', 'Allowed link must reach YOURLS native code.');
}
$expect(count($options['ach_url_guard_events'] ?? []) === 2, 'Allowed URL should not be counted as violation.');
echo "PASS real YOURLS 1.10.6 shunt contract (no DB)\n";
