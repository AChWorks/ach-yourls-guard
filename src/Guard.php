<?php
declare(strict_types=1);

namespace ACh\Yourls\UrlGuard;

/**
 * Evaluation pipeline. Never deletes, rewrites, scans all existing links, or
 * changes a redirect. A created-link decision is distinct from redirect policy.
 */
final class Guard
{
    /** @var HttpProbe */
    private $probe;
    /** @var WebRisk */
    private $risk;
    /** @var DomainDnsbl */
    private $dnsbl;

    public function __construct(?HttpProbe $probe = null, ?WebRisk $risk = null, ?DomainDnsbl $dnsbl = null)
    {
        $this->probe = $probe ?? new HttpProbe();
        $this->risk = $risk ?? new WebRisk();
        $this->dnsbl = $dnsbl ?? new DomainDnsbl();
    }

    /** @return array{status:string,reason:string,host?:string,details?:array} */
    public function evaluate(string $url, array $settings, string $webRiskKey = ''): array
    {
        $settings = Policy::settings($settings);
        $policy = Policy::inspect($url, $settings);
        if ($policy['status'] !== 'allow') {
            return $policy;
        }
        $unknowns = [];
        $host = $policy['host'];

        if ($settings['dnsbl_enabled'] && $settings['dnsbl_zones'] !== []) {
            $dns = $this->dnsbl->lookup($host, $settings['dnsbl_zones']);
            if ($dns['status'] === 'deny') {
                return ['status' => 'deny', 'reason' => $dns['reason'], 'host' => $host, 'details' => $dns];
            }
            if ($dns['status'] === 'unknown') {
                $unknowns[] = $dns['reason'];
            }
        }

        $checkRisk = function (string $candidate) use ($settings, $webRiskKey, $host, &$unknowns): ?array {
            $result = $this->risk->lookup($candidate, $webRiskKey, $settings['request_timeout_seconds']);
            if ($result['status'] === 'deny') {
                return ['status' => 'deny', 'reason' => $result['reason'], 'host' => $host, 'details' => $result];
            }
            if ($result['status'] === 'unknown') {
                $unknowns[] = $result['reason'];
            }
            return null;
        };
        if ($settings['web_risk_enabled']) {
            if ($found = $checkRisk($url)) {
                return $found;
            }
        }

        if ($settings['reachability_enabled']) {
            $probe = $this->probe->check($url, $settings);
            if ($probe['status'] === 'deny') {
                return ['status' => 'deny', 'reason' => $probe['reason'], 'host' => $host, 'details' => $probe];
            }
            if ($probe['status'] === 'unknown') {
                $unknowns[] = $probe['reason'];
            }
            if ($settings['web_risk_enabled']) {
                $checked = [$url => true];
                $candidates = array_merge($probe['chain'] ?? [], [(string) ($probe['final_url'] ?? $url)]);
                foreach ($candidates as $candidate) {
                    if ($candidate === '' || isset($checked[$candidate])) {
                        continue;
                    }
                    $checked[$candidate] = true;
                    if ($found = $checkRisk($candidate)) {
                        return $found;
                    }
                }
            }
        }

        if ($unknowns !== []) {
            return [
                'status' => $settings['unknown_action'] === 'deny' ? 'deny' : 'unknown',
                'reason' => $settings['unknown_action'] === 'deny' ? 'unverifiable_destination' : 'uncertain_destination',
                'host' => $host,
                'details' => ['uncertainties' => array_values(array_unique($unknowns))],
            ];
        }
        return ['status' => 'allow', 'reason' => 'checks_passed', 'host' => $host];
    }
}
