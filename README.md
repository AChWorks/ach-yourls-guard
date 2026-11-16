# ACh URL Guard for YOURLS

An independent YOURLS plugin for safer creation of **new** short links. The implementation uses the supported `shunt_add_new_link` hook rather than modifying YOURLS core or depending on a fixed internal version. Validated with PHP 8.4/8.5 syntax and offline tests and the actual YOURLS 1.10.6 hook dispatcher. Full database-backed E2E and independent security approval are separate delivery gates. See [project specification](docs/PROJECT-SPEC.md).

**No existing short links are ever deleted, modified, blocked on redirect, or rewritten by this plugin.** It does not change existing user credentials, admin login, branding, `Random ShortURLs`, `Allow Hyphens`, or the YOURLS database schema.

## Features

- Exact hostname denylist (not substring matching); explicit `example.com`, `.example.com` and `*.example.com` matching.
- Disallow destination URLs whose effective path is empty or root (`/`, `/?x=1`, `/./`, `/%2e/`). Configurable exceptions for known trustworthy sites.
- URL syntax and public HTTP(S) only; reject embedded credentials and clearly private/local/reserved IPs, including ambiguous numeric-IP encodings.
- Optional reachability check using bounded HEAD, with GET fallback for HEAD-rejecting sites. `404/410` is a clear negative; `403`, `429`, `5xx`, DNS timeout and provider errors are **inconclusive**, not proof of malware or a missing page.
- Follow redirects in application code and independently inspect each destination host and resolved IP; no automatic cURL redirects, no HTTP proxy, verify TLS and stop downloading bodies after a small sample. This helps prevent SSRF and private-network access.
- Optional **Google Web Risk Lookup** for malware, social engineering and unwanted software. Check original and intermediate/final redirected URLs. Requires an operator-supplied API key and billing-enabled Google Cloud project; does **not** attempt to create or provision a vendor account.
- Optional domain DNSBL checking against operator-specified DNSBL zones, never deleting links or changing redirection behavior.
- Simple YOURLS admin settings page with monitoring/enforcement, separate uncertainty handling, domain rules, network controls and recent sampled decision events (host/reason/URL hash only, no full URL or query tokens). Entries of the same reason and mode are sampled per UTC second across hosts, limiting repeated DB option writes in abusive traffic. Sampling is best-effort under concurrent requests and is not a complete audit trail.
- A separate, read-only CLI tool to batch-audit historical links. Neither batch scanning nor ongoing scheduled checks are started automatically.

## Defaults and production gate

New installations default to **Monitor only**, with root-path rule prepared but *not enforced*, reachability checks off, DNSBL off, Web Risk off, and no blocked domains. This avoids silently restricting public creation or adding external costs. To deploy actual protections, the operator must explicitly select **Enforce** and enable the desired checks. `unknown_action=allow` remains the default; to reject unverified destinations, an operator can choose strict unknown handling, acknowledging that bot-protected sites might be falsely rejected.

In enforcement mode, clearly invalid URLs and explicit denylist/known-threat matches are rejected. Uncertain network/provider results follow the operator's selected policy.

## Domain rule examples

```
bad.example
.bad.example
*.bad.example
```

The first line matches only the apex, the second matches apex plus children, and the third matches only children. Lines beginning with `#` are comments. The `root_exceptions` list uses exactly the same grammar. Blacklisted-domain rules take precedence over root exceptions. A URL with no path but query parameters counts as root. Domain matching is case-insensitive, but path and query strings are not altered.

## Google Web Risk

Official Lookup endpoint: `GET https://webrisk.googleapis.com/v1/uris:search` with `MALWARE`, `SOCIAL_ENGINEERING` and `UNWANTED_SOFTWARE` threat types. A successful non-listed result means **not currently on these lists**, not guaranteed safe. API errors are inconclusive, never assumed safe. URL information (including full path/query) is transmitted to Google when this feature is enabled.

Add the API key to the private, non-public YOURLS `user/config.php` configuration (outside the plugin directory):

```php
define('ACH_URL_GUARD_WEB_RISK_KEY', getenv('ACH_URL_GUARD_WEB_RISK_KEY') ?: '');
```

Provision the secret through the host's existing protected environment/secret mechanism, not in a repository or shell history. The key is never displayed by the admin page and is not written to the recent-event log.

**Billing:** the official Web Risk Lookup pricing page currently states 100,000 `uris.search` calls per month free, with charges beyond that threshold. Confirm the provider's current terms and budget before enabling. This plugin deliberately does not run bulk scans or schedule vendor requests automatically.

Google Safe Browsing API is restricted to non-commercial use; this package does **not** silently use that API.

## Installation and activation

1. Review/test this package, then place the entire directory as `user/plugins/ach-url-guard/` in the intended YOURLS installation. Keep the existing three active plugins unchanged.
2. PHP syntax-check the package; inspect its file ownership and permissions.
3. Enable **ACh URL Guard** from YOURLS **Manage Plugins**. Its default is monitoring; normal link creation and existing redirects must still work.
4. Open **Plugins → ACh URL Guard**. Configure the root rule, denylist, optional reachability and external providers. Review monitoring output before moving to **Enforce**.
5. Test representative allowed, root-only, blocked-domain, known 404, HTTPS and redirect cases, including an existing short link and administrator login.
6. To roll back, deactivate the plugin through YOURLS or rename its directory if the admin page becomes unavailable. It does not mutate existing link records. Any persistent monitoring options may be retained without affecting the site.

**Do not deploy to a production host without the host owner's explicit approval for that exact operation.** In particular, enabling automatic rejections or an externally billed API is a separate policy decision from installing a plugin in monitor mode.

## Inspect old links (read-only)

Run from the installed plugin path, using the private CLI session:

```bash
php bin/audit.php --site=/www/acdomains/lrl.li --limit=200 --after=LAST_KEYWORD
```

Options: `--network` checks HTTPS reachability; `--reputation` uses Google Web Risk if a key is configured. These flags can generate external requests/costs; without them it is purely a structural/domain-policy audit. Results are CSV on STDOUT; progress and next cursor go to STDERR. By default this scans a finite batch of 200, and the operator can choose their own batch size. Protect exported CSV because destination URL query strings may contain sensitive material.

**No cron is installed; no existing URLs are automatically deleted or blocked.**

## Tests

```bash
php -l plugin.php
find src bin tests -name '*.php' -type f -exec php -l {} \;
php tests/run.php
php tests/curl-safety-contract.php
YOURLS_SOURCE=/path/to/YOURLS-1.10.6 php tests/yourls-hook-contract.php
```

Coverage includes root-only URLs, exact/wildcard rules, private/reserved addresses, numeric aliases, dangerous redirect targets, valid redirects, HEAD/GET fallback, HTTP error handling, Google Web Risk and DNSBL mocks, unknown handling, and the YOURLS shunt/monitor/enforce contract. Network calls are mocked in the test harness, so no outside URLs are fetched. The cURL transport tests explicitly verify that failed option configuration never executes a network request and that DNS pinning, TLS and proxy restrictions are selected. The hook contract uses the actual upstream YOURLS filter implementation, without an active database.

## Relationship to Force Lowercase

This plugin **does not** normalize the path/keyword portion of lrl.li short URLs. If mixed-case custom keywords are needed, separately install the maintained official [`YOURLS/force-lowercase`](https://github.com/YOURLS/force-lowercase) plugin and run integration tests with `Random ShortURLs`, `Allow Hyphens`, `YOURLS_URL_CONVERT=36`, and existing aliases. The destination URL path can legitimately be case-sensitive and must never be lowercased.

## Limitations

- HTTP status is not a definitive existence/quality or safety oracle. Authentication, geo-blocking, anti-bot challenges, rate limiting and transient failures can make good sites appear unavailable.
- Google Web Risk and DNSBL have limited list coverage and may have false positives/negatives. They cannot guarantee that a link will never trigger Google Search Console or Cloudflare warnings. Reported abuse and malicious existing links still require operational review and service-provider reconsideration.
- This v0.1.0 only offers manual, read-only scanning of previously created URLs. It does not deploy background jobs, create new tables, implement automated takedown, manage Search Console, or change Cloudflare settings.
- Internationalized domain names should be supplied in standard ASCII/Punycode form. No extra composer dependencies or vendor packages are required.
- CIDR safety checks use protocol/IANA special-purpose network assignments, independently of PHP's incomplete reserved-address flags; these safety boundaries may require maintenance when authoritative registries change.
- HTTP redirect checking does not render JavaScript or execute a browser. JS-only redirects cannot be inferred reliably from an HTTP header.

## Upstream references

- YOURLS Plugin API: https://yourls.org/docs/development/plugins
- Google Web Risk Lookup API: https://docs.cloud.google.com/web-risk/docs/lookup-api
- Web Risk pricing: https://cloud.google.com/web-risk/pricing
- Google Safe Browsing Terms: https://developers.google.com/safe-browsing/terms
