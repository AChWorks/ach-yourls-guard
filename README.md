# ACh URL Guard for YOURLS

An independent YOURLS plugin for safer creation of **new** short links. The implementation uses the supported `shunt_add_new_link` hook rather than modifying YOURLS core or depending on a fixed internal version. Validated with PHP 8.4/8.5 syntax and offline/cURL-contract tests, and against a disposable YOURLS 1.10.6 + MariaDB installation with real HTTP API, redirects and the three existing plugin types. Independent security review and authorized Production rollout remain separate delivery gates. See [project specification](docs/PROJECT-SPEC.md).

**No existing short links are ever deleted, modified, blocked on redirect, or rewritten by this plugin.** It does not change existing user credentials, admin login, branding, `Random ShortURLs`, `Allow Hyphens`, or the YOURLS database schema.

## Features

- **Custom short keyword length:** maximum characters for a user-chosen alias after the domain (default **20**, `0` disables); enforced in Monitor and Enforce, without capping full destination URLs or generated short aliases.
- Editable exact/apex/subdomain denylist (`example.com`, `.example.com`, `*.example.com`).
- Local operator-managed plain-text URL phrases, optional full-URL PCRE regex patterns, and exact reserved custom short keywords; no external provider or rule feed required.
- Disallow destination URLs whose effective path is empty or root (`/`, `/?x=1`, `/./`, `/%2e/`). Configurable exceptions for known trustworthy sites.
- URL syntax and public HTTP(S) only; reject embedded credentials and clearly private/local/reserved IPs, including ambiguous numeric-IP encodings.
- Optional reachability check using bounded HEAD, with GET fallback for HEAD-rejecting sites. `404/410` is a clear negative; `403`, `429`, `5xx`, DNS timeout and provider errors are **inconclusive**, not proof of malware or a missing page.
- Follow redirects in application code and independently inspect each destination host and resolved IP; no automatic cURL redirects, no HTTP proxy, verify TLS and stop downloading bodies after a small sample. This helps prevent SSRF and private-network access.
- Optional **Google Web Risk Lookup** for malware, social engineering and unwanted software. Check original and intermediate/final redirected URLs. Requires an operator-supplied API key and billing-enabled Google Cloud project; does **not** attempt to create or provision a vendor account.
- Optional domain DNSBL checking against operator-specified DNSBL zones, never deleting links or changing redirection behavior.
- Simple YOURLS admin settings page with monitoring/enforcement, separate uncertainty handling, domain rules, network controls and recent sampled decision events (host/reason/URL hash only, no full URL or query tokens). Entries of the same reason and mode are sampled per UTC second across hosts, limiting repeated DB option writes in abusive traffic. Sampling is best-effort under concurrent requests and is not a complete audit trail.
- A separate, read-only CLI tool to batch-audit historical links. Neither batch scanning nor ongoing scheduled checks are started automatically.

## Defaults and production gate

New installations default to **Monitor** for destination-safety rules, with root-path checks prepared, reachability off, DNSBL off and Web Risk off. The editable starter domain denylist contains `.bit.ly`, `.tinyurl.com`, `.cutt.ly` and `.is.gd` to discourage nested shortened links. These are popular URL shorteners, **not a verified list of malicious sites**. They are only blocked when an operator enables **Enforce**, and all entries can be removed. Destination phrase/regex rules also follow Monitor/Enforce.

**Exception:** the requested custom short alias cap defaults to **20 characters** and is enforced in **both Monitor and Enforce**. It measures the YOURLS-sanitized keyword after the domain, not the destination URL length. Setting `max_custom_keyword_length` to `0` disables this added cap, leaving native YOURLS keyword validation intact. The operator must explicitly choose **Enforce** before any domain/URL-safety rules reject newly submitted destinations. `unknown_action=allow` remains the default; strict handling of unverifiable URLs is optional and may cause false positives.

In enforcement mode, clearly invalid URLs and explicit denylist/known-threat matches are rejected. Uncertain network/provider results follow the operator's selected policy.

## Domain rule examples

```
bad.example
.bad.example
*.bad.example
```

The first line matches only the apex, the second matches apex plus children, and the third matches only children. Lines beginning with `#` are comments. The `root_exceptions` list uses exactly the same grammar. Blacklisted-domain rules take precedence over root exceptions. A URL with no path but query parameters counts as root. Domain matching is case-insensitive, but path and query strings are not altered.

## Local phrase, Regex and reserved-keyword rules

The YOURLS admin page exposes three additional multiline inputs:

- **Blocked phrases within destination URLs:** one literal phrase per line. For instance, `casino` also matches `CASINO` anywhere in the destination hostname, path or query, including once-percent-decoded text. This is substring matching, so choose terms carefully to avoid false positives.
- **Blocked destination URL patterns (Regex):** one complete PHP/PCRE pattern per line, including delimiters. Example: `~^https?://(?:[^/]+\.)?example\.com/ads(?:/|$)~i`. The entire URL and once-decoded URL are checked. Invalid regex syntax is rejected on save without partially updating the settings. Patterns are an advanced trusted-admin option: overly broad or expensive patterns can reject legitimate links or consume CPU. Empty by default.
- **Reserved custom short keywords:** one exact short alias per line, such as `support`. In Enforce, `lrl.li/support` is blocked, but `lrl.li/supporters` is not. The alias length cap is separate. Empty by default.

Lines beginning with `#` are ignored as comments. All rules are local, editable, use no external API and only examine newly created links (and redirect hops when reachability checking is enabled). Existing links and redirect behavior are not altered.

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
4. Open **Plugins → ACh URL Guard**. Review the editable starter denylist, set the custom short alias cap (20 by default, 0 to disable), and optionally add local phrase/Regex/reserved alias rules. Review URL safety events in Monitor before selecting **Enforce**.
5. Test representative allowed, root-only, blocked-domain, known 404, HTTPS and redirect cases, including an existing short link and administrator login.
6. To roll back, deactivate the plugin through YOURLS or rename its directory if the admin page becomes unavailable. It does not mutate existing link records. Any persistent monitoring options may be retained without affecting the site.

**Do not deploy to a production host without the host owner's explicit approval for that exact operation.** In particular, enabling automatic rejections or an externally billed API is a separate policy decision from installing a plugin in monitor mode.

## Inspect old links (read-only)

Run from the installed plugin path, using the private CLI session:

```bash
php bin/audit.php --site=/path/to/yourls --limit=200 --after=LAST_KEYWORD
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
YOURLS_SOURCE=/path/to/YOURLS-1.10.6 FORCE_LOWERCASE_SOURCE=/path/to/force-lowercase bash tests/db-integration.sh
```

Coverage includes the default anti-chaining domain rules, custom alias cap in Monitor/Enforce and 0-disable behavior, local URL terms/Regex and reserved aliases, invalid admin-rule rejection and real HTTP API status checks, as well as root-only URLs, exact/wildcard rules, private/reserved addresses, numeric aliases, dangerous redirect targets, valid redirects, HEAD/GET fallback, HTTP error handling, Google Web Risk and DNSBL mocks, unknown handling, and the YOURLS shunt/monitor/enforce contract. Network calls are mocked in the test harness, so no outside URLs are fetched. The cURL transport tests explicitly verify that failed option configuration never executes a network request and that DNS pinning, TLS and proxy restrictions are selected. The hook contract uses the actual upstream YOURLS filter implementation, without an active database. The separate database/HTTP integration test installs actual YOURLS 1.10.6 into a disposable MariaDB instance and isolated site, loads Random ShortURLs, Allow Hyphens, Force Lowercase and ACh URL Guard, verifies monitoring/enforcement, authenticated HTTP API allow/deny and HTTP status, existing/new redirect targets, protected admin settings, and compares a full database snapshot before/after the read-only historical audit. It never fetches an external test URL or points at Production.

The integration script requires `mariadb-install-db`, `mariadbd`, PHP with `pdo_mysql` and `mysqli`, plus the two source checkouts. It uses an auto-generated local socket-only database and a private temporary directory (`TMPDIR` can select a filesystem with sufficient space), and tears down its resources on completion. GitHub Actions uses a loopback-only MariaDB service in the same test. The disposable fixture sets YOURLS's documented flood delay to zero to permit repeated rapid test creations; this does not change the site's anti-flood policy or the plugin code.

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
