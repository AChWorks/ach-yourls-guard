# ACh URL Guard for YOURLS

An independent YOURLS plugin for safer creation of **new** short links. The implementation uses the supported `shunt_add_new_link` hook rather than modifying YOURLS core or depending on a fixed internal version. Validated with PHP 8.4/8.5 syntax and offline/cURL-contract tests, and against a disposable YOURLS 1.10.6 + MariaDB installation with real HTTP API, redirects and the three existing plugin types. Independent security review and authorized Production rollout remain separate delivery gates. See [project specification](docs/PROJECT-SPEC.md).

**Published packages:** [GitHub Releases](https://github.com/AChWorks/ach-yourls-guard/releases/latest). A published release does not mean it has been installed on any particular YOURLS site.

**Existing short links are never automatically deleted, modified, blocked on redirect or rewritten.** The authenticated admin page can remove a reviewed individual link **or a frozen set matching explicitly approved filters**. Filtered bulk deletion does not require reviewing each link individually, but requires a complete dry-run and explicit final confirmation. Starting bulk review creates one indexed candidate table plus small job records in YOURLS options. It does not alter YOURLS core schema, admin credentials, branding, or existing plugins.

## Features

- **Custom short keyword length:** configurable **minimum** (default **0**, disabled) and **maximum** (default **20**, `0` disables either bound) for newly submitted custom aliases after the domain. Both bounds apply in Monitor and Enforce, without capping destination URLs, generated aliases or existing redirects.
- Editable exact/apex/subdomain denylist (`example.com`, `.example.com`, `*.example.com`).
- Local operator-managed plain-text URL phrases, optional full-URL PCRE regex patterns, and exact reserved custom short keywords; no external provider or rule feed required.
- Disallow destination URLs whose effective path is empty or root (`/`, `/?x=1`, `/./`, `/%2e/`). Configurable exceptions for known trustworthy sites.
- URL syntax and public HTTP(S) only; reject embedded credentials and clearly private/local/reserved IPs, including ambiguous numeric-IP encodings.
- Optional reachability check using bounded GET (a HEAD 200 can conceal GET-only redirects). `404/410` is a clear negative; `403`, `429`, `5xx`, DNS timeout and provider errors are **inconclusive**, not proof of malware or a missing page.
- Follow redirects in application code and independently inspect each destination host and resolved IP; no automatic cURL redirects, no HTTP proxy, verify TLS and stop downloading bodies after a small sample. This helps prevent SSRF and private-network access.
- Optional **Google Web Risk Lookup** for malware, social engineering and unwanted software. Check original and intermediate/final redirected URLs. Requires an operator-supplied API key and billing-enabled Google Cloud project; does **not** attempt to create or provision a vendor account.
- Optional domain DNSBL checking against operator-specified DNSBL zones, never deleting links or changing redirection behavior.
- Simple YOURLS admin settings page with monitoring/enforcement, separate uncertainty handling, domain rules, network controls and recent sampled decision events (host/reason/URL hash only, no full URL or query tokens). Entries of the same reason and mode are sampled per UTC second across hosts, limiting repeated DB option writes in abusive traffic. Sampling is best-effort under concurrent requests and is not a complete audit trail.
- An admin-only historical review page with per-link HTTP checks, **Select all visible**, **Select all matching filters across all pages**, and manual single or explicitly confirmed bulk deletion. Bulk operations are keyset-paginated, restartable, and never delete new candidates outside the completed dry-run snapshot.
- A separate, read-only CLI tool to batch-audit historical links, including optional network/provider checks. Neither batch scanning nor ongoing scheduled checks are started automatically.

## Defaults and production gate

New installations default to **Monitor** for destination-safety rules, with root-path checks prepared, reachability off, DNSBL off and Web Risk off. The editable starter domain denylist contains `.bit.ly`, `.tinyurl.com`, `.cutt.ly` and `.is.gd` to discourage nested shortened links. These are popular URL shorteners, **not a verified list of malicious sites**. They are only blocked when an operator enables **Enforce**, and all entries can be removed. Destination phrase/regex rules also follow Monitor/Enforce.

**Exception:** newly submitted custom short alias length bounds are enforced in **both Monitor and Enforce**. The minimum defaults to **0 (disabled)** and the maximum to **20**. They count characters in the YOURLS-sanitized alias after the domain, not URL bytes or the destination URL length. Setting `min_custom_keyword_length` or `max_custom_keyword_length` to `0` disables that respective limit, leaving native YOURLS keyword validation intact. When the maximum is enabled, the minimum cannot exceed it. For example, setting the minimum to **5** rejects new custom aliases shorter than five characters with HTTP 400 but does not invalidate existing or automatically generated short codes. The operator must explicitly choose **Enforce** before any domain/URL-safety rules reject newly submitted destinations. `unknown_action=allow` remains the default; strict handling of unverifiable URLs is optional and may cause false positives.

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
- **Blocked destination URL patterns (Regex):** one complete PHP/PCRE pattern per line, including delimiters. Example: `~^https?://(?:[^/]+\.)?example\.com/ads(?:/|$)~i`. The entire URL and once-decoded URL are checked. Invalid regex syntax is rejected on save without partially updating the settings. Runtime evaluation temporarily caps PCRE backtracking to 10,000, recursion depth to 1,000 and evaluated input to 64 KiB per pattern, restoring PHP INI values afterward. Exceeding a budget is reported as `regex_unavailable` and follows the chosen `unknown_action`; it is **not** a general destination URL length limit. Patterns are an advanced trusted-admin option; overly broad rules can still reject legitimate links. Empty by default.
- **Reserved custom short keywords:** one exact short alias per line, such as `support`. In Enforce, `lrl.li/support` is blocked, but `lrl.li/supporters` is not. The minimum/maximum custom alias length bounds are separate. Empty by default.

Lines beginning with `#` are ignored as comments. All rules are local, editable, use no external API and apply automatically only to newly created links (and reachable redirect hops when configured). The historical admin page can also inspect old links on demand. Existing redirects are unchanged unless an administrator manually confirms deletion of that exact link.

## Expensive-validation work admission

The new-link shunt runs before YOURLS's native flood check. Before optional expensive Regex, DNS, HTTP or Web Risk evaluation, ACh URL Guard now calls the native YOURLS flood check and uses its **configured flood delay** for cost admission (rather than introducing a new unrelated rate limit). It coalesces repeated identical rejected checks and defers different costly checks from the same non-exempt client within that interval. Each admitted verification has an independent random generation ID; the result is cached only if that exact admission still owns the state, so a slow previous attempt cannot overwrite a newer in-flight or completed attempt. Cheap local domain, phrase, root and URL-structure denials remain immediately enforceable.

Deferred checks are explicitly recorded as `work_deferred`, not treated as clean passes. Their acceptance/rejection follows the existing `unknown_action` setting: the default is unverified/allowed; the operator-selected strict mode temporarily rejects with HTTP 503. Authenticated private admins and native whitelisted IPs remain exempt; native delay 0 deliberately disables this admission budget.

Temporary admission state is private, bounded (256 buckets x 32 anonymous client identities), under PHP's writable temporary directory, outside the YOURLS document root. Only keyed IP fingerprints, request fingerprints, per-admission generation IDs and small verdicts are stored, never raw IPs, URLs, query tokens or API keys. No new table, cron or external provider. If safe shared temporary storage is unavailable, `work_control_unavailable` is visible under the same unknown policy rather than silently executing unlimited costly operations. Check temporary-directory writability before opting in to costly validation.

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
4. Open **Plugins → ACh URL Guard**. Review the editable starter denylist, configure custom short alias minimum (0 disables) and maximum (20 by default, 0 disables), and optionally add local phrase/Regex/reserved alias rules. Review URL safety events in Monitor before selecting **Enforce**.
5. Test representative allowed, root-only, blocked-domain, known 404, HTTPS and redirect cases, including an existing short link and administrator login. For older links, open **Plugins → ACh URL Guard — Historical Review** to preview them without changing their targets.
6. To roll back the Guard's automatic new-link policy, deactivate the plugin through YOURLS or rename its directory if the admin page becomes unavailable. Manual historical deletions, once explicitly confirmed, are **not** undone by deactivation; arrange your site's normal recoverable backups before using that feature. Any persistent monitoring options may be retained without affecting the site.

**Do not deploy to a production host without the host owner's explicit approval for that exact operation.** In particular, enabling automatic rejections or an externally billed API is a separate policy decision from installing a plugin in monitor mode.

## Review older links (admin page; manual deletion)

Open **YOURLS admin → Plugins → ACh URL Guard — Historical Review** (also linked from Guard settings). This page shows a cursor-paginated, read-only evaluation of **every existing link in the selected page** against the *current* local destination and reserved-alias rules. A positive local match is a **review candidate**, not proof of malware; a homepage-only URL or a rule term could be legitimate. The default scan does not perform DNSBL, Web Risk or HTTP requests and does not record private query tokens in its HTML.

For links with no definite local violation, **Check HTTP** performs a bounded GET/redirect/DNS/SSRF check and reports definite failure (HTTP 404/410) versus inconclusive outcomes (403/429/5xx, timeout). Explicit **HTTP 404/410**, **Private DNS address** and **Invalid redirect** bulk filters are supported, each requiring the same outbound HTTP/DNS consent checkbox. Each network-derived filter examines at most one link per request during preview and again before deletion; mixed private DNS answers are rejected before any HTTP connection, and invalid redirects are not followed. This can be slow for large selections; DNSBL and Web Risk are not used.

Only definite violations offer **Review deletion** followed by an explicit confirmation checkbox and **Delete this short link permanently**. The selected row, authoritative stored policy and definite reason are rechecked under a database transaction immediately before deleting; changed or no-longer-flagged rows are preserved even if another administrator saved policy settings while a slow HTTP check was running. Deletion uses YOURLS's native function and therefore follows YOURLS's normal cache, hook, and click-log behavior. **There is no unapproved auto-delete, scheduled scan, redirect-time blocking, or restore button.** Reverting plugin settings/deactivating the plugin will not restore manually deleted links. Do not use the button without site-owner authorization and a tested recovery path.

### Filtered bulk selection (large datasets)

Use **Filter and select existing links**. Choose **Only checked rows on this page** (including the **Select all visible** checkbox), or **Select All Matching Filters across every page**. Filters: definite policy reason, any/zero/positive clicks, exact destination host, short-keyword prefix and created-before date. Unknown/uncertain results and historic/generated aliases outside either new-link custom length bound do not authorize deletion.

**Preview** performs a restartable keyset dry-run in small requests, creating one indexed private candidate table that stores only job ID, exact keyword, HMAC row snapshot, definite reason and processing outcome. No plaintext destination paths or query tokens are saved in these candidate records. Per-job progress/cursor and owner identity are saved in YOURLS options. The completed preview shows the exact matched count. Before deletion, the admin must check a confirmation box and type **DELETE N**, where N is the displayed matched count. Only previously snapshotted candidates can be deleted; new records are never substituted. Each attempt rechecks the current link, original proof, stored policy, metadata filter and reason; changed, healthy, or unknown records are skipped. Even if a slow HTTP verification started when the link had **zero clicks**, a concurrent click before the URL row lock prevents deletion under the zero-click filter. Date, keyword prefix and host criteria are also rechecked under the row lock, without holding a lock during network I/O.

Execution works in bounded batches while the browser is open, with progress and a bookmarkable resume link. **Pause automatic continuation** stops only the browser's next submission and can be resumed from the saved job; **Cancel job permanently** puts that job into a terminal cancelled state and cannot resume it. Closing the browser pauses further requests. Neither cancellation nor deactivation restores deletions already committed. Completed/cancelled/paused report metadata can be cleared separately without touching short URLs.

**Network-derived bulk filters (HTTP 404/410, Private DNS address, Invalid redirect):** require explicit acknowledgment for outbound DNS/HTTP verification; check one destination per request during preview and again before deletion, with no DNSBL/Google API usage. It may require many browser requests for large datasets. The admin is responsible for deciding if a 404 is genuine; 403/429/5xx/timeouts and all other unknown results cannot authorize bulk removal.

Use a tested backup and specific Production permission before permanent deletion. Native YOURLS delete hooks may have external effects not reversible by a database rollback. The job report does not store a full destination-URL export.

The review **table** shows only destination hostnames, not URL paths, embedded credentials or query values. After the authenticated admin explicitly selects **Review deletion** for one exact link, its confirmation shows both the full short URL and the full original destination URL (which may contain private tokens). The display measures the available rendered width: values that fit stay intact, while overflowing values stay on one line with a visible middle `[...]` and an exact trailing suffix (also for Unicode); Copy preserves the full address. URLs are displayed as inert text, never automatically opened, and are not written to logs or bulk job records. Avoid sharing screenshots of a confirmation containing sensitive destinations.

## Inspect old links (read-only CLI)

Run from the installed plugin path, using the private CLI session:

```bash
php bin/audit.php --site=/path/to/yourls --limit=200 --after=LAST_KEYWORD
```

Options: `--network` checks HTTPS reachability; `--reputation` uses Google Web Risk if a key is configured. These flags can generate external requests/costs; without them it is purely a structural/domain-policy audit. Results are CSV on STDOUT; progress and next cursor go to STDERR. By default this scans a finite batch of 200, and the operator can choose their own batch size. Protect exported CSV because destination URL query strings may contain sensitive material.

**No cron is installed; no existing URLs are automatically deleted or blocked.** Historical deletion occurs only via a separately confirmed admin action.

## Tests

```bash
php -l plugin.php
find src bin tests -name '*.php' -type f -exec php -l {} \;
php tests/run.php
php tests/curl-safety-contract.php
php tests/workgate-concurrency.php
php tests/history-review.php
php tests/bulk-history.php
YOURLS_SOURCE=/path/to/YOURLS-1.10.6 php tests/yourls-hook-contract.php
YOURLS_SOURCE=/path/to/YOURLS-1.10.6 FORCE_LOWERCASE_SOURCE=/path/to/force-lowercase bash tests/db-integration.sh
```

Coverage includes the default anti-chaining domain rules, custom alias cap in Monitor/Enforce and 0-disable behavior, local URL terms/Regex and reserved aliases, invalid admin-rule rejection and real HTTP API status checks, as well as root-only URLs, exact/wildcard rules, private/reserved addresses, numeric aliases, dangerous redirect targets, GET-only redirect validation, HTTP error handling, Google Web Risk and DNSBL mocks, unknown handling, and the YOURLS shunt/monitor/enforce contract. Network calls are mocked in the test harness, so no outside URLs are fetched. The cURL transport tests explicitly verify that failed option configuration never executes a network request and that DNS pinning, TLS and proxy restrictions are selected. The hook contract uses the actual upstream YOURLS filter implementation, without an active database. Additional historical review regressions verify paginated previews, non-secret HTML, stale-record/rule protection, nonce and confirmation handling, and deliberate fixture-only native deletion. The separate database/HTTP integration test installs actual YOURLS 1.10.6 into a disposable MariaDB instance and isolated site, loads Random ShortURLs, Allow Hyphens, Force Lowercase and ACh URL Guard, verifies monitoring/enforcement, authenticated HTTP API allow/deny and HTTP status, existing/new redirect targets, protected admin settings, and compares a full database snapshot before/after the read-only historical audit. It never fetches an external test URL or points at Production.

The responsive Historical Review renderer also has a synthetic browser fixture
`tests/history-layout-fixture.php` and an isolated Playwright regression
`tests/history-layout-browser.mjs` covering one-line shortening and exact-value
copying at nine viewport widths. These tests use no live YOURLS URLs and are
not part of the PHP-only CI jobs.

The integration additionally proves repeated rejected checks are coalesced and other expensive requests are deferred across separate PHP processes with the **actual native YOURLS 15-second flood delay**; it verifies no YOURLS database mutations from this admission state.

A deterministic Fiber-based regression test suspends two overlapping verifications past the native delay, checks both allow/deny orders and different request fingerprints, and asserts that older completion cannot replace a newer working or completed verdict. It also verifies normal caching, expiry, original caller results and cleanup, without real network requests or timing sleeps.

The integration script requires `mariadb-install-db`, `mariadbd`, PHP with `pdo_mysql` and `mysqli`, plus the two source checkouts. It uses an auto-generated local socket-only database and a private temporary directory (`TMPDIR` can select a filesystem with sufficient space), and tears down its resources on completion. GitHub Actions uses a loopback-only MariaDB service in the same test. The disposable fixture sets YOURLS's documented flood delay to zero to permit repeated rapid test creations; this does not change the site's anti-flood policy or the plugin code.

CI checks out the **literal PR HEAD** rather than GitHub's synthetic merge commit and asserts both its commit SHA and GitHub API tree SHA in each PHP matrix job.

## Relationship to Force Lowercase

This plugin **does not** normalize the path/keyword portion of lrl.li short URLs. If mixed-case custom keywords are needed, separately install the maintained official [`YOURLS/force-lowercase`](https://github.com/YOURLS/force-lowercase) plugin and run integration tests with `Random ShortURLs`, `Allow Hyphens`, `YOURLS_URL_CONVERT=36`, and existing aliases. The destination URL path can legitimately be case-sensitive and must never be lowercased.

## Limitations

- HTTP status is not a definitive existence/quality or safety oracle. Authentication, geo-blocking, anti-bot challenges, rate limiting and transient failures can make good sites appear unavailable.
- Google Web Risk and DNSBL have limited list coverage and may have false positives/negatives. They cannot guarantee that a link will never trigger Google Search Console or Cloudflare warnings. Reported abuse and malicious existing links still require operational review and service-provider reconsideration.
- Since v0.2.0, the plugin supports individually confirmed deletion and operator-approved filtered bulk deletion. A plugin-owned candidate table is created on the first bulk preview, and small resume/progress records are stored in YOURLS options. There is no autonomous background worker, cron, Search Console or Cloudflare integration.
- Internationalized domain names should be supplied in standard ASCII/Punycode form. No extra composer dependencies or vendor packages are required.
- CIDR safety checks use protocol/IANA special-purpose network assignments, independently of PHP's incomplete reserved-address flags; these safety boundaries may require maintenance when authoritative registries change.
- HTTP redirect checking does not render JavaScript or execute a browser. JS-only redirects cannot be inferred reliably from an HTTP header.

## Upstream references

- YOURLS Plugin API: https://yourls.org/docs/development/plugins
- Google Web Risk Lookup API: https://docs.cloud.google.com/web-risk/docs/lookup-api
- Web Risk pricing: https://cloud.google.com/web-risk/pricing
- Google Safe Browsing Terms: https://developers.google.com/safe-browsing/terms
