# ACh URL Guard — Project Specification

## Outcome

Reduce abusive, malicious and broken destinations created through the lrl.li
YOURLS shortener while protecting legitimate creation, site reputation, existing
redirects and customer data.

## Accepted behavior

- Use a maintainable YOURLS plugin, not edits to the YOURLS core. New-link
  creation through the normal YOURLS function must receive consistent policy
  evaluation across public, admin and API paths.
- Validate URL structure, public HTTP(S) destinations and configurable
  reachability. Evaluate each redirect and DNS answer before network access;
  pin approved IP addresses against rebinding.
- Maintain admin-managed domain rules (exact apex, apex plus children, or
  children only); a small editable starter set of well-known URL shorteners
  is monitored by default, not represented as a verified malicious list.
  Support operator-defined literal URL phrases, validated full-URL PCRE,
  and exact reserved custom short aliases. Optionally reject bare/root
  destinations, including root with query arguments, with explicit exceptions.
- Enforce a configurable maximum length for user-chosen short aliases,
  default 20 characters and 0 to disable, even in Monitor. Measure the
  YOURLS-sanitized alias; never cap target URL lengths, generated codes
  or existing aliases.
- Consider confirmed HTTP 404/410 meaningful absence. Treat 403/429/5xx,
  authentication challenges and network failure as inconclusive rather
  than definitely malicious or missing.
- Preserve native YOURLS anti-flood and interoperability with Random ShortURLs,
  Allow Hyphens and Force Lowercase, existing aliases and case-sensitive URL paths.
- Offer bounded manual read-only auditing of older links, no automatic
  deletion, rewriting, blocking on redirect, background scans or migrations.
- Record privacy-preserving, diagnostic, bounded observations without leaking
  URL query tokens, credentials or costly excessive log/database writes.

## Settled policy / non-goals

- Default to Monitor for destination safety; only the deterministic custom
  alias length cap is immediately enforced. Domain/phrase/Regex/reserved alias
  rules are observational until Enforce. Enabling Enforce and denying unknown
  outcomes need explicit owner policy approval after monitoring.
- Google APIs and external DNSBL requests remain disabled; no vendor
  signup, new credentials, billing, silent external calls or cron jobs.
- No guarantee against future Cloudflare or Google reputation flags.
  Operators remain responsible for handling reports of abuse.
- Preserve the lrl.li homepage, branding, other plugins, credentials,
  database schema and every existing short URL.

## Delivery and approval boundaries

- Require PHP 8.5 and YOURLS 1.10.6 compatibility evidence, targeted
  security/SSRF/redirect/permission tests and exact-candidate CI. Acceptance
  includes a disposable MariaDB-backed installation with the three existing
  plugin types, real loopback authenticated API/redirect checks, valid admin
  form nonce and historical-audit read-only database snapshot. Validate the
  custom alias cap, zero disable, default denylist behavior, URL phrases,
  regex syntax/atomic admin save, reserved aliases, native API HTTP status,
  and intact existing links. The flood-delay override is fixture-only;
  the actual product retains native anti-flood.
- Require an independent review before integrating or deploying security code.
- Production environments permit only explicitly authorized operations;
  every potentially state-changing operation requires specific owner approval.
  A previous general installation request does not replace this requirement.
- An authorized rollout installs only the reviewed plugin and activates
  Monitor. External APIs, Enforce, background scans and destructive changes
  need their applicable separate decision and grant.
- Verify artifact identity and old-link behavior; roll back by deactivating
  this plugin alone, without restoring nonexistent legacy backups.

Git/GitHub own code identity and review; checks own test results;
Production observation owns installed-state claims. Never store secrets,
customer URL query data or database dumps in GitHub.
