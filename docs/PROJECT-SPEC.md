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
  than definitely malicious or missing. Validate the actual bounded GET
  redirect chain, including each per-hop URL, DNS and IP policy; HEAD 200
  does not establish safety of GET.
- Bound operator-configured PCRE match work, recursion and evaluated input
  size. Report budget exhaustion as an explicit unknown rather than a clean
  nonmatch; never impose a global maximum destination URL length.
- Before costly PCRE, DNS, HTTP or provider checks on the pre-flood shunt,
  reuse YOURLS native flood admission, and coalesce repeated rejected work.
  Defer other costly work during the native delay without imposing an
  unrelated rate limit; honor native private-admin/IP exemptions. Deferred
  decisions follow the established operator unknown policy. Store only
  hashed fingerprints, unique per-admission generation IDs and small verdicts
  in bounded private temporary state, never full URLs/keys or extra
  schema/cron state. Completions must verify that the exact generation owns
  the active entry, preventing stale results from overwriting newer work.
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
  regex syntax/atomic admin save and resource budgeting, reserved aliases,
  GET-only redirect behavior, native API HTTP status, and intact existing
  links. Rapid fixture creation disables native flood only for that phase;
  separate tests enable real native flood delay and verify cross-process
  work admission. Deterministic overlapping tests cover stale allow versus
  newer deny, stale deny versus newer allow, different fingerprints, normal
  caching, expiry and original caller results. PR CI must assert literal
  candidate SHA and GitHub tree,
  never substitute the synthetic merge commit for exact-HEAD evidence.
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
