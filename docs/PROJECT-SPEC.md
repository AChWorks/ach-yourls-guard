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
- Offer bounded historical auditing: read-only CLI batches and an authenticated,
  cursor-paginated native YOURLS admin page showing the current local policy
  outcome and reason without exposing sensitive URL query data. Permit explicit
  per-link HTTP verification only on operator request; never scan external
  destinations, DNSBL or Web Risk simply by opening the admin page.
- Provide individual manual review and operator-approved **filtered bulk
  deletion**. Selection supports visible-page checkboxes/Select All and all
  matching a set of filters across every page, without individual inspection.
  A complete dry-run materializes exact candidate row proofs in an indexed
  plugin table, plus small owner-bound progress records in YOURLS options.
  Require a typed count and checkbox to confirm permanent deletion; support
  restartable keyset batches, stop, progress and saved resume link.
- On explicit single-link review by an authenticated admin, show full short and
  destination URLs (which may include private query tokens) as inert text,
  abbreviating long display labels in one line with `[...]`. Provide full-value
  Copy without fetching the destination. Keep full destinations absent from the
  default review table, bulk snapshots, reports and ordinary logs.
- Recheck each candidate's exact stored row, effective policy, reason, filter
  and CSRF authorization before native YOURLS deletion. Skip changed, healthy
  or unknown candidates and never substitute later links for snapshotted
  candidates. Historical/generated alias length alone is not a delete reason.
  Network-derived HTTP 404/410, private DNS and invalid-redirect bulk filters
  must be explicitly opted into. Bound verification to one target per request,
  repeat the network check before deletion, and recheck click count (plus date,
  keyword prefix and host) on the locked URL row in both local/network modes
  without performing HTTP under a row lock. No DNSBL/Google scans merely by
  opening the admin page.
- No unattended auto-delete, scheduled worker/cron, redirect-time block or
  unrelated site mutation. Permanent deletion requires an authenticated admin
  and specific approval. One plugin-owned candidate table is created on first
  bulk review without altering YOURLS core tables.
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
  YOURLS core tables and existing links except those individually or as a
  frozen candidate set explicitly deleted by an authenticated admin. A
  plugin-owned candidate snapshot table is permitted for scalable review.

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
