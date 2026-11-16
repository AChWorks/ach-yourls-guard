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
  children only). Optionally reject bare/root destinations, including root
  with query arguments, with explicit exceptions.
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

- Default to Monitor; enabling Enforce and denying unknown outcomes need
  explicit owner policy approval after monitoring.
- Google APIs and external DNSBL requests remain disabled; no vendor
  signup, new credentials, billing, silent external calls or cron jobs.
- No guarantee against future Cloudflare or Google reputation flags.
  Operators remain responsible for handling reports of abuse.
- Preserve the lrl.li homepage, branding, other plugins, credentials,
  database schema and every existing short URL.

## Delivery and approval boundaries

- Require PHP 8.5 and YOURLS 1.10.6 compatibility evidence, targeted
  security/SSRF/redirect/permission tests and exact-candidate CI.
- Require an independent review before integrating or deploying security code.
- Production Target ach-host-aapanel permits read-only inspection, but every
  potentially state-changing operation requires new, specific owner approval.
  A previous general installation request does not replace this requirement.
- An authorized rollout installs only the reviewed plugin and activates
  Monitor. External APIs, Enforce, background scans and destructive changes
  need their applicable separate decision and grant.
- Verify artifact identity and old-link behavior; roll back by deactivating
  this plugin alone, without restoring nonexistent legacy backups.

Git/GitHub own code identity and review; checks own test results;
Production observation owns installed-state claims. Never store secrets,
customer URL query data or database dumps in GitHub.
