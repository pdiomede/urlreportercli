# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.3] - 2026-10-07

Security fixes from an audit of the web app, in code the CLI shares. The version
tracks the web app's 1.1.3, and the User-Agent now reads `urlreporter/1.1.3`.

### Security

- **A scanned site can no longer size a scan's memory or hold it open.** Responses stop at 8 MiB, three scanners read headers only, security.txt reads at most 64 KiB, and every scanner is stopped `SCAN_TIMEOUT_SECONDS` plus 20 s after it started.
- **Markdown report:** a blank line in an error no longer breaks out of its code span, and the registrar link is http(s)-checked.

## [1.1.2] - 2026-10-06

A slow SSL Labs is explained, the User-Agent carries the version, and an unused
setting is gone.

### Added

- **The CLI explains a slow SSL Labs.** Once it is the only scanner left after
  15 seconds, the progress block adds: "SSL Labs is still testing this site: if
  it hasn't tested the site recently, it runs a fresh test, which usually takes
  1-3 minutes." It clears on a terminal when SSL Labs finishes; piped output
  gets it once.

### Changed

- **A timed-out SSL Labs says so plainly.** Its row reads "SSL Labs was still
  testing after 3 minutes, so it isn't included in the grade. Scan again in a
  few minutes to include it." (second sentence omitted when `SSL_LABS_USE_CACHE`
  is off).

- **The User-Agent follows the release.** It was a pinned `urlreporter/0.1`; now
  `urlreporter/<version> (+https://urlreporter.com)` unless `HTTP_USER_AGENT`
  overrides it.

### Removed

- **The `INTERNETNL_API_TOKEN` setting.** It never did anything: internet.nl is
  always a link-out. Leftover lines are ignored.

### Fixed

- **Running timers froze on a terminal.** The block redrew only on scanner start
  or finish, so a row could read "running... 3.4s" for minutes; it now redraws
  every second.

## [1.1.1] - 2026-10-06

Fixes found reviewing 1.1.0, mostly in the reports, crt.sh, RPKI and
security.txt.

### Added

- **`SECURITY.md`**: private vulnerability reporting (security@pdiomede.com),
  scope, safe-harbour terms, acknowledgments. Linked from the README.

### Changed

- **The securityheaders.com row is now called "Security headers".** It was
  really Url Reporter's own grading. Weight stays 1.5; it still links to
  securityheaders.com; `--only security_headers` is unchanged.

### Fixed

- **Three more report bugs.**
  - An SSL Labs assessment error ("Unable to connect to the server") was blamed
    on Url Reporter.
  - Default report filenames used local time, not UTC.
  - `--out Report.HTML --html` wrote both reports to one file on
    case-insensitive macOS and Windows, losing the Markdown.
- **Ten bugs in the Markdown and HTML reports.**
  - Markdown passed raw HTML through: `http://<host>/` lost its `<host>`, a
    `<script>` mention hid the rest of the report, and a site's security.txt
    could inject a live `<img onerror>`. Text is now escaped outside code spans.
  - Printed or saved as PDF, the HTML report showed grades, scores and
    registration details in near-white on white and omitted findings and error
    explanations; print now uses a dark palette and opens them.
  - A report saved after Ctrl-C or a crash looked complete; it now opens with
    "Partial report: N of M scanners did not finish (...)".
  - In Markdown, advice under the tenth and later recommendations left the
    numbered list.
  - An expired or mismatched TLS certificate was explained as a DNS or TCP
    failure; it now says verification failed.
  - The HTML report listed only the first ten recommendations.
  - On a phone the HTML report scrolled sideways (at 375px its scanner table was
    about 450px wide) and cut off long text such as a DKIM key.
- **The README was out of date.** It said the tool sends "a single GET" (it
  sends a few) and that HSTS covers "the domain" (it checks the hostname).
- **RPKI waited on a cosmetic lookup and could fail on odd JSON.** The
  operator-name lookup's default 3/8/20s retries delayed RPKI 31 seconds or more
  when RIPEstat `as-overview` failed; it now gets one short attempt. Non-object
  JSON from DoH or RIPEstat failed the scanner.
- **A refused securityheaders.com grade was misexplained** as a Url Reporter
  fault when the target was also unreachable.
- **crt.sh's fallback claimed too much.** With CertSpotter listing nothing, the
  finding said none was "ever" issued, but it lists unexpired certificates only.
- **The README's `config.env` example lacked `SCANNER_RPKI`,** and "Adding a
  scanner" now names the `explain_score` weight table.
- **crt.sh mis-graded healthy sites and counted one CA as several.**
  - No certificate issued in the last 90 days earned a C with no finding. Such
    sites are now graded on their still-valid certificates; the C stays only
    when all have expired, with a medium finding.
  - Issuers were counted by intermediate name, so Let's Encrypt alone (R10, R11,
    E5, E6) could count as four CAs and cost the A+; they are now counted per
    organisation.
  - The A for three or four issuers now has a low finding explaining it.
- **A failing crt.sh cost every scan about 45 seconds.** On 6 Oct 2026 crt.sh
  returned HTTP 502 throughout, and three retries (3, 8, 20 seconds of backoff)
  preceded the CertSpotter fallback. It now retries once, after 3 seconds, with
  a 20-second timeout, and never after a timeout: crt.sh also stalled about 36
  seconds before a 502.
- **"Top recommendations" was mostly confirmations.** Informational findings
  ("SPF policy is hardfail") no longer count as recommendations. Nothing-to-fix
  sites are told so. SPF softfail (`~all`, 7 points) is now low severity, and a
  CAA record with no `issue` directive (graded C) gets a medium finding.
- **securityheaders.com was called "unreachable" on every scan.** Cloudflare
  answers non-browser clients with HTTP 403 and `cf-mitigated: challenge`, so
  headers are graded locally. The summary now says "graded locally because
  securityheaders.com blocks automated requests (HTTP 403)".
- **security.txt now flags an `Expires` more than a year ahead** (RFC 9116
  recommends under a year), as a low finding costing no points. The example for
  a missing `Expires`, `2027-01-01T00:00:00Z`, would itself expire; it now falls
  inside the coming year.
- **security.txt lost points without saying why.** The optional Policy (+5),
  Encryption (+4) and Acknowledgments (+3) fields were scored silently; a new
  low finding names the missing ones (its example once suggested `Policy:` to a
  file that had one).
- **Link-outs were described as having "no public API".** Output now says
  "link-out (manual check)".
- **`urlreporter explain-score` no longer matched the code.** It cited Mozilla
  Observatory as a directly used score (it is kept inside its letter's band) and
  listed two kinds of skipped result, not three.
- **A RIPEstat refusal was explained as the site refusing to be scanned.** It
  now says RIPEstat rejected the lookup.
- **RPKI: two smaller fixes.** The "Checked N of the M addresses" note now also
  appears when every checked address was unannounced; a prefix announced by two
  networks is listed once.
- **Two defensive fixes:** an off-spec Observatory letter is normalised to the
  letter its score reads as, and a non-text RIPEstat network name no longer
  fails RPKI.
- The README's RPKI row called routes with no ROA "most" of the internet; it now
  says "much".

## [1.1.0] - 2026-10-06

Covers everything since 1.0.12. Minor because scores change: a new graded
scanner joins the average, and letters count for slightly less.

### Added

- **A 13th scanner: RPKI route origin (`rpki`).** Resolves the site's IPv4 and
  IPv6 addresses, asks RIPEstat which prefix and network announce each, then
  whether a signed ROA authorises that pair. All valid is an A+. No ROA is a B:
  much address space has none, and it is usually the host's to fix. A route
  contradicting its ROA is a critical finding and an F. Weighted 1.0. Runs on IP
  targets. No API key; skip with `--only` or `SCANNER_RPKI=false`.

### Fixed

- **The overall grade was a step more generous than its inputs.** Letters became
  numbers through one table (A = 95, B = 80) and averages became letters through
  another (90 or more is A+), so an SSL Labs A alone gave an A+. A letter now
  counts as the top of its band (A = 89, B = 74); `urlreporter explain-score`
  prints the new table. Hand-set letter/score pairs (HSTS Preload, HTTP
  redirect, CAA, crt.sh, security.txt) were reconciled, and Observatory's number
  stays inside its letter's band.
- **The DoS posture check ignored the current rate-limit headers.** It now
  credits the IETF draft's `RateLimit` and `RateLimit-Policy` alongside
  `X-RateLimit-*` and the older `RateLimit-Limit` / `-Remaining` / `-Reset`.
- **A domain that sends no mail was graded B for having no DKIM key.** No MX (or
  a null MX), `v=spf1 -all` and DMARC `p=reject` mean no mail to sign; that
  setup now grades A+ ("Domain sends no mail; DKIM not applicable"). For a
  subdomain, the parent's `sp=` counts.
- **A revoked DKIM key earned full DKIM credit.** An empty `p=` is a revoked key
  (RFC 6376), and a `*._domainkey` wildcard returns one for every selector. Only
  non-empty keys count now.

### Fixed after the first 1.1.0 push

The first push of 1.1.0 (`3f2e22f`) shipped RPKI with these defects, fixed
without a version change.

- **RPKI checked a different sample of addresses on every scan.** It kept the
  first 2 addresses per family in the resolver's rotating order (five scans of
  yahoo.com gave four route sets). Now up to 8 per family are checked in sorted
  order, the summary says when a site has more, and routes with no ROA appear
  once per announcing network.
- **A failed RPKI lookup left sibling requests running** on the closed HTTP
  client; they are now cancelled.
- **A DNS failure on the site was blamed on Url Reporter.** A SERVFAIL on its
  address lookup now gets the usual DNS explanation.
- **A check that does not apply was labelled a link-out.** For an IP target,
  CAA, DNSSEC, HSTS Preload and email auth (and RPKI, for hosts with no or
  unannounced addresses) showed as "link-out (no public API)" with an "Open
  external scan" link in the HTML report. They now read "not applicable" and are
  counted separately. Grades were unaffected.
- **Several unannounced addresses read as one** ("… is not announced").
- **internet.nl's summary implied a token would enable it.** Its batch API terms
  rule out single-site scans, so the row is always a link-out; the summary now
  says so, and a configured token is reported as unused.
- **Mozilla Observatory showed two scores on one line.** The summary printed
  Mozilla's raw number unlabelled ("A (89/100) - HTTP best-practice grade A
  (90/100)", even "(115/100)"). It now says "Mozilla's score 90, counted as 89
  here".
- **An SSL Labs E read back as an F.** The ladder jumped from D- (35 to 39) to
  F. There is now an E rung at 30 to 34 and F starts under 30 (`urlreporter
  explain-score` prints it); only the letter for averages of 30 to 34 changes.
- **SSL Labs' T and M showed a letter the scale doesn't have.** Both count as 0,
  but the row showed "T" or "M", so a T alone became an unexplained overall F.
  The row now shows F, with SSL Labs' letter and reason in its summary ("SSL
  Labs graded T, the certificate is not trusted"), and the endpoint finding
  gives certificate rather than cipher-suite advice. Scores are unchanged.

- **Mozilla Observatory's reason for refusing a site was thrown away.**
  Observatory answers an ungradable site with HTTP 422 and a reason such as
  `site-down` or `unexpected-status-code`; the scanner reported only "returned
  HTTP 422". The error now carries the reason.
- **A one-off `HTTP 4xx` was called "not an HTTP error".** Errors worded
  "<service> returned HTTP NNN" hit a catch-all claiming the scanner "raised an
  exception that wasn't an HTTP or network error". A 4xx is now explained as the
  service refusing the site, or, for DNS scanners, Cloudflare's DoH endpoint
  rejecting the lookup.
- **A SERVFAIL on an email-auth lookup was blamed on Url Reporter.** It now says
  SERVFAIL usually means the domain's own DNS is broken, and points at DNSSEC.

## [1.0.12] - 2026-10-05

The first CLI release since 1.0.5; the web app's 1.0.6 through 1.0.11 had no
CLI-facing changes.

### Fixed

- **A domain that had just enabled DNSSEC was told to enable DNSSEC.** The
  scanner trusted Cloudflare's AD flag alone, and a resolver that cached a zone
  before its DS record reached the parent serves unsigned answers until they
  expire, so for up to an hour a correctly signed zone scored D with "Enable
  DNSSEC at your registrar".

  An unauthenticated answer is now checked, best effort, against Google's
  resolver (`https://dns.google/resolve`) and the parent zone's DS record:

  | Google | DS at parent | Result |
  | --- | --- | --- |
  | validates | — | **A+**, with an info note that Cloudflare disagreed |
  | SERVFAIL | published | **F**: the DS record matches no DNSKEY |
  | not validated, host is a CNAME out of the zone | published | **D**: the alias points into an unsigned zone |
  | not validated | published | **D**, "enabled but not validating yet" |
  | not validated | absent | **D**, "not enabled", unchanged |

  This also fixes zones Cloudflare never marks as validated (`cdc.gov` went from
  D to A+). A failed extra lookup falls back to the previous verdict.

  The hostname now goes to Google's resolver when Cloudflare's answer is
  unvalidated.

### Changed

- **`config.env.example` carries a `GA_MEASUREMENT_ID` key.** It configures web
  analytics; the CLI ignores it.

## [1.0.5] - 2026-09-16

### Fixed (the published CLI package could not import — plus twenty-seven engine defects)

- **`urlreporter` was unusable when installed from this repo.** `urlreporter/registration.py` was added to the package but never to the `ALLOWLIST` in the mirror script that builds this repo, so the published `runner.py` imported a module that was not there. Every invocation died before parsing an argument:

  ```
  File "urlreporter/runner.py", line 14, in <module>
      from .registration import RegistrationInfo, fetch_registration
  ModuleNotFoundError: No module named 'urlreporter.registration'
  ```

  The module is now in the allowlist. Two guards prevent a repeat: the build refuses to publish when any `urlreporter/*.py` in source is absent from the staged tree and not on an explicit `WEB_ONLY` opt-out list, then runs `python3 -c "import urlreporter.cli"` against the staged tree and aborts on failure.

- **A URL carrying another URL was rejected outright** (`urlutil.py`). `normalize_url` branched on `"://" in s`, so `urlreporter scan 'example.com/r?u=https://a.b'` split at the *inner* separator and exited `2` with `Unsupported URL scheme: 'example.com/r?u=https'`. Now anchored on a leading `scheme://`; `ftp://`, `file://`, `data:` and `javascript:` are still rejected.

- **A resolver that refused to answer produced a confident grade** (`scanners/caa.py`). Only network and retry failures counted toward the all-ancestors-failed check, so a non-transient HTTP error from DoH on *every* ancestor fell through to "No CAA records found". Verified: 403 on every lookup yielded `ok=True, grade="D", score=40` — a fabricated grade from zero signal. Now `ok=False`.

- **Edge-cacheable responses were graded on directive order** (`scanners/dos_posture.py`). `_has_useful_cache` inspected only the leftmost freshness directive, so `Cache-Control: max-age=0, s-maxage=3600` scored `False` while `s-maxage=3600, max-age=0` scored `True`. A 25-point swing decided by directive order.

- **One malformed record killed the whole CT scanner** (`scanners/crtsh.py`). A numeric `entry_timestamp` made `ts.replace("Z", "+00:00")` raise `AttributeError`, which the surrounding `except (TypeError, ValueError)` does not catch, aborting the scan instead of skipping the record.

- **Twelve DNS lookups outlived the scanner that gave up on them** (`scanners/email_auth.py`). The ~20 DoH queries run through `asyncio.gather`; without `return_exceptions=True` it completes when one child raises but leaves siblings running against the shared `AsyncClient` the runner then closes. Measured: 12 lookups pending when `scan()` returned. The error string is byte-identical.

- **IPv6 targets crashed two scanners** (`scanners/https_redirect.py`, `scanners/security_txt.py`). `normalize_url` accepts `https://[2001:db8::1]/`, but `urlparse().hostname` drops the brackets and both scanners rebuilt a URL from the bare address, so text after the first colon parsed as a port. httpx raised `httpx.InvalidURL`, which is **not** an `httpx.HTTPError`, so it escaped both `except` clauses.

- **`--out report.html --html` silently destroyed the markdown report** (`cli.py`). `out_path.with_suffix(".html")` collapsed onto `out_path`, so the HTML overwrote the markdown while the CLI printed both success lines. The path you name now keeps the markdown; the HTML goes to `<stem>.report.html`.

- **`ScanResult.link` reached an `href` without a scheme check** (`report.py`). A `javascript:` value would have rendered as a live link in the `--html` report. Not reachable today (every scanner builds `link` from a constant plus a validated host), but it matches `registration._safe_http_url` for RDAP URLs. Legitimate links are unaffected.
- **An unrecognised SSL Labs grade hijacked the verdict and voided the score** (`ssllabs.py:143`). The key `min(grades, key=lambda g: letter_to_score(g) or 0)` collapsed a genuine `F` and a grade absent from `LETTER_TO_SCORE` into zero; the unknown grade won the `min()` and `letter_to_score` then returned `None`. One odd endpoint could decide the verdict *and* silently drop this **weight-2.0** scanner from the average (`aggregate_score` skips `score is None`). Now ranks only interpretable grades, reports the worst *known* one, names any unreadable grade in a finding, and degrades to a link-out when none is interpretable. All ten documented SSL Labs v3 grades are in the table, so this was latent.
- **The most severe duplicate finding was discarded for the first-seen one** (`runner._prioritize`). Findings were deduped by lowercased title *before* the severity sort, so a `critical` from a later scanner was dropped for a `low` with the same title. Now sorts first and dedupes second, as the docstring said; `CLAUDE.md` documented the reverse and is corrected. Byte-identical across 400 randomised no-collision cases, so nothing changes today — no two scanners emit the same title.
- **The report heading's link broke on characters the URL validator accepts** (`report.py`). The markdown heading wraps the URL in a code span and an angle-bracket link destination. A literal `>` ended the destination early, and a backtick closed the code span and took the whole link with it — `https://example.com/?q=%60x%60` rendered with **no link at all**. Backslash escaping is unusable (code spans outrank links in CommonMark), so the destination percent-encodes the few unusable characters, leaving existing `%XX` alone, and the code span uses a backtick fence longer than any run in the URL. Verified against a real markdown engine across seven URL shapes.
- **The parent walk climbed into the public suffix and read the registry's DNS** (`publicsuffix.py`, new; `caa.py`, `email_auth.py`, `registration.py`). Three copies of a "take the last two labels" rule decided where a hostname stops belonging to its owner. Under a multi-label public suffix that is one label too far: `example.co.za` resolved its apex to `co.za`. **Not hypothetical** — `co.za` publishes MX *and* SPF and `com.mx` publishes SPF (verified live over DoH), so a domain under either inherited email authentication it never configured and scored for it on a **weight-2.0** scanner, while the registry's MX suppressed the "not a mail-sending host" link-out. CAA would credit a registry's issuance policy, and RDAP (`www.example.co.uk` asked about `co.uk`) rendered no registration card. All three now share a `publicsuffix` module whose walk stops at the registrable domain; `www.bbc.co.uk` now resolves RDAP to `bbc.co.uk` and renders the card it previously lacked. The list was curated rather than the full PSL, to avoid bundled data ageing inside our pin.
- **Platform subdomains inherited the platform's DNS** (`publicsuffix.py`). The curated list lacked the PSL "private section" — platforms that hand out subdomains. Whoever owns `myapp.vercel.app` does not control `vercel.app`'s DNS, but the walk climbed there. Verified live over DoH: `vercel.app` and `netlify.app` publish SPF **and** DMARC, `github.io` publishes SPF and six CAA records, `amazonaws.com` publishes MX, SPF and DMARC. A scan of the nonexistent `myapp.vercel.app` returned **A+/100 on both CAA and email auth**, entirely on Vercel's records — the more damaging half of the bug, since such hosts are likelier to be scanned than a ccTLD second-level. Now D/40 and F/0.
- **Three-label suffixes were unrepresentable, not merely absent** (`publicsuffix.py`). `public_suffix` compared only the last two labels, so an entry like `s3.amazonaws.com` was never consulted: `bucket.s3.amazonaws.com` matched `amazonaws.com` and left the walk inside `s3.amazonaws.com`, itself a suffix. Now longest-match.
- **Email auth graded a target that has no domain** (`email_auth.py`). An IP literal or bare public suffix owns no SPF, DMARC or DKIM. `https://1.1.1.1` produced a fabricated **F/0** at weight 2.0, masked until the suffix fix because the old walk invented parent names (`1.1.1.1` → `1.1.1` → `1.1`) and tripped the subdomain link-out by accident. Now "not applicable" and excluded from the score.
- **CAA graded the same targets** (`caa.py`). `https://1.1.1.1` reported "No CAA records found" with a **D/40** — a finding about a name that cannot have one. Pre-existing. Now a link-out.
- **CAA stopped climbing at the public suffix, and said so out loud** (`caa.py`, `publicsuffix.py`). A regression from the previous fix in this release: the boundary was applied to CAA as well as SPF/DMARC, but the protocols climb differently. **SPF** (RFC 7208) does not climb; **DMARC** (RFC 7489 §6.6.3) falls back only to the Organizational Domain, defined *using a public suffix list*; **CAA** (RFC 8659 §3) walks `domain -> Parent(domain)` toward the root and does **not** exclude public suffixes. So `vercel.app`'s CAA genuinely constrains `myapp.vercel.app`, and reporting no CAA was false, in the reassuring direction. CAA now uses `ancestor_domains` while email auth keeps `parent_domains`, and a match above the registrable domain adds a finding that the policy is inherited from the platform or registry and is not the owner's to change.
- **HSTS preload graded a target that cannot have HSTS** (`hsts_preload.py`). RFC 6797 §8.1.1 says a user agent MUST NOT apply HSTS to an IP-addressed host, and the preload list holds names only, yet `https://1.1.1.1/` returned **B+/80 "Domain is NOT on the HSTS preload list"**. Now a link-out.
- **DNSSEC told an IP target to check its spelling** (`dnssec.py`). A DoH SOA query for `1.1.1.1` returns NXDOMAIN, rendered as *"The domain does not exist. Check spelling and registration status"*. It was `ok=False`, so the score was safe, but the guidance was wrong. Now a link-out saying DNSSEC signs zones and an IP has none.
- **The public-suffix boundary now uses the real Public Suffix List** (`publicsuffix.py`, `publicsuffixlist>=1.0.2,<2`). The curated table **invented three entries that are not suffixes** (`amazonaws.com`, `k12.us`, `netlify.live`) and **omitted all nine sampled ccTLD families** (`.ug`, `.tz`, `.gh`, `.rw`, `.fj`, `.np`, `.lk`, `.mm`, `.kh`), which fell back to last-two-labels and the original bug.
- **The PSL's PRIVATE section is included deliberately**, and **IP literals are screened before the library sees them**. The ICANN section alone would put the boundary for `myapp.vercel.app` at `vercel.app`, the bug this module prevents. And `PublicSuffixList().privatesuffix("1.1.1.1")` returns `"1.1"`, so delegating without the `is_ip_literal` guard would reopen the fabricated-grade bugs. Both pinned by tests. 35 of 37 existing boundary tests passed unchanged across the swap; the two failures asserted the curated table's own mistakes.
- **IPv6 targets still got a fabricated grade — the same bug, half-fixed** (`publicsuffix.py`). `parent_domains` told "bare public suffix" from "single-label host" by counting dots; an IPv6 literal has none, so `2001:db8::1` was read as a single-label hostname and `email_auth` scored it **F/0 at weight 2.0**, while IPv4 was excluded because `caa` guards with `is_ip_literal` directly. `normalize_url` accepts bracketed IPv6, so this was reachable. IP literals are now screened in every entry point.
- **`public_suffix` returned a confident wrong answer for IP literals** (`publicsuffix.py`). `1.1.1.1` gave `"1"` and `2001:db8::1` gave itself, and it disagreed with `registrable_domain`, which already returned None. Now returns `""`.
- **Malformed names were expanded into queries that cannot resolve** (`publicsuffix.py`). `ancestor_domains("")` returned `[""]` and `ancestor_domains("a..b.com")` returned `['a..b.com', '.b.com', 'b.com']`. `normalize_url` rejects these upstream, but the helpers are called directly.
- **Four entry points normalised their input separately** (`publicsuffix.py`). Each repeated `host.lower().strip().strip(".")`, which is how the IP guard ended up on three of them and not the fourth. One `_clean` helper now.
- **A rate-limited RDAP registry cost 31 seconds of every scan** (`registration.py`, `runner.py`). Found in production logs. `_retry.py` lists 429 as transient, so an RDAP 429 — *you are over quota*, not *try again shortly* — walked the full 3 + 8 + 20 second backoff ladder and failed anyway, and `run_scans` awaits the registration task before the `done` event, so that time landed on the user's clock: a production `.uk` scan reported **32s** when every scanner had finished by **10.3s**. Nominet has 429-ed the production IP since 2026-08-25. RDAP now makes a single attempt (`backoffs=()`), bounded by `REGISTRATION_TIMEOUT_SECONDS = 5.0`. Measured: the rate-limited path went from 31s to **0.03s**; a healthy lookup still returns in 0.7s. A slow registry now costs only its own section.
- **RDAP is now cached per registrable domain** (`registration.py`). Registration data changes about once a year, and re-querying every scan is what earns the HTTP 429 above. Successes are cached for 24h, failures for 10 minutes: a negative entry stops a rate-limiting registry being hit per scan, while the short TTL stops one blip hiding the card for a day. Measured: scans of `www.bbc.co.uk`, `bbc.co.uk/path` and `news.bbc.co.uk` make **one** RDAP call instead of three, and five scans against a 429-ing registry make **one** instead of five. Bounded at 512 entries with prune-then-evict-oldest (an unbounded dict keyed by user input is a slow leak, as `urlutil._DNS_CACHE` was until earlier in this release) and keyed on `time.monotonic()` so a clock step cannot resurrect or freeze an entry.

### Changed (dependency ceiling)

- **`httpx` is now capped at `>=0.27,<1`.** CI resolves dependencies fresh against unbounded `>=` specifiers, so an upstream major release becomes a red build with no commit of ours. All twelve scanners build on `httpx` directly (`AsyncClient`, `Headers`, the `RequestError`/`HTTPStatusError` taxonomy `scanners/_retry.py` branches on), and `respx` pins to it too. The installed 0.28.1 satisfies the bound; nothing else changes.
- **Why now.** `httpx2` is published at 2.13.0, and Starlette 1.0 has begun deprecating `httpx` in favour of it. That does not touch this package (no web framework), but the 0.x line now has a visible successor, so an unbounded `>=` is no longer free.

### Changed (two scanners now score some sites differently)

- **`caa` and `dos_posture` now score some sites differently.** Both are corrections, but grades from before and after this release are not directly comparable.

### Notes

- **Coverage added for the two thinnest scanners**, separately from the fixes — no defect had shipped in either. `mozilla_observatory` went from 1 test to 13 and `internetnl` from 1 to 6, taking the suite from 184 to **201**. Observatory now pins the upper score clamp (bonus points make >100 real), the grade→score fallback (without it the scanner drops out of the average silently while reporting `ok=True`), the severity thresholds ordering "Top recommendations", four malformed `tests` payload shapes, and HTTP/non-JSON errors returning `ok=False`. internetnl asserts **zero** HTTP calls and that a configured token reaches neither report nor logs.
- **`caplog` does not work for `urlreporter.*` loggers in this suite.** `logging_setup.setup_logger()` sets `propagate = False` and `urlreporter.web` calls it at import time, so `caplog` — attached to the *root* logger — captures nothing once any test has imported the web module: a test passes alone and fails in the full suite. Attach a handler to the module's own logger.
- **A stale version string corrected.** `README.md`'s credits footer read `Url Reporter v1.0.4` while its header said v1.0.5; it now reads v1.0.5. Each README's footer is an unnamed further occurrence of the version, so it drifted.
- **The web surface took two further bounds** that do not apply here, since this package ships no `fastapi` or `starlette`: `fastapi>=0.110,<1` and `starlette>=0.46,<2`. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).
- **Packaging and docs only.** The ceiling and footer fix landed after the 1.0.5 tag was pushed and are recorded here, not under a version of their own: no engine, scanner, parser, runner, grading, retry, URL-normalization, report-format or CLI-flag change.
- **Every fix carries a regression test verified to fail against the unfixed code.** The suite grew from 121 tests to 184 through the fixes; further coverage work since took it to 204.
- **CLI-surface scope.** Three fixes touch only the web surface and are absent here: the `POST /scan` concurrency cap, the result-page behaviour when `reports/` is unwritable, and the `safe_link` filter in `templates/result.html`. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).
- **No CLI flag, exit code, config key, or report format changed.** `scan`, `explain-score`, `--config`, `--out`, `--only`, `--quiet`, `--html` and exit codes `0`/`1`/`2`/`130` are unchanged.

## [1.0.4] - 2026-08-23

Backfilled. This release shipped at the time — `pyproject.toml` and
`urlreporter/__init__.py` went to 1.0.4 — but no entry was written, so the log
jumped 1.0.3 → 1.0.5. Reconstructed from the release commit.

### Changed (README is now CLI-only, not a shared document)

- **`README.md` restructured — 143 lines touched, +89/-60.** It had described both surfaces. The **`Web UI`** and **`Architecture`** sections were dropped, **`CLI`** became **`Usage`**, **`Reports`** moved above configuration, and a new **`How it works`** section replaced the architecture prose. Nine lines referencing the web surface (urlreporter.com, the browser UI, `runUrlReporter.sh`, `/stats`, templates) went too; `README_WEB.md` keeps the equivalent.

### Removed (a web-only setting that never applied here)

- **`STATS_HIDE_HOSTNAMES` dropped from `config.env.example`.** It gates hostname display on the web `/stats` dashboard, which this package does not ship. `config.py` still recognises it, so an inherited value is parsed and ignored as before; no behaviour changed.

### Notes

- **No engine, scanner, parser, runner, grading, retry, URL-normalization, or CLI-flag change** between v1.0.3 and v1.0.4. Only four files changed: `README.md`, `config.env.example`, `pyproject.toml`, and `urlreporter/__init__.py` (version string only). Every scanner module, `runner.py`, `report.py`, `grading.py`, `urlutil.py` and `cli.py` are byte-identical across the two tags.
- **The corresponding web release was large.** v1.0.4 split the one-page landing site into six routes with shared Jinja chrome: `index.html` went from 1,960 lines to 79, with `static/site.css` / `static/chrome.css` carved out of its inline `<style>`. None of it reaches this package. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [1.0.3] - 2026-05-26

### Removed (Google Analytics)

- **Google Analytics (GA4) removed from the app.** Deleted `urlreporter/static/gtag-init.js` and the two-line gtag snippet (`<script async src="https://www.googletagmanager.com/gtag/js?id=G-6NCTMMRH1H">` + the `/static/gtag-init.js` loader) from all seven templates: `index.html`, `about.html`, `contact.html`, `score.html`, `scanners.html`, `result.html`, `progress.html`. The app no longer loads `googletagmanager.com`.

### Notes

- **Web-surface-only change.** No engine, scanner, runner, grading, retry, URL-normalization, web-route, or CLI-flag changes. Mirrored in [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [1.0.2] - 2026-05-10

### Changed (unsigned-DNSSEC registration cell now renders an orange warning bar)

- **`urlreporter/report.py:_render_registration_html` updated:** the unsigned-DNSSEC branch (`elif reg.dnssec is False`) now passes `"reg-warning"` as the urgency class instead of an empty string, giving the cell the orange left border and tinted value text of Registrar lock OFF, Registry lock OFF, and the single-nameserver case. It had fallen through to the default gray border despite its cache-poisoning / MITM tooltip warning. Pure visual classification — no data shape, tooltip copy, or CSS change (`.reg-cell.reg-warning` already existed). The web template got the matching change; see [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

### Notes

- **No engine, scanner, parser, runner, grading, retry, URL-normalization, web-route, or CLI-flag change** between v1.0.1 and v1.0.2. The 51-test suite is byte-identical and still passes.
- **Why orange, not red:** red (`reg-critical`) is reserved for stronger cases. Unsigned DNSSEC is in the same "registry-side state worth flagging" tier as locks-off and single-NS, all already orange.

## [1.0.1] - 2026-05-10

### Changed (registry-lock cell now wraps "(out-of-band auth)" to a new line)

- **`urlreporter/report.py:_render_registration_html` updated:** the Registry Lock cell value (both On and Off in `cells_row2`) now uses `via the TLD registry<br>(out-of-band auth)` so the parenthetical sits below the main text. Pure visual layout — no data shape change. The web result page got the matching change; see [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

### Added (full automated test suite + CI gating)

- **46 new automated tests** under `tests/`, bringing the total from 5 to **51**. All pass in ~0.4s; no real network calls — every scanner test mocks via `respx`.
  - `tests/test_grading.py` (5 tests) — `aggregate_score` empty/link-out/failed-scanner exclusion, weighted-mean math (the documented "weight-2 SSL Labs at 50 + weight-1 CAA at 100 → 67" case), and the full `score_to_letter` bucket-boundary table from `100→A+` down to `0→F`.
  - `tests/test_retry.py` (5 tests) — 2xx fast path, 503-retry-then-200, exhaustion → `RetryExhausted` with status_code, 404 default, 404 with `treat_404_as_transient=True`.
  - `tests/test_urlutil.py` (6 tests) — scheme prepend, javascript-scheme, embedded-credentials and control-char rejection, SSRF gate vs literal `127.0.0.1` and vs `metadata.google.internal`.
  - `tests/test_scanners/` (23 tests across 12 files) — a mocked-upstream test per scanner: DNSSEC AD-flag/SERVFAIL/NXDOMAIN, SSL Labs worst-of-endpoints + deadline link-out, Mozilla Observatory negative-score clamp, Email auth apex-walk + subdomain link-out, Security Headers X-Grade + local-synth fallback, HTTPS redirect chain + ECONNREFUSED-as-HTTPS-only, CAA walk-up, DoS posture cf-ray, HSTS Preload branches, security.txt canonical/legacy, crt.sh→CertSpotter failover, internet.nl no-token link-out.
  - `tests/test_report.py` (3 tests) — `render_summary` Overall-line format, markdown-vs-HTML score parity (pins the v0.0.35 cross-renderer drift class), `explain_error` short-circuit on `ok=True` results.
  - `tests/test_web.py` (4 tests) — `POST /scan` cross-origin → 403, capacity → 503 with `Retry-After: 60`, `GET /scan/<id>/status` 404 for unknown job, `GET /report/<id>.md` 404 for missing file.
- **GitHub Actions workflow** at `.github/workflows/test.yml` runs the full suite on every push to `main` and every PR, using Python 3.11 + `pip install -e ".[dev]"` + `pytest tests/ -v`.
- **Test plan** at `TEST_PLAN.md` — tier scoping (P0/P1/P2), per-test assertions, and out-of-scope items (live integration, browser E2E, log strings, CSS layout).

### Notes

- **Zero production-code changes** between v1.0.0 and v1.0.1 except the one-line `<br>` insertion in `_render_registration_html`; everything else is byte-identical to v1.0.0.
- **Two test patterns worth recording** for future scanner additions:
  1. `email_auth` uses a `side_effect=` handler on a single `respx.get(DOH_URL)` route to branch on `?type=` and `?name=`, cleaner than 26 mocks (26 DoH calls per scan: SPF×2 parents + MX×2 + DMARC×2 + DKIM×(2 targets × 10 selectors)).
  2. `crt.sh` failover and `https_redirect` ECONNREFUSED tests use `monkeypatch.setattr("urlreporter.scanners._retry.DEFAULT_BACKOFFS", (0.0, 0.0, 0.0))` so retry exhaustion is instant; otherwise each would take ~31s in `asyncio.sleep`.

## [1.0.0] - 2026-05-10

### Notes (milestone release: graduating from 0.x to first stable)

- **Stability badge, not a code change.** No engine, scanner, parser, CLI, web, template, CSS, or test change between v0.0.72 and v1.0.0 — only the version string and a milestone callout in both READMEs. A `0.x` prefix was no longer accurate.
- **What stabilized us, in numbers** (May 2 → May 10, 2026):
  - **71 versions shipped** across CHANGELOG.md, all on the `0.0.x` line (v0.0.1 through v0.0.72; v0.0.46 was skipped) — roughly one release every 2.5 hours.
  - **25 of those were bug-fix releases** (at least one `### Fixed` section). Headlines: v0.0.72 (IANA RDAP bootstrap silently disabled after one parse-but-empty response), v0.0.67 (web template emitted empty grid rows), v0.0.65 (HTML report missing Registrant country cell), v0.0.64 (wrong RFC citation in Nameservers tooltip), v0.0.62 (result page hid registration card when only registry-lock data was present), v0.0.53 (audit pass: validation, cancellation, write errors, TTL cleanup), v0.0.52 (SSRF gate no longer blocks the event loop), v0.0.50 (CT failover correctness), v0.0.49 (registration data integrity + safety), v0.0.45 (securityheaders.com local grade synthesis when third-party blocks us), v0.0.44 (securityheaders.com HTML fallback for removed X-Grade header), v0.0.39 (HEAD requests on public routes returned 405), v0.0.36 (footer link color on inner pages), v0.0.29 (report parity audit: 4 content drifts between markdown / HTML / CLI summary), v0.0.25 (homepage GitHub button), v0.0.24 and v0.0.11 (per-scanner audits, 4 real bugs across 12 scanners each), v0.0.22 (template syntax bug that blanked every page), v0.0.13 (file-by-file bug audit), v0.0.10 / v0.0.7 / v0.0.6 / v0.0.5 (core logic + UI early fixes; v0.0.5 has two `### Fixed` sub-sections), v0.0.3 and v0.0.2 (early bootstrapping fixes).
  - **7 broad code-audit passes** (v0.0.12, v0.0.21, v0.0.24, v0.0.35, v0.0.49, v0.0.61, and v0.0.72). The signal we were ready for `1.0`: the v0.0.72 audit found 1 real bug across 17 modules, the lowest yield ever; the four prior audits each found 4+.
  - **51 automated tests** under `tests/`, gated by `.github/workflows/test.yml` on every push to `main` and every PR: `grading.py` math + bucket boundaries, `_retry.py` backoff and `RetryExhausted`, `urlutil.py` normalization + SSRF gate, all 12 scanners' parsing via `respx` mocks, markdown-vs-HTML parity, and 4 web-route paths (cross-origin POST → 403, capacity → 503 with Retry-After, unknown job → 404, missing report → 404). ~0.4s; no real network calls.
- **Web surface counterpart** documented in [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) under the same `[1.0.0]` header.

## [0.0.72] - 2026-05-10

### Fixed (IANA RDAP bootstrap silently disabled forever after one parse-but-empty response)

- **`urlreporter/registration.py:_get_bootstrap` no longer caches an empty `_bootstrap` mapping** when the IANA bootstrap fetch returns 200 + valid JSON but yields zero TLD→URL pairs (e.g. `{"services": []}`, or every entry malformed). The docstring promised an empty mapping *WITHOUT populating `_bootstrap`* on failure so the next scan retries, and the error paths honored it, but the success-but-empty path assigned `_bootstrap = out` with `out = {}`, so every later scan returned the cached `{}`. Now it logs a warning and returns `{}` without populating the global.
- **Realistic impact is low** (IANA's `dns.json` is not empty in practice), but it violated documented intent.

### Notes

- **One-line behavioral fix** plus a `log.warning`. No change to `_parse_rdap`, `fetch_registration`, the bootstrap-locking pattern, or any caller of `_get_bootstrap`.
- **Web template footers got a separate change** in lockstep: the four internal-page links (Score / Scanners / About / Contact) in every template's `<footer>` now carry `target="_blank" rel="noopener noreferrer"`. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for detail and the implicit reversal of the v0.0.70 progress-page decision.

## [0.0.71] - 2026-05-10

### Changed (registration card row layout: DNSSEC moved back to row 2; "Registration" raw-summary header now stands alone)

- **`urlreporter/report.py:_render_registration_html` moves the DNSSEC cell from `cells_row1` back to `cells_row2`**, as the **first** cell of row 2 (before Registrar lock). Row 1 reads `Registrar / Created / Expires` (4th column intentionally empty); row 2 reads `DNSSEC / Registrar lock / Registry lock / Nameservers`, with optional `Registrant country` as a 5th cell wrapping to a new line. Reverses the v0.0.68 placement.
- **`urlreporter/report.py:_registration_summary_line` now returns `"Registration\n" + …`** instead of `"Registration: " + …`. The raw-text summary block (CLI stdout and the web result page's `<details>` "Raw text summary" panel) now reads as a three-line group: a standalone `Registration` header, the registrar/expires bits, and the existing `Security: …` line. The leading colon read awkwardly when the field list itself contained colons.

### Notes

- **Both rows still use `grid-template-columns: repeat(4, 1fr)`** (inline `_HTML_CSS` and `static/style.css`), so every `.reg-cell` left-bar lines up between rows although row 1 fills 3 columns: `DNSSEC` under `REGISTRAR`, `REGISTRAR LOCK` under `CREATED`, `REGISTRY LOCK` under `EXPIRES`, `NAMESERVERS` under the empty slot.
- **No change to `_render_registration_md`.** Markdown is row-based; field order is unchanged.
- **Web result page got the matching changes.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side row reshuffle plus a small `.site-header` padding tweak tightening the gap below the "scan another URL" pill.
- **No engine, scanner, route, or runtime change.**

## [0.0.70] - 2026-05-10

### Notes

- **Web-template-only release.** Fixes a navigation-consistency bug on the live progress page (5 internal-page links now stay in the same tab). See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for detail and the audit across 7 templates / 12 static assets.
- **No engine, scanner, parser, CLI, or CSS change.**

## [0.0.69] - 2026-05-10

### Notes

- **Web-template-only release.** Reorders the live web result page so the registration card appears **after** the overall-score / per-scanner grid and **before** the Raw text summary. The standalone HTML report and markdown export are unchanged &mdash; the card stays near the top, right for an archival/printable artifact. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).
- **No engine, scanner, parser, runtime, CSS, or CLI change.**

## [0.0.68] - 2026-05-09

### Changed (registration card row layout: 4 + 3 with vertically-aligned cell bars)

- **Both renderer and template now place DNSSEC in row 1 instead of row 2,** flipping the v0.0.66 layout from "3 + 4" to "**4 + 3**". Row 1 is `Registrar, Created, Expires, DNSSEC`; row 2 is `Registrar lock, Registry lock, Nameservers` (with `Registrant country` as a 4th cell when present).
- **Both rows now use the same 4-column grid (`grid-template-columns: repeat(4, 1fr)`),** so each `.reg-cell` left-bar aligns between rows: `REGISTRAR LOCK` under `REGISTRAR`, `REGISTRY LOCK` under `CREATED`, `NAMESERVERS` under `EXPIRES`. Row 2's 4th column is empty when no registrant country is exposed (typical post-GDPR).
- **`urlreporter/report.py:_render_registration_html` updated:** the `if reg.dnssec is True / elif reg.dnssec is False` branch now appends to `cells_row1`, between the Expires branch and the Registrar lock branch.
- **`urlreporter/templates/result.html` updated:** the DNSSEC cell block moved from the row-2 grid to the row-1 grid (between Expires and the row-1 closing `</div>`); the row-1 / row-2 `{% if %}` gates updated to match (`reg.dnssec is not none` moved to row 1's gate).
- **CSS in both `report.py` (inline `_HTML_CSS`) and `static/style.css`:** `.reg-grid-row1` was `repeat(3, 1fr)` and `.reg-grid-row2` was `repeat(4, 1fr)`; both are now `repeat(4, 1fr)`. The `margin-bottom: 14px` on `.reg-grid-row1` is preserved as a row separator.

### Notes

- **No change to `_render_registration_md`.** Markdown is row-based; field order is unchanged (DNSSEC at registry still renders between Registry lock and Name servers).
- **No change to the CLI `Security:` summary line.** It is a one-line text summary.
- **Responsive breakpoints unchanged.** At `max-width: 720px` both rows fall back to 2-column; at `max-width: 480px` both collapse to single-column.
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.67] - 2026-05-09

### Fixed (web template emitted empty grid rows when one row had no cells)

- **`urlreporter/templates/result.html` row-grid divs are now individually gated on having at least one cell**, fixing an asymmetry with `_render_registration_html` from the v0.0.66 refactor. The Python renderer skips an empty row via `if not cells_list: continue`; the Jinja template emitted both `<div class="reg-grid reg-grid-row1">` and `row2` unconditionally, so a domain whose RDAP exposed signals for only one row rendered an empty grid div whose `margin-bottom: 14px` showed as blank space at the top of the card.
- **Audit of the v0.0.66 refactor.** The only real bug found; the `reg_has_data` gate, `{% if %}` / `{% endif %}` pairing, responsive breakpoints and per-cell branches all balance. The "(the cell to the right)" Registrar-lock tooltip is positional and reads differently on mobile, but predates v0.0.66.

### Notes

- **Web-template-only fix.** `_render_registration_html` is unchanged. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).
- **No engine, scanner, parser, CSS, or runtime behavior change.**

## [0.0.66] - 2026-05-09

### Changed (Registration card laid out as 3 + 4 two-row grid)

- **`urlreporter/report.py:_render_registration_html` and `urlreporter/templates/result.html` now split the registration card cells into two rows.** Row 1 carries the identity/dates cells (Registrar, Created, Expires); row 2 the four security signals (Registrar lock, Registry lock, DNSSEC, Nameservers). The previous single auto-fit grid (`repeat(auto-fit, minmax(140px, 1fr))`) landed on 3+4, 4+3, or 7-in-a-row by viewport width. Now 3 and 4 at desktop widths: "what the domain *is*" above "how it is *protected*".
- **`_render_registration_html` refactored:** `cells: list[...]` is split into `cells_row1` and `cells_row2`, rendered via `((cells_row1, "reg-grid-row1"), (cells_row2, "reg-grid-row2"))` into separate `<div class='reg-grid reg-grid-row1'>` / `<div class='reg-grid reg-grid-row2'>` containers. Per-cell logic is unchanged.
- **CSS in both surfaces** (inline `_HTML_CSS` in `report.py` and `static/style.css`): `.reg-grid` keeps `display: grid; gap: 14px 22px;`; `.reg-grid-row1` adds `grid-template-columns: repeat(3, 1fr); margin-bottom: 14px;`; `.reg-grid-row2` adds `grid-template-columns: repeat(4, 1fr);`.
- **Responsive media queries:** at `max-width: 720px` both rows fall back to 2-column; at `max-width: 480px`, single-column.

### Notes

- **Registrant country (when present) lands in row 2 as a 5th cell,** wrapping to a new line. Rare, since most domains redact it post-GDPR; forcing it into row 1 would make that row inconsistently 3 or 4 cells, and a row 3 felt over-engineered.
- **Standalone HTML report and live web page changed in lockstep,** with the same row structure and CSS class names (`report.py` inline and `static/style.css`). See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).
- **Markdown export unchanged.** One row per field; no grid to split.
- **CLI terminal `Security:` summary line unchanged.**

## [0.0.65] - 2026-05-09

### Fixed (HTML report was missing the Registrant country cell)

- **`urlreporter/report.py:_render_registration_html` now appends a `Registrant country` cell after `Nameservers`, matching the markdown export (`_render_registration_md`, since v0.0.55) and the live web page (`templates/result.html`, since v0.0.55).** Found in a sync audit: the HTML report was the only surface silently dropping the signal when RDAP returned one (typically `.gov` and a few ccTLDs not fully redacted post-GDPR; most commercial domains return `None` and the cell is gated `if reg.registrant_country:`). Neutral color, no tooltip, as in the web template.

### Notes

- **Sync audit results.** Renderer and `templates/result.html` now match in logic (gates, urgency colors, tooltips) for all cells.
- **Two minor wording variations remain** (intentional): the DNSSEC cell value is `Signed`/`Unsigned` (HTML report) vs `Signed at registry`/`Unsigned at registry` (web template); the Expires sub-text is `in 3 months` / `expired 5 days ago` (HTML) vs `3 months from now` / `5 days ago` (web). Presentation choices, not logic differences.
- **One markdown-only field remains:** `Last changed` (`reg.updated`) is a markdown row but not a cell in the HTML report or live page (design choice from v0.0.55).

## [0.0.64] - 2026-05-09

### Fixed (RFC citation in Nameservers tooltip was wrong)

- **`urlreporter/report.py:_render_registration_html` and `urlreporter/templates/result.html` had the Nameservers cell tooltip cite RFC 1035 §6.1.2 for "you should have at least 2 nameservers".** That section is "Boot file format", unrelated to redundancy. The correct reference is **RFC 1912 §2.3 "NS records"**: *"You should have at least two name servers for every domain, though more is preferred."* Both surfaces' `ns_count == 1` warning and `ns_count <= 6` good-state tooltips now cite and quote it.
- **CLI scope:** the standalone HTML report (`--html`) carries the same tooltip via `_render_registration_html`, so the fix reaches live web and downloaded reports alike. The markdown export was not affected: it cites no RFC section, only "RFC violation; need 2+" and "RFC-compliant", both accurate against RFC 1912 §2.3.

### Notes

- **Audit found no other bugs** in the v0.0.63 Nameservers feature. Ruled out: label "Nameservers" vs footer "Name servers", identical tooltip for counts 2-6, markdown count-and-list redundancy for ≤4 NSes, `§` in attribute values, `reg_has_data` already including `or reg.name_servers`, and the 0-NS case.

## [0.0.63] - 2026-05-09

### Added (Nameservers count cell on the registration card)

- **`urlreporter/report.py:_render_registration_html` now emits a `Nameservers` cell on the registration card, surfacing the nameserver count with a state-aware urgency color.** The cell sits after `DNSSEC` and before any registrant-country cell, alongside the existing `Name servers:` footer (which still lists the hostnames): the cell answers "how many, and is that fine?", the footer "what are they?". State buckets:
  - **`1`** &mdash; **orange / `reg-warning`**, sub-text `RFC violation (need 2+)`. RFC 1035 §6.1.2 effectively requires two or more; a single NS is a single point of failure (provider outage = total blackout, provider compromise = full DNS hijack).
  - **`2`** &mdash; **green / `reg-good`**, sub-text `RFC-compliant`.
  - **`3` to `6`** &mdash; **green / `reg-good`**, sub-text `healthy count`.
  - **`7+`** &mdash; **neutral**, sub-text `above typical`. Not a problem; some large operators publish many for redundancy or anycast diversity.
- **Each state ships its own info-tooltip** (the `.reg-info` pattern from v0.0.57), covering the security and availability angle and the threat model (provider compromise = DNS hijack, the vector v0.0.58's Registry Lock work addresses).
- **`urlreporter/report.py:_render_registration_md` enhanced the existing `Name servers` row to include the count and state inline,** e.g. `Name servers: bailey.ns.cloudflare.com, jeff.ns.cloudflare.com (2, RFC-compliant)`. No new row.

### Notes

- **No new RDAP fetch logic.** `RegistrationInfo.name_servers` has been populated since v0.0.55.
- **CLI terminal `Security:` summary line is unchanged.** It is already crowded with lock and DNSSEC signals; users running `urlreporter scan ... --html` or `--out` see the new cell / row in the report files.
- **The `0`-count state is unreachable** &mdash; with no nameservers the footer is skipped and the cell is gated on the same `if reg.name_servers`.
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.62] - 2026-05-09

### Fixed (web result page hid registration card when only registry-lock data was present)

- **`urlreporter/templates/result.html` `reg_has_data` gate now also checks `reg.registry_locked is not none`.** v0.0.58 added `registry_locked` to `RegistrationInfo` without updating this gate, so an RDAP response carrying only server*Prohibited codes (nothing else) evaluated false and the **entire registration card was suppressed**, hiding the very signal the user enabled. One OR clause added.
- **CLI scope:** `--html` and `--out` outputs were not affected. `_render_registration_html` and `_render_registration_md` gate on whether any cell or row was built, so a card with only the Registry lock cell renders correctly. Web-template-only bug.

### Notes

- **Audit found no other bugs** in the v0.0.58&ndash;v0.0.61 registry-lock work. Ruled out: warning-color cascade onto the Off-cell actor sub-text (matches the Expires-cell precedent), substring-matching on EPP status codes (no real code triggers a false match), and `_registration_security_line` edge cases (each signal null-checked independently).

## [0.0.61] - 2026-05-09

### Changed (lock cells now name the actor in always-visible sub-text)

- **`urlreporter/report.py:_render_registration_html` rewrote the value sub-text on all four lock-cell branches to name the actor that controls the lock,** after two users asked whether `Registrar lock` and `Registry lock` were duplicates. Previously `Registrar lock: On` showed `transfer/update/delete prohibited` (the **actions blocked**), `Registry lock: On` showed `server-level: requires out-of-band auth` (the **mechanism**), and both Off states showed nothing. Now parallel "via X" framing: Registrar lock On/Off → `via your registrar account`; Registry lock On/Off → `via the TLD registry (out-of-band auth)`, naming the real client* vs server* EPP distinction.
- **`urlreporter/report.py:_render_registration_md` got the matching change:** the four lock rows now end with the actor clause in parentheses (`On (via your registrar account)`, `Off (via the TLD registry, out-of-band auth)`, etc.), compact since markdown can't show two-line cells gracefully.

### Notes

- **Tooltip aria-labels and popover content are unchanged;** the new sub-text serves users who don't hover.
- **Cell labels (`REGISTRAR LOCK`, `REGISTRY LOCK`) are unchanged,** keeping standard EPP terminology for anyone grepping screenshots / docs / tickets.
- **Urgency colors unchanged from v0.0.60.** Registrar/Registry On = green, Off = orange.
- **CLI `Security:` summary line unchanged from v0.0.59.** It already names the locks unambiguously.
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.60] - 2026-05-09

### Changed (Registry lock: Off now renders as orange warning, not neutral)

- **`urlreporter/report.py:_render_registration_html` now applies the `reg-warning` urgency class to the `Registry lock: Off` cell** (previously neutral), mirroring `Registrar lock: Off`: orange left-bar and value text. Url Reporter's audience is professional / high-value sites, where a missing Registry Lock is a real, actionable gap; the earlier "neutral, like DNSSEC: Unsigned" treatment was calibrated for general audiences.
- **`Registrar lock: Off` and `Registry lock: Off` now share the orange treatment;** if both are off, both flag, making it obvious the domain has neither layer of EPP-status protection.

### Changed (em dashes removed from all tooltip strings)

- **All three tooltip strings introduced in v0.0.58** (`Registrar lock: On`, `Registry lock: On`, `Registry lock: Off`) **had their em-dash sentence breaks replaced with proper punctuation** (period + new sentence, or semicolon + clause). Em dashes can render like hyphens or misaligned in some fonts at the tooltip's small size; plain ASCII punctuation is robust across fallback fonts.

### Notes

- **Both surfaces updated in lockstep,** with the same string verbatim; see [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).
- **No engine, scanner, runner, grading, CLI-flag, or CSS-rule change.** Pure tooltip-copy and one urgency-class swap.

## [0.0.59] - 2026-05-09

### Added (terminal summary now surfaces the security signals on a dedicated second line)

- **`urlreporter/report.py:render_summary` now emits a second line, `Security: …`, immediately under the existing `Registration: …` line.** It consolidates the three lock/DNSSEC signals v0.0.58 added to the HTML/markdown reports; the terminal output gave the registrar and expiry date but nothing on registrar lock, registry lock or DNSSEC. Each signal renders as `<Name> <State>` (e.g. `Registrar lock On`, `Registry lock Off`, `DNSSEC Signed`), joined by the same `·` separator as the existing line.
- **New helper `_registration_security_line(reg)` in `report.py`** parallels `_registration_summary_line(reg)`. Returns an empty string when **none** of the three signals are determinate (e.g. some ccTLD RDAP responses omit status codes), so no bare `Security:` is printed.
- **`render_summary` now skips the trailing blank-line separator only if both the registration line and the security line are empty.** Previously the blank line depended on the registration line alone, so a domain with security signals but no registrar/expiry data printed without a separator before `Overall:`.

### Notes

- **No behavior change for the HTML/markdown reports**; only `render_summary` text changes. `--out` and `--html` reports got the Registry lock signal in v0.0.58.
- **`render_summary` output is also stored on the web side** (`web.py:381`, `job["summary"]`), so any future API or logged copy gets the second line.
- **Example** &mdash; before:
  ```
  Registration: Registrar: HOSTINGER operations, UAB · Expires 21/Jun/2028 (2 years)
  ```
  after:
  ```
  Registration: Registrar: HOSTINGER operations, UAB · Expires 21/Jun/2028 (2 years)
  Security: Registrar lock On · Registry lock Off · DNSSEC Signed
  ```

## [0.0.58] - 2026-05-09

### Added (Registry-lock detection separated from Registrar-lock detection)

- **`urlreporter/registration.py:RegistrationInfo` gained a `registry_locked: bool | None` field, and `_parse_rdap` now derives Registrar lock and Registry lock as two independent flags from RDAP's EPP status codes.** The single `info.locked` flag came from a substring match on `"transfer prohibited"` or `"delete prohibited"`, collapsing `client*Prohibited` (registrar-level, liftable by anyone with registrar-account access) and `server*Prohibited` (registry-level, lifted only via out-of-band auth, defeating the registrar-account-compromise DNS hijack behind incidents like Cow Protocol and Curve Finance frontends). `info.locked` now looks for `clienttransferprohibited` / `clientupdateprohibited` / `clientdeleteprohibited`, and `info.registry_locked` for `servertransferprohibited` / `serverupdateprohibited` / `serverdeleteprohibited`. A domain with both (e.g. paypal.com, google.com) renders two greens; registrar lock only (e.g. example.com) shows registrar green + registry neutral.
- **Detection handles both RDAP status forms.** Responses use EPP camelCase (`"clientTransferProhibited"`) or the RFC 8056 space-separated form (`"client transfer prohibited"`); the parser strips whitespace and lowercases before matching. Caught in verification when paypal.com / google.com showed `locked=False`: their RDAP server uses the space-separated form.
- **`urlreporter/report.py:_render_registration_html` now emits a separate `Registry lock` cell** (mirroring DNSSEC) after `Registrar lock`. Both states (On / Off) carry a tooltip on the security model and threat; the `Registrar lock` tooltip now names Registry lock as the stronger escalation. **Deliberate: `Registry lock: Off` renders neutral, not orange** &mdash; it is opt-in, often paid and rare on consumer domains, so a warning color would be alarmist and unactionable. Mirrors `DNSSEC: Unsigned`.
- **`urlreporter/report.py:_render_registration_md` got the matching row** &mdash; `Registry lock: On (server-level: requires out-of-band auth)` / `Registry lock: Off (no registry-level protection)`.

### Notes

- **Small correctness regression for domains with only server* codes.** They previously showed `Registrar lock: On` because the match was broad; they now show `Registrar lock: Off, Registry lock: On`, which is accurate. Rare.
- **Tooltip copy stays generic**, describing the threat model without naming orgs.
- **No new HTTP calls, RDAP fetch logic, or schema changes.** Detection reuses `RegistrationInfo.status_codes` (raw since v0.0.55).
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.57] - 2026-05-09

### Added (registration-card cell tooltips for state-sensitive fields)
- **`urlreporter/report.py:_render_registration_html` now supports an optional tooltip per cell, wired to `Registrar lock` and `DNSSEC`.** The cell tuple grew from `(label, value_html, urgency)` to `(label, value_html, urgency, tooltip)`. With a tooltip, the label gains an `&#9432;` trigger that shows a popover on hover/focus, explaining what _off_ means beyond the colored accent. Copy covers Lock On / Lock Off / DNSSEC Signed / DNSSEC Unsigned (transfer-out hijacking risk for Lock Off; missing DS chain-of-trust for DNSSEC Unsigned; etc.). Cells without a tooltip pass `None` and render unchanged, so Registrar, Created, Expires and Registrant country can adopt tooltips in one line each.
- **Inline `_HTML_CSS` gained `.reg-info` / `.reg-info-icon` / `.reg-info-tip` rules adapted from `.linkout-info` in `static/style.css`.** `.reg-label` is now `display: flex; align-items: center; gap: 6px;` so the icon sits inline. The popover anchors to the icon's left edge (`left: 0`) so it doesn't clip past the rightmost grid cell; `text-transform: none` and `letter-spacing: normal` reset inherited uppercase styling. The trigger is keyboard-focusable (`tabindex='0'`) with an `aria-label` carrying the description, matching `.linkout-info` (no `role`; a tooltip surface, not a button). The print stylesheet hides `.reg-info`.

### Notes
- **No engine, scanner, runner, grading, or CLI-flag behavior changed.** Pure renderer addition; `RegistrationInfo` is unchanged.
- **Markdown report unchanged** (no hover surface).
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template + static-CSS detail.

## [0.0.56] - 2026-05-09

### Notes
- **Version-only bump to track the web release.** v0.0.56 ships a small `urlreporter/web.py` cleanup: an unreachable scanner-picker code path survived after the homepage form lost its checkboxes, and the dead branch is removed ("web is opinionated; CLI is flexible"). No engine, scanner, runner, grading, report-renderer, or CLI-flag behavior changed. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.55] - 2026-05-09

### Changed (SSL Labs slow-poll degrades to link-out instead of red ERROR)
- **`urlreporter/scanners/ssllabs.py:scan` now returns a link-out result when the polling deadline expires while SSL Labs is still working.** Hitting `SCAN_TIMEOUT_SECONDS` (default 180) during `status: IN_PROGRESS` produced `ok=False, error="Timed out after 180s waiting for SSL Labs."`, a red ERROR row implying a TLS problem when the assessment was merely slow (1-3 minutes is typical on a cache miss). The deadline branch now returns `ok=True, grade=None, score=None, link=https://www.ssllabs.com/ssltest/analyze.html?d=<host>` with a summary like `"Assessment still running after 180s. First-time SSL Labs scans take 1-3 minutes; cached scans return in seconds. Open the link to watch live progress on ssllabs.com."`. The row joins the "no public API" link-out bucket used by InternetNL and the crt.sh double-fail tail, and `aggregate_score`'s `score is not None` filter excludes it, so the overall grade is unaffected.

### Notes
- **No behavior change on cache hits or normal cache-miss completions.** Only the long tail (>180s) changes.
- **Other SSL Labs failure modes still surface as red ERROR:** `status=ERROR` from SSL Labs (a real TLS problem), exhausted retries on HTTP 5xx or `httpx.RequestError`, and missing endpoints / grades in the response still return `ok=False`.
- **Consistent with v0.0.50:** third-party flake degrades to link-out.

## [0.0.54] - 2026-05-09

### Notes
- **Version-only bump to track the web release.** v0.0.54 ships web-side template / CSS edits only (progress-page notice line break, in-page top nav cleanup, result-page registration-card domain chip recoloring, and a "More about our Scanners" CTA at the foot of the landing page's twelve-scanners section). No engine, scanner, runner, grading, report-renderer, or CLI-flag behavior changed. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.53] - 2026-05-09

### Fixed (audit pass: validation, cancellation, write errors, and TTL cleanup)
- **`urlreporter/urlutil.py:normalize_url` now converts malformed bracketed IPv6 into `InvalidURL` instead of leaking raw `ValueError`.** Inputs like `https://[not::ip]/` and `https://[::1` turned bad CLI input into an unhandled exception and bad web input into a 500. Host validation now requires real IPv6 literals for colon-containing hosts, catches parser `ValueError`s, and rejects IPv4-like numeric shorthand / legacy forms (e.g. `127.1`, `010.000.000.001`) rather than leaving their meaning to platform resolver normalization.
- **`urlreporter/runner.py:run_scans` now cancels and drains child tasks when the parent scan is cancelled.** A Ctrl-C, uvicorn shutdown, or self-cancelling scanner could leave scanner tasks and the parallel RDAP task running against an already-closing `httpx.AsyncClient`. It now cancels pending scanner tasks plus the registration task, awaits them with `return_exceptions=True`, then re-raises the cancellation.
- **`urlreporter/cli.py:scan` now exits nonzero when report output cannot be written.** The CLI caught `OSError`, printed `Failed to write report`, then still printed `Report written to:`. Directory creation and final Markdown / HTML writes now fail the command and suppress false success messaging.
- **`urlreporter/web.py` now enforces in-memory job TTL on read routes, not only when a new scan starts.** `/scan/{job_id}`, `/scan/{job_id}/status`, and `/scan/{job_id}/result` call `_cleanup_old_jobs()` before lookup, so a stale job no longer stays readable until a later scan.
- **`urlreporter/web.py:_cleanup_old_reports` now prunes stale `.md`, `.html`, and `.name` files independently.** Startup cleanup only iterated `*.md`, so orphaned HTML or filename sidecars accumulated. It checks all three suffixes and leaves unrelated files alone.

### Tests
- **Added regression coverage in `tests/test_audit_fixes.py`** for malformed IPv6 validation, child-task cancellation cleanup, CLI write-failure exit behavior, stale job TTL on the status route, and orphan sidecar report cleanup.

## [0.0.52] - 2026-05-09

### Fixed (web concurrency: SSRF gate no longer blocks the event loop)
- **`urlreporter/urlutil.py:assert_publicly_routable` is now `async def` and uses `loop.getaddrinfo` instead of `socket.getaddrinfo`.** It runs from two async paths in `web.py`: once up-front in the `POST /scan` handler, and once per outbound HTTP request via the `_ssrf_request_hook` httpx event hook (every redirect on every scanner). Under uvicorn's single event loop, each blocking DNS lookup paused every other in-flight scan, the `/scan/<id>/status` poll, and the hook for all other requests. `await loop.getaddrinfo(host, None)` dispatches DNS to asyncio's thread executor; both `web.py` call sites now `await` it.
- **Verified non-blocking under load.** During a 12.6 ms DNS resolve, a 5 ms-interval heartbeat coroutine ticked 3 times.

### Notes
- **No public-surface change.** No new route, scanner, config key, or CLI flag. `assert_publicly_routable` changed from `def` to `async def` but is called only from `web.py` (the CLI is intentionally unguarded), and both call sites were updated in the same commit.

## [0.0.51] - 2026-05-09

### Notes
- **Version-only bump to track the web release.** v0.0.51 ships web-side template updates (new `/contact` page, footer Contact link on every page, the nav version-pill moved into a `Current build` pill on the About page, copy fixes, link-style cleanup) plus four template-side bug fixes. No engine, scanner, runner, grading, report-renderer, or CLI-flag behavior changed. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md).

## [0.0.50] - 2026-05-09

### Added (crt.sh resilience: CertSpotter failover + link-out tail)
- **`urlreporter/scanners/crtsh.py` rebuilt around a three-tier fallback chain.** crt.sh remains primary; on `RetryExhausted` / non-2xx / non-JSON / wrong-shape it falls over to **CertSpotter** (`api.certspotter.com/v1/issuances`), a different operator (SSLmate) covering the same CT data with a generous unauthenticated free tier. If CertSpotter also fails, the scanner degrades to a **link-out result** (`ok=True, score=None, grade=None, link=https://crt.sh/?q=<host>`) instead of a red `ERROR` row, as InternetNL does with no API token, so the row is excluded from the weighted average. When CertSpotter is the source, the summary appends ``(via CertSpotter — crt.sh unreachable)``.
- **Internals refactored into composable helpers.** `_fetch_crtsh` and `_fetch_certspotter` each return a normalized cert list (or raise a private `_SourceFailed`), so `_grade` sees the same shape from either source. CertSpotter responses are mapped to crt.sh's field names (`entry_timestamp`, `not_before`, `issuer_name`) at parse time; the grading model is untouched.

### Fixed (CT failover correctness)
- **CertSpotter now uses `include_subdomains=true` to match crt.sh's substring-search semantics.** crt.sh's `?q=<apex>` is a fuzzy substring match: for `pdiomede.com` it returns certs for the apex AND every subdomain. With `include_subdomains=false`, CertSpotter returns only exact CN/SAN matches, so a failover graded a narrower sample and could land on a different letter. The sources must behave equivalently for the failover to be transparent.
- **`_grade` no longer takes an unused `host` parameter.** Dead code dropped.
- **CertSpotter-source summary tightened.** ``(via CertSpotter; crt.sh unreachable: crt.sh: gave up after 4 attempts; last HTTP 502)`` repeated "crt.sh" and stuffed a retry trace into the summary cell. It now reads ``(via CertSpotter — crt.sh unreachable)``; upstream-error detail still lands in the per-run log.

### Notes
- **No new dependencies, routes, or scoring change.** The link-out has `score=None`, so `aggregate_score` excludes it: a CT double-outage no longer drags the grade down or shows red ERROR.
- **No SSRF surface added;** CertSpotter goes through `_ssrf_request_hook`.
- **Failover budget.** Worst case (both upstreams down) adds CertSpotter's retry budget (~31s) before link-out, the same as a single scanner under the existing retry policy. Best case (crt.sh works first try) is unchanged.

## [0.0.49] - 2026-05-09

### Added (domain registration card via RDAP)
- **New `urlreporter/registration.py` module fetches RDAP metadata for the scanned URL's domain.** `runner.run_scans` starts `fetch_registration(url, client)` in parallel with the 12 scanners, awaits it before emitting a new `registration` event, and attaches the result to a new `Report.registration: RegistrationInfo | None` field. The fetcher does an IANA bootstrap (cached process-wide via an `asyncio.Lock`), looks up the TLD's RDAP service, GETs `/domain/{name}` with `retry_request`, and parses registrar, creation / expiration / last-changed events, EPP status codes (for registrar-lock detection), registry-level DNSSEC, name servers, and registrant country. Always on (no `SCANNER_*` toggle), excluded from the weighted score, never produces Top-recommendation findings; purely informational, never blocks or fails the scan.
- **All three report renderers carry the new section.** `render_summary` adds a one-line "Registration: Registrar X · Expires …" between the URL line and Overall. `render_markdown` adds a `## Registration` section with bullet rows. `render_html` adds a full-width `.registration-card` between the hero and the gauge/table grid, with color-coded expiration urgency: red ≤30 days or expired, orange ≤90, neutral otherwise; green left border on healthy lock/DNSSEC indicators.
- **CLI `_IncrementalWriter` handles the new `registration` event** so the partial-on-interrupt path (Ctrl-C / engine crash) keeps the registration section in `writer.last_report` even without `done`.

### Changed (report polish)
- **Markdown report heading format updated.** `# Security report - <url>` is now `# Security report: <small>[\`<url>\`](<<url>>)</small>`: colon instead of hyphen, URL smaller and clickable. The angle-bracket target keeps URLs with parens or special characters from breaking the link.
- **"by Url Reporter" is now a link to `https://urlreporter.com/`.** Markdown footer (`_Generated … by [Url Reporter](https://urlreporter.com/)_`), HTML report hero `<p class='generated'>` (inherits the muted color, no underline, cyan on hover), and HTML report footer `<p class='footnote'>` (matches the accent-color "Paolo Diomede" link).
- **Footer attribution everywhere now reads "Built by".** `credit_line()` (CLI banner via `--version`), HTML report footer, and all six web templates changed from "Made by".
- **HTML report registration card visual cleanup.** The domain chip in `<h2>` is neutralized: `.registration-card h2 code` uses `var(--mute)` text on a neutral white-tinted background, matching the `REGISTRAR` / `CREATED` labels instead of cyan. `.reg-grid` `minmax(170px, 1fr)` → `minmax(140px, 1fr)` so all five cells share row 1 at the report's 916px content width instead of wrapping DNSSEC to row 2.

### Fixed (registration data integrity + safety)
- **`_get_bootstrap` no longer poisons its cache on transient failure.** A 503 / non-JSON / network error used to set `_bootstrap = {}` permanently, so later scans in the process got no registration data even after recovery. The failure path now returns `{}` from local scope without touching the module-level cache.
- **`registrar_url` and `rdap_link` are now scheme-validated at parse time.** A compromised registry RDAP server could deliver e.g. a `javascript:alert(1)` registrar URL; the HTML escapers (`_esc`, Jinja autoescape, markdown link syntax) don't strip dangerous schemes. New `_safe_http_url` accepts only `http://` / `https://`, applied to both fields.
- **Print stylesheet's `.reg-sub` rule no longer overrides urgency colors.** The `!important` on `.reg-label, .reg-sub, .reg-ns, .reg-ns-label { color: #555 !important; }` defeated the more-specific `.reg-cell.reg-warning .reg-sub { color: #b87a16; }` (specificity 0,0,3,0). With it removed, warn/critical sub-text keeps its orange/red when printed.
- **`_format_age` no longer prints "12 months" for 360-364 days.** `months = min(days // 30, 11)` caps it; the 365-day boundary already escalates to "1 year".
- **`_get_bootstrap` validates `data` is a dict.** A non-dict JSON value from IANA's `dns.json` would make `data.get("services", [])` raise `AttributeError`; it now checks `isinstance(data, dict)` and returns `{}` with a warning log otherwise.

### Notes
- **No new dependencies.** RDAP uses the existing `httpx.AsyncClient` and `retry_request`; bootstrap is parsed with stdlib `json`.
- **No SSRF surface added;** `data.iana.org` and registry RDAP servers are public.
- **Backward compatible.** No public route, config key, scanner registry, or CLI-flag change. Reports without RDAP coverage (unsupported TLD, IP target, RDAP unreachable) omit the section in every renderer.

## [0.0.48] - 2026-05-06

### Notes
- **Version-only bump to track the web release.** v0.0.48 ships a small web-side `robots.txt` adjustment (now disallowing `/version`, the polling endpoint added in v0.0.47). No scanner, runner, grading, report, or CLI-flag behavior changed.

## [0.0.47] - 2026-05-06

### Notes
- **Version-only bump to track the web release.** v0.0.47 ships a web-UI feature (an in-page "new version available" banner driven by a polling `/version` endpoint) plus a small progress-page tagline tweak. No scanner, runner, grading, report, or CLI-flag behavior changed.

## [0.0.45] - 2026-05-05

### Fixed (securityheaders.com scanner: local grade synthesis when third-party blocks us)
- **`urlreporter/scanners/security_headers.py` now computes the headers grade locally when securityheaders.com is unreachable.** v0.0.44 added an HTML body fallback for the removed `X-Grade` header, but post-deploy testing showed securityheaders.com now sits behind Cloudflare bot protection: non-browser User-Agents (including ours) get HTTP 403 with `cf-mitigated: challenge` and a JavaScript challenge page, so neither the `X-Grade` path nor the HTML parse can succeed. `X-Grade` wasn't *removed*; we're blocked from seeing it.
- **The fix drops securityheaders.com as the source of truth.** The scanner already fetches the target's response headers as a parallel direct-GET fallback. It now computes a grade from those with a calibrated penalty table (high-severity miss = -25, medium = -15, low = -5, from 100) and maps it back with `score_to_letter`. Sites with all six modern security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) score 100/A+; sites missing all score 0/F. The summary states the source (e.g. *"Headers grade A+ (100/100) — graded locally; securityheaders.com unreachable."*).
- **Order of preference unchanged.** When securityheaders.com *does* return a grade (`X-Grade` header or scrapable HTML body), it still wins; local synthesis is only a fallback.

### Documentation
- **`urlreporter/templates/scanners.html` (`/scanners`) securityheaders.com card updated.** The "Notes" paragraph claimed the fallback produced "no overall letter, only a list of findings"; it now always produces a letter. New copy describes the Cloudflare bot protection, the local penalty table (high = -25, medium = -15, low = -5), and that the summary names the grade source.
- **`README_WEB.md` (scanner #3 row) updated** with the same explanation in compact form.

### Notes
- **Calibration.** The table makes the high-severity headers (HSTS, CSP) the dominant drivers, matching securityheaders.com's emphasis. HSTS + CSP but no other modern headers scores 60 (C+); no HSTS but everything else scores 75 (B+); no headers scores 0 (F). Erring slightly strict.
- **No new dependencies or external API calls.**
- **Backward compatible.** Sites already graded via `X-Grade` see no change. Sites that were ERRORing (urlreporter.com itself, plus any all-modern-headers site behind the bot block) now get an accurate local grade and contribute to the overall score (weight 1.5).

## [0.0.44] - 2026-05-05

### Fixed (securityheaders.com scanner: HTML fallback for removed X-Grade header)
- **`urlreporter/scanners/security_headers.py` now extracts the grade from the HTML body when the `X-Grade` response header is absent.** securityheaders.com silently stopped returning `X-Grade`, so the scanner returned ERROR on this path regardless of the target's headers. A regex fallback on the HTML body, `class="score"...<span>GRADE</span>` (how the site's own page shows the grade), fixes it. Sites with all security headers (e.g. urlreporter.com itself) now return **A+ · 100/100** instead of ERROR, and the weight-1.5 scanner contributes to the overall grade again.
- **Audit: no other scanner has this dependency.** `ssllabs.py`, `mozilla_observatory.py`, and `hsts_preload.py` already use `.get()` with fallbacks or explicit error returns.

### Notes
- **No changes to grading weights, report renderers, CLI flags, templates, or other scanners.** One scanner file changed.
- **Backward compatible.** Sites already graded via `X-Grade` keep that path; the HTML fallback fires only when the header is absent.

## [0.0.43] - 2026-05-05

### Changed (footer + recommendations card polish)
- **Copyright prefix added to every footer.** All six templates (`index.html`, `about.html`, `score.html`, `scanners.html`, `progress.html`, `result.html`) now read `© 2026 · Made by Paolo Diomede`.
- **Cascading-rain chevrons shifted right** on the result page's "+ N more in the downloaded report" cluster. The three stacked chevrons hugged the card's left edge, left of the Markdown / Self-contained HTML buttons, so they didn't point at them. `padding-left: 64px` on `.report-card .recs-more-chevrons` centers the cascade over the Markdown button.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI runtime changes.** Templates and one CSS rule.

## [0.0.42] - 2026-05-05

### Changed (email_auth scanner: parent-walk + MX-aware skip)
- **`urlreporter/scanners/email_auth.py` rewritten to walk up the parent chain for SPF and DMARC lookups** instead of probing only the input host. SPF/DMARC records are typically published at the registered domain (apex), not every subdomain, so a webapp host like `app.aave.com` was graded F=0 even when `aave.com` had strict policies. The scanner now walks `app.aave.com → aave.com` and uses the closest ancestor with records. Findings say where records were found (e.g. *"DMARC policy is `p=reject` (on aave.com, inherited by app.aave.com)"*).
- **MX-aware skip for non-mail-sending subdomains.** When the input host is a subdomain (≥3 labels) and the parent chain has no SPF, no DMARC, AND no MX records, the scanner returns a link-out result (`grade=None, score=None`) instead of an F, and `grading.aggregate_score` excludes it. Apex domains (≤2 labels) are still scored without MX, since the *"we don't send mail, but lock spoofing down anyway"* pattern is meaningful there.
- **DKIM probing extended to the apex** for subdomain scans. Previously only `<selector>._domainkey.<input host>` was probed; `<selector>._domainkey.<apex>` is now probed in parallel too, catching transactional mail signed at the apex (the common case).
- **New helpers in `email_auth.py`**: `_parent_domains(host)` (mirrors `caa.py`'s walk-up), `_doh_answers(client, name, rrtype, *, label)` (generic DoH JSON fetcher replacing the SPF/DMARC-only `_doh_txt` path), and `_doh_has_mx(client, name, *, label)` for MX detection.

### Notes
- **Concrete impact.** A scan of `https://app.aave.com` aggregated to **B / 72** because email_auth returned F=0 (weight 2.0) on a webapp subdomain with no email records of its own. Now it either uses `aave.com`'s apex SPF/DMARC, or, with no mail records or MX in the chain, returns link-out and is excluded, moving the grade closer to the site's real posture.
- **Scoring unchanged for correct apex domains.** Direct apex scans (e.g. `https://aave.com`) with SPF + DMARC + DKIM grade exactly as before; only subdomains and edge cases that produced false-positive Fs change.
- **No new dependencies** (same Cloudflare DoH endpoint).
- **No changes to the CLI surface, runner, grading thresholds, or report renderers.** The scanner returns the same `ScanResult` shape.

## [0.0.41] - 2026-05-05

### Added (homepage install block: copy button + cleaner pip-upgrade step)
- **Copy button on the "Install from GitHub" terminal mockup.** Sits in the term-bar's top-right with a copy icon and a "copy" tooltip on hover/focus. On click it collects every `.term-line.cmd .exe` in the surrounding `.term` block, joins them with newlines, writes them with `navigator.clipboard.writeText`, and flashes a "copied!" tooltip + green border for ~1.6s. Falls back to `document.execCommand('copy')` without the async Clipboard API.
- **`pip install --upgrade pip` added as the fourth install step.** The lede ("up in N commands") changed from "four" to "six", and the homepage mockup and both READMEs show the same six-line flow.

### Changed (READMEs)
- **README.md (CLI distribution) and README_WEB.md (full web project)** install blocks gain the `pip install --upgrade pip` line between `source .venv/bin/activate` and `pip install -e .`.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI runtime changes.** Templates + CSS + ~25 LOC of vanilla JS in the existing inline IIFE.
- **Backward compatible.** Routes, config keys, on-disk reports unchanged. The copy button degrades gracefully without JS (commands can be hand-selected).

## [0.0.40] - 2026-05-05

### Documentation (production cleanup ops)
- **README: new "Cleanup in production" subsection under Reports.** The in-app `_cleanup_old_reports()` in `web.py` runs only once, at uvicorn startup, so a long-lived production uvicorn lets reports older than the documented 24h TTL accumulate between restarts. Documented complement: a one-line `find /var/www/urlreporter/reports -type f -mmin +1440 -delete` script run by a systemd timer (`OnUnitActiveSec=1h`) or hourly cron entry. Deployed on urlreporter.com as a `urlreporter-cleanup.timer` unit running hourly.

### Notes
- **Documentation only.** No engine, scanner, grading, report-renderer, template, CSS, or CLI changes.
- **No code deploy required;** the timer is server-side ops.

## [0.0.39] - 2026-05-05

### Fixed (HEAD requests on public routes returned 405)
- **All public-facing GET routes now also accept HEAD.** Every route used `@app.get(...)`, which binds only GET, so HEAD got `HTTP 405 Method Not Allowed` with `allow: GET`. RFC 7231 §4.1 requires GET and HEAD support, and this tripped uptime monitors (Pingdom, UptimeRobot, StatusCake) and link checkers that prefer HEAD. The routes now use `@app.api_route(..., methods=["GET", "HEAD"])`, so Starlette serves HEAD as a body-stripped GET with the same headers.
- **Routes updated**: `/`, `/score`, `/scanners`, `/about` (HTML pages), `/robots.txt`, `/.well-known/security.txt`, `/sitemap.xml`. The dynamic per-job and per-report routes (`/scan/{id}`, `/scan/{id}/status`, `/scan/{id}/result`, `/report/{id}.md`, `/report/{id}.html`) stay GET-only: they need valid UUIDs and monitors won't HEAD them.

### Notes
- **No engine, scanner, grading, report-renderer, template, CSS, or CLI changes.** Seven decorator changes in `web.py` only.
- **No effect on social card scraping** (uses GET).
- **Backward compatible.** GET behavior is byte-identical; HEAD requests that returned 405 now succeed.
- **Verify after deploy**: `curl -sI 'https://urlreporter.com/' | head -1` should return `HTTP/2 200` (was `HTTP/2 405`).

## [0.0.38] - 2026-05-05

### Changed (live-scan page: links no longer interrupt the watch)
- **All same-origin links on `/scan/{job_id}` (the live progress page) now open in a new tab.** The brand/logo (`href="/"`) and the footer's `Score` / `Scanners` / `About` links navigated in-tab, so clicking one mid-scan replaced the live progress UI (the scan kept running, but the polling JS and table were gone). Each of those four links now carries `target="_blank" rel="noopener noreferrer"`.

### Changed (recommendations card: cascading-rain chevrons)
- **The chevron pointer under "+ N more in the downloaded report" was redesigned** as a vertical "raindrop" cascade pointing at the Markdown / Self-contained HTML download buttons below it. The new layout stacks 3 chevrons with a staggered fade-and-translate cycle (each child offset 0.3s on a 1.8s loop) so one is always mid-flight: each fades in 4px above its rest position, settles, then fades out 6px below. CSS lives under `.report-card .recs-more-chevrons` and a new `chevron-rain` keyframe in `static/style.css`. `@media (prefers-reduced-motion: reduce)` shows all 3 chevrons static at full opacity.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI changes.** Templates and CSS only.

## [0.0.37] - 2026-05-05

### Added (version pill + GitHub link on every page's top nav)
- **`<span class="right">` block added to the `.system-strip` nav on all five inner pages** (`/about`, `/score`, `/scanners`, `/scan/{id}` progress, `/scan/{id}/result`). Each carries the version pill (`v{{ app_version }}`) and a GitHub link button to `https://github.com/pdiomede/urlreportercli`, mirroring the homepage's `nav-actions`; previously only the homepage had them.
- **New CSS in `static/style.css`** for `.system-strip .right .version-pill` and `.system-strip .right .github-link`. Both opt out of the parent's uppercasing (`text-transform: none`) so they read `v0.0.37` and `GitHub`. The pill uses `var(--text)` (`#eef1f8`) on a 22%-opacity white border; the GitHub button uses the same text on a 16%-opacity border, brightening to `var(--accent)` blue on hover.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI changes.** Templates and CSS only.

## [0.0.36] - 2026-05-05

### Fixed (footer link color on inner pages)
- **"Made by Paolo Diomede" link on inner pages (`/about`, `/score`, `/scanners`, `/scan/{id}` progress, `/scan/{id}/result`) rendered muted instead of bright like the homepage.** The 0.0.33 rule `.site-footer .footer-end a { color: var(--text-primary); }` in `static/style.css` used a variable `style.css` doesn't define (it defines `--text`, line 26; `--text-primary` exists only in the homepage's inline `<style>`), so it fell through to the inherited `color: var(--text-mute)`. The rule now uses `color: var(--text)` (`#eef1f8`, near-white). Hover unchanged; the homepage was unaffected.

### Notes
- **One-line CSS fix.** No engine, scanner, grading, report-renderer, template, or CLI changes.

## [0.0.35] - 2026-05-05

### Security (web surface only — CLI unchanged)
- **Origin / cross-origin POST defense on `/scan`.** Without it, a malicious site embedding `<form action="https://urlreporter.com/scan" method="post">` could silently trigger scans from any visitor's browser. Impact is low alone but it amplifies the 0.0.34 concurrency cap by using a victim's browser to consume server slots. The `/scan` POST handler now compares the `Origin` header's `netloc` to the request's `Host` header. If `Origin` is set and doesn't match, the request is rejected with HTTP 403 and a "Cross-origin requests are not allowed" form-error banner. If `Origin` is *missing* (curl, server-to-server callers, older browsers), the request passes; those aren't the threat model and rejecting them would break API use. The check sits at the top of the handler, before the concurrency cap, so cross-origin floods consume no resources.
- **Default `MAX_CONCURRENT_SCANS` raised from 8 → 16.** More lenient for traffic spikes; still tunable via env var.

### Notes
- **No changes to scanners, runner, grading, report renderers, templates, or CLI.** The check is ~15 LOC in `web.py:scan()`.
- **Backward compatible**: same-origin browser submits and non-browser clients keep working; only cross-origin browser POSTs from foreign sites are rejected.
- **Defense in depth**: nginx already rate-limits at the perimeter; this covers a visitor's browser triggered by a malicious page.
- **Verified**: same-origin curl POSTs (no Origin header) → 303; cross-origin browser submits with `Origin: https://attacker.com` → 403.

## [0.0.34] - 2026-05-05

### Security (web surface only — CLI unchanged)
- **SSRF gate on `/scan` POST.** New `assert_publicly_routable(url)` in `urlreporter/urlutil.py` rejects URLs whose host is, or DNS-resolves to, a private/loopback/link-local/multicast/reserved/unspecified IP, and is wired into `web.py:scan()` after `normalize_url`. Before, a user could submit `http://127.0.0.1:6379` (Redis), `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (cloud metadata), or any RFC1918 address; the scanners made real HTTP requests there and reflected responses into the public report. The gate uses `ipaddress.ip_address(...).is_private/.is_loopback/.is_link_local/.is_multicast/.is_reserved/.is_unspecified` for literal IPs and resolves hostnames via `socket.getaddrinfo` with a 30s in-process cache. Cloud-metadata hostnames (`metadata.google.internal`, `metadata.aws.internal`, `metadata.goog`, `instance-data*`) are also blocked by name in case DNS is intercepted. The error message is deliberately generic ("This URL is not allowed") to avoid fingerprinting internal topology. The CLI does **not** call this gate, since local operators may scan internal hosts.
- **Concurrency cap on `/scan` POST.** The `_running_tasks` set in `web.py` grew unboundedly: each scan opens an `httpx.AsyncClient` and runs 12 outbound scanners (SSL Labs alone takes 1-3 min), so a loop of `POST /scan` could exhaust memory, file descriptors and connections until OOM, or until upstream scanners (SSL Labs, crt.sh) rate-limit *us*. New `MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "16"))` gates the handler: when `len(_running_tasks) >= cap`, it returns HTTP 503 with `Retry-After: 60` and a friendly "We're at capacity" page. Tunable via env var without redeploy.

### Notes
- **No changes to scanners, runner, grading, report renderers, templates, or CLI.** Both fixes are in `web.py` and `urlutil.py`.
- **Backward compatible** for public-URL scans. Internal-host URLs via the web are now rejected with a 400; the CLI behaves as before.
- **Verified**: 13 SSRF test cases pass locally (loopback IPv4, RFC1918, link-local IPv6, AWS/GCP metadata addresses, multicast, unspecified, plus two public-host positive controls).

## [0.0.33] - 2026-05-05

### Changed (homepage / nav / footer polish)
- **GitHub button + install block point at the new public CLI repo** (`pdiomede/urlreportercli`) instead of `pdiomede/urlreporter`, in both the homepage nav button (`.btn.btn-ghost`) and the "Install from GitHub" terminal mockup. The walk-through now reads `git clone .../urlreportercli.git` → `cd urlreportercli` → `python3 -m venv .venv && source .venv/bin/activate` → `pip install -e .`. The `about.html` "Run it yourself" paragraph was retargeted at the CLI repo and trimmed to drop the "self-host the web UI" claim (the CLI repo lacks the web surface).
- **Top nav got a new "CLI" link** between Scanners and Trust, anchoring at `#surfaces` ("CLI for CI. Web UI for everyone else."). `section[id] { scroll-margin-top: 88px; }` makes every anchored section (How it works, Report, Scanners, CLI, Trust) clear the ~72px sticky nav instead of cutting off the heading.
- **Version pill in the nav is now legible.** `var(--text-muted)` (`#6e7896`) text on an 8%-opacity white border was nearly invisible on navy. Now `var(--text-primary)` (`#e8ecf6`) text + 22%-opacity border.
- **Footer "Made by Paolo Diomede" link now matches the version pill color** on all six pages (`/`, `/scanners`, `/about`, `/score`, `/scan/{id}` progress, `/scan/{id}/result`). It was `var(--accent-2)` cyan on inner pages and inherited a muted color on the homepage; both now use `var(--text-primary)` near-white, cyan on hover.

### Added (result page)
- **"+ N more in the downloaded report" hint** under the Top recommendations card on `/scan/{id}/result`. The card shows only the top 3 recs (glanceable triage); the full deduped list is in the Markdown report (top 10 in the HTML report). With more than 3 recs, a small italic line says how many more the download holds. Cosmetic, no engine change.

### Notes
- **No engine, scanner, grading, or report-renderer changes.** Templates, CSS, and one new line in `result.html`.

## [0.0.32] - 2026-05-05

### Changed (raw summary now matches the result-page KPIs)
- **`render_summary()` now emits a `Scanners: N of M ok.` line** between the overall grade and the scan-completed line. The result page's left card has a "Scanners ok" KPI tile (e.g., `11/12`), but the raw text summary, shown on `urlreporter scan ...` stdout and in the result page's collapsible "Raw text summary" `<details>` block, omitted the count. Now every surface carries the same header data.
- **Counts treat link-out scanners as "ok"** (they ran successfully, just return no number), matching the KPI tile semantics in `urlreporter/templates/result.html`. So `11/12` typically means 1 failed and 11 finished, graded or link-out.

### Notes
- **No engine, scanner, web-route, or rendering changes beyond the new line.** The Markdown / HTML renderers already had a more verbose "Aggregated from X graded scanner(s); Y link-out only (...); Z failed (...)" line in Overall; the raw summary's terser form is intentional, since the per-scanner list below it names every scanner and outcome.
- **Backward compatible.** Existing reports re-render with one extra line; no schema or route change.

## [0.0.31] - 2026-05-05

### Removed (standalone landing-page mirror at project root)
- **Deleted `index.html` from the project root** (1,838 lines). Added in 0.0.21 as a static mirror for design preview and CDN-cached deploys, it served neither: dev preview is `./runUrlReporter.sh`, and production serves the live Jinja template via nginx + uvicorn. It kept drifting (stale GitHub hrefs, placeholder clone URL, hardcoded `v0.0.21` pill).
- **Nothing in code, scripts, routes, configs, deploy units, or nginx references it.** Only historical CHANGELOG entries (0.0.21, 0.0.25, 0.0.27) mention it, left as-is.
- **The live homepage (urlreporter.com) is unaffected.** It renders from `urlreporter/templates/index.html` via FastAPI.

### Notes
- **No engine, scanner, web-route, CLI, or report-renderer changes.** Only the removal plus routine version-pill / footer-credit / changelog updates.

## [0.0.30] - 2026-05-05

### Changed (OG / social-card metadata)
- **Replaced `static/og-image.png` (1.4 MB, 1536x1024) with `static/og-image.jpg` (122 KB, 1200x630).** The PNG was 2.4x WhatsApp's 600 KB cap, so WhatsApp / Telegram / Signal previews broke, and it contradicted the `og:image:width=1200 og:image:height=630` tags. Made via `sips` (resize to 1200x800, center-crop to 1200x630, JPEG quality 85): 11.5x smaller.
- **All four indexable templates updated** (`index.html`, `about.html`, `score.html`, `scanners.html`): five `og:image` / `twitter:image` references now point at the `.jpg`. The old PNG was deleted.

### Changed (homepage SEO copy length)
- **Homepage `<title>` shortened from 65 chars to 57** to fit Google's 50-60 char window: `Url Reporter: Free security audit from 12 public scanners` (was `...Free website security audit...`).
- **Homepage `<meta name="description">` shortened from ~180 chars to ~150** to fit the 110-160 char SERP window.
- **Homepage `<meta property="og:description">` shortened from ~210 chars to ~117** so link cards stop truncating mid-sentence. The named-scanner list became a category summary (TLS, headers, DNSSEC, email auth, security.txt).
- **Homepage `<meta property="og:title">` aligned with the new `<title>`.**

### Notes
- **Other pages' titles / descriptions unchanged.** Only the homepage triggered audit warnings.
- **No engine, scanner, or report-renderer changes.** Static asset + meta tags only.
- **Backward compatible.** Routes, scoring, CLI flags, on-disk reports unchanged.

## [0.0.29] - 2026-05-05

### Fixed (report parity audit: 4 content drifts between markdown / HTML / CLI summary)
- **Generation credit case mismatch.** Markdown said `_Generated <ts> by urlreporter_`; HTML said `Generated <ts> by Url Reporter`. Both now use the display name.
- **HTML overall score format used spaces around the slash.** Markdown / CLI render `(87/100)`; HTML rendered `87 / 100`. Spaces removed.
- **HTML aggregate summary dropped the link-out explainer tail.** Markdown's "Aggregated from..." line includes "1 link-out only (internet.nl) - no public API; the report points at the external site for a manual check"; HTML stopped at "1 link-out only (internet.nl)". HTML now carries the full explainer.
- **`Report.total_elapsed` now appears in every report.** On the dataclass since 0.0.22, it showed only in the result page's "Scan time" tile. Both downloadable renderers and the CLI's `render_summary()` (stdout and the "Raw text summary" `<details>`) now append `Scan completed in {N}s.` after the aggregate summary.

### Notes
- **Audit method.** Diffed a synthetic `Report` through `render_markdown` / `render_html` / `render_summary`; these four are the only content-level differences, the rest is intentional layout.
- **Gaps left as-is.** The recommendation cap differs by surface (MD: all; HTML: top 10; result page: top 3) by design. Per-scanner findings appear only in the downloadable reports.
- **Backward compatible.** Same `Report` dataclass, routes, scanner outputs. Reports written before 0.0.29 lack the elapsed line.

## [0.0.28] - 2026-05-05

### Changed (within-scanner concurrency, tier A from the perf roadmap)
- **`security_headers` now fires its two HTTP calls in parallel.** The X-Grade probe at `securityheaders.com/?q=...` and the direct fetch of the user's URL are independent and now run as helpers (`_fetch_grade`, `_fetch_target`) via `asyncio.gather(...)`: wall time is `max(call)` instead of `sum(call)` (~1s saved).
- **`security_txt` now probes `/.well-known/security.txt` and `/security.txt` in parallel.** It used to fall back to the legacy path only after a 4xx, so the common no-security.txt case paid two RTTs; now one. Results are walked in `(WELLKNOWN_PATH, LEGACY_PATH)` order, so well-known wins if both return 200.
- **Both use the `asyncio.gather` pattern from 0.0.23's `email_auth`.** `RetryExhausted` propagates as before, and transient HTTP errors are folded into the per-call return tuple so one failure never cancels the other.

### Notes
- **No new dependencies.** Adds `import asyncio` to two scanner modules; a refactor of the existing `scan()` body.
- **Backward compatible.** Same `ScanResult` shape, scoring, and finding text; the same target yields byte-identical reports.
- **Two optimization tiers remain** (shared httpx client, scan-result cache); see the perf roadmap.

## [0.0.27] - 2026-05-05

### Changed (brand-mark parity across all pages)
- **Inner-page brand mark now matches the homepage.** `style.css` `.brand-logo` went from 48x48 / `border-radius: 12px` to 44x44 / `border-radius: 11px`, matching `index.html`'s `.brand-mark`. `.brand-name` went from 26px / `letter-spacing: 0.04em` to `1.125rem` (18px) / `letter-spacing: 0`.
- **The wordmark no longer renders as `URL REPORTER` in all caps on inner pages.** The parent `.system-strip nav`'s `text-transform: uppercase` cascaded to it; added `text-transform: none` on `.brand-name`. Affects `/about`, `/score`, `/scanners`, `/scan/{id}` (progress), and `/scan/{id}/result`.

### Changed (footer parity across all pages)
- **Inner-page footers replaced with the homepage's pattern.** The old flex row of `version-pill | Made by Paolo Diomede` in uppercase mono became a 2-column grid on all five inner pages (`about`, `score`, `scanners`, `progress`, `result`): `Score | Scanners | About` left, `Made by Paolo Diomede` right, in title-case sans-serif, stacking below 720px.
- **New CSS in `style.css`:** `.site-footer .footer-grid` / `.footer-mid` / `.footer-end` with title-case overrides (`text-transform: none`, `letter-spacing: 0`, `font-family: var(--font-sans)`, `font-size: 0.875rem`). The outer `.site-footer` keeps its 64px top margin and hairline border.
- **Version pill is no longer shown in the inner-page footer.** `{{ app_version }}` lives only in the homepage nav (`.version-pill`).

### Removed (redundant nav button)
- **`OUR SCORE` button removed from the top-right of every inner page.** The `<a class="header-score-link" href="/score">Our score</a>` block inside `.system-strip > .right` duplicated the new footer links; the `<span class="right">…</span>` block is gone from all five templates. The `.header-score-link` rule in `style.css` is now dead code, left in place.

### Notes
- **No engine, scanner, grading, route, or report-renderer changes.** Templates and CSS only.
- **Backward compatible.** Routes, config keys, CLI flags, report formats unchanged.

## [0.0.26] - 2026-05-05

### Added (homepage install block)
- **New "Install from GitHub" block** in the homepage's `#surfaces` section, between the "CLI for CI. Web UI for everyone else." heading and the CLI/Web mockups: an eyebrow, one-sentence lede, and centered terminal mockup (`max-width: 780px`) showing:
  - `git clone https://github.com/pdiomede/urlreporter.git`
  - `cd urlreporter`
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -e .`
  - then `./bin/urlreporter scan https://example.com`
  It reuses `.term` / `.term-bar` / `.term-line` (no new CSS); the "Successfully installed" line uses `urlreporter-{{ app_version }}`.
- **README "Install" section now starts with `git clone`**, matching the homepage.

### Notes
- **Cosmetic / docs only.** No engine, scanner, grading, web-route, or report changes.
- **Backward compatible.** No new deps; routes and CLI flags unchanged.

## [0.0.25] - 2026-05-04

### Fixed (homepage GitHub button)
- **The GitHub button in the homepage nav pointed at `https://github.com/`.** The static mirror `index.html` kept the placeholder href. It now points at `https://github.com/pdiomede/urlreporter` with `target="_blank" rel="noopener noreferrer"`.
- **Stale `https://github.com/your-org/urlreporter.git` placeholder in the install codeblock** on the same page, replaced with `https://github.com/pdiomede/urlreporter.git`.
- **Hardcoded `v0.0.21` version pill in the static mirror** is now `v0.0.25`. The live template uses `{{ app_version }}`; the mirror needs a manual edit each release.

### Added (live template parity)
- **Mirrored the GitHub button into the live Jinja template** (`urlreporter/templates/index.html`). The button existed only on the static side; both now show `version-pill` + `GitHub` button (existing inline `.btn-ghost.btn-sm` styles), same href and target.

### Notes
- **Cosmetic / link-correctness only.** No engine, scanner, grading, or report changes.
- **Backward compatible.** Routes unchanged.

## [0.0.24] - 2026-05-04

### Fixed (per-scanner bug audit, 4 real bugs across 12 scanners)
- **`caa.py`: a transient DoH failure on the leaf name aborted the ancestor walk.** CAA records inherit from the closest ancestor, so walking `_parent_domains(host)` is the point. The old code returned a hard error on the first `RetryExhausted` (or `httpx.HTTPError`/`ValueError`) for `www.example.com` and never tried `example.com`, where the record lives. Each failure is now logged as a warning and the loop continues; an error is returned only if **every** ancestor lookup raised.
- **`dnssec.py`: non-zero RCODE finding had identical `detail` and `recommendation` text.** The `rcode_meta` table's second tuple element was passed as both fields. `detail` now states `"The resolver returned RCODE <n>."`; `recommendation` carries the advice.
- **`dos_posture.py`: `("Generic CDN (via header)", [("via", None)])` flagged any `Via` header as a CDN.** RFC 7230 §5.7.1 requires every proxy (forward, reverse, non-CDN) to add a Via entry, so ordinary proxies counted as a CDN, inflating the score by 60 points and dropping the true "No CDN/WAF detected" finding. Removed the catch-all entry and its dedup branch.
- **`internetnl.py`: setting `INTERNETNL_API_TOKEN` made the result *worse*.** Without a token the scanner emitted a link-out (`ok=True`, no score, link to internet.nl). With one it returned `ok=False` with `"internet.nl batch-API integration is not implemented yet."`, counting as a failed scanner. The token path now also falls back to link-out, logging a WARNING that the token is ignored.

### Notes
- **No web/template/CSS changes.** Scanner Python only.
- **Backward compatible.** Same routes, config keys, CLI flags, report format; existing reports re-render unchanged.

## [0.0.23] - 2026-05-04

### Changed (scanner concurrency: tier-1 speed improvements)
- **`email_auth` now fires every DNS probe in parallel.** It ran a sequential SPF lookup, then DMARC, then up to ten DKIM-selector probes (`default`, `google`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `s1`, `s2`), exiting on the first DKIM hit. One `asyncio.gather(...)` of all 12 queries replaces the loop, so a healthy DoH path takes roughly one RTT (~200-300ms) instead of up to twelve. First-hit-wins selector preference is kept by walking the `DKIM_SELECTORS` tuple in order.
- **SSL Labs polling cadence is now adaptive.** It slept `await asyncio.sleep(10)` between every poll, so even a cached READY response paid up to 10 seconds. Now: 3-second cadence for the first 4 polls, then 10 seconds. Cache-miss worst case is unchanged; cached scans land 0-7 seconds faster. Well under Qualys's ~150 req/min/IP limit.

### Changed (result-page polish)
- **Linkified URLs are now legible on the dark theme.** The `linkify` filter's classless `<a>` tags took the default deep blue, nearly invisible on the navy card. Added `.report-card .rec a`, `.report-table .summary-cell a`, and `.report-table .err-explain-body a` rules in `style.css`: cyan `var(--accent-2)`, 1px underline at 2px offset, hover to `var(--text)`, `word-break: break-word`.
- **Both cards on `/scan/{id}/result` now stretch to equal height.** `.report-grid` switched from `align-items: start` to `stretch` at >=960px, so the shorter left card fills the right card's height instead of leaving a notch.
- **Brand mark in the system-strip header is bigger and rounder.** `.brand-logo`: 44px to 48px, border-radius 5px to 12px, plus a drop shadow (`0 8px 24px -8px rgba(0,0,0,0.6)`). `.brand-name`: 23px to 26px, letter-spacing 0.06em to 0.04em. Matches the homepage nav on the result, about, score, scanners, and progress pages.

### Notes
- **No engine changes beyond the two scanner concurrency tweaks.** Grading, retry helper, web routes, CLI, and downloadable renderers are untouched.
- **Backward compatible.** No change to results, reports, routes, or config; just faster.

## [0.0.22] - 2026-05-04

### Fixed (template syntax bug that blanked every page)
- **Closed the unclosed `<script>` tag for `gtag-init.js` on all six templates** (`index.html`, `about.html`, `result.html`, `score.html`, `progress.html`, `scanners.html`). `<script src="/static/gtag-init.js?v={{ app_version }}">` lacked `</script>`, so browsers parsed the rest of the document as the script's contents and rendered a blank page. The server returned `200 OK`; the failure was client-side, starting when the GA init moved to a separate file in 0.0.18.

### Added (favicon set)
- **Generated a multi-size `static/favicon.ico`** (16/32/48 in one ICO) plus `apple-touch-icon.png` (180x180), `icon-192.png`, and `icon-512.png` from `static/pfp.png`, built with Pillow:
  ```python
  src.save("favicon.ico", sizes=[(16,16),(32,32),(48,48)])
  src.resize((180,180), Image.LANCZOS).save("apple-touch-icon.png")
  ```
- **Three favicon `<link>` tags wired into all six templates:** `<link rel="icon" href="/static/favicon.ico" sizes="any">`, `<link rel="icon" type="image/png" href="/static/pfp.png">`, and `<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">`. This silences the `/favicon.ico` 404 and fixes iOS / iPadOS home-screen icons; only `index.html` had a favicon before.

### Changed (`/scan/{id}/result` redesign)
- **Result page rewritten as a 2-column card layout** matching the homepage. It replaces the stacked `<section class="overall">` + `<table>` + recommendations sections with a `.report-grid` (`360px 1fr` at >=960px, single column below), using the existing `--bg-elev`, `--accent-2`, `--good`/`--warn`/`--bad`, and font tokens.
  - **Left card**: SVG-free conic-gradient gauge (`.grade-circle`), 168x168, filling `var(--pct)` with a grade-aware colour (`--gauge-color`: green A, cyan B, amber C/D, red E/F, mute unknown). Inside: the grade in `var(--font-mono)` 3.25rem and a small `XX / 100` caption. Below: a 3-column KPI grid with **Weighted** (overall_score), **Scanners ok** (`ok_count`/`total`), **Scan time** (e.g. `23s`); top-3 recommendations with severity dots (red/amber/cyan/green); two ghost-style download buttons (Markdown, Self-contained HTML).
  - **Right card**: per-scanner table with one Grade column as a colored pill (`.grade-chip`, variants `a/b/c/d/f/na`); the Score column was merged into Grade. ERROR rows show a red `—` chip plus the existing `<details class="err-explain">` "What does this mean?" disclosure.
- **All new CSS lives in one `/* Result page (verdict) */` section in `static/style.css`** (between the responsive breakpoints and the `/score` rules), about 230 lines, touching no pre-existing class.
- **The standalone `<section class="recommendations">` block is gone.** Recommendations are top-3 in the left card; the full deduped list remains in the `.md` and `.html` reports.
- **The "Raw text summary" `<details>` and footer are unchanged.**

### Added (timing data on the result page)
- **`Report.total_elapsed: float | None`** is a new dataclass field in `runner.py`, set to `round(time.monotonic() - run_started, 1)` at the end of `run_scans()`. The web layer records `started_at` on the `start` event and threads it through `_write_partial_report()`. The result template renders `{{ elapsed|int }}s` in the third KPI tile (or `—` when unavailable, e.g. partial reports written before any scanner finished).

### Notes
- **No engine changes.** Scanners, grading, retry helper, and downloadable renderers are untouched; `.md` and `.html` downloads render byte-for-byte as in 0.0.21.
- **Backward compatible.** Routes, download URLs, config keys, CLI flags unchanged.

## [0.0.21] - 2026-05-04

### Changed (web home page redesign)
- **The web home page is now a marketing landing page.** Layout: hero, four-step "How it works" flow, live-progress preview, sample-report preview (grade circle, KPI tiles, top recommendations, per-scanner table), twelve scanner-category cards, CLI/Web mockups, trust & safety section, and a footer linking `/score`, `/scanners`, `/about`, `/.well-known/security.txt`. CSS and vanilla JS are inline; the only external script is the GA4 gtag.
- **The hero URL input is now the real scan-starting form.** A pill-shaped input + Scan button POSTs to `/scan` with `name="url"`. On submit the button is disabled, its label becomes "Scanning…", an indeterminate progress strip appears, and the page moves to `/scan/{job_id}` via 303 once the job is enqueued.
- **The per-scan SCANNERS picker has been removed from the home page** (twelve checkboxes plus Select all / Deselect all). Scans use the config-enabled set (`SCANNER_*` knobs in `config.env` / `config.env.local`). The `/scan` POST handler still accepts a `scanners` form list (e.g. internal automation), but an absent or empty list now falls back to `cfg.enabled` instead of a `Select at least one scanner` 400.
- **`_render_index` no longer passes `all_scanners` or `selected_scanners` to the template.** SEO meta, Open Graph tags, Twitter cards, JSON-LD `WebApplication` schema, and the GA4 gtag init from `static/gtag-init.js` are preserved verbatim.
- **The header brand mark is now `static/pfp.png`**, replacing the inline gradient SVG placeholder.

### Added
- **Project-root `index.html`**, a self-contained static mirror of the live home page (embedded CSS and vanilla JS, no Jinja, GA, or external assets), for previewing the design or CDN-cached deploys.

### Changed (error messages)
- **Per-run log paths are now substituted into error explanations.** Three `explain_error()` strings contained the literal `./logs/error_<timestamp>.log`; they now interpolate the real path from `setup_logger()` (e.g. `/Users/.../logs/error_20260504-141230.log`) when known. `render_summary`, `render_markdown`, `render_html`, and `_render_scanner_section` accept a new `log_path: str | None` keyword argument, wired through by CLI and web.
- **Error explanations now appear in the CLI text summary**, not just the on-disk reports. Each failed scanner prints `↳ <title>` plus a wrapped body under the `ERROR -` line.
- **Four new error-explanation patterns** in `explain_error()`:
  - **SSL Labs polling timeout** (`scanner == "SSL Labs"` AND `"Timed out after"` in error). Explains the 1-3 minute live assessment; recommends retrying with `SSL_LABS_USE_CACHE=true`.
  - **Cloudflare DoH unreachable** (DNS scanners CAA / DNSSEC / Email auth + network-shaped error). Explains their dependency on `cloudflare-dns.com/dns-query`.
  - **Target unreachable on direct-target scanner** (`HTTP→HTTPS redirect`, `DoS posture`, `security.txt` + connection-shaped error). Says the URL is unreachable from this machine; firewall / DNS likely.
  - **Missing `INTERNETNL_API_TOKEN`** is now named in the link-out summary string (was "no API token configured").
- **Two new helpers in `report.py`:** `_logs_pointer(log_path)` for consistent log-path rendering, plus `_DOH_SCANNERS` and `_UNREACHABLE_MARKERS` constants for the new matchers.

### Changed (project rename)
- **Renamed the project to `urlreporter` (display name "Url Reporter"), live at [urlreporter.com](https://urlreporter.com).** Affects the package directory, console script and import path (`urlreporter.cli`, `urlreporter.web`), launcher scripts (`bin/urlreporter`, `runUrlReporter.sh`, `gitUrlReporter.sh`), the package logger name (`urlreporter`), the default `HTTP_USER_AGENT` (`urlreporter/0.1`), the report filename prefix (`urlreporter-<host>-<ts>.md`), the HTML `<title>`, the markdown footer, and the `APP_NAME` constant. The git remote in `gitUrlReporter.sh` is now `https://github.com/pdiomede/urlreporter`. Earlier CHANGELOG entries were retro-fitted to the new name.

## [0.0.20] - 2026-05-04

### Changed (scoring methodology)
- **Optional scanners no longer tank the overall grade.** `hsts_preload` returned `D / 40` for domains not on the Chrome HSTS preload list, and `security_txt` returned `F / 0` without a `/.well-known/security.txt`. Both are opt-in yet dragged down excellent sites (polymarket.com: B / 79 despite TLS A+, DNSSEC A+, CAA A+, redirect A+, email auth A+). Rescaled: `hsts_preload` returns `B+ / 80` (not preloaded), `A / 90` (pending), `A+ / 100` (preloaded); `security_txt` returns `B- / 70` when missing. Finding severity dropped from `medium` to `low`.
- **Overall grade is now a weighted mean** (previously a plain average). `grading.aggregate_score()` weights by security impact: 2.0 for SSL Labs, Mozilla Observatory, DNSSEC, Email auth (SPF/DMARC/DKIM); 1.5 for HTTP→HTTPS redirect and securityheaders.com; 1.0 for CAA, DoS posture, HSTS Preload, security.txt, crt.sh, internet.nl. Weights live in `SCANNER_WEIGHTS` keyed by `ScanResult.scanner` (display name); unknown scanners fall back to `DEFAULT_WEIGHT = 1.0`.
- **Letter-grade buckets loosened by 5 points.** `score_to_letter()` thresholds shifted down so a few weak optional categories can't push a secure site below A-. New ladder: `>=90 A+`, `>=85 A`, `>=80 A-`, `>=75 B+`, `>=70 B`, `>=65 B-`, `>=60 C+`, `>=55 C`, `>=50 C-`, `>=45 D+`, `>=40 D`, `>=35 D-`, else `F`. The `LETTER_TO_SCORE` map (third-party letters to numbers) is unchanged.
- **Combined effect on the polymarket.com sample report:** B / 79 → A+ / 93.
- **`/score`, `urlreporter explain-score`, and the README "How the overall grade is calculated" paragraph updated** for the weighted average, weights, new ladder (90 = A+), and a caveat that weights are a judgment call.

## [0.0.19] - 2026-05-04

### Changed (report rendering)
- **Em dashes removed across all user-facing strings** (templates, scanner outputs, error explanations, summaries, CHANGELOG/README), replaced with hyphens or commas.
- **Timestamps in reports are now human-readable.** A new `_format_timestamp()` helper formats `report.generated_at` as `4/May/2026 at 22:33 UTC` instead of ISO `2026-05-03T22:33:12+00:00`, in the CLI summary, markdown, and HTML.
- **HTML report footer simplified.** Removed the `Config sources: ...` line; the footer is now `Url Reporter · made by Paolo Diomede`, the name linking to https://pdiomede.com.
- **Markdown report footer simplified.** Dropped the `_Config sources: ..._` line and the `---` separator above it. The `.md` ends on `_Generated <timestamp> by urlreporter_`.

### Changed (UI on `/scan/<id>/result`)
- **Severity chips (HIGH / MEDIUM / LOW / INFO) are larger and more vivid.** Font 10px to 12px (weight 700), more padding, a bigger dot with stronger glow, and full `--bad`/`--warn`/`--accent-2`/`--good` tones instead of pastels.
- **`// detailed findings` reads better.** Summary header 15px weight 600 (was 13px), finding titles 15.5px, bodies (`.rec`/`.detail`) 14.5px with `line-height: 1.5`.
- **All `//` eyebrow labels in the HTML report are unified.** `.eyebrow` (`// security audit`) and `.section-eyebrow` (`// recommended actions`, `// per scanner`, `// detailed findings`) both render at 15px / weight 700 / `var(--accent2)`; section eyebrows were 11px / weight 500 / muted.
- **Removed the floating `// recommended_actions` corner label** (`.recommendations::before` rule deleted); the eyebrow above the heading says the same.
- **`What does this mean?` toggle is more legible.** 11.5px / weight 500 / muted became 13px / weight 600 / full text colour, with more padding.

### Changed (progress page copy)
- **Tagline now reads "SSL Labs and crt.sh are usually the slowest"** (was just SSL Labs); crt.sh polling can take 5+ seconds on cold cache.

### Notes
- **No engine changes.** Templates, static assets, report renderer, and the report.py timestamp helper only.
- **Backward compatible.** Report files on disk keep the old timestamp until they expire (24h TTL).

## [0.0.18] - 2026-05-04

### Changed (CSP hardening: drop `'unsafe-inline'` from script-src)
- **All inline `<script>` blocks moved to external static files.** Every template had one (GA4 init, the `index.html` form handler, the `result.html` copy handler, the `progress.html` polling IIFE), and Mozilla Observatory docked 20 points for `'unsafe-inline'` in `script-src`. Moving them lets nginx serve a stricter CSP, pushing Observatory to A or A+.
- **Four new files under `static/`:**
  - `static/gtag-init.js` (shared GA4 init, on all six templates).
  - `static/index-form.js` (homepage form-submission handler).
  - `static/result-copy.js` (result page copy-to-clipboard handler).
  - `static/progress-poll.js` (live-progress polling IIFE).
- **`progress.html` lost its Jinja-injected JS variable.** The inline script interpolated `{{ job_id }}` into JavaScript; the job ID now travels in a `<div id="poll-config" data-job-id="{{ job_id }}" hidden>` that `progress-poll.js` reads via `getAttribute`.
- **JSON-LD on `index.html` stays inline** (`type="application/ld+json"` isn't executable, so CSP doesn't gate it).

### Notes (deploy-time)
- **nginx CSP needs `'unsafe-inline'` removed from `script-src`** in `/etc/nginx/sites-available/all-sites.conf`. New value:
  `script-src 'self' https://www.googletagmanager.com;`
  Reload nginx after editing.
- **No engine changes.** No scanner, runner, grading, or report file is touched.
- **Backward compatible.** Routes and behaviour are identical; only the asset layout changed.

## [0.0.17] - 2026-05-04

### Changed (UI consistency)
- **`progress.html` and `result.html` now use the same header and footer pattern as the rest of the site.** Both showed the old CSS-drawn `.brand-mark` and a muted footer "Our score" link with no version badge. The header now shows the logo and the OUR SCORE button; the footer shows `v{{ app_version }} · ready` next to the credit.

### Notes
- **No engine changes.** Templates only.

## [0.0.16] - 2026-05-04

### Added
- **`/.well-known/security.txt` route** in `urlreporter/web.py` (RFC 9116). Returns `text/plain` with `Contact:`, `Expires:` (2027-12-31), `Preferred-Languages:`, and `Canonical:`. The site's own `security_txt` scanner now grades urlreporter.com correctly.

### Changed (UI contrast)
- **Footer text and version badge use the accent colour.** The bottom strip (`v0.0.16 · ready` and `MADE BY PAOLO DIOMEDE`) used `var(--text-mute)` / `var(--text-faint)`, nearly invisible on dark. `.site-footer` and `.site-footer .footer-version` now use `var(--accent-2)`, weight 600, size 11.5px to 13px.

### Notes
- **No engine changes.** No scanner, runner, grading, report, or config file is touched.
- **Backward compatible.** Routes and download URLs unchanged.

## [0.0.15] - 2026-05-03

### Added (SEO, content pages, GA)
- **Two new public content pages** at `/scanners` (breakdown of all 12 public security scanners) and `/about` (project overview, scope, non-goals, self-host pointer). They render new templates `scanners.html` and `about.html`, are in the sitemap, and are indexable.
- **Full SEO meta-tag suite** on every indexable page (`/`, `/score`, `/scanners`, `/about`): per-page `<title>` and `<meta name="description">`, canonical URLs, Open Graph (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`), Twitter Card (`summary_large_image`), `meta robots`, `meta keywords`. The homepage adds a JSON-LD `WebApplication` block; a new 1200x630 `static/og-image.png` is the social-preview image.
- **`/robots.txt` and `/sitemap.xml`** routes served by FastAPI. `robots.txt` allows everything except `/scan/` and `/report/` (per-job pages) and links the sitemap; `sitemap.xml` lists `/`, `/scanners`, `/score`, `/about`.
- **`noindex, nofollow`** on `progress.html` and `result.html`: per-job pages have random IDs and 24h-TTL content.
- **Google Analytics 4** (`G-6NCTMMRH1H`) on all four templates.

### Changed (header, footer, branding)
- **Brand image in the header.** The CSS-drawn `.brand-mark` placeholder became the actual `static/pfp.png` logo, with a new `.brand-logo` rule (44x44, `border-radius: 5px`, `object-fit: cover`)., and the brand-name font doubled (11.5px to 23px).
- **"Our score" promoted to a header button.** Formerly a muted footer link, it is now a bordered, accent-coloured button on the right of the system strip on every public page. The version-and-status badge (`v0.0.15 · ready`) moved from header to footer.
- **Header and footer pattern unified across all public pages.** `score.html` now matches `/`, `/scanners`, and `/about`.
- **Section eyebrow labels are more visible.** The `// TL;DR`, `// METHODOLOGY`, etc. labels were 11px in `var(--text-faint)`, nearly invisible on dark backgrounds. Now 14px, weight 700, `var(--accent-2)`.

### Notes
- **No engine changes.** No scanner, runner, grading, report, or config file is touched; only templates, static assets, web routes, and meta data.
- **Backward compatible.** Routes and download URLs unchanged; `/score` keeps its content and URL; old report links keep working.

## [0.0.14] - 2026-05-03

### Added (CLI parity with web UI)
- **`--html` flag on `scan`**. The CLI writes a self-contained HTML report next to the Markdown one (same `report.render_html()` as the web UI, byte-for-byte identical). Default off, so existing scripts still produce only `.md`. The path is `<out>.html` (`--out reports/foo.md --html` produces `reports/foo.html`).
- **Incremental report writes** during a CLI scan. After every `scanner_done` event the CLI re-renders the partial Markdown (and HTML, if `--html`) to disk, mirroring the web app's `_write_partial_report()`. A `Ctrl-C` or `kill -9` now leaves a usable report with every finished scanner.
- **Partial report on engine exception / interrupt.** `asyncio.run(run_scans(...))` is wrapped in a `try/except` for `KeyboardInterrupt` (exit 130, the POSIX SIGINT convention) and any other unexpected exception (exit 1, with a `Scan failed:` banner). Either way the CLI falls back to the last incremental write, prints its path, and still emits the per-scanner summary.
- **`urlreporter explain-score`** subcommand. Prints the plain-English methodology the web UI shows at `/score` (letter→number table, the "skipped scanners" rule, the score-to-letter ladder, the five honest caveats). No URL argument, no network calls, exit 0.

### Notes
- **No engine changes.** All four additions reuse `runner.run_scans()`, `report.render_summary()`, `report.render_markdown()`, `report.render_html()`, `grading.aggregate_score()`, and `runner._prioritize` / `runner.Report` exactly as the web UI does.
- **Backward compatible.** Flags (`--config`, `--out`, `--quiet`, `--only`) and exit codes (0 success, 1 all-failed, 2 args error) are preserved. The new exit code `130` occurs only on Ctrl-C, which previously crashed with a traceback.

## [0.0.13] - 2026-05-03

### Fixed (file-by-file bug audit)
- **`config.py`**: environment overrides applied only to keys already in a loaded config file, so `INTERNETNL_API_TOKEN=…` (or any `SCANNER_*` toggle) set in the shell with no `config.env` was silently ignored. The `for k in merged.keys()` loop became an explicit `_RECOGNIZED_KEYS` tuple.
- **`grading.py`**: `aggregate_score()` returned `(round(avg), score_to_letter(avg))`. With an unrounded avg of `94.6`, the score rounded to `95` while the letter came from `94.6` as `"A"`, giving the contradictory `(95, "A")`. The letter now derives from the rounded integer.
- **`urlutil.py`**: `_SCHEME_PREFIX_RE` matched any RFC 3986 scheme prefix, so `localhost:3000` or `example.com:8080` were rejected as `Unsupported URL scheme: 'localhost'.` Added a host:port discriminator: when the segment after `:` parses as a port (digits, optionally followed by `/path`), it falls through to the default-https branch. The `javascript:` / `data:` / `file:` / `vbscript:` defenses still fire, since their tails aren't numeric.
- **`web.py`**: `_write_partial_report()` rendered `Report.results` from `job["partial_results"]` in completion order, so on-disk sections reshuffled between runs, though `runner.py` re-sorts to registry order ("so reports stay stable"). The web path now mirrors that sort, so CLI and web reports agree.
- **`templates/progress.html` (two bugs)**:
 - When `runner_task` swallowed an exception it set both `job["error"]` *and* `job["done"] = True`. The poller's `if (data.error)` branch returned before the `done && report_id` branch, stranding the user on the progress page though `/scan/{id}/result` would render the partial report with its `partial_error` banner. Removed the early `data.error` return; `done && report_id` now always redirects.
 - The reconnect/give-up handlers did `caption.textContent = "Reconnecting…"`, detaching the cached `completed-count` / `total-count` / `bar-pct` spans from the DOM. If polling recovered, updates hit orphaned elements and the percentage froze. Added a sibling `<p id="poll-status">` for status messages, leaving the counter row intact.

### Verified clean (no bugs found)
- `report.py`, `logging_setup.py`, `runner.py`, `templates/index.html`, `templates/result.html`, `templates/score.html`, `static/style.css`, and every file in `scanners/` (`base.py`, `_retry.py`, `caa.py`, `crtsh.py`, `dnssec.py`, `dos_posture.py`, `email_auth.py`, `hsts_preload.py`, `https_redirect.py`, `internetnl.py`, `mozilla_observatory.py`, `security_headers.py`, `security_txt.py`, `ssllabs.py`) were audited in the same 5-bug-cap pass with no defects found.

## [0.0.12] - 2026-05-03

### Changed (UI / copy)
- **Index hero copy simplified.** Headline is now `Audit any URL with the best public security scanners` (was a literal scanner count). Tagline is `Paste a URL and get a consolidated report drawn from a battery of public security scanners`.
- **`/score` page rewritten in plain English.** Same sections and tables, jargon removed: "letter to score" became "How letter grades become numbers", "aggregate" became "How we combine scanners into one number", the ladder uses ranges like `90 to 94` instead of `≥ 90`, and the caveat block suits a non-engineer. The `Where to read the code` section (it pointed at internals) was removed; the back-to-scanner link now sits just before the footer.

## [0.0.11] - 2026-05-03

### Added
- **Two new scanners** (default count now 12, all free, no API keys):
 - **`email_auth` (SPF / DMARC / DKIM)**: Cloudflare DoH TXT lookups for apex SPF, `_dmarc.<host>` DMARC, and DKIM across 10 common selectors (`default`, `google`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `s1`, `s2`). Weights: SPF 35 pts (`-all` full, `~all` partial, `+all` flagged "passes everyone"), DMARC 45 pts (reject 45, quarantine 32, none 14), DKIM 20 pts on any hit. Findings: missing-record, no-`all`-qualifier, multiple-SPF-records (RFC 7208 §3.2 violation), `p=none`, weaker-subdomain-policy, and a low-severity DKIM-not-found hint.
 - **`security_txt` (RFC 9116)**: fetches `/.well-known/security.txt` (then legacy `/security.txt`); grades canonical location, `Contact:`, `Expires:` (present, parseable, future), plus partial credit for `Policy:`, `Encryption:`, `Acknowledgments:`, `Preferred-Languages:`. `Expires` within 30 days is low-sev; unknown field names info-level (typo catch).
- **`/score` methodology page** linked from every footer as `OUR SCORE` (silver mono link, new tab). Six cards: TL;DR, letter→score lookup, aggregation rules, score→letter ladder, caveats (equal weighting, differing per-scanner ladders, link-out exclusions, snapshot-in-time, no vendor opinion). No em dashes.

### Changed (UI)
- **Footer simplified**: dropped the `URL REPORTER vX.Y.Z` label and the em-dash before "Made by". Now `OUR SCORE` (left, silver pill) and `MADE BY PAOLO DIOMEDE` (right).

### Fixed (per-scanner audit, 4 real bugs across 12 scanners)
- **`mozilla_observatory.py`**: a `null` or scalar from `…/{scan_id}/tests` crashed with `TypeError: 'NoneType' is not iterable`. Now defaults to empty.
- **`dnssec.py`**: any non-zero DNS RCODE was reported as `SERVFAIL=2` (broken chain). NXDOMAIN, REFUSED, FORMERR, NOTIMP now each map to the correct message and advice.
- **`dos_posture.py`**: `Age: 0` counted as cacheable, because `bool("0")` is `True`. Now int-parses and counts only positive ages.
- **`email_auth.py`** (SPF parser): `\b([-~?+])all\b` could **never** match `-all` / `~all` / `+all` / `?all` after whitespace (`\b` needs a word↔non-word transition; space and `-` are both non-word). **Every** SPF policy ending in `-all` scored as having no `all` qualifier (10 pts, not 35). Replaced with `(?:^|\s)([-~?+])all(?:\s|;|$)`.

## [0.0.10] - 2026-05-03

### Added
- **HTML report download.** The result page offers a pulsing "Download HTML" and a "Download Markdown" button. Both are rewritten after every `scanner_done`, surviving mid-scan crashes. New `render_html(report)` in `report.py` produces a self-contained, no-CDN document with embedded CSS and a `@media print` stylesheet (clean white-on-black for paper/PDF). New endpoint `GET /report/{report_id}.html`; cleanup TTL also removes `.html`.
- **Partial-failure banner on the result page.** When a scan errors mid-flight after `_write_partial_report()` saved a partial report, the page renders it under a `Partial report: …` banner (`.form-error` style) instead of HTTP 500.

### Changed (UI)
- **Full visual redesign - "Verification Lab" aesthetic.** Midnight-blue console meets editorial security advisory.
 - Type: **Bricolage Grotesque** (variable, opsz) for body & UI, **Fraunces** (variable serif, opsz 144) for the giant grade letter, **JetBrains Mono** for technical fragments (URLs, scanner keys, status pills, version chips). No Inter / Space Grotesk / Roboto.
 - Palette: midnight `#060914`, four-step elevation, hairlines `#1f2b4d → #3a4d80`, brand gradient `#4f8cff → #66e0ff → #b794ff` on top hairline, primary CTA, focus rings, checkbox fill, grade letter, download hover.
 - System strip: brand monogram + "scan in progress / scan complete" indicator with pulsing dot.
 - Mono `// section_name` eyebrow headers; floating `// per_scanner` / `// recommended_actions` card labels.
 - Geometric checkboxes, pill buttons (`border-radius: 999px`), pulsing "Download HTML" button (`download-blink`, paused on hover).
 - Mono uppercase status pills with colored dot; `running` pills pulse.
 - Recommendations numbered `01`, `02`, `03` in mono.
 - Dot-grid texture, radial blue glow; sections rise in with staggered `rise-in` delays.
 - Container width raised from 880px to 1080px.
 - Mobile (<720px): strip text shrinks, progress-table time column hides, overall card stacks, copy button repositions, fonts step down.
- **High-contrast warning callout** on the progress page: "Don't close it!" now in an amber-bordered, amber-tinted panel with `#ffd9a3` text.
- **Silver back-link** (`← scan another URL`): `#c0c4cc` outline pill, near-white with underline on hover.
- **Single-line tagline.** Removed `max-width: 56ch` from `.tagline`.

### Fixed (core logic)
- **`runner.py` elapsed time was always 0.0.** `asyncio.as_completed` yields wrapper coroutines, **not** the original Tasks, so the `task in starts` lookup always missed. Replaced with `asyncio.wait(FIRST_COMPLETED)`.
- **`web.py:result_page` returned HTTP 500** on a mid-scan runner error despite a saved partial report. Now renders it with an inline error banner.
- **`scanners/ssllabs.py`** called `asyncio.get_event_loop()` twice inside an async function (deprecated since Python 3.10). Switched to `asyncio.get_running_loop()`.
- **`scanners/internetnl.py` `host = urlparse(url).hostname or url`** fell back to the whole URL, giving a broken link-out like `https://internet.nl/site/https://example.com/`. Now bails with a clean error.

## [0.0.9] - 2026-05-02

### Changed (UI)
- **Inline ⓘ explainer next to *Open external scan ↗*** on link-out rows (progress and result pages). Tooltip: *"No public API for programmatic results. Click the link to run the check on the external site in a new tab."* New `.linkout-info`, `.linkout-info-icon`, `.linkout-info-tip` rules in `static/style.css`, reusing the `.copy-tip` pattern.

### Changed (CLI / markdown)
- CLI progress block now reads `link-out (no public API)` (was bare `link-out`).
- Markdown text summary line now reads `<scanner>: link-out (no public API) - …`.
- Markdown overall paragraph appends, with any link-out scanner: *"… 1 link-out only (internet.nl) - no public API; the report points at the external site for a manual check."*
- Per-scanner header for link-out scanners is now `### internet.nl - link-out (manual check on external site)`.

## [0.0.8] - 2026-05-02

### Changed (UI)
- Restyled the *"← scan another URL"* link: silver (`#c0c4cc`), no underline, near-white (`#e6e8ef`) with underline on hover, via a reusable `.back-link` class.

## [0.0.7] - 2026-05-02

### Fixed (core logic)
- **Crash safety**: `runner_task` deferred *all* report writes until every scanner finished, so a mid-scan kill lost everything. Reports are now written **incrementally**: after each `scanner_done` the web app appends the `ScanResult` to a job-local list, re-renders the markdown, and writes `./reports/<job_id>.md` (overwritten on `done`). The `.name` sibling is pre-written at job creation.
- **`render_markdown` heading**: the URL on the `# Security report - …` line is now backtick-wrapped; `_`, `*`, `~`, `[` rendered as italics / strikethrough / links.
- **`runner.run_scans`**: `SCAN_TIMEOUT_SECONDS` now sets the shared `httpx.AsyncClient` read timeout (clamped to [30, 300] s); before, only SSL Labs honored it and the rest were hard-coded at 60 s.
- **`download` endpoint** 500'd if `<id>.name` passed `exists()` but failed `read_text()` (race / permission flap); now falls back to the synthetic `<id>.md` filename.

### Changed (UI)
- All buttons (`Run scan`, `Download full markdown report`, `Select all`, `Deselect all`, copy-text) now have **fully rounded pill borders** (`border-radius: 999px`).
- The download button **pulses** (opacity + box-shadow ring, 2.4 s cycle); hover pauses it, `prefers-reduced-motion: reduce` disables it.
- Removed the copy under the scanner checkboxes ("Defaults come from config.env. Selections here override that for this run only.").
- Progress-page notice now reads: *"This page refreshes every 1.5s - Don't close it! Results are stored in memory until the scan finishes."*
- Removed the underline on URL links in `<h1>` headings (e.g. *Scanning `…`*); hover still underlines.

## [0.0.6] - 2026-05-02

### Changed
- **Renamed user-facing product to "Url Reporter"** (was "Url Reporter"). Header, footer, tab title, CLI banner, and `--version` read `Url Reporter v0.0.6 | Made by Paolo Diomede`. Package, CLI command, and repo directory remain `urlreporter`.
- URL-form helper note cut to *"Scans can take 1-3 minutes (SSL Labs is the slow one)."* The validation copy ("Only http(s) URLs are accepted; the scheme is added for you if you omit it") was redundant given inline rejection.

### Added
- **`LICENSE.md`** at the repo root (MIT, 2026 Paolo Diomede), linked from README's License section.
- **`gitUrlReporter.sh`** at the repo root: one-command stage / commit / push to `https://github.com/pdiomede/urlreporter`.
 - First run: `git init -b main`, adds `origin`, switches to `main`.
 - Default commit message is the package version, e.g. `v0.0.6`, from `pyproject.toml` (fallback `urlreporter/__init__.py`). Override with an argument.
 - **Secret-file guard**: refuses to run if `.env`, `.env.*`, `pat.txt`, `*.pat`, `*.token`, `token.txt`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`, `secrets.*`, or `config.env.local` exists in the repo root *and* is not covered by `.gitignore`.
 - **PAT-aware push**: with `pat.txt` present, the push uses a one-shot `GIT_ASKPASS` helper in a sandboxed `HOME` (so macOS Keychain, `~/.netrc`, `~/.gitconfig`, `/etc/gitconfig` can't supply a stale credential). The PAT never enters argv, shell history, or git config; helper and `HOME` are removed on exit.

### Fixed (UI)
- **Select all / Deselect all buttons** inherited `.scan-form button`'s primary-blue style and went *invisible on hover* (dark on dark). Fixed via `button.ghost-btn` with `!important` color/background; now outline pills with a blue hover tint.

## [0.0.5] - 2026-05-02

### Added
- **Shared retry helper** (`scanners/_retry.py`) wraps every outbound scanner HTTP call, retrying transient statuses (408, 429, 500, 502, 503, 504, 520-527, 529) and `httpx.RequestError` (timeouts, DNS failures, connection refused) with exponential backoff (3s, 8s, 20s). Each retry is logged at WARNING.
- **Per-scanner module loggers** - each scanner emits to `urlreporter.scanners.<name>`, propagating to the package file handler. Retries, fallbacks, and secondary-fetch failures land in `logs/error_<timestamp>.log`.
- **`describe_exc(e)` helper** - readable error string even when `httpx`'s `__str__` is empty.
- **`treat_404_as_transient`** retry flag, used by crt.sh, which serves 404s for valid queries under DB load.

### Fixed (core logic)
- **Empty error messages** when `httpx.HTTPStatusError` (and a few others) had blank `__str__`. All scanners now use `describe_exc`.
- **No retries** on most scanners (only SSL Labs and crt.sh had them); added to Mozilla Observatory, securityheaders.com, hstspreload.org, CAA, DNSSEC, HTTP→HTTPS redirect, and DoS posture.
- **`config.py`**: `INTERNETNL_API_TOKEN` is now `.strip()`ed.
- **`config.py`**: `SCAN_TIMEOUT_SECONDS` clamped to ≥ 10 so SSL Labs polling can't quit early.
- **`runner._safe_scan`** lets `asyncio.CancelledError` propagate instead of trapping it in `except Exception`.
- **`runner._emit`** wraps `on_event` in try/except so a buggy listener can't sink the scan; failures log at WARNING.
- **Logger restructure**: the handler now sits on the package logger (`urlreporter`) so every submodule reaches the per-run file; previously only `urlreporter.cli` and `urlreporter.web` logged.

### Fixed (UI)
- **Bar caption inconsistency**: showed "0%" then "(0%)"; now `(0%)` throughout.
- **Stuck shimmer**: the progress-bar highlight kept animating after the scan finished or errored; now stopped via `stopShimmer()`.
- **Endless polling**: `/scan/{id}/status` was polled forever on server errors; now capped at 12 consecutive failures (~72 s) with "Lost contact (gave up after N attempts)".
- **Reconnect counter**: while retrying, the caption shows "Reconnecting (N/12)" instead of an opaque "Lost contact".

## [0.0.4] - 2026-05-02

### Added
- **`dos_posture` scanner** - passive DoS / DDoS resilience check. One GET (zero load); inspects headers for CDN/WAF fingerprints (Cloudflare, Akamai, Fastly, AWS CloudFront, Google GFE, Azure Front Door, Sucuri, Imperva, KeyCDN, StackPath, BunnyCDN, CDN77, Vercel, Netlify, GitHub Pages, Varnish), positive-`max-age` / `s-maxage` or `x-cache` HIT signals, and rate-limit headers (`x-ratelimit-*`, `ratelimit-*`, `retry-after`). Weights: CDN presence 60, useful caching 25, rate-limit headers 15. Toggle via `SCANNER_DOS_POSTURE`.
- This is **not** a load test; active DoS testing is out of scope (legality, blast radius). Use k6, Locust, or gatling on your own staging with authorization.

## [0.0.3] - 2026-05-02

### Added
- **Four new scanners** (free, key-free), raising the default count to nine:
 - **crt.sh (Certificate Transparency)** - surveys certificates issued for the host in the last 90 days. Grades by CA concentration: A+/A for ≤4 CAs, downgrading when many CAs signed for one name. Retries on transient 404/5xx.
 - **CAA records** (Cloudflare DoH) - verifies the domain pins which CAs may issue certs, walking up the DNS tree for inheritance. Decodes presentation form (`0 issue "letsencrypt.org"`) and generic `\# <length> <hex>` (RFC 3597). A+ when issuance is restricted, C when only iodef is set, D when no records exist.
 - **DNSSEC** (Cloudflare DoH `AD` flag) - A+ for an authenticated response, F on SERVFAIL (broken chain), D when absent.
 - **HTTP→HTTPS redirect** - walks the redirect chain from `http://<host>`. A+ for a direct redirect to HTTPS on the same host, B with an intermediate http hop, C if it crosses to another host first, F if HTTPS is never reached. No HTTP listener: A.
- Each has a `SCANNER_<KEY>=true` toggle in `config.env` (`SCANNER_CRTSH`, `SCANNER_CAA`, `SCANNER_DNSSEC`, `SCANNER_HTTPS_REDIRECT`), enabled by default.
- Web UI: the index form lists every `REGISTRY` scanner as a checkbox, pre-checked from `config.env`, with `Select all` / `Deselect all`. Submission overrides the config for that scan only, so slow scanners (e.g. SSL Labs) can be dropped without editing config.

### Changed
- Renamed user-facing strings from "Url Reporter" to **Url Reporter**.

### Fixed
- `result.html` `<title>` was still hard-coded `urlreporter - {{ url }}`; now uses `{{ app_name }}`.
- `result.html` produced an empty `<a href="">` when a `ScanResult` had no `link`; now conditional on `r.link`.
- `urlutil.normalize_url` raised `ValueError` (HTTP 500) on an out-of-range port like `:99999`; now a clean form error.

## [0.0.2] - 2026-05-02

### Changed
- Renamed product to **Url Reporter** (dropping "" from the user-facing name). Footer, CLI banner, titles, and version output read `Url Reporter v0.0.2 | Made by Paolo Diomede`. Package, CLI command, and repo directory remain `urlreporter`.
- CLI reports now default to `./reports/<filename>.md` (matching the web app), not the current directory. Override with `--out PATH`.

### Added
- **Live progress page**: POST `/scan` schedules a background job and redirects to `/scan/{job_id}`, showing a progress bar and per-scanner status table polling `/scan/{job_id}/status`. Icons: ⏳ waiting, 🏃 running, ✅ done, ❌ error.
- **Indeterminate "starting…" bar** on submit, before the redirect.
- **Per-scanner CLI progress** block on stderr, updating in place on a TTY, plain when piped.
- **Copy-to-clipboard button** on the result page's *Raw text summary* with `execCommand` fallback.
- **Auto-linkified URLs** in recommendations, findings, summaries, and scanner errors, as `<a target="_blank" rel="noopener noreferrer">`.
- **Clickable "Open external scan ↗"** link for link-out scanners (e.g. internet.nl) on the progress and result pages.
- **Per-run error log** at `./logs/error_<YYYYMMDD-HHMMSS>.log`, one per CLI invocation and web startup, holding WARNING+ scanner errors and unexpected exceptions.
- **`./runUrlReporter.sh`** web launcher: `./runUrlReporter.sh [port] [host]` (defaults `127.0.0.1:8000`). `CH_RELOAD=1` enables uvicorn auto-reload.
- **`./bin/fix-venv-launcher`**: patches the pip-generated `urlreporter` console script to inject the project root into `sys.path`, working around iCloud-hidden editable `.pth` files (Python 3.13+ skips them).
- **Strict URL validation** (`urlreporter/urlutil.py`, shared by CLI and web): rejects non-http/https schemes (`javascript:`, `data:`, `file:`, `ftp:` …), control characters, embedded credentials, malformed hosts; prepends `https://` if no scheme; strips fragment and userinfo; caps length at 2000. Bad URLs show an inline form error.
- **Index form hardening**: `maxlength`, `autocomplete=off`, `spellcheck=false`, server-side errors preserving the typed value.
- **SSL Labs retries**: transient responses (429, 500, 502, 503, 504, 521-526, 529) and network errors retry with backoff (5s, 15s, 30s); the counter resets between successful polls.

### Fixed
- **Race condition** in `progress_status`: serializing `job["states"]` could collide with runner mutation (`RuntimeError: dictionary changed size during iteration`). Now serializes a `copy.deepcopy` snapshot.
- **`_cleanup_old_reports`** orphaned the `.name` sibling when expiring `.md` files; both now removed together.
- **`asyncio.create_task(runner_task())`** result wasn't retained, so GC could drop tasks. Now held in a `_running_tasks` set with a `discard` done-callback.
- **`@app.on_event("startup")`** is deprecated in FastAPI ≥ 0.110; migrated to `lifespan`.
- **`{job_id}` path parameters** require a 32-char hex pattern at the route level, so probes get 422, not a 404 lookup.
- **`result_page`** raised `KeyError` if the scan produced no report; now a clean 500.
- **`download` endpoint** re-sanitizes the on-disk `.name` through the writer's character whitelist (defense against CRLF / path separators in `Content-Disposition`).
- **`urlutil.normalize_url`** dropped IPv6 brackets (`[::1]:8080` became `::1:8080`); now preserved when the host contains a colon.
- **`logs/`** added to `.gitignore`.

## [0.0.1] - 2026-05-02

Initial release of **Url Reporter** (`urlreporter`).

### Added
- CLI (`./bin/urlreporter scan <url>`) runs configured scanners and writes a Markdown report to the current directory.
- Web UI (FastAPI + Jinja2): URL form, summary page, downloadable Markdown report.
- Five built-in scanners, toggleable via `config.env`:
 - SSL Labs (TLS / certificate grade, polling API)
 - Mozilla Observatory v2 (HTTP best-practices score & grade)
 - securityheaders.com (HTTP-headers grade, with header-inference fallback when the public `X-Grade` is gated by an API key)
 - internet.nl (link-out - no free single-scan API)
 - hstspreload.org (Chrome HSTS preload status)
- Overall grade aggregated over scanners with a numeric score; link-out / failed scanners excluded and noted.
- Recommendations deduped by title, sorted by severity.
- Parallel async execution with per-scanner error isolation.
- `config.env` + optional `config.env.local`; process environment variables override both.
- macOS / iCloud Drive workaround for hidden-flagged `.pth` files: bundled `./bin/urlreporter` launcher, `__main__.py`, and `PYTHONPATH=$PWD` instructions.
- Versioned CLI banner and web footer: *Url Reporter v0.0.1 | Made by [Paolo Diomede](https://pdiomede.com)*.

### Known limitations
- internet.nl is link-out only until an API token is wired in.
- securityheaders.com no longer exposes the letter grade to anonymous clients; the fallback flags only missing headers, not relative weight.
- SSL Labs scans can take 1–3 minutes the first time (cache miss).
