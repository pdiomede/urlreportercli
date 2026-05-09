# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.71] - 2026-05-10

### Changed (registration card row layout: DNSSEC moved back to row 2; "Registration" raw-summary header now stands alone)

- **`urlreporter/report.py:_render_registration_html` moves the DNSSEC cell from `cells_row1` back to `cells_row2`**, and places it as the **first** cell of row 2 (before Registrar lock). Row 1 now reads `Registrar / Created / Expires` (3 cells, with the 4th column intentionally empty); row 2 now reads `DNSSEC / Registrar lock / Registry lock / Nameservers` (with optional `Registrant country` joining as a 5th cell that wraps to a new line within row 2 on domains where it's exposed). Reverses the v0.0.68 placement.
- **`urlreporter/report.py:_registration_summary_line` now returns `"Registration\n" + …`** instead of `"Registration: " + …`. The raw-text summary block (used both by CLI stdout and by the web result page's `<details>` "Raw text summary" panel) now reads as a three-line group: a standalone `Registration` header, the registrar/expires bits below it, and the existing `Security: …` line below that. Same data, different vertical rhythm — the leading colon was doing the work of both labelling and starting the field list, which read awkwardly when the field list itself contained colons.

### Notes

- **Both rows still use `grid-template-columns: repeat(4, 1fr)`** in the inline `_HTML_CSS` (and in `static/style.css` for the web surface), so the vertical left-bar of every `.reg-cell` lines up between row 1 and row 2 even though row 1 only fills 3 of 4 columns. `DNSSEC` now sits directly under `REGISTRAR`, `REGISTRAR LOCK` under `CREATED`, `REGISTRY LOCK` under `EXPIRES`, `NAMESERVERS` under the empty 4th slot.
- **No change to `_render_registration_md`.** Markdown is row-based with no grid concept; field order in the markdown export is unchanged.
- **Web result page got the matching changes in lockstep.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side row reshuffle plus a small `.site-header` padding tweak that tightens the gap below the "scan another URL" pill on the result page.
- **No engine, scanner, route, or runtime change.**

## [0.0.70] - 2026-05-10

### Notes

- **Web-template-only release.** Fixes a navigation-consistency bug on the live progress page (5 internal-page links now stay in the same tab instead of opening new tabs). See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the per-line detail and the audit findings that surfaced this one issue out of 7 templates / 12 static assets.
- **No engine, scanner, parser, CLI, or CSS change.**

## [0.0.69] - 2026-05-10

### Notes

- **Web-template-only release.** This release reorders the live web result page so the registration card appears **after** the overall-score / per-scanner-breakdown grid and **before** the Raw text summary block. The standalone HTML report and markdown export are unchanged &mdash; the renderer keeps the registration card at its existing position near the top of the document, which is the right ordering for an archival/printable artifact. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail and the rationale for keeping the two surfaces' orderings different.
- **No engine, scanner, parser, runtime, CSS, or CLI change.**

## [0.0.68] - 2026-05-09

### Changed (registration card row layout: 4 + 3 with vertically-aligned cell bars)

- **Both renderer and template now place DNSSEC in row 1 instead of row 2,** flipping the v0.0.66 layout from "3 + 4" to "**4 + 3**". Row 1 is now `Registrar, Created, Expires, DNSSEC`; row 2 is now `Registrar lock, Registry lock, Nameservers` (with `Registrant country` joining row 2 as a 4th cell when present).
- **Both rows now use the same 4-column grid (`grid-template-columns: repeat(4, 1fr)`),** so the vertical left-bar of each `.reg-cell` aligns between row 1 and row 2 along the horizontal axis. Specifically: `REGISTRAR LOCK`'s bar sits directly under `REGISTRAR`'s, `REGISTRY LOCK` under `CREATED`, `NAMESERVERS` under `EXPIRES`. Row 2's 4th column is empty when no registrant country is exposed (the typical case post-GDPR).
- **`urlreporter/report.py:_render_registration_html` updated:** the `if reg.dnssec is True / elif reg.dnssec is False` branch now appends to `cells_row1` instead of `cells_row2`, placed between the Expires branch and the Registrar lock branch.
- **`urlreporter/templates/result.html` updated:** the DNSSEC cell block moved from the row-2 grid to the row-1 grid (between Expires and the row-1 closing `</div>`); the row-1 / row-2 `{% if %}` gate conditions updated to match (`reg.dnssec is not none` moved from row 2's gate to row 1's gate).
- **CSS in both `report.py` (inline `_HTML_CSS`) and `static/style.css`:** `.reg-grid-row1` was `repeat(3, 1fr)` and `.reg-grid-row2` was `repeat(4, 1fr)`; both are now `repeat(4, 1fr)` so the column boundaries are shared and bars align. The `margin-bottom: 14px` on `.reg-grid-row1` is preserved as a separator between the rows.

### Notes

- **No change to `_render_registration_md`.** Markdown is row-based with no grid concept; field order in the markdown export is unchanged (DNSSEC at registry still renders between Registry lock and Name servers).
- **No change to the CLI `Security:` summary line.** It's a one-line text summary; the row-grid layout doesn't apply there.
- **Responsive breakpoints unchanged.** At `max-width: 720px` both rows fall back to 2-column; at `max-width: 480px` both rows collapse to single-column. So mobile stacks cleanly.
- **Web result page got the matching change in lockstep.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail.

## [0.0.67] - 2026-05-09

### Fixed (web template emitted empty grid rows when one row had no cells)

- **`urlreporter/templates/result.html` row-grid divs are now individually gated on having at least one cell to render**, fixing an asymmetry with `_render_registration_html` introduced in the v0.0.66 two-row refactor. The Python renderer correctly skips an empty row via `if not cells_list: continue`; the Jinja template emitted both `<div class="reg-grid reg-grid-row1">` and `<div class="reg-grid reg-grid-row2">` unconditionally, so a domain whose RDAP only exposed signals from one of the two row-buckets would render an empty grid div with `margin-bottom: 14px` showing as visible empty space at the top of the card.
- **Audit of the v0.0.66 refactor.** This was the only real bug found. The `reg_has_data` section-level gate, the `{% if %}` / `{% endif %}` pairing inside each row, the responsive media-query breakpoints, and the existing per-cell conditional branches all balance and behave correctly. The "(the cell to the right)" tooltip phrasing on Registrar lock is technically positional and reads slightly differently on mobile, but it's a pre-v0.0.66 wording choice, not a regression.

### Notes

- **Web-template-only fix.** `_render_registration_html` is unchanged. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail.
- **No engine, scanner, parser, CSS, or runtime behavior change.**

## [0.0.66] - 2026-05-09

### Changed (Registration card laid out as 3 + 4 two-row grid)

- **`urlreporter/report.py:_render_registration_html` and `urlreporter/templates/result.html` now split the registration card cells into two rows.** Row 1 carries the three identity/dates cells (Registrar, Created, Expires); row 2 carries the four security signals (Registrar lock, Registry lock, DNSSEC, Nameservers). Previously a single auto-fit grid (`repeat(auto-fit, minmax(140px, 1fr))`) flowed all cells in one or two visual rows depending on viewport width &mdash; the layout could land on 3+4, 4+3, or 7-in-a-row on wide screens with no semantic correspondence between the row break and the meaning of the cells. The new layout enforces 3 cells in row 1 and 4 cells in row 2 at desktop widths, putting "what the domain *is*" above "how the domain is *protected*".
- **`_render_registration_html` refactored:** the single `cells: list[...]` is split into `cells_row1` and `cells_row2`. The render loop iterates `((cells_row1, "reg-grid-row1"), (cells_row2, "reg-grid-row2"))` and emits a separate `<div class='reg-grid reg-grid-row1'>` / `<div class='reg-grid reg-grid-row2'>` container per row. Existing per-cell logic (urgency, tooltips, sub-text) is unchanged; the cells just land in different containers now.
- **CSS in both surfaces** (inline `_HTML_CSS` block in `report.py` and `static/style.css`): `.reg-grid` keeps `display: grid; gap: 14px 22px;` as the base; `.reg-grid-row1` adds `grid-template-columns: repeat(3, 1fr); margin-bottom: 14px;` (the bottom margin separates the two rows visually); `.reg-grid-row2` adds `grid-template-columns: repeat(4, 1fr);`.
- **Responsive media queries** keep the layout sensible on narrow viewports: at `max-width: 720px` both rows fall back to 2-column; at `max-width: 480px` both rows collapse to single-column. So mobile users see a stack rather than awkward 3-cell or 4-cell rows that would force tiny cells.

### Notes

- **Registrant country (when present) lands in row 2 as a 5th cell.** Most domains have it redacted post-GDPR, so the 5-cell case is rare; when it appears, the row 2 grid wraps the 5th cell to a new line within row 2 (still visually attached to the security row, just slightly taller). This was a deliberate scope decision: forcing it into row 1 would make row 1 inconsistently 3 or 4 cells; giving it its own row 3 felt over-engineered for a rare case.
- **Standalone HTML report and live web result page changed in lockstep.** Both surfaces emit the same row structure with the same CSS class names; the matching CSS lives in both `report.py` (inline) and `static/style.css` (web). See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail.
- **Markdown export unchanged.** Markdown is one row per field; no grid layout to split.
- **CLI terminal `Security:` summary line unchanged.** Already a one-line text summary; no card layout involved.

## [0.0.65] - 2026-05-09

### Fixed (HTML report was missing the Registrant country cell)

- **`urlreporter/report.py:_render_registration_html` now appends a `Registrant country` cell after the `Nameservers` cell, matching the existing behavior of both the markdown export (`_render_registration_md`, since v0.0.55) and the live web result page (`templates/result.html`, since v0.0.55).** Found during a sync audit between the renderer and the Jinja template &mdash; the HTML report was the only surface that silently dropped the registrant-country signal when RDAP returned one. Affected domains where RDAP exposes a country (typically `.gov` and a handful of ccTLDs that haven't fully redacted post-GDPR; most commercial domains return `None` and the cell is gated `if reg.registrant_country:` so they're unaffected). The cell is neutral-color (no urgency), no tooltip &mdash; consistent with the web template's existing render.

### Notes

- **Sync audit results.** `_render_registration_html` and `templates/result.html` are now in sync at the logic level (same gate conditions, same urgency colors, same tooltip strings) for all seven cells: Registrar, Created, Expires, Registrar lock, Registry lock, DNSSEC, Nameservers, Registrant country. The CLI's `--html` and `--out` outputs and the live web result page produce equivalent decisions for the same input.
- **Two minor wording variations remain** (intentional, not synced): the DNSSEC cell value text differs between `Signed`/`Unsigned` (HTML report) and `Signed at registry`/`Unsigned at registry` (web template); the Expires cell sub-text differs between `in 3 months` / `expired 5 days ago` (HTML report) and `3 months from now` / `5 days ago` (web template). These are presentation-layer choices ("layout" per the user's framing), not logic differences. Left untouched in this release.
- **One markdown-only field remains:** `Last changed` (`reg.updated`) is rendered as a row in the markdown export but not as a cell in either the HTML report or the live result page. Pre-existing design choice from v0.0.55; left as-is.

## [0.0.64] - 2026-05-09

### Fixed (RFC citation in Nameservers tooltip was wrong)

- **`urlreporter/report.py:_render_registration_html` and `urlreporter/templates/result.html` had the Nameservers cell tooltip cite RFC 1035 §6.1.2 as the basis for "you should have at least 2 nameservers".** RFC 1035 §6.1.2 is actually titled "Boot file format" and has nothing to do with nameserver redundancy. The correct reference is **RFC 1912 §2.3 "NS records"**, which explicitly says: *"You should have at least two name servers for every domain, though more is preferred."* Both surfaces' tooltip strings now cite RFC 1912 §2.3 and quote that operative sentence directly so the user can see the actual basis for the recommendation. Affects both the `ns_count == 1` warning tooltip and the `ns_count <= 6` good-state tooltip.
- **CLI scope:** the standalone HTML report (CLI's `--html` output) carries the same tooltip text via `_render_registration_html`, so this fix lands on both the live web result page and the downloaded report files in the same release. The markdown export (`_render_registration_md`) was not affected — it never cited a specific RFC section, only used the strings "RFC violation; need 2+" and "RFC-compliant" which remain accurate against RFC 1912 §2.3.

### Notes

- **Audit found no other bugs** in the v0.0.63 Nameservers feature. Considered and ruled out: the cell label "Nameservers" vs the footer label "Name servers" (stylistic, not a bug), tooltip identical for counts 2-6 (sub-text differentiates), markdown count-and-list redundancy for ≤4 NSes (informational, not buggy), `§` Unicode in attribute values (renders fine), `reg_has_data` gate already includes `or reg.name_servers` from v0.0.55, and the 0-NS case already gated by the same `if reg.name_servers` check that hides the existing footer.

## [0.0.63] - 2026-05-09

### Added (Nameservers count cell on the registration card)

- **`urlreporter/report.py:_render_registration_html` now emits a new `Nameservers` cell on the registration card, surfacing the count of nameservers and a state-aware urgency color.** The cell sits after `DNSSEC` and before any registrant-country cell, alongside the existing `Name servers:` footer (which keeps showing the actual list of NS hostnames). The new cell is the at-a-glance answer to "how many NSes does this domain have, and is that fine?"; the footer answers "what are they?". State buckets:
  - **`1`** &mdash; **orange / `reg-warning`**, sub-text `RFC violation (need 2+)`. RFC 1035 §6.1.2 effectively requires two or more nameservers; a single NS is a single point of failure (provider outage = total domain blackout, provider compromise = full DNS hijack of the domain).
  - **`2`** &mdash; **green / `reg-good`**, sub-text `RFC-compliant`.
  - **`3` to `6`** &mdash; **green / `reg-good`**, sub-text `healthy count`.
  - **`7+`** &mdash; **neutral**, sub-text `above typical`. Not a problem; some large operators publish many for global redundancy or anycast diversity.
- **Each state ships its own info-tooltip** (using the existing `.reg-info` pattern from v0.0.57), explaining the security and availability angle in plain text. The tooltip names the threat model (provider compromise = DNS hijack, same vector v0.0.58's Registry Lock work addresses) so the cell is self-explanatory at a glance.
- **`urlreporter/report.py:_render_registration_md` enhanced the existing `Name servers` row to include the count and state inline,** e.g. `Name servers: bailey.ns.cloudflare.com, jeff.ns.cloudflare.com (2, RFC-compliant)`. No new row is added &mdash; the markdown export carries the same disambiguation in a single line per the markdown convention used elsewhere on the card.

### Notes

- **No new RDAP fetch logic.** The `RegistrationInfo.name_servers` list has been populated since v0.0.55; this release just adds analysis on top of the data we already have.
- **CLI terminal `Security:` summary line is unchanged.** The line is already crowded with the lock and DNSSEC signals; nameserver count is non-critical context that belongs in the visual card rather than the one-line summary. Users running `urlreporter scan ... --html` or `--out` see the new cell / row in the report files.
- **The `0`-count state is unreachable in practice** &mdash; if RDAP returns no nameservers, the existing footer is also skipped, and the new cell is gated on the same `if reg.name_servers` check. No code path emits a "0" cell today; left out of the state table to avoid implying a state that won't render.
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail.

## [0.0.62] - 2026-05-09

### Fixed (web result page hid registration card when only registry-lock data was present)

- **`urlreporter/templates/result.html` `reg_has_data` gate now also checks `reg.registry_locked is not none`.** When the v0.0.58 `registry_locked` field was added to `RegistrationInfo`, this gate condition wasn't updated alongside it &mdash; so on an RDAP response carrying only server*Prohibited codes and nothing else (no client* codes, no DNSSEC, no registrar entity, no dates, no name servers, no registrant country), the gate evaluated to false and the **entire registration card was suppressed**, hiding the very signal the user enabled. The fix adds one OR clause to the boolean.
- **CLI scope:** `--html` and `--out` outputs were not affected. The standalone HTML report (`_render_registration_html`) and markdown export (`_render_registration_md`) gate on whether any cell or row was actually built, so a card with only the Registry lock cell renders correctly. Bug was web-template-only.

### Notes

- **Audit found no other bugs** in the v0.0.58&ndash;v0.0.61 registry-lock work. Considered and ruled out: warning-color cascade onto the new actor sub-text on Off cells (matches the existing Expires-cell precedent), substring-matching on EPP status codes (theoretically over-broad but no real status code triggers a false match), and `_registration_security_line` edge cases (each signal independently null-checked, returns empty when all three are None).

## [0.0.61] - 2026-05-09

### Changed (lock cells now name the actor in always-visible sub-text)

- **`urlreporter/report.py:_render_registration_html` rewrote the value sub-text on all four lock-cell branches to consistently name the actor that controls the lock,** replacing the previous asymmetric copy that was confusing two consecutive users into asking whether `Registrar lock` and `Registry lock` were duplicates. Before this release, `Registrar lock: On` showed `transfer/update/delete prohibited` (described the **actions blocked**), `Registry lock: On` showed `server-level: requires out-of-band auth` (described the **enforcement mechanism**), and both Off states showed nothing &mdash; so the eye couldn't latch onto a parallel signal that distinguished the two cells. New copy uses parallel "via X" framing across all four states: Registrar lock On/Off → `via your registrar account`; Registry lock On/Off → `via the TLD registry (out-of-band auth)`. Always visible, parallel structure, names the actor (which is the actual point of distinction between client* and server* EPP codes).
- **`urlreporter/report.py:_render_registration_md` got the matching change:** the four lock rows now end with the actor clause in parentheses (`On (via your registrar account)`, `Off (via the TLD registry, out-of-band auth)`, etc.) so the markdown export carries the same disambiguation. Compact since markdown can't show two-line cells gracefully.

### Notes

- **Tooltip aria-labels and popover content are unchanged.** The hover/focus tooltips already explained the distinction in detail; the v0.0.61 sub-text exists for at-a-glance disambiguation by users who don't hover.
- **Cell labels (`REGISTRAR LOCK`, `REGISTRY LOCK`) are unchanged.** Standard EPP-derived terminology preserved so security-industry users still find what they expect when grepping screenshots / docs / tickets.
- **Urgency colors unchanged from v0.0.60.** Registrar/Registry On = green, Registrar/Registry Off = orange.
- **CLI `Security:` summary line unchanged from v0.0.59.** It already names the locks unambiguously on separate words and isn't visually crammed.
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail.

## [0.0.60] - 2026-05-09

### Changed (Registry lock: Off now renders as orange warning, not neutral)

- **`urlreporter/report.py:_render_registration_html` now applies the `reg-warning` urgency class to the `Registry lock: Off` cell** (previously empty / neutral). Mirrors the treatment of `Registrar lock: Off`: orange left-bar, orange value text. Url Reporter's audience is professional / high-value sites where missing Registry Lock is a real, actionable security gap, not a neutral fact &mdash; so the absence of the strongest available domain-level protection should be visually flagged the same way absent Registrar lock is. The previous "neutral, like DNSSEC: Unsigned" treatment was calibrated for general-purpose audiences and underweighted the signal for the actual user base.
- **`Registrar lock: Off` and `Registry lock: Off` now share the orange treatment;** if both are off, both cells flag, making it immediately obvious the domain has neither layer of EPP-status protection.

### Changed (em dashes removed from all tooltip strings)

- **All three new tooltip strings introduced in v0.0.58** (`Registrar lock: On`, `Registry lock: On`, `Registry lock: Off`) **had their em-dash sentence breaks replaced with proper punctuation** (period + new sentence, or semicolon + clause continuation). Em dashes render fine in some fonts but can look like hyphens or render as a misaligned glyph in others, especially at the small font size and tight max-width the tooltip uses; switching to plain ASCII punctuation makes the tooltip robust across all the platform fonts the report and result page might fall back to.

### Notes

- **Both surfaces updated in lockstep.** The standalone HTML report's tooltip CSS class change and the punctuation change land in the same edits the web result page got &mdash; see [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail. The same string appears verbatim in both surfaces.
- **No engine, scanner, runner, grading, CLI-flag, or CSS-rule change.** Pure tooltip-copy and one urgency-class swap.

## [0.0.59] - 2026-05-09

### Added (terminal summary now surfaces the security signals on a dedicated second line)

- **`urlreporter/report.py:render_summary` now emits a second line, `Security: …`, immediately under the existing `Registration: …` line.** The new line consolidates the three lock/DNSSEC signals that v0.0.58 surfaced in the HTML/markdown reports but that the terminal summary had no place for &mdash; before this release the terminal output told the user the registrar and the expiry date but said nothing about whether the domain had any of the registrar lock / registry lock / DNSSEC protections set, which made the CLI output materially less informative than the report files written by the same scan. Each signal renders as `<Name> <State>` (e.g. `Registrar lock On`, `Registry lock Off`, `DNSSEC Signed`) joined by the same `·` separator the existing line uses, so the look is consistent with the rest of the summary block.
- **New helper `_registration_security_line(reg)` in `report.py`** parallels the existing `_registration_summary_line(reg)`. Returns an empty string when **none** of the three signals are determinate (e.g. some ccTLD RDAP responses don't include status codes), so the line is omitted entirely on those domains rather than printing a bare `Security:`.
- **`render_summary` now skips the trailing blank-line separator only if both the registration line and the security line are empty.** Previously the blank line was tied to just the registration line, so a domain with security signals but no registrar/expiry data would have printed without a separator before the `Overall:` block; the new logic groups both lines as one section.

### Notes

- **No behavior change for the HTML/markdown reports** &mdash; this release only affects the text rendered by `render_summary`. The report files written by `--out` and `--html` got the same Registry lock signal in v0.0.58 via the renderer changes there.
- **`render_summary` output is also stored on the web side** (per `web.py:381`, `job["summary"]` keeps the same string), so anywhere the web ever surfaces it (e.g. a future API or a logged copy) gets the same second line for free.
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

- **`urlreporter/registration.py:RegistrationInfo` gained a `registry_locked: bool | None` field, and `_parse_rdap` now derives Registrar lock and Registry lock as two independent flags from the EPP status codes returned by RDAP.** Previously the single `info.locked` flag was set by a substring match on `"transfer prohibited"` or `"delete prohibited"`, which collapsed `client*Prohibited` (registrar-level, owner-set, defeats casual transfers but liftable by anyone with registrar-account access) and `server*Prohibited` (registry-level, lifted only via out-of-band auth at the registry — defeats the registrar-account-compromise DNS-hijack vector behind incidents like Cow Protocol and Curve Finance frontends) into one boolean. The new derivation looks for the canonical `clienttransferprohibited` / `clientupdateprohibited` / `clientdeleteprohibited` tokens for `info.locked`, and `servertransferprohibited` / `serverupdateprohibited` / `serverdeleteprohibited` for `info.registry_locked` &mdash; correctly distinguishing the two protections so a domain with full defense-in-depth (both client* and server* codes set, e.g. paypal.com, google.com) renders as two greens, while a domain with registrar lock only (e.g. example.com) shows registrar green + registry neutral.
- **Detection handles both RDAP status forms.** RDAP responses arrive in either the EPP camelCase form (`"clientTransferProhibited"`) or the RFC 8056 space-separated form (`"client transfer prohibited"`); the parser canonicalizes by stripping all whitespace and lowercasing before substring-matching, so both forms reduce to the same comparison key. Caught during verification when paypal.com / google.com initially showed `locked=False` despite obviously being locked &mdash; their RDAP server returns the space-separated form, which a naive camelCase substring check missed.
- **`urlreporter/report.py:_render_registration_html` now emits a separate `Registry lock` cell** (mirroring the existing DNSSEC branch shape) immediately after the `Registrar lock` cell. Both states (On / Off) carry their own tooltip explaining the security model and the threat each control defends against. The existing `Registrar lock` tooltip copy was updated to reference Registry lock as the stronger escalation path. **Deliberate UX choice: `Registry lock: Off` renders neutral (no urgency color), not orange** &mdash; Registry Lock is opt-in / often-paid and rare on consumer domains, so warning-coloring it on every domain would be alarmist and unactionable. Mirrors how `DNSSEC: Unsigned` is already shown neutral.
- **`urlreporter/report.py:_render_registration_md` got the matching new row** &mdash; `Registry lock: On (server-level: requires out-of-band auth)` / `Registry lock: Off (no registry-level protection)` &mdash; so the markdown export carries the same signal as the HTML report.

### Notes

- **Small correctness regression for domains with only server* codes set (no client* codes).** Before this release such domains showed `Registrar lock: On` because the substring match was broad; they will now correctly show `Registrar lock: Off, Registry lock: On`. The old label was technically incorrect (the registrar control wasn't actually set); the new pair of labels is accurate. This combination is rare in practice.
- **Tooltip copy stays intentionally generic about real-world incidents** &mdash; describes the threat model (registrar-account compromise → nameserver swap) without naming specific orgs in the user-visible string. Keeps the copy durable as past incidents fade from awareness.
- **No new HTTP calls, no new RDAP fetch logic, no schema changes.** Registry-lock detection reuses `RegistrationInfo.status_codes` (already populated raw from the RDAP response since v0.0.55).
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template-side detail.

## [0.0.57] - 2026-05-09

### Added (registration-card cell tooltips for state-sensitive fields)
- **`urlreporter/report.py:_render_registration_html` now supports an optional explanatory tooltip per cell, wired up to `Registrar lock` and `DNSSEC`.** The cell tuple was extended from `(label, value_html, urgency)` to `(label, value_html, urgency, tooltip)`. When a tooltip string is provided, the label gains an `&#9432;` info trigger that renders the explanation in a popover on hover/focus &mdash; closing the gap between "the colored accent says something is off" and "the user understands what _off_ actually means". Tooltip copy distinguishes all four states: Lock On / Lock Off / DNSSEC Signed / DNSSEC Unsigned, each describing the security meaning of that specific state (transfer-out hijacking risk for Lock Off; missing DS chain-of-trust for DNSSEC Unsigned; etc.). Cells without a tooltip pass `None` and render unchanged &mdash; the 4-tuple shape is opt-in so other cells (Registrar, Created, Expires, Registrant country) can adopt tooltips later in one line each.
- **Inline `_HTML_CSS` block gained `.reg-info` / `.reg-info-icon` / `.reg-info-tip` rules adapted from the existing `.linkout-info` pattern in `static/style.css`.** `.reg-label` switched to `display: flex; align-items: center; gap: 6px;` so the icon sits inline with the label text. Popover anchored to the icon's left edge (`left: 0`, not centered) so it does not clip past the rightmost grid cell on a wide registration card; `text-transform: none` and `letter-spacing: normal` reset the inherited uppercase tracked styling inside the popover. Trigger is keyboard-focusable (`tabindex='0'`) with `aria-label` carrying the same description &mdash; matches the project's existing `.linkout-info` accessibility pattern (no `role` on the trigger; the icon is a tooltip surface, not an activatable button). Print stylesheet hides `.reg-info` so the icon does not appear as an orphan glyph on paper.

### Notes
- **No engine, scanner, runner, grading, or CLI-flag behavior changed.** Pure renderer addition; the registration data shape (`RegistrationInfo` in `urlreporter/registration.py`) is unchanged.
- **Markdown report unchanged.** Markdown has no hover surface; adding parenthetical explanations would clutter every row. Left for a separate decision if ever requested.
- **Web result page got the matching change.** See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the template + static-CSS detail.

## [0.0.56] - 2026-05-09

### Notes
- **Version-only bump to track the web release.** v0.0.56 ships a small `urlreporter/web.py` cleanup &mdash; an unreachable scanner-picker code path was kept warm after the homepage form lost its checkboxes, and this release commits to the "web is opinionated; CLI is flexible" stance by removing the dead branch. No engine, scanner, runner, grading, report-renderer, or CLI-flag behavior changed; the version is bumped here purely to keep `pyproject.toml` / `__version__` in sync with the web release. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the per-line detail.

## [0.0.55] - 2026-05-09

### Changed (SSL Labs slow-poll degrades to link-out instead of red ERROR)
- **`urlreporter/scanners/ssllabs.py:scan` now returns a link-out result when the polling deadline expires while SSL Labs is still working.** Previously, hitting `SCAN_TIMEOUT_SECONDS` (default 180) while SSL Labs was still in `status: IN_PROGRESS` produced `ok=False, error="Timed out after 180s waiting for SSL Labs."` &mdash; surfacing as a red ERROR row in the per-scanner table, which mis-implied the scanned site had a TLS problem when in fact the third-party assessment was simply slow (1-3 minutes is typical for first-time scans on a cache miss). The deadline branch now returns `ok=True, grade=None, score=None, link=https://www.ssllabs.com/ssltest/analyze.html?d=<host>` with a summary like `"Assessment still running after 180s. First-time SSL Labs scans take 1-3 minutes; cached scans return in seconds. Open the link to watch live progress on ssllabs.com."`. The row drops out of the red ERROR bucket into the same "no public API" link-out bucket InternetNL and the crt.sh double-fail tail use; already excluded from the weighted average via `aggregate_score`'s `score is not None` filter, so the overall grade is unaffected. Click-through goes to the live SSL Labs analyze page where the user can watch the assessment finish naturally.

### Notes
- **No behavior change on cache hits or normal cache-miss completions.** The vast majority of scans never hit the deadline (cache hit returns in seconds; typical cache miss completes in 90-180s). This release only changes what the user sees on the long tail of slow assessments (>180s).
- **Other SSL Labs failure modes still surface as red ERROR.** Hard failures &mdash; `status=ERROR` from SSL Labs (real TLS problem on the target), exhausted retries on transient HTTP 5xx, exhausted `httpx.RequestError` retries, missing endpoints / grades in the parsed response &mdash; still return `ok=False` so genuine target-side issues remain visible. Only the "polling timed out, but SSL Labs is still happy and working" path is now graceful.
- **Consistent with the v0.0.50 crt.sh + CertSpotter pattern.** Same "third-party flake degrades to link-out, never a red ERROR for the target" stance applied to SSL Labs.

## [0.0.54] - 2026-05-09

### Notes
- **Version-only bump to track the web release.** v0.0.54 ships web-side template / CSS edits only (progress-page notice line break, in-page top nav cleanup, result-page registration-card domain chip recoloring, and a "More about our Scanners" CTA at the foot of the landing page's twelve-scanners section). No engine, scanner, runner, grading, report-renderer, or CLI-flag behavior changed. The version is bumped here purely to keep `pyproject.toml` / `__version__` in sync with the web release. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the per-file detail.

## [0.0.53] - 2026-05-09

### Fixed (audit pass: validation, cancellation, write errors, and TTL cleanup)
- **`urlreporter/urlutil.py:normalize_url` now converts malformed bracketed IPv6 into `InvalidURL` instead of leaking raw `ValueError`.** Inputs like `https://[not::ip]/` and `https://[::1` used to escape the normal validation path, which could turn a bad CLI input into an unhandled exception and a bad web form input into a 500. Host validation now requires real IPv6 literals for colon-containing hosts, catches parser `ValueError`s, and rejects IPv4-like numeric shorthand / legacy forms (for example `127.1`, `010.000.000.001`) rather than letting platform resolver normalization decide what they mean.
- **`urlreporter/runner.py:run_scans` now cancels and drains child tasks when the parent scan is cancelled.** A Ctrl-C, uvicorn shutdown, or self-cancelling scanner could previously leave scanner tasks and the parallel RDAP task running against an `httpx.AsyncClient` that was already closing. The cancellation path now cancels pending scanner tasks plus the registration task, awaits them with `return_exceptions=True`, and then re-raises the original cancellation.
- **`urlreporter/cli.py:scan` now exits nonzero when report output cannot be written.** The CLI used to catch `OSError`, print `Failed to write report`, but still continue to the success path and print `Report written to:`. Directory creation and final Markdown / HTML writes now fail the command honestly and suppress false success messaging.
- **`urlreporter/web.py` now enforces in-memory job TTL on read routes, not only when a new scan starts.** `/scan/{job_id}`, `/scan/{job_id}/status`, and `/scan/{job_id}/result` all call `_cleanup_old_jobs()` before lookup, so a stale job no longer remains readable forever if no later scan is submitted.
- **`urlreporter/web.py:_cleanup_old_reports` now prunes stale `.md`, `.html`, and `.name` files independently.** The previous startup cleanup only iterated `*.md`, so orphaned HTML or filename sidecars could accumulate indefinitely. Cleanup now checks all three report suffixes and leaves unrelated files alone.

### Tests
- **Added focused regression coverage in `tests/test_audit_fixes.py`.** Tests cover malformed IPv6 validation, child-task cancellation cleanup, CLI write-failure exit behavior, stale job TTL enforcement on the status route, and orphan sidecar report cleanup.

## [0.0.52] - 2026-05-09

### Fixed (web concurrency: SSRF gate no longer blocks the event loop)
- **`urlreporter/urlutil.py:assert_publicly_routable` is now `async def` and uses `loop.getaddrinfo` instead of `socket.getaddrinfo`.** The function is invoked from two async paths in `web.py` (once up-front in the `POST /scan` handler, and once per outbound HTTP request via the `_ssrf_request_hook` httpx event hook, which fires for every redirect on every scanner). Under uvicorn's single event loop, every blocking DNS lookup paused every other in-flight scan, the `/scan/<id>/status` poll, and the SSRF hook for every other concurrent request. The 30s `_DNS_CACHE` masked it for repeat lookups within a scan, but a typical scan first-touches ~8-10 distinct third-party hostnames (cloudflare-dns.com, hstspreload.org, securityheaders.com, observatory-api.mdn.mozilla.net, crt.sh, api.certspotter.com, …), each triggering a fresh blocking lookup. Switching to `await loop.getaddrinfo(host, None)` dispatches DNS to asyncio's thread executor so the event loop keeps running. Both call sites in `web.py` (`_ssrf_request_hook` and the `/scan` handler) were updated to `await` the call.
- **Verified the fix is non-blocking under load.** Live test: during a 12.6 ms DNS resolve, a 5 ms-interval heartbeat coroutine ticked 3 times (under the previous synchronous version it would have ticked 0 or 1). All correctness cases preserved (still rejects literal RFC 1918, loopback v4 / v6, link-local incl. 169.254.169.254, multicast, reserved, unspecified, and the cloud-metadata hostname blocklist; still allows public hosts).

### Notes
- **No public-surface change.** No new route, scanner, config key, or CLI flag; `urlutil.assert_publicly_routable`'s signature changed from `def` to `async def` but is called only from `web.py` (the CLI is intentionally unguarded since operators may legitimately scan internal hosts), and both call sites were updated in the same commit.

## [0.0.51] - 2026-05-09

### Notes
- **Version-only bump to track the web release.** v0.0.51 ships web-side template updates (new `/contact` page, footer Contact link added across every page, the nav version-pill moved into a `Current build` pill on the About page, copy fixes, link-style cleanup) plus four template-side bug fixes. No engine, scanner, runner, grading, report-renderer, or CLI-flag behavior changed; the version is bumped here purely to keep `pyproject.toml` / `__version__` in sync with the web release. See [CHANGELOG_WEB.md](./CHANGELOG_WEB.md) for the detailed change list.

## [0.0.50] - 2026-05-09

### Added (crt.sh resilience: CertSpotter failover + link-out tail)
- **`urlreporter/scanners/crtsh.py` rebuilt around a three-tier fallback chain.** crt.sh remains the primary source; on `RetryExhausted` / non-2xx / non-JSON / wrong-shape it falls over to **CertSpotter** (`api.certspotter.com/v1/issuances`), a different operator (SSLmate) covering the same CT data with a generous unauthenticated free tier. If CertSpotter also fails, the scanner degrades to a **link-out result** (`ok=True, score=None, grade=None, link=https://crt.sh/?q=<host>`) instead of returning a red `ERROR` row — same pattern InternetNL uses when no API token is set, so the row drops out of the scanner table's error bucket and is automatically excluded from the weighted average. Provenance is honest: when CertSpotter is the source, the summary appends ``(via CertSpotter — crt.sh unreachable)``.
- **Internals refactored into composable helpers.** `_fetch_crtsh` and `_fetch_certspotter` each return a normalized cert list (or raise a private `_SourceFailed`) so the existing grading logic in `_grade` operates on the same shape regardless of which source served the data. CertSpotter responses are mapped into crt.sh's field names (`entry_timestamp`, `not_before`, `issuer_name`) at parse time; the grading model is untouched.

### Fixed (CT failover correctness)
- **CertSpotter now uses `include_subdomains=true` to match crt.sh's substring-search semantics.** crt.sh's `?q=<apex>` is a fuzzy substring match — for an apex query like `pdiomede.com` it returns certs for the apex AND every subdomain (whose SANs contain the apex string). CertSpotter with `include_subdomains=false` returns only certs whose CN/SAN exactly matches the apex, so when the failover fired for an apex scan the grade was computed from a much narrower sample and could land on a different letter than crt.sh would have produced. The two sources need to behave equivalently for the failover to be transparent.
- **`_grade` no longer takes an unused `host` parameter.** Dead code dropped from the helper signature and call site.
- **CertSpotter-source summary tightened.** The previous ``(via CertSpotter; crt.sh unreachable: crt.sh: gave up after 4 attempts; last HTTP 502)`` repeated "crt.sh" twice (once from our prefix, once from `retry_request`'s `label="crt.sh"` error message) and stuffed a verbose retry trace into the report's summary cell. Now reads ``(via CertSpotter — crt.sh unreachable)``; the full upstream-error detail still lands in the per-run log.

### Notes
- **No new dependencies, no new routes, no scoring change.** The link-out result has `score=None` so `aggregate_score` already excludes it from the weighted average — a CT double-outage no longer drags the overall grade down or surfaces as red ERROR.
- **No SSRF surface added.** Web scans run the CertSpotter fetch through the same `_ssrf_request_hook` as every other outbound call; `api.certspotter.com` resolves to public IPs.
- **Failover budget.** Worst case (both upstreams down) adds CertSpotter's retry budget (~31s) before falling through to link-out — same total budget as a single scanner under the existing retry policy. Best case (crt.sh works first try) is unchanged.

## [0.0.49] - 2026-05-09

### Added (domain registration card via RDAP)
- **New `urlreporter/registration.py` module fetches RDAP metadata for the scanned URL's domain.** `runner.run_scans` now kicks off `fetch_registration(url, client)` in parallel with the 12 scanners, awaits it before emitting a new `registration` event, and attaches the result to a new `Report.registration: RegistrationInfo | None` field. The fetcher does an IANA bootstrap (cached process-wide via an `asyncio.Lock`), looks up the TLD's RDAP service, GETs `/domain/{name}` with the existing `retry_request` helper, and parses registrar, creation / expiration / last-changed events, EPP status codes (for registrar-lock detection), DNSSEC at the registry level, name servers, and registrant country. Always-on (no `SCANNER_*` toggle), excluded from the weighted score, never produces Top-recommendation findings — purely informational, never blocks or fails the scan.
- **All three report renderers carry the new section.** `render_summary` adds a one-line "Registration: Registrar X · Expires …" between the URL line and the Overall section. `render_markdown` adds a `## Registration` section with bullet rows. `render_html` adds a full-width `.registration-card` between the hero and the gauge/table grid, with color-coded expiration urgency: red ≤30 days or expired, orange ≤90, neutral otherwise; green left border on healthy lock/DNSSEC indicators.
- **CLI `_IncrementalWriter` handles the new `registration` event** so the partial-on-interrupt path (Ctrl-C / engine crash) preserves the registration section in `writer.last_report` even when the scan didn't emit `done`.

### Changed (report polish)
- **Markdown report heading format updated.** `# Security report - <url>` is now `# Security report: <small>[\`<url>\`](<<url>>)</small>` — colon instead of hyphen, URL rendered smaller via inline HTML and now clickable. Angle-bracket form on the link target so URLs containing parens or other special characters don't break the link.
- **"by Url Reporter" is now a link to `https://urlreporter.com/`.** Markdown footer (`_Generated … by [Url Reporter](https://urlreporter.com/)_`), HTML report's hero `<p class='generated'>` (inherits the surrounding muted color, no underline, transitions to cyan on hover), and HTML report's footer `<p class='footnote'>` (matches the existing accent-color "Paolo Diomede" link styling).
- **Footer attribution everywhere now reads "Built by".** `credit_line()` (used in CLI banner via `--version`), HTML report footer, and all six web templates updated from "Made by".
- **HTML report registration card visual cleanup.** Domain chip in `<h2>` neutralized: `.registration-card h2 code` now uses `var(--mute)` text on a neutral white-tinted background, matching the gray of the per-cell `REGISTRAR` / `CREATED` labels instead of standing out in cyan. `.reg-grid` `minmax(170px, 1fr)` → `minmax(140px, 1fr)` so all five cells share row 1 at the report's 916px content width instead of wrapping DNSSEC to row 2.

### Fixed (registration data integrity + safety)
- **`_get_bootstrap` no longer poisons its cache on transient failure.** Previously a 503 / non-JSON / network error would set `_bootstrap = {}` permanently; every subsequent scan in the same process returned no registration data even after the network recovered. Now the failure path returns `{}` from local scope without touching the module-level cache, so the next scan retries.
- **`registrar_url` and `rdap_link` are now scheme-validated at parse time.** A compromised registry RDAP server could deliver e.g. a `javascript:alert(1)` URL for the registrar 'about' link; the HTML escapers (`_esc`, Jinja autoescape, markdown link syntax) handle special characters but do not strip dangerous schemes. New `_safe_http_url` helper accepts only `http://` / `https://` URLs at parse time, applied to both fields.
- **Print stylesheet's `.reg-sub` rule no longer overrides urgency colors.** The `!important` on `.reg-label, .reg-sub, .reg-ns, .reg-ns-label { color: #555 !important; }` defeated the more-specific `.reg-cell.reg-warning .reg-sub { color: #b87a16; }` (specificity 0,0,3,0). Removed `!important` so the cascade resolves correctly — warn/critical sub-text retains its orange/red coloring when printed.
- **`_format_age` no longer prints "12 months" for 360-364 days.** Capped `months = min(days // 30, 11)` so the months branch never displays 12; the 365-day boundary already escalates to "1 year".
- **`_get_bootstrap` validates `data` is a dict.** If IANA's `dns.json` ever returned a non-dict JSON value, `data.get("services", [])` would raise `AttributeError`; now we `isinstance(data, dict)` and return `{}` with a warning log on mismatch.

### Notes
- **No new dependencies.** RDAP is fetched via the existing `httpx.AsyncClient` and the same `retry_request` helper every scanner uses; bootstrap is parsed with stdlib `json`.
- **No SSRF surface added.** Web scans run the bootstrap and RDAP fetches through the same `_ssrf_request_hook` as scanners; both targets (`data.iana.org`, registry RDAP servers) are publicly routable, so the hook is a no-op in practice.
- **Backward compatible.** No public route, config key, scanner registry, or CLI-flag change. Reports without RDAP coverage (unsupported TLD, IP target, RDAP unreachable) gracefully omit the section in every renderer.

## [0.0.48] - 2026-05-06

### Notes
- **Version-only bump to track the web release.** v0.0.48 ships a small web-side `robots.txt` adjustment (now disallowing `/version`, the polling endpoint added in v0.0.47). No CLI surface is affected — no scanner, runner, grading, report, or CLI-flag behavior changed.

## [0.0.47] - 2026-05-06

### Notes
- **Version-only bump to track the web release.** v0.0.47 ships a web-UI feature (an in-page "new version available" banner driven by a polling `/version` endpoint) plus a small progress-page tagline tweak. Neither affects the CLI surface — no scanner, runner, grading, report, or CLI-flag behavior changed. The version is bumped here purely to keep `pyproject.toml` / `__version__` in sync with the web release.

## [0.0.45] - 2026-05-05

### Fixed (securityheaders.com scanner: local grade synthesis when third-party blocks us)
- **`urlreporter/scanners/security_headers.py` now computes the headers grade locally when securityheaders.com is unreachable.** v0.0.44 added an HTML body fallback for the removed `X-Grade` response header, but post-deploy testing revealed that securityheaders.com is now sitting behind Cloudflare bot protection — non-browser User-Agents (including ours) get an HTTP 403 with `cf-mitigated: challenge` and a JavaScript challenge page instead of the actual scan result. So neither the `X-Grade` header path nor the HTML body parse can succeed. The X-Grade wasn't *removed*; we're just being blocked from seeing it.
- **The fix removes the dependency on securityheaders.com entirely (as the source of truth).** The scanner already fetches the target's own response headers as a parallel direct-GET fallback. We now compute a synthesized grade from those headers using a calibrated penalty table (high-severity miss = -25, medium = -15, low = -5, starting from 100), and call `score_to_letter` to map back to a letter. Sites with all six modern security headers present (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) score 100/A+; sites missing every header score 0/F. The summary line makes the source explicit (e.g. *"Headers grade A+ (100/100) — graded locally; securityheaders.com unreachable."*) so the report still credits the third-party check when it works and discloses local fallback when it doesn't.
- **Order of preference unchanged.** When securityheaders.com *does* return a grade (`X-Grade` header or scrapable HTML body), that grade still takes precedence — the local synthesis is purely a fallback. So the day Cloudflare's challenge eases up or securityheaders.com publishes a documented API, no further work is needed.

### Documentation
- **`urlreporter/templates/scanners.html` (the `/scanners` page) — securityheaders.com card updated.** The previous "Notes" paragraph said the fallback path produced "no overall letter, only a list of findings." That's no longer true; the v0.0.45 fallback always produces a letter. New copy describes the Cloudflare bot-protection situation, explains the local penalty table (high = -25, medium = -15, low = -5), and notes that the result summary makes the grade source explicit so readers can tell which path produced their grade.
- **`README_WEB.md` (scanner #3 row) updated** to mirror the same explanation in compact form.

### Notes
- **Calibration.** Penalty table chosen so that the dominant scoring drivers are the high-severity headers (HSTS, CSP), matching securityheaders.com's own emphasis. A site with HSTS + CSP but no other modern headers scores 60 (C+); a site with no HSTS but everything else scores 75 (B+); a site with no headers at all scores 0 (F). Rough calibration to securityheaders.com's typical letter ranges, intentionally erring slightly strict.
- **Backward compatible.** Sites that were already getting a grade from `X-Grade` see no change. Sites that were ERRORing (urlreporter.com itself, plus any site with all-modern-headers behind a securityheaders.com bot block) now get an accurate locally-graded result and contribute to the overall score (weight 1.5).
- **No new dependencies.** No external API calls added. All grading uses headers we were already fetching.

## [0.0.44] - 2026-05-05

### Fixed (securityheaders.com scanner: HTML fallback for removed X-Grade header)
- **`urlreporter/scanners/security_headers.py` now extracts the grade from the HTML body when the `X-Grade` response header is absent.** securityheaders.com silently stopped returning `X-Grade` as a response header; the scanner was returning ERROR for every scan that hit this path, regardless of how well-configured the target site's headers were. The fix adds a regex fallback on the HTML body — specifically `class="score"...<span>GRADE</span>` — which is how the site's own page always displayed the grade. Sites with all security headers present (e.g. urlreporter.com itself) now correctly return **A+ · 100/100** instead of ERROR, and the weight-1.5 scanner properly contributes to the overall grade again.
- **Audit: all other scanners checked for the same pattern.** Every other scanner was reviewed for similar reliance on specific third-party HTTP response headers or fragile JSON paths. Findings: `ssllabs.py`, `mozilla_observatory.py`, and `hsts_preload.py` already use `.get()` with explicit fallbacks and/or explicit error returns for missing fields. No other scanner has a silently-breaking dependency of this type.

### Notes
- **No changes to grading weights, report renderers, CLI flags, templates, or other scanners.** One scanner file changed.
- **Backward compatible.** Sites that already received a grade from `X-Grade` continue to use that path; the HTML fallback only fires when the header is absent.

## [0.0.43] - 2026-05-05

### Changed (footer + recommendations card polish)
- **Copyright prefix added to every footer.** All six templates (`index.html`, `about.html`, `score.html`, `scanners.html`, `progress.html`, `result.html`) now read `© 2026 · Made by Paolo Diomede` instead of just `Made by Paolo Diomede`. Middle-dot separator keeps the line readable and matches the existing minimalist footer aesthetic.
- **Cascading-rain chevrons shifted right** on the result page's "+ N more in the downloaded report" cluster. Previously the three vertically-stacked chevrons hugged the left edge of the recommendations card, which was below where the Markdown / Self-contained HTML buttons start; the cascade visually didn't point at the buttons. Added `padding-left: 64px` to `.report-card .recs-more-chevrons` so the cascade sits over the rough horizontal center of the Markdown button below it. The chevron rain now reads as an actual pointer toward the download CTA.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI runtime changes.** Templates and one CSS rule.
- **Backward compatible.** Existing routes, config keys, on-disk reports unchanged.

## [0.0.42] - 2026-05-05

### Changed (email_auth scanner: parent-walk + MX-aware skip)
- **`urlreporter/scanners/email_auth.py` rewritten to walk up the parent chain for SPF and DMARC lookups** instead of probing only the input host. SPF/DMARC records are typically published at the registered domain (apex), not on every subdomain — so a webapp host like `app.aave.com` previously got penalized as F=0 even when `aave.com` was correctly configured with strict policies. Now the scanner walks `app.aave.com → aave.com` and uses the closest ancestor with records. Findings annotate where records were found (e.g. *"DMARC policy is `p=reject` (on aave.com, inherited by app.aave.com)"*) so the report stays informative about which level enforces the policy.
- **MX-aware skip for non-mail-sending subdomains.** When the input host is a subdomain (≥3 labels), and walking the parent chain finds no SPF, no DMARC, AND no MX records anywhere, the scanner now returns a link-out result (`grade=None, score=None`) instead of an F. Webapp hosts that don't send or receive mail aren't graded as if they were broken — they're correctly identified as not-applicable, and `grading.aggregate_score` excludes link-outs from the overall score. Apex domains (≤2 labels) still get scored normally even without MX, since the *"we don't send mail, but lock spoofing down anyway"* pattern is meaningful there.
- **DKIM probing extended to the apex** when scanning a subdomain. Previously only `<selector>._domainkey.<input host>` was probed; now `<selector>._domainkey.<apex>` is also probed in parallel, so transactional mail signed at the apex (the common case) is correctly detected.
- **New helpers in `email_auth.py`**: `_parent_domains(host)` (mirrors `caa.py`'s walk-up pattern), `_doh_answers(client, name, rrtype, *, label)` (generic DoH JSON fetcher that replaces the SPF/DMARC-only `_doh_txt` data path), and `_doh_has_mx(client, name, *, label)` for the MX detection.

### Notes
- **Concrete impact for the example case.** A scan of `https://app.aave.com` previously aggregated to **B / 72** because the email_auth scanner returned F=0 (weight 2.0) on a webapp subdomain that doesn't have its own email records. With the fix, the scanner either picks up `aave.com`'s actual apex SPF/DMARC and grades accordingly, or — if the chain genuinely has no mail records or MX — returns link-out and is excluded from the overall, lifting the grade meaningfully closer to the real posture of the site.
- **Backward compatible scoring for already-correct apex domains.** Direct apex scans (e.g. `https://aave.com`) with locally-published SPF + DMARC + DKIM produce the exact same grade as before. The change only affects subdomains and the edge cases that were producing false-positive Fs.
- **No new dependencies.** All DNS lookups use the same Cloudflare DoH endpoint already in place for `caa`, `dnssec`, and `email_auth`. No PSL / `tldextract` / `dnspython` needed.
- **No changes to the CLI surface, runner, grading thresholds, or report renderers** — the scanner returns the same `ScanResult` shape it always did. Existing reports re-render unchanged; new scans pick up the more accurate scoring automatically.

## [0.0.41] - 2026-05-05

### Added (homepage install block: copy button + cleaner pip-upgrade step)
- **Copy button on the "Install from GitHub" terminal mockup.** Sits in the term-bar's top-right with a standard copy icon and a "copy" tooltip on hover/focus. On click, it grabs every `.term-line.cmd .exe` from the surrounding `.term` block, joins them with newlines, writes to the clipboard via `navigator.clipboard.writeText`, and flashes a "copied!" tooltip + green border for ~1.6s. Falls back to `document.execCommand('copy')` on older browsers without the async Clipboard API. Reads commands from the live DOM rather than a hardcoded list, so adding a new install step in the markup updates the copied text automatically.
- **`pip install --upgrade pip` added as the fourth install step.** Old pip versions print a "new release available" notice that confused new users into thinking the install had failed; ensuring pip is current also gives the latest dependency resolver. The lede ("up in N commands") was updated from "four" to "six" to match the new step count. Both surfaces in the install path — the homepage terminal mockup and both READMEs — now show the same six-line install flow.

### Changed (READMEs)
- **README.md (CLI distribution) and README_WEB.md (full web project)** install blocks both gain the new `pip install --upgrade pip` line in the same position, between `source .venv/bin/activate` and `pip install -e .`. New users see a clean install run with no version-mismatch noise from pip.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI runtime changes.** Templates + CSS + ~25 LOC of vanilla JS in the existing inline IIFE.
- **Backward compatible.** Existing routes, config keys, on-disk reports unchanged. The copy button degrades gracefully if JS is disabled (the terminal mockup still renders correctly and users can hand-select the commands).

## [0.0.40] - 2026-05-05

### Documentation (production cleanup ops)
- **README: new "Cleanup in production" subsection under Reports.** The in-app `_cleanup_old_reports()` in `web.py` only runs once, at uvicorn startup — sufficient for short-lived dev processes, but a long-lived production uvicorn lets reports older than the documented 24h TTL accumulate between restarts. Documented the recommended complement: a one-line `find /var/www/urlreporter/reports -type f -mmin +1440 -delete` script wired into a systemd timer (`OnUnitActiveSec=1h`) or a hourly cron entry. With either external scheduler, the on-disk lifecycle stays bounded regardless of app uptime. The pattern is now deployed on urlreporter.com via a `urlreporter-cleanup.timer` unit running every hour.

### Notes
- **Documentation only.** No engine, scanner, grading, report-renderer, template, CSS, or CLI changes.
- **No code deploy required.** The systemd timer is server-side ops; the README change just makes the recommended pattern discoverable for self-hosters and future maintainers.

## [0.0.39] - 2026-05-05

### Fixed (HEAD requests on public routes returned 405)
- **All public-facing GET routes now also accept HEAD.** Previously every route was registered with `@app.get(...)`, which only binds GET — a HEAD request received `HTTP 405 Method Not Allowed` with `allow: GET`. RFC 7231 §4.1 states that GET and HEAD MUST be supported by all general-purpose servers, and this behavior tripped up uptime monitors (Pingdom, UptimeRobot, StatusCake) and link-checker tools that prefer HEAD over GET to validate cheaply. Switched the affected routes to `@app.api_route(..., methods=["GET", "HEAD"])`, which lets Starlette serve HEAD as a body-stripped GET automatically — same headers, no body, correct semantics.
- **Routes updated**: `/`, `/score`, `/scanners`, `/about` (HTML pages), `/robots.txt`, `/.well-known/security.txt`, `/sitemap.xml`. The dynamic per-job and per-report routes (`/scan/{id}`, `/scan/{id}/status`, `/scan/{id}/result`, `/report/{id}.md`, `/report/{id}.html`) intentionally stay GET-only — they require valid UUIDs and external monitors won't HEAD them.
- **No effect on social card rendering.** Twitter, Slack, LinkedIn, Discord, Facebook, etc. all use GET to scrape OG metadata; HEAD support is hygiene, not a fix for any visible-to-users issue. Spec compliance + uptime-monitor-friendly is the win.

### Notes
- **No engine, scanner, grading, report-renderer, template, CSS, or CLI changes.** Seven decorator changes in `web.py` only.
- **Backward compatible.** Existing GET behavior on every route is byte-identical; HEAD requests that previously errored with 405 now succeed with the same headers a GET would return.
- **Verify after deploy**: `curl -sI 'https://urlreporter.com/' | head -1` should return `HTTP/2 200` (was `HTTP/2 405`).

## [0.0.38] - 2026-05-05

### Changed (live-scan page: links no longer interrupt the watch)
- **All same-origin links on `/scan/{job_id}` (the live progress page) now open in a new tab.** Previously the brand/logo (`href="/"`) and the footer's `Score` / `Scanners` / `About` links were normal in-tab navigations — clicking any of them mid-scan replaced the live progress UI, so the user lost their view of in-flight scanners (the scan itself kept running on the server, but the polling JS and progress table were gone). Each of those four links now carries `target="_blank" rel="noopener noreferrer"`. The GitHub button, the scanned-URL anchor in the heading, and the "Made by Paolo Diomede" credit already had the new-tab treatment; this release brings the rest of the page in line with that pattern. Other pages keep their normal in-tab navigation — only the progress page treats every internal link as "open elsewhere so the live scan stays visible".

### Changed (recommendations card: cascading-rain chevrons)
- **The chevron pointer under "+ N more in the downloaded report" was redesigned** as a vertical "raindrop" cascade that visually points at the Markdown / Self-contained HTML download buttons stacked below it. The previous 5-chevron horizontal row blinked in unison and didn't really direct the eye downward; the new layout is 3 chevrons stacked vertically with a staggered fade-and-translate cycle (each child offset by 0.3s on a 1.8s loop) so the cascade always has at least one chevron mid-flight. Each chevron fades in 4px above its rest position, settles, then fades out 6px below — reading as a gentle drip toward the buttons. The "+ N more" text keeps the existing `recs-more-blink` rhythm; only the chevrons changed. CSS lives under `.report-card .recs-more-chevrons` and a new `chevron-rain` keyframe in `static/style.css`. `@media (prefers-reduced-motion: reduce)` shows all 3 chevrons static at full opacity with no animation.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI changes.** Templates and CSS only.
- **Backward compatible.** Existing routes, config keys, on-disk reports unchanged.

## [0.0.37] - 2026-05-05

### Added (version pill + GitHub link on every page's top nav)
- **`<span class="right">` block added to the `.system-strip` nav on all five inner pages** (`/about`, `/score`, `/scanners`, `/scan/{id}` progress, `/scan/{id}/result`). Each carries the version pill (`v{{ app_version }}`) and a GitHub link button pointing at `https://github.com/pdiomede/urlreportercli`, mirroring the homepage's `nav-actions` area. Previously only the homepage showed those affordances; the five inner pages had only the brand mark on the left and an empty-feeling top-right corner.
- **New CSS in `static/style.css`** for `.system-strip .right .version-pill` and `.system-strip .right .github-link`. Both opt out of the parent `.system-strip`'s uppercasing (`text-transform: none`) so the pill reads `v0.0.37` and the link reads `GitHub` in mixed case, matching the homepage. The pill uses `var(--text)` (`#eef1f8`) on a 22%-opacity white border for contrast; the GitHub button uses the same near-white text on a 16%-opacity border, brightening to `var(--accent)` blue on hover.

### Notes
- **No engine, scanner, grading, report-renderer, or CLI changes.** Templates and CSS only.
- **Backward compatible.** Existing routes, config keys, on-disk reports unchanged.

## [0.0.36] - 2026-05-05

### Fixed (footer link color on inner pages)
- **"Made by Paolo Diomede" link on inner pages (`/about`, `/score`, `/scanners`, `/scan/{id}` progress, `/scan/{id}/result`) was rendering muted instead of bright like the homepage.** The 0.0.33 release added `.site-footer .footer-end a { color: var(--text-primary); }` to `static/style.css`, but `style.css` defines `--text` (line 26) — not `--text-primary` (which is only declared in the homepage's inline `<style>` block). With the variable undefined, the rule fell through to the inherited `color: var(--text-mute)` from the parent `.site-footer .footer-end`, producing the dim look. Fixed by switching the rule to the variable that actually exists in `style.css`: `color: var(--text)` (`#eef1f8`, near-white). Hover behavior unchanged. The homepage already used the correct variable name internally and was unaffected.

### Notes
- **One-line CSS fix.** No engine, scanner, grading, report-renderer, template, or CLI changes.
- **Backward compatible.** Existing routes, config keys, on-disk reports, and CLI flags all unchanged.

## [0.0.35] - 2026-05-05

### Security (web surface only — CLI unchanged)
- **Origin / cross-origin POST defense on `/scan`.** Without this, a malicious site embedding `<form action="https://urlreporter.com/scan" method="post">` could silently trigger scans from any visitor's browser — low impact in isolation (no destructive action, no auth state to abuse) but it amplifies the concurrency cap from 0.0.34 by spending a victim's browser to consume server slots. Now the `/scan` POST handler reads the `Origin` header and compares its `netloc` to the request's `Host` header. If `Origin` is set and doesn't match `Host`, the request is rejected with HTTP 403 + a "Cross-origin requests are not allowed" form-error banner. If `Origin` is *missing* (legitimate non-browser clients like curl, server-to-server callers, older browsers), the request is allowed through — those aren't the threat model and rejecting them would break legitimate API usage. The check sits at the top of the handler, before the concurrency cap, so cross-origin floods are rejected with no resource consumption.
- **Default `MAX_CONCURRENT_SCANS` raised from 8 → 16.** More lenient out of the box for traffic spikes; still tunable via env var.

### Notes
- **No changes to scanners, runner, grading, report renderers, templates, or CLI.** The check is ~15 LOC in `web.py:scan()`.
- **Backward compatible**: every legitimate same-origin browser submit and every non-browser client (curl, scripts, monitoring) continues to work. Only cross-origin browser POSTs from foreign sites are now rejected.
- **Defense in depth**: nginx already perimeter-rate-limits (we observed 429s during testing of 0.0.34). The Origin check protects against the abuse path that nginx rate-limiting *doesn't* catch — a single visitor's browser triggered by a malicious page on another domain.
- **Verified**: same-origin curl POSTs (no Origin header) → 303; cross-origin browser submits with `Origin: https://attacker.com` → 403.

## [0.0.34] - 2026-05-05

### Security (web surface only — CLI unchanged)
- **SSRF gate on `/scan` POST.** New `assert_publicly_routable(url)` in `urlreporter/urlutil.py` rejects URLs whose host is, or DNS-resolves to, a private/loopback/link-local/multicast/reserved/unspecified IP. Wired into `web.py:scan()` after `normalize_url`. Previously, a user could submit `http://127.0.0.1:6379` (Redis), `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (cloud metadata), or any RFC1918 address; the scanners would issue real HTTP requests to those internal hosts and reflect responses into the public report (job IDs are unguessable but the attacker creates the job and reads their own report, so anonymity wasn't a barrier). The gate uses `ipaddress.ip_address(...).is_private/.is_loopback/.is_link_local/.is_multicast/.is_reserved/.is_unspecified` for literal IPs and resolves hostnames via `socket.getaddrinfo` with a 30s in-process cache to keep the added latency under ~5ms typical. Cloud-metadata hostnames (`metadata.google.internal`, `metadata.aws.internal`, `metadata.goog`, `instance-data*`) are also blocked by name in case DNS is intercepted. The error message is intentionally generic ("This URL is not allowed") to avoid fingerprinting internal topology. The CLI does **not** call this gate — local operators may legitimately scan internal hosts.
- **Concurrency cap on `/scan` POST.** `_running_tasks` set in `web.py` previously grew unboundedly: each scan opens an `httpx.AsyncClient` and runs 12 outbound scanners (SSL Labs alone takes 1-3 min), so unlimited concurrency is a real DoS vector — an attacker hitting `POST /scan` in a loop can exhaust memory, file descriptors, and outbound-connection slots until OOM, or until upstream scanners (SSL Labs, crt.sh) start rate-limiting *us*. New `MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "16"))` gates the handler at the top: when `len(_running_tasks) >= cap`, returns HTTP 503 with `Retry-After: 60` and a friendly "We're at capacity" page. Tunable via env var without redeploy.

### Notes
- **No changes to scanners, runner, grading, report renderers, templates, or CLI.** Both fixes are localized to `web.py` and `urlutil.py`.
- **Backward compatible** for legitimate public-URL scans: every URL that worked in 0.0.33 still works in 0.0.34. URLs targeting internal hosts via the web surface are now rejected with a 400; the same URL via the CLI continues to work as before.
- **Verified**: 13 SSRF test cases pass locally (loopback IPv4, RFC1918, link-local IPv6, AWS/GCP metadata addresses, multicast, unspecified, plus two public-host positive controls).

## [0.0.33] - 2026-05-05

### Changed (homepage / nav / footer polish)
- **GitHub button + install block point at the new public CLI repo** (`pdiomede/urlreportercli`) instead of `pdiomede/urlreporter`. Both the homepage nav button (`.btn.btn-ghost`) and the "Install from GitHub" terminal mockup were updated. The terminal walk-through now reads `git clone .../urlreportercli.git` → `cd urlreportercli` → `python3 -m venv .venv && source .venv/bin/activate` → `pip install -e .`. The `about.html` "Run it yourself" paragraph was also retargeted at the CLI repo and trimmed to drop the "self-host the web UI" claim (the public CLI repo doesn't carry the web surface).
- **Top nav got a new "CLI" link** between Scanners and Trust, anchoring at `#surfaces` ("CLI for CI. Web UI for everyone else."). Clicking it now lands cleanly below the sticky header instead of cutting the section heading off — added `section[id] { scroll-margin-top: 88px; }` so every anchored section (How it works, Report, Scanners, CLI, Trust) accounts for the ~72px-tall sticky nav.
- **Version pill in the nav is now legible.** Was `var(--text-muted)` (`#6e7896`) text on an 8%-opacity white border — both effectively invisible against the deep navy background. Bumped to `var(--text-primary)` (`#e8ecf6`) text + 22%-opacity border.
- **Footer "Made by Paolo Diomede" link now matches the version pill color** across all six pages (`/`, `/scanners`, `/about`, `/score`, `/scan/{id}` progress, `/scan/{id}/result`). Was `var(--accent-2)` cyan on inner pages and inheriting a muted color on the homepage; both surfaces now render the link in `var(--text-primary)` near-white with cyan on hover.

### Added (result page)
- **"+ N more in the downloaded report" hint** under the Top recommendations card on `/scan/{id}/result`. The card has always shown only the top 3 recs (by design: glanceable triage), with the full deduped list living in the downloadable Markdown report (and top 10 in the HTML report). When the report has more than 3 recs, a small italic line now tells users how many more are in the downloaded file. Cosmetic, no engine change.

### Notes
- **No engine, scanner, grading, or report-renderer changes.** Templates, CSS, and one new line in `result.html`.
- **Backward compatible.** Existing routes, config keys, CLI flags, and on-disk report formats unchanged.

## [0.0.32] - 2026-05-05

### Changed (raw summary now matches the result-page KPIs)
- **`render_summary()` now emits a `Scanners: N of M ok.` line** between the overall grade and the scan-completed line. The result page's left card has a "Scanners ok" KPI tile (e.g., `11/12`) that conveys at-a-glance how many scanners successfully ran. The raw text summary - shown both on `urlreporter scan ...` stdout and inside the result page's collapsible "Raw text summary" `<details>` block - was the only surface that omitted this count. Now every surface (visual gauge tiles, raw summary, downloadable Markdown / HTML reports) carries the same set of header data.
- **Counts treat link-out scanners as "ok"** (they ran successfully, they just don't return a number). Matches the existing KPI tile semantics in `urlreporter/templates/result.html`. So a run of `11/12` typically means 1 failed and 11 finished, where "finished" includes both graded and link-out.

### Notes
- **No engine, scanner, web-route, or rendering changes beyond the new line.** The Markdown / HTML report renderers already had a more verbose "Aggregated from X graded scanner(s); Y link-out only (...); Z failed (...)" line in the Overall section; the raw summary's terser form is intentional - the per-scanner list directly below it already names every scanner and its outcome.
- **Backward compatible.** Existing reports re-render with one extra line; no schema or route change.

## [0.0.31] - 2026-05-05

### Removed (standalone landing-page mirror at project root)
- **Deleted `index.html` from the project root** (1,838 lines). It was added in 0.0.21 as a "self-contained static mirror of the live home page" with the stated purposes of *previewing the design without running the app* and *deploying as a CDN-cached landing page*. Neither materialized in practice: the dev preview path is just `./runUrlReporter.sh` (which boots the actual app, not just the homepage), and the production deploy serves the live Jinja template via nginx + uvicorn at urlreporter.com without any CDN-cached static. Meanwhile the file was the source of repeated drift bugs - the GitHub button hrefs went stale, the `git clone` placeholder was `your-org/urlreporter` for too long, the version pill was hardcoded `v0.0.21` while the live template auto-updated via `{{ app_version }}`, the install commands had to be touched twice on every release, and so on. Net: no consumer, 2x maintenance burden, recurring drift.
- **Nothing in code, scripts, routes, configs, deploy units, or nginx references the deleted file.** The only outstanding mentions are historical CHANGELOG entries (0.0.21 added it, 0.0.25 fixed its GitHub link, 0.0.27 mirrored a footer change to it). Those entries describe what was true at their respective release times and are intentionally left as-is.
- **The live homepage (urlreporter.com) is unaffected.** It's rendered from `urlreporter/templates/index.html` via FastAPI and has been the actual source of truth all along.

### Notes
- **No engine, scanner, web-route, CLI, or report-renderer changes.** Removal of an unused file plus the routine version-pill / footer-credit / changelog updates.

## [0.0.30] - 2026-05-05

### Changed (OG / social-card metadata)
- **Replaced `static/og-image.png` (1.4 MB, 1536x1024) with `static/og-image.jpg` (122 KB, 1200x630).** The PNG was 2.4x WhatsApp's 600 KB cap so WhatsApp / Telegram / Signal previews showed a broken-image icon for the link card. The dimensions also did not match the `og:image:width=1200 og:image:height=630` meta tags, which is the kind of inconsistency Facebook's Sharing Debugger and LinkedIn's Post Inspector flag silently. Generated via `sips` (resize-to-1200x800 preserving aspect, center-crop to 1200x630, save as JPEG quality 85). 11.5x smaller, exact aspect ratio, every social-card preview now renders the image.
- **All four indexable templates updated** (`index.html`, `about.html`, `score.html`, `scanners.html`) — five total `og:image` / `twitter:image` references now point at the new `.jpg`. The old PNG file was deleted.

### Changed (homepage SEO copy length)
- **Homepage `<title>` shortened from 65 chars to 57** to fit Google's 50-60 char optimal window. Was `Url Reporter: Free website security audit from 12 public scanners`; now `Url Reporter: Free security audit from 12 public scanners` (the URL already implies "website").
- **Homepage `<meta name="description">` shortened from ~180 chars to ~150** to fit the 110-160 char SERP snippet window. Was the long enumerated list of scanners (TLS, HTTP headers, DNSSEC, CAA, HSTS, email auth, security.txt, and more); now a tighter version that keeps the key signals.
- **Homepage `<meta property="og:description">` shortened from ~210 chars to ~117 chars** so Facebook / LinkedIn / WhatsApp link cards no longer truncate it mid-sentence. Was the full named-scanner enumeration (SSL Labs, Mozilla Observatory, securityheaders.com, ...); now a category-level summary (TLS, headers, DNSSEC, email auth, security.txt).
- **Homepage `<meta property="og:title">` aligned with the new `<title>`.** Twitter card title and description were already within their respective limits and were left as-is.

### Notes
- **Other pages' titles / descriptions unchanged.** about, score, and scanners had reasonable lengths already; only the homepage triggered the audit's title/description warnings.
- **No engine, scanner, or report-renderer changes.** Static asset + meta tags only.
- **Backward compatible.** Existing routes, scoring, CLI flags, on-disk reports unchanged.

## [0.0.29] - 2026-05-05

### Fixed (report parity audit: 4 content drifts between markdown / HTML / CLI summary)
- **Generation credit case mismatch.** Markdown reports said `_Generated <ts> by urlreporter_` (lowercase package name); HTML reports said `Generated <ts> by Url Reporter` (display name). Aligned to the display name `Url Reporter` in both renderers - the package name is an implementation detail and shouldn't surface in user-visible footers.
- **HTML overall score format used spaces around the slash.** Markdown / CLI summary render `(87/100)`; HTML rendered `87 / 100`. Removed the spaces so the score string is consistent across all surfaces (`87/100`).
- **HTML aggregate summary dropped the link-out explainer tail.** Markdown's "Aggregated from..." line includes "1 link-out only (internet.nl) - no public API; the report points at the external site for a manual check"; HTML truncated to just "1 link-out only (internet.nl)". Ported the same explainer string to the HTML renderer so both spell out *why* link-out scanners aren't graded.
- **`Report.total_elapsed` now appears in every report.** The field has been on the dataclass since 0.0.22 and showed up only in the result page's "Scan time" KPI tile. The downloadable Markdown / HTML reports never embedded it. Both renderers now append `Scan completed in {N}s.` after the aggregate summary; the CLI's `render_summary()` (used both as the stdout printout and as the result page's "Raw text summary" `<details>` block) gets the same line.

### Notes
- **Audit method.** Built a synthetic `Report` in `urlreporter/report.py`'s in-process API, ran it through `render_markdown` / `render_html` / `render_summary`, diffed the three textual outputs section-by-section. The four bullets above are the only content-level differences found; everything else is intentional layout choice (per-scanner findings inline in MD vs. separate "// detailed findings" section in HTML; gauge + KPI tiles only on the live result page; etc.).
- **Result page → report gaps that were left as-is.** The recommendation cap differs by surface (MD: all; HTML: top 10; result page: top 3). This is by design - each surface has different real estate, and the result page intentionally surfaces the highest-priority three for one-glance triage. Per-scanner findings are also shown only in the downloadable reports, not on the result page; users wanting the full breakdown can click the Markdown / HTML download buttons in the left card.
- **Backward compatible.** Same `Report` dataclass, same routes, same scanner outputs. Existing on-disk reports written before 0.0.29 won't have the elapsed line; new scans do.

## [0.0.28] - 2026-05-05

### Changed (within-scanner concurrency, tier A from the perf roadmap)
- **`security_headers` now fires its two HTTP calls in parallel.** The X-Grade probe at `securityheaders.com/?q=...` and the direct fetch of the user's own URL (used to surface missing-header findings when the X-Grade is gated) are independent — the direct fetch never depended on anything from the X-Grade response. The previous sequential pair was wrapped into two inner async helpers (`_fetch_grade`, `_fetch_target`) and dispatched via `asyncio.gather(...)`. Wall time becomes `max(call)` instead of `sum(call)` — saves roughly half the scanner's time on a healthy run, ~1s in the typical case.
- **`security_txt` now probes `/.well-known/security.txt` and `/security.txt` in parallel** instead of sequentially. Previously the scanner walked the canonical path first, then fell back to the legacy path only on a 4xx — meaning the no-security.txt case (the common one for the 70th-percentile site) paid two RTTs to learn the file isn't there. With `asyncio.gather` over both candidates, that case now takes one RTT. Canonical-first preference is preserved by walking the gathered results in `(WELLKNOWN_PATH, LEGACY_PATH)` order; if both 200, the well-known result wins as before.
- **Both scanners use the same `asyncio.gather` pattern that landed in 0.0.23 for `email_auth`** (the 12-DKIM-selector parallelization). Same retry-helper semantics, same exception handling — `RetryExhausted` propagates as before, transient HTTP errors are folded into the per-call return tuple so a failure on one parallel call never cancels the other.

### Notes
- **No new dependencies.** Adds `import asyncio` to two scanner modules; otherwise just a refactor of the existing `scan()` body.
- **Backward compatible.** Same `ScanResult` shape, same scoring, same finding text, same on-disk report format. A scan run on the same target before and after this release produces byte-identical reports.
- **Two further tiers of optimization remain available** (cross-scan shared httpx client, scan-result cache); see the perf roadmap. The cache layer is the next big single ROI win when traffic warrants it.

## [0.0.27] - 2026-05-05

### Changed (brand-mark parity across all pages)
- **Inner-page brand mark now matches the homepage exactly.** `style.css` `.brand-logo` was 48x48 with `border-radius: 12px`; now 44x44 with `border-radius: 11px` to match `index.html`'s inline `.brand-mark` rule. `.brand-name` was 26px / `letter-spacing: 0.04em`; now `1.125rem` (18px) / `letter-spacing: 0` to match the homepage wordmark.
- **The wordmark is no longer rendered as `URL REPORTER` in all-caps on inner pages.** The parent `.system-strip nav` applies `text-transform: uppercase` so the right-side `OUR SCORE` link reads correctly, but that style was cascading to the brand-name span on the left. Added `text-transform: none` on `.brand-name` so the wordmark renders as `Url Reporter` (title case) like on the homepage. Affects `/about`, `/score`, `/scanners`, `/scan/{id}` (progress), and `/scan/{id}/result`.

### Changed (footer parity across all pages)
- **Inner-page footers replaced with the homepage's footer pattern.** Old footer was a flex row of `version-pill | Made by Paolo Diomede` in uppercase mono. Replaced on all five inner pages (`about`, `score`, `scanners`, `progress`, `result`) with the homepage layout: a 2-column grid showing nav links `Score | Scanners | About` on the left and `Made by Paolo Diomede` on the right, in title-case sans-serif. Stacks single-column below 720px.
- **New CSS in `style.css`:** `.site-footer .footer-grid` / `.footer-mid` / `.footer-end` with title-case overrides (`text-transform: none`, `letter-spacing: 0`, `font-family: var(--font-sans)`, `font-size: 0.875rem`) to opt out of the parent `.site-footer`'s uppercase-mono treatment. The outer `.site-footer` keeps its 64px top margin and hairline border so vertical rhythm is unchanged.
- **Version pill is no longer shown in the inner-page footer.** The homepage's footer doesn't have one either; the `{{ app_version }}` is on the homepage's nav (`.version-pill`) only. The CLI / web report files still embed the version in their content where it matters.

### Removed (redundant nav button)
- **`OUR SCORE` button removed from the top-right of every inner page.** The button (the `<a class="header-score-link" href="/score">Our score</a>` block inside `.system-strip > .right`) used to live on `/about`, `/score`, `/scanners`, `/scan/{id}` (progress), and `/scan/{id}/result`. With the new homepage-style footer adding `Score | Scanners | About` links to every page, the header button became duplicate navigation. Removed the entire `<span class="right">…</span>` block from all five templates; the system-strip now just shows the brand mark on the left. The `.header-score-link` CSS rule in `style.css` is dead code and can be cleaned up later (kept for now to avoid CSS churn this release).

### Notes
- **No engine, scanner, grading, route, or report-renderer changes.** Templates and CSS only.
- **Backward compatible.** All routes, config keys, CLI flags, and on-disk report formats unchanged.

## [0.0.26] - 2026-05-05

### Added (homepage install block)
- **New "Install from GitHub" block** on the homepage's `#surfaces` section, between the "CLI for CI. Web UI for everyone else." heading and the existing CLI/Web mockup pair. Adds a small eyebrow + one-sentence lede + a centered terminal mockup (`max-width: 780px`) showing the four-command install flow:
  - `git clone https://github.com/pdiomede/urlreporter.git`
  - `cd urlreporter`
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -e .`
  - then `./bin/urlreporter scan https://example.com`
  Reuses the existing `.term` / `.term-bar` / `.term-line` styles already on the page (no new CSS), so it visually matches the run-time CLI mockup directly below it. The "Successfully installed" line uses `urlreporter-{{ app_version }}` so it auto-updates on each release.
- **README "Install" section now starts with `git clone`** so the documentation matches the homepage walkthrough. Previously the section assumed the user was already inside the repo directory and only showed venv + `pip install`.

### Notes
- **Cosmetic / docs only.** No engine, scanner, grading, web-route, or report changes.
- **Backward compatible.** No new deps in `pyproject.toml`; existing routes and CLI flags unchanged.

## [0.0.25] - 2026-05-04

### Fixed (homepage GitHub button)
- **The GitHub button in the homepage nav pointed at `https://github.com/` instead of the actual repo.** The static landing-page mirror at `index.html` had the original placeholder href; clicking it landed users on github.com's homepage instead of the project. Now points at `https://github.com/pdiomede/urlreporter` with `target="_blank" rel="noopener noreferrer"`.
- **Stale `https://github.com/your-org/urlreporter.git` placeholder in the install codeblock** on the same static page; replaced with `https://github.com/pdiomede/urlreporter.git` so the copy-paste command actually works.
- **Hardcoded `v0.0.21` version pill in the static mirror** is now `v0.0.25`. The live template uses `{{ app_version }}` and updates automatically; the static mirror has to be touched on each release.

### Added (live template parity)
- **Mirrored the GitHub button into the live Jinja template** (`urlreporter/templates/index.html`). Per the 0.0.21 changelog the static and live homepages are supposed to stay content-equivalent, but the GitHub button only existed on the static side. Now both surfaces show the same nav: `version-pill` + `GitHub` button (using the existing `.btn-ghost.btn-sm` styles already defined inline). Same href and target as the static side.

### Notes
- **Cosmetic / link-correctness only.** No engine, scanner, grading, or report changes.
- **Backward compatible.** All routes unchanged.

## [0.0.24] - 2026-05-04

### Fixed (per-scanner bug audit, 4 real bugs across 12 scanners)
- **`caa.py`: a transient DoH failure on the leaf name aborted the ancestor walk.** CAA records inherit from the closest ancestor that has them, so the walk-up over `_parent_domains(host)` is the whole point of this scanner. The previous code returned a hard error on the first `RetryExhausted` (or `httpx.HTTPError`/`ValueError`) on `www.example.com` and never tried `example.com` where the CAA record actually lives. Now each candidate's lookup failure is logged as a warning and the loop continues; an error result is only returned if **every** ancestor lookup raised, in which case we have no signal at all and surfacing the failure is correct.
- **`dnssec.py`: non-zero RCODE finding had identical `detail` and `recommendation` text.** The `rcode_meta` table's second tuple element was being passed as both fields, so the user saw the same sentence twice in the report. The advice is genuinely a recommendation; `detail` now states `"The resolver returned RCODE <n>."` and `recommendation` carries the actionable advice.
- **`dos_posture.py`: `("Generic CDN (via header)", [("via", None)])` flagged any `Via` header as a CDN.** RFC 7230 §5.7.1 requires every proxy in the chain (forward, reverse, non-CDN) to add a Via entry, so the fingerprint produced false positives - corporate forward proxies and origin-attached reverse proxies were counting as a CDN, inflating the score by 60 points and dropping the "No CDN/WAF detected" finding that is actually true. Removed the catch-all entry and the now-redundant dedup branch that suppressed it.
- **`internetnl.py`: setting `INTERNETNL_API_TOKEN` made the result *worse*.** Without a token the scanner emitted a link-out result (`ok=True`, no score, links to internet.nl for a manual check). With a token configured, the scanner returned `ok=False` with the error message `"internet.nl batch-API integration is not implemented yet."`, which counted as a failed scanner in the report. Now the no-token path stays unchanged, and the token-set path also falls back to link-out (logging a WARNING so the operator knows the configured token is being ignored). A configured token can no longer produce a worse report than no token at all.

### Notes
- **No web/template/CSS changes.** Scanner Python only.
- **Backward compatible.** Same routes, config keys, CLI flags, and on-disk report format. Existing reports re-render unchanged.

## [0.0.23] - 2026-05-04

### Changed (scanner concurrency: tier-1 speed improvements)
- **`email_auth` now fires every DNS probe in parallel.** Previously a sequential SPF lookup, then DMARC lookup, then up to ten DKIM-selector probes (`default`, `google`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `s1`, `s2`) - early-exiting on the first DKIM hit but still one round trip at a time. Replaced the loop with a single `asyncio.gather(...)` of all 12 queries. On a healthy DoH path the scanner now completes in roughly one RTT (~200-300ms) instead of up to twelve. The first-hit-wins selector preference is preserved deterministically by walking the `DKIM_SELECTORS` tuple in order over the gathered results. Costs up to 9 extra DKIM probes per scan when the first selector hits; DoH is free and rate-limit-generous, so the trade is heavily favorable.
- **SSL Labs polling cadence is now adaptive.** Previous behavior: `await asyncio.sleep(10)` between every poll, so even a fully-cached READY response paid up to a 10-second tax for the second poll. New behavior: 3-second cadence for the first 4 polls (catches cache hits and DNS-lookup stalls quickly), then 10-second cadence for everything beyond. Worst case for first-time cache-miss scans is identical to before; cached scans land roughly 0-7 seconds faster. Stays well under Qualys's published rate limit (~150 req/min/IP, our worst case is ~20 polls).

### Changed (result-page polish)
- **Linkified URLs are now legible on the dark theme.** The `linkify` Jinja filter emits raw `<a>` tags (no class), which were inheriting the browser-default deep blue (`#0000ee` ish) and rendering nearly invisible against the navy result-card background. Added `.report-card .rec a`, `.report-table .summary-cell a`, and `.report-table .err-explain-body a` rules in `style.css`: cyan `var(--accent-2)` text, 1px underline at 2px offset, hover brightens to `var(--text)`. `word-break: break-word` so long URLs in recommendations wrap inside the narrow left card.
- **Both cards on `/scan/{id}/result` now stretch to equal height.** `.report-grid` switched from `align-items: start` to `align-items: stretch` at the >=960px breakpoint. The left card (gauge + KPIs + top-3 recs + downloads) is shorter than the right card (12-row scanner table); previously this left a visual notch. Now the left card fills the height of the taller right card with empty space below the download buttons - the outer frame is symmetric without changing any font size, button size, or content.
- **Brand mark in the system-strip header is bigger and rounder.** `.brand-logo`: 44px to 48px, border-radius 5px to 12px, plus a subtle drop shadow (`0 8px 24px -8px rgba(0,0,0,0.6)`). `.brand-name`: 23px to 26px, letter-spacing 0.06em to 0.04em. Brings the result, about, score, scanners, and progress pages in line with the homepage's nav brand treatment.

### Notes
- **No engine changes beyond the two scanner concurrency tweaks.** Grading, retry helper, web routes, CLI, and downloadable report renderers are untouched.
- **Backward compatible.** No change to scan results, reports, routes, or config. Just faster.

## [0.0.22] - 2026-05-04

### Fixed (template syntax bug that blanked every page)
- **Closed the unclosed `<script>` tag for `gtag-init.js` on all six templates** (`index.html`, `about.html`, `result.html`, `score.html`, `progress.html`, `scanners.html`). The line `<script src="/static/gtag-init.js?v={{ app_version }}">` was missing its `</script>`, so browsers parsed the rest of the document - the `<style>` block, `<body>`, all content - as the contents of that script element and rendered a blank page. Server returned `200 OK` with full HTML; the failure was purely client-side parsing. Symptom started after splitting the inline GA init out into a separate file in 0.0.18.

### Added (favicon set)
- **Generated a multi-size `static/favicon.ico`** (16/32/48 bundled in one ICO) plus `apple-touch-icon.png` (180x180), `icon-192.png`, and `icon-512.png` from `static/pfp.png`. Built with Pillow:
  ```python
  src.save("favicon.ico", sizes=[(16,16),(32,32),(48,48)])
  src.resize((180,180), Image.LANCZOS).save("apple-touch-icon.png")
  ```
- **Three favicon `<link>` tags wired into all six templates:** `<link rel="icon" href="/static/favicon.ico" sizes="any">`, `<link rel="icon" type="image/png" href="/static/pfp.png">`, and `<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">`. Silences the `/favicon.ico` 404 in browser logs and gives proper touch icons on iOS / iPadOS home-screen pins. The other five templates previously had no favicon link at all; only `index.html` carried the original single-PNG declaration.

### Changed (`/scan/{id}/result` redesign)
- **Result page rewritten as a 2-column card layout** to match the homepage's design language. Replaces the old stacked `<section class="overall">` + `<table>` + recommendations sections with a `.report-grid` (`360px 1fr` on >=960px, single column below). Uses the same `--bg-elev`, `--accent-2`, `--good`/`--warn`/`--bad`, and font tokens already defined in `style.css`.
  - **Left card**: SVG-free conic-gradient circular gauge (`.grade-circle`) sized 168x168, fills `var(--pct)` with a grade-aware colour (`--gauge-color`: green for A, cyan for B, amber for C/D, red for E/F, mute for unknown). Inside the ring: the letter grade in `var(--font-mono)` 3.25rem and a small `XX / 100` caption. Below the gauge: a 3-column KPI mini-grid showing **Weighted** (overall_score), **Scanners ok** (`ok_count`/`total`), **Scan time** (e.g. `23s`). Top-3 recommendations with severity dots (red/amber/cyan/green). Two ghost-style download buttons (Markdown, Self-contained HTML) at the bottom.
  - **Right card**: per-scanner table with a single Grade column rendered as a colored pill (`.grade-chip` with `a/b/c/d/f/na` variants). The Score column was merged into Grade. ERROR rows show a red `—` chip plus the existing `<details class="err-explain">` "What does this mean?" disclosure.
- **All new CSS lives in a single `/* Result page (verdict) */` section in `static/style.css`** (between the responsive breakpoints and the `/score` page rules). About 230 lines. Self-contained; doesn't touch any pre-existing class. The matching homepage demo styles in `index.html` stay inline and continue to render.
- **The standalone `<section class="recommendations">` block is gone.** Recommendations are now top-3 in the left card. The full deduped list is still rendered in the downloadable `.md` and `.html` reports.
- **The "Raw text summary" `<details>` and footer are unchanged** and sit below the new grid.

### Added (timing data on the result page)
- **`Report.total_elapsed: float | None`** is a new dataclass field in `runner.py`, populated with `round(time.monotonic() - run_started, 1)` at the end of `run_scans()`. The web layer also tracks `started_at` on the `start` event and threads the value through `_write_partial_report()` so the in-process `job["report"]` carries elapsed time, not just the runner's discarded return value. The result template renders it as `{{ elapsed|int }}s` in the third KPI tile (or `—` when unavailable, e.g. for partial reports written before any scanner finished). The CLI's partial-write Report still constructs without the field; default `None` keeps it backwards compatible.

### Notes
- **No engine changes.** Scanners, grading, retry helper, and downloadable report renderers are untouched. The `.md` and `.html` download paths render byte-for-byte the same as 0.0.21.
- **Backward compatible.** Existing routes, download URLs, config keys, and CLI flags are unchanged.

## [0.0.21] - 2026-05-04

### Changed (web home page redesign)
- **The web home page is now a polished marketing landing page.** New layout with a hero, four-step "How it works" flow, live-progress preview, sample-report preview (grade circle, KPI tiles, top recommendations, per-scanner breakdown table), twelve scanner-category cards, CLI/Web mockups, trust & safety section, and a footer linking the secondary pages (`/score`, `/scanners`, `/about`, `/.well-known/security.txt`). Same dark navy / cyan palette as the rest of the app. CSS and vanilla JS are embedded inline; the only external script is the GA4 gtag.
- **The hero URL input is now the real scan-starting form.** A pill-shaped input + Scan button POSTs to `/scan` with `name="url"`. On submit the button is disabled, the label switches to "Scanning…", and an indeterminate progress strip appears under the input. The page transitions to `/scan/{job_id}` via 303 once the background job is enqueued. Decorative caret was removed; the real text cursor takes over. `:focus-within` highlights the input pill with the accent ring.
- **The per-scan SCANNERS picker has been removed from the home page.** Users no longer see twelve checkboxes plus Select all / Deselect all on the front door. Scans run with the config-enabled scanner set (`SCANNER_*` env knobs in `config.env` / `config.env.local`) by default. The `/scan` POST handler still accepts a `scanners` form list for callers that submit one (e.g. internal automation), but an absent or empty list now falls back to `cfg.enabled` instead of returning a `Select at least one scanner` 400.
- **`_render_index` no longer passes `all_scanners` or `selected_scanners` to the template.** Both keys are unused on the new home page. SEO meta (title, description, keywords, canonical, theme-color), Open Graph tags, Twitter cards, JSON-LD `WebApplication` schema, and the GA4 gtag init from `static/gtag-init.js` are preserved verbatim.
- **The brand mark in the header is now `static/pfp.png`** (the project's profile image), replacing the inline gradient SVG placeholder.

### Added
- **Project-root `index.html`**, a self-contained static mirror of the live home page. Single file with embedded CSS and vanilla JS, no Jinja, no GA, no external assets. Useful for previewing the design without running the app, or for deploying as a CDN-cached landing page. Stays content-equivalent to the live template so the two don't drift.

### Changed (error messages)
- **Per-run log paths are now substituted into error explanations.** Three `explain_error()` strings previously contained the literal placeholder `./logs/error_<timestamp>.log`. They now interpolate the real path returned by `setup_logger()` (e.g. `/Users/.../logs/error_20260504-141230.log`) when one is known. `render_summary`, `render_markdown`, `render_html`, and `_render_scanner_section` accept a new `log_path: str | None` keyword argument; the CLI and web both wire the real path through.
- **Error explanations are surfaced in the CLI text summary**, not just the on-disk HTML/Markdown reports. Each failed scanner now prints `↳ <title>` plus a wrapped body underneath the `ERROR -` line. Previously the user had to open the `.md` file to see the explanation.
- **Four new error-explanation patterns** are matched in `explain_error()`:
  - **SSL Labs polling timeout** (`scanner == "SSL Labs"` AND `"Timed out after"` in error). Explains the 1-3 minute live assessment, recommends retry with `SSL_LABS_USE_CACHE=true`.
  - **Cloudflare DoH unreachable** (DNS scanners CAA / DNSSEC / Email auth + network-shaped error). Explains that these scanners depend on `cloudflare-dns.com/dns-query`.
  - **Target unreachable on direct-target scanner** (`HTTP→HTTPS redirect`, `DoS posture`, `security.txt` + connection-shaped error). Explains the user's URL is unreachable from this machine and points at firewall / DNS as likely causes.
  - **Missing `INTERNETNL_API_TOKEN`** is now named explicitly in the link-out summary string (was a generic "no API token configured").
- **Two new helpers in `report.py`:** `_logs_pointer(log_path)` for consistent log-path rendering across patterns, plus `_DOH_SCANNERS` and `_UNREACHABLE_MARKERS` constants used by the new pattern matchers.

### Changed (project rename)
- **Renamed the project to `urlreporter` (display name "Url Reporter"), live at [urlreporter.com](https://urlreporter.com).** Affects the package directory, the console script and import path (`urlreporter.cli`, `urlreporter.web`), the launcher scripts (`bin/urlreporter`, `runUrlReporter.sh`, `gitUrlReporter.sh`), the package logger name (`urlreporter`), the default `HTTP_USER_AGENT` (`urlreporter/0.1`), the report filename prefix (`urlreporter-<host>-<ts>.md`), the HTML page `<title>`, the markdown footer, and the `APP_NAME` constant. The git remote target in `gitUrlReporter.sh` is now `https://github.com/pdiomede/urlreporter`. Earlier CHANGELOG entries have been retro-fitted to the new name so the project has a single, consistent identifier; the historical product names from prior releases are preserved only in git history.

## [0.0.20] - 2026-05-04

### Changed (scoring methodology)
- **Optional scanners no longer tank the overall grade.** `hsts_preload` previously returned `D / 40` when a domain was not on the Chrome HSTS preload list, and `security_txt` returned `F / 0` when no `/.well-known/security.txt` was published. Both are opt-in / recommended and were dragging the overall average down for sites with otherwise excellent posture (e.g. polymarket.com landed at B / 79 despite TLS A+, DNSSEC A+, CAA A+, redirect A+, email auth A+). Re-scaled to reflect their actual nature as hardening / hygiene markers: `hsts_preload` now returns `B+ / 80` (not preloaded), `A / 90` (pending), `A+ / 100` (preloaded); `security_txt` returns `B- / 70` when the file is missing instead of `F / 0`. Severity of the corresponding findings was lowered from `medium` to `low`.
- **Overall grade is now a weighted mean.** Previously a plain average of all graded scanners. `grading.aggregate_score()` now weights scanners by security impact: weight 2.0 for SSL Labs, Mozilla Observatory, DNSSEC, Email auth (SPF/DMARC/DKIM); weight 1.5 for HTTP→HTTPS redirect and securityheaders.com; weight 1.0 for CAA, DoS posture, HSTS Preload, security.txt, crt.sh, internet.nl. Weights live in `SCANNER_WEIGHTS` keyed by `ScanResult.scanner` (display name). Unknown scanners fall back to `DEFAULT_WEIGHT = 1.0`.
- **Letter-grade buckets loosened by 5 points.** `score_to_letter()` thresholds shifted down so a few weak optional categories cannot push a fundamentally secure site below A-. New ladder: `>=90 A+`, `>=85 A`, `>=80 A-`, `>=75 B+`, `>=70 B`, `>=65 B-`, `>=60 C+`, `>=55 C`, `>=50 C-`, `>=45 D+`, `>=40 D`, `>=35 D-`, else `F`. The `LETTER_TO_SCORE` map (used to convert third-party letters back to numbers) is unchanged.
- **Combined effect on the polymarket.com sample report:** B / 79 → A+ / 93. SSL Labs A+, DNSSEC A+, CAA A+, redirect A+, email auth A+ now properly anchor the overall grade rather than being averaged down by two optional opt-in items.
- **`/score` page and `urlreporter explain-score` updated** to describe the weighted average, the new weight table, the new letter ladder, and a revised caveat about scanner weights being a judgment call.
- **README "How the overall grade is calculated" paragraph** updated to mention the weighted average and the new top-of-ladder threshold (90 = A+).

## [0.0.19] - 2026-05-04

### Changed (report rendering)
- **Em dashes removed across all user-facing strings.** Templates, scanner outputs, error explanations, summary lines, and CHANGELOG/README. Replaced with hyphens or commas depending on grammatical context. House style is now em-dash-free.
- **Timestamps in reports are now human-readable.** New `_format_timestamp()` helper formats `report.generated_at` as `4/May/2026 at 22:33 UTC` instead of the previous ISO `2026-05-03T22:33:12+00:00`. Applied to all three rendering paths: CLI summary, downloaded markdown, downloaded HTML.
- **HTML report footer simplified.** Removed the `Config sources: ...` line. Footer now contains only `Url Reporter · made by Paolo Diomede`, with the name as a link to https://pdiomede.com. Font bumped from 11px to 14px (weight 600), colour switched to `var(--accent2)` to match the rest of the accent treatment on the report.
- **Markdown report footer simplified.** Same change: dropped the `_Config sources: ..._` italic line and the `---` separator above it. The downloaded `.md` ends on the credit line `_Generated <timestamp> by urlreporter_`.

### Changed (UI on `/scan/<id>/result`)
- **Severity chips (HIGH / MEDIUM / LOW / INFO) are larger and more vivid.** Font 10px to 12px (weight 700), padding bumped, dot enlarged with stronger glow, colours moved from pastel tints to the full `--bad`/`--warn`/`--accent-2`/`--good` palette tones. Same hue family as before, just less faded.
- **`// detailed findings` section reads better.** Summary header (e.g. `internet.nl (1 findings)`) now 15px weight 600 (was 13px). Finding titles 15.5px. Finding bodies (`.rec`/`.detail`) 14.5px with `line-height: 1.5`.
- **All `//` eyebrow labels in the HTML report are unified.** `.eyebrow` (`// security audit`) and `.section-eyebrow` (`// recommended actions`, `// per scanner`, `// detailed findings`) both render at 15px / weight 700 / `var(--accent2)`. Previously the section eyebrows were 11px / weight 500 / muted.
- **Removed the floating `// recommended_actions` corner label** on the result page (`.recommendations::before` rule deleted). The `// recommended actions` eyebrow above the heading already says the same thing.
- **`What does this mean?` toggle is more legible.** Font 11.5px / weight 500 / muted bumped to 13px / weight 600 / full text colour. Padding nudged up so the bigger text breathes.

### Changed (progress page copy)
- **Tagline now reads "SSL Labs and crt.sh are usually the slowest"** (was just SSL Labs). crt.sh polling can also take 5+ seconds on cold cache.

### Notes
- **No engine changes.** Templates, static assets, report renderer, and the report.py timestamp helper.
- **Backward compatible.** Existing report files on disk render with the old timestamp until they expire (24h TTL); new scans use the new format.

## [0.0.18] - 2026-05-04

### Changed (CSP hardening: drop `'unsafe-inline'` from script-src)
- **All inline `<script>` blocks moved to external static files.** Previously every template carried at least one inline script (the GA4 init across all six pages, the form-submission handler in `index.html`, the copy-to-clipboard handler in `result.html`, the polling IIFE in `progress.html`). Mozilla Observatory was docking 20 points for `'unsafe-inline'` in `script-src`. Splitting them out lets nginx serve a stricter CSP and pushes the Observatory grade to A or A+.
- **Four new files under `static/`:**
  - `static/gtag-init.js` (shared GA4 init, loaded on all six templates).
  - `static/index-form.js` (form-submission handler for the homepage).
  - `static/result-copy.js` (copy-to-clipboard handler on the result page).
  - `static/progress-poll.js` (the live-progress polling IIFE).
- **`progress.html` lost its Jinja-injected JS variable.** The previous inline script interpolated `{{ job_id }}` directly into JavaScript. The job ID now travels through a `<div id="poll-config" data-job-id="{{ job_id }}" hidden>` element which `progress-poll.js` reads via `getAttribute`. Cleaner separation of template data from logic, and the polling JS is now cacheable.
- **JSON-LD on `index.html` stays inline** (it's `type="application/ld+json"`, not executable code, so CSP doesn't gate it).

### Notes (deploy-time)
- **nginx CSP needs `'unsafe-inline'` removed from `script-src`** in `/etc/nginx/sites-available/all-sites.conf`. New value:
  `script-src 'self' https://www.googletagmanager.com;`
  Reload nginx after editing.
- **No engine changes.** No scanner, runner, grading, or report file is touched.
- **Backward compatible.** All routes and behaviour are identical for users; only the asset layout changed.

## [0.0.17] - 2026-05-04

### Changed (UI consistency)
- **`progress.html` and `result.html` now use the same header and footer pattern as the rest of the site.** Both pages were still rendering the old CSS-drawn `.brand-mark` placeholder in the header instead of the actual `static/pfp.png` logo, and still kept "Our score" as a muted footer link with no version badge in the footer. Header now shows the logo and the prominent OUR SCORE button on the right; footer now shows `v{{ app_version }} · ready` next to the credit. Pattern is now identical across `/`, `/scanners`, `/about`, `/score`, `/scan/<id>` (progress), and `/scan/<id>/result`.

### Notes
- **No engine changes.** Templates only.

## [0.0.16] - 2026-05-04

### Added
- **`/.well-known/security.txt` route** in `urlreporter/web.py` (RFC 9116). Returns a `text/plain` response with `Contact:`, `Expires:` (set to 2027-12-31), `Preferred-Languages:`, and `Canonical:` fields. The site's own `security_txt` scanner now grades urlreporter.com correctly on this check.

### Changed (UI contrast)
- **Footer text and version badge use the accent colour.** The bottom strip (`v0.0.16 · ready` and `MADE BY PAOLO DIOMEDE`) was previously rendered in `var(--text-mute)` / `var(--text-faint)` which sat almost invisible against the dark background. Both `.site-footer` and `.site-footer .footer-version` now use `var(--accent-2)`, matching the OUR SCORE header button. Font weight bumped to 600 and size from 11.5px to 13px.

### Notes
- **No engine changes.** No scanner, runner, grading, report, or config file is touched in this release.
- **Backward compatible.** Existing routes and download URLs are unchanged.

## [0.0.15] - 2026-05-03

### Added (SEO, content pages, GA)
- **Two new public content pages** at `/scanners` (detailed breakdown of all 12 public security scanners that contribute to a report) and `/about` (project overview, scope, non-goals, self-host pointer). Both routes render new templates `scanners.html` and `about.html`, both are listed in the sitemap, both are indexable.
- **Full SEO meta-tag suite** on every indexable page (`/`, `/score`, `/scanners`, `/about`): `<title>` and `<meta name="description">` tuned per page, canonical URLs, Open Graph (`og:title`, `og:description`, `og:image`, `og:url`, `og:type`), Twitter Card (`summary_large_image`), `meta robots`, `meta keywords`. The homepage also carries a JSON-LD `WebApplication` block for structured-data results. New 1200x630 `static/og-image.png` referenced as the social-preview image.
- **`/robots.txt` and `/sitemap.xml`** routes served directly by FastAPI. `robots.txt` allows everything except `/scan/` and `/report/` (per-job pages), and links the sitemap. `sitemap.xml` lists `/`, `/scanners`, `/score`, `/about`.
- **`noindex, nofollow`** on `progress.html` and `result.html`, since per-job pages have random IDs and 24h-TTL content and should not be in search results.
- **Google Analytics 4** (`G-6NCTMMRH1H`) on all four templates.

### Changed (header, footer, branding)
- **Brand image in the header.** Replaced the CSS-drawn `.brand-mark` placeholder with the actual `static/pfp.png` logo. New `.brand-logo` CSS rule (44x44, `border-radius: 5px`, `object-fit: cover`). The brand-name font size was doubled (11.5px to 23px) so it visually balances the larger logo.
- **"Our score" promoted to a header button.** The link used to live in the footer in muted colour next to the credit. It is now a bordered, accent-coloured button on the right of the system strip on every public page. The version-and-status badge (`v0.0.15 · ready`) moved from the header to the footer so the header focuses on the scanner action.
- **Header and footer pattern unified across all public pages.** `score.html` was still using the old `.brand-mark` CSS placeholder and the muted footer "Our score" link. It now uses the same logo + header button + footer-version pattern as `/`, `/scanners`, and `/about`.
- **Section eyebrow labels are more visible.** The small `// TL;DR`, `// METHODOLOGY`, etc. labels above each card heading were rendering at 11px in `var(--text-faint)`, which made them effectively invisible on dark backgrounds. Bumped to 14px, weight 700, and switched colour to `var(--accent-2)` so they read as proper section markers.

### Notes
- **No engine changes.** No scanner, runner, grading, report, or config file is touched in this release. All changes are templates, static assets, web routes, and meta data.
- **Backward compatible.** Existing routes and download URLs are unchanged; `/score` keeps the same content and URL; old report links keep working.

## [0.0.14] - 2026-05-03

### Added (CLI parity with web UI)
- **`--html` flag on `scan`**. When set, the CLI writes a self-contained HTML report next to the existing Markdown one (same `report.render_html()` the web UI calls, byte-for-byte identical output). Default off, so existing scripts keep producing only `.md`. The HTML path is `<out>.html` (i.e. `--out reports/foo.md --html` produces `reports/foo.html`).
- **Incremental report writes** during a CLI scan. After every `scanner_done` event the CLI now re-renders the partial Markdown (and HTML, if `--html`) to disk, mirroring the web app's `_write_partial_report()` behavior. A `Ctrl-C` mid-scan, or a `kill -9`, leaves a usable report file containing every scanner that finished before the interrupt - instead of losing everything as the previous all-or-nothing write at the end did.
- **Partial report on engine exception / interrupt.** `asyncio.run(run_scans(...))` is now wrapped in a `try/except` for both `KeyboardInterrupt` (exit 130, POSIX convention for SIGINT) and any other unexpected exception (exit 1, with a `Scan failed:` banner). In either path the CLI falls back to whatever the incremental writer last wrote, prints the partial-report path, and still emits the per-scanner summary so the user sees the partial verdict instead of a bare traceback.
- **`urlreporter explain-score`** subcommand. Prints the same plain-English methodology the web UI exposes at `/score` (letter→number table, the "skipped scanners" rule, the score-to-letter ladder, the five honest caveats). No URL argument; no network calls; exit 0. Closes the gap between "the web UI explains the big letter" and "the CLI just shows it".

### Notes
- **No engine changes.** All four additions reuse `runner.run_scans()`, `report.render_summary()`, `report.render_markdown()`, `report.render_html()`, `grading.aggregate_score()`, and `runner._prioritize` / `runner.Report` exactly as the web UI does. The web UI, the runner, the scanners, the templates, and the static assets are untouched in this release.
- **Backward compatible.** Existing flags (`--config`, `--out`, `--quiet`, `--only`) and exit codes (0 success, 1 all-failed, 2 args error) are preserved. The new exit code `130` is only reached if the user hits Ctrl-C, which previously crashed out of `asyncio.run` with a traceback anyway.

## [0.0.13] - 2026-05-03

### Fixed (file-by-file bug audit)
- **`config.py`**: process-environment overrides only applied to keys that already existed in a loaded config file, so setting `INTERNETNL_API_TOKEN=…` (or any `SCANNER_*` toggle) in the shell with no `config.env` present was silently ignored. Replaced the `for k in merged.keys()` loop with an explicit `_RECOGNIZED_KEYS` tuple so env vars override regardless of file presence - matching the behavior the docstring already promised.
- **`grading.py`**: `aggregate_score()` returned `(round(avg), score_to_letter(avg))`. With an unrounded avg of, say, `94.6`, the score rounded up to `95` while the letter was still computed from `94.6` and came out as `"A"` - yielding the contradictory pair `(95, "A")` even though the documented buckets put `95 → A+`. Now derives the letter from the same rounded integer the user sees.
- **`urlutil.py`**: `_SCHEME_PREFIX_RE` matched any RFC 3986 scheme prefix, so common inputs like `localhost:3000` or `example.com:8080` were rejected as `Unsupported URL scheme: 'localhost'.` Added a host:port discriminator: when the segment after `:` parses as a port number (digits, optionally followed by `/path`), fall through to the default-https branch instead. The `javascript:` / `data:` / `file:` / `vbscript:` defenses still fire (their tails aren't numeric).
- **`web.py`**: `_write_partial_report()` rendered `Report.results` from `job["partial_results"]` in scanner-completion order, so the on-disk report reshuffled per-scanner sections every time a scan re-ran - even though `runner.py` explicitly re-sorts to registry order with the comment "so reports stay stable". Mirrored that sort in the web path so CLI and web reports now agree.
- **`templates/progress.html` (two bugs)**:
 - When `runner_task` swallowed an exception it set both `job["error"]` *and* `job["done"] = True`. The poller's `if (data.error)` branch returned before the `done && report_id` branch, so the user was stuck on the live progress page with "Scan failed: …" forever - even though `/scan/{id}/result` would have happily rendered the partial report with its existing `partial_error` banner. Removed the early `data.error` return; `done && report_id` now redirects unconditionally.
 - The reconnect/give-up handlers did `caption.textContent = "Reconnecting…"`, which detaches the cached `completed-count` / `total-count` / `bar-pct` child spans from the DOM. If polling later recovered, subsequent updates wrote to the orphaned elements and the percentage display silently froze. Added a sibling `<p id="poll-status">` for status messages and updated the JS to write there instead of clobbering the live counter row.

### Verified clean (no bugs found)
- `report.py`, `logging_setup.py`, `runner.py`, `templates/index.html`, `templates/result.html`, `templates/score.html`, `static/style.css`, and every file in `scanners/` (`base.py`, `_retry.py`, `caa.py`, `crtsh.py`, `dnssec.py`, `dos_posture.py`, `email_auth.py`, `hsts_preload.py`, `https_redirect.py`, `internetnl.py`, `mozilla_observatory.py`, `security_headers.py`, `security_txt.py`, `ssllabs.py`) were each audited against the same 5-bug-cap pass and produced no defects worth fabricating fixes for.

## [0.0.12] - 2026-05-03

### Changed (UI / copy)
- **Index hero copy simplified.** Headline is now `Audit any URL with the best public security scanners` (was a literal scanner count). Tagline is `Paste a URL and get a consolidated report drawn from a battery of public security scanners` (no fluff, no Markdown-format mention).
- **`/score` page rewritten in plain English.** Same five sections, same data tables, but every piece of jargon is gone: "letter to score" became "How letter grades become numbers", "aggregate" became "How we combine scanners into one number", the score-to-letter ladder uses ranges like `90 to 94` instead of `≥ 90`, and the caveat block is rewritten so a non-engineer can follow it. The `Where to read the code` section was removed (it pointed at internals); the back-to-scanner link now sits just before the footer.

## [0.0.11] - 2026-05-03

### Added
- **Two new scanners** (default count is now 12, all free, no API keys):
 - **`email_auth` (SPF / DMARC / DKIM)**: TXT lookups via Cloudflare DoH for the apex SPF, `_dmarc.<host>` DMARC, and DKIM probes across 10 common selectors (`default`, `google`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `s1`, `s2`). Scoring weights: SPF 35 pts (`-all` full credit, `~all` partial, `+all` flagged as a "passes everyone" anti-pattern), DMARC 45 pts (reject 45, quarantine 32, none 14), DKIM 20 pts on any selector hit. Findings include missing-record, no-`all`-qualifier, multiple-SPF-records (RFC 7208 §3.2 violation), `p=none` monitoring-only nag, weaker-subdomain-policy, and a DKIM-not-found-at-common-selectors low-severity hint (we explicitly note that DKIM may live on a non-default selector we couldn't enumerate).
 - **`security_txt` (RFC 9116)**: fetches `/.well-known/security.txt` (then `/security.txt` as a legacy fallback), parses it, and grades on canonical-location compliance, `Contact:` presence, `Expires:` presence + parseability + future-dated, plus partial credit for `Policy:`, `Encryption:`, `Acknowledgments:`, `Preferred-Languages:`. Flags `Expires` within 30 days as low-sev (renewal warning) and totally unknown field names as info-level (typo catch).
- **`/score` methodology page** linked from every footer's left side as `OUR SCORE` (silver mono link, opens in new tab). Six cards explain: TL;DR, letter→score lookup, aggregation rules (which scanners contribute, which are excluded), score→letter ladder, honest caveats (equal weighting, per-scanner ladders differ, link-out exclusions, snapshot-in-time, no vendor opinion). Contains zero em dashes per house style.

### Changed (UI)
- **Footer simplified**: dropped the left-side `URL REPORTER vX.Y.Z` label and the small em-dash divider before "Made by". Footer is now `OUR SCORE` (left, silver pill link) and `MADE BY PAOLO DIOMEDE` (right, no em dash).

### Fixed (per-scanner audit, 4 real bugs across 12 scanners)
- **`mozilla_observatory.py`**: if the `…/{scan_id}/tests` endpoint returned `null` JSON (or any non-list / non-dict scalar), the scanner crashed with `TypeError: 'NoneType' is not iterable`. Now defaults to an empty iterable and proceeds.
- **`dnssec.py`**: a non-zero DNS RCODE was always reported as if it were `SERVFAIL=2` (broken DNSSEC chain). NXDOMAIN, REFUSED, FORMERR, NOTIMP each have very different causes and recommendations; the scanner now translates the RCODE into the correct human message and advice.
- **`dos_posture.py`**: an `Age: 0` response header was treated as cacheable, because `bool("0")` is `True` in Python. Now int-parses the value and only counts strictly positive ages.
- **`email_auth.py`** (the SPF parser, found same release): the regex `\b([-~?+])all\b` could **never** match `-all` / `~all` / `+all` / `?all` when preceded by whitespace, because `\b` requires a word↔non-word transition and both space and `-` are non-word characters. **Every** SPF policy ending in `-all` was being scored as if it had no `all` qualifier (10 pts instead of 35). Replaced with `(?:^|\s)([-~?+])all(?:\s|;|$)` which anchors on actual whitespace boundaries. Verified empirically against the four standard qualifiers.

## [0.0.10] - 2026-05-03

### Added
- **HTML report download.** The result page now offers two download buttons: a primary, pulsing "Download HTML" on top and a "Download Markdown" below. Both are written to disk after every `scanner_done` event (alongside the existing `.md` partial-write), so a server crash mid-scan still yields downloadable HTML *and* markdown of whatever finished. New `render_html(report)` in `report.py` produces a self-contained, no-CDN-dependency document with embedded CSS that mirrors the brand aesthetic, plus a `@media print` stylesheet that flips to a clean white-on-black layout for paper/PDF export. New endpoint `GET /report/{report_id}.html`. The cleanup TTL also removes `.html` siblings.
- **Partial-failure banner on the result page.** When a scan errors mid-flight but `_write_partial_report()` already saved a partial report, the result page now renders the partial report with a `Partial report: …` banner (using the existing `.form-error` style) instead of returning HTTP 500. Previously the user saw a hard 500 page even though usable data was on disk.

### Changed (UI)
- **Full visual redesign - "Verification Lab" aesthetic.** Midnight-blue console crossed with editorial security advisory.
 - Type system: **Bricolage Grotesque** (variable, opsz) for body & UI, **Fraunces** (variable serif, opsz 144) for the giant grade letter, **JetBrains Mono** for every technical fragment (URLs, scanner keys, status pills, version chips). Avoids Inter / Space Grotesk / Roboto.
 - Palette: deep midnight `#060914`, four-step elevation, hairlines `#1f2b4d → #3a4d80`, brand gradient `#4f8cff → #66e0ff → #b794ff` (electric blue → cyan → aurora violet) translated to top-of-page hairline, primary CTA, focus rings, scanner-checkbox fill, the giant grade letter (background-clip), and the download button hover.
 - System strip: brand monogram + "scan in progress / scan complete" indicator with pulsing live dot, like an SSH banner.
 - Section headers prefixed with mono `// section_name` eyebrow labels.
 - Custom geometric checkboxes (gradient fill on check), pill-shaped buttons (`border-radius: 999px`), pulsing "Download HTML" button (`download-blink` animation, paused on hover).
 - Status pills mono uppercase with leading colored dot; `running` pills carry a soft halo pulse.
 - Recommendations numbered `01`, `02`, `03` in mono with leading zeros (terminal/listing aesthetic).
 - Decorative `// per_scanner` / `// recommended_actions` floating labels in the corners of those cards.
 - Subtle dot-grid texture and radial blue glow at the top of the body for atmosphere.
 - Page-load entrance: each section rises in with staggered `rise-in` delays.
 - Container width raised from 880px to 1080px.
 - Mobile (<720px): atmosphere strip text shrinks, time column hides on the progress table, overall card stacks single-column, copy button repositions, fonts step down.
- **High-contrast warning callout** on the progress page replaced the dim mono note. The "Don't close it!" line now sits in an amber-bordered panel with amber-tinted background and `#ffd9a3` text - readable at a glance.
- **Silver back-link** on the result page (`← scan another URL`) replaces the default-blue underlined link with a `#c0c4cc` outline pill that brightens to near-white with an underline on hover.
- **Single-line tagline.** Removed the `max-width: 56ch` reading-width cap on `.tagline` so the index hero text stays on one line on desktop and only wraps on narrow viewports.

### Fixed (core logic)
- **`runner.py` elapsed time was always 0.0** for every scanner. `asyncio.as_completed` yields wrapper coroutines, **not** the original Task objects, so the per-task identity lookup `task in starts` always missed. Replaced with `asyncio.wait(FIRST_COMPLETED)` which returns the original tasks; per-scanner timings now reflect real wall-clock (verified live: `0.1s` / `0.5s` instead of `0.0s` / `0.0s`).
- **`web.py:result_page` returned HTTP 500** when the runner errored mid-scan, even though `_write_partial_report()` had already saved a usable partial report. Now renders the partial report with an inline error banner.
- **`scanners/ssllabs.py` used `asyncio.get_event_loop()`** inside an async function (twice), which is deprecated in Python 3.10+ and raises `DeprecationWarning`. Switched to `asyncio.get_running_loop()`.
- **`scanners/internetnl.py` `host = urlparse(url).hostname or url`** fell back to the whole URL string when hostname extraction failed, producing a broken link-out like `https://internet.nl/site/https://example.com/`. Now bails with a clean error like every other scanner.

## [0.0.9] - 2026-05-02

### Changed (UI)
- **Inline ⓘ explainer next to *Open external scan ↗*** for link-out scanner rows on both the live progress page and the final result page. Hovering or keyboard-focusing the icon reveals a small tooltip: *"No public API for programmatic results. Click the link to run the check on the external site in a new tab."* Reuses the existing `.copy-btn` / `.copy-tip` hover-tooltip pattern (new `.linkout-info` / `.linkout-info-icon` / `.linkout-info-tip` rules in `static/style.css`).

### Changed (CLI / markdown)
- The CLI live per-scanner progress block now reads `link-out (no public API)` (was bare `link-out`).
- The downloaded markdown report's text summary line now reads `<scanner>: link-out (no public API) - …`.
- The markdown report's overall paragraph now appends an inline explanation when any link-out scanner is present: *"… 1 link-out only (internet.nl) - no public API; the report points at the external site for a manual check."*
- The per-scanner section header for link-out scanners is now `### internet.nl - link-out (manual check on external site)`.

## [0.0.8] - 2026-05-02

### Changed (UI)
- Restyled the *"← scan another URL"* link on the result page. It now uses a silver text color (`#c0c4cc`) with no underline, brightening to near-white (`#e6e8ef`) with an underline on hover. Wired via a new `.back-link` class so the same treatment is reusable on other "back" affordances if they get added later.

## [0.0.7] - 2026-05-02

### Fixed (core logic)
- **Crash safety**: `runner_task` previously deferred *all* report file writes until every scanner had finished, so a server kill / restart in the middle of a scan threw away every completed scanner's data. Reports are now written **incrementally**: after each `scanner_done` event the web app appends the `ScanResult` to a job-local list, re-renders the markdown, and writes `./reports/<job_id>.md`. The same file is overwritten on the final `done` event with the complete version. If the uvicorn process is killed mid-scan, the on-disk file already has every scanner that finished before the kill. The `.name` (download filename) sibling is pre-written at job creation, so `/report/<job_id>.md` is downloadable as soon as the first scanner lands.
- **`render_markdown` heading**: the URL on the top-level `# Security report - …` line is now backtick-wrapped. Previously, URLs containing markdown-special chars (`_`, `*`, `~`, `[`) got formatted as italics / strikethrough / link syntax in many renderers (GitHub, VS Code preview, etc.).
- **`runner.run_scans`**: the user-tunable `SCAN_TIMEOUT_SECONDS` from `config.env` now actually flows through to the shared `httpx.AsyncClient` as the read timeout (clamped to [30, 300] s). Before, only SSL Labs honored this knob; everything else was hard-coded at 60 s.
- **`download` endpoint** would 500 if the `<id>.name` file existed at `exists()` check time but failed at `read_text()` (race / permission flap). Wraps the read in try/except and falls back to the synthetic `<id>.md` filename instead of crashing.

### Changed (UI)
- All buttons (`Run scan`, `Download full markdown report`, `Select all`, `Deselect all`, the copy-text button) now use **fully rounded pill borders** (`border-radius: 999px`).
- The download button on the result page **gently pulses** (opacity + box-shadow ring, 2.4 s cycle) so it's visually obvious where to click. Hover pauses the animation. `prefers-reduced-motion: reduce` disables the pulse entirely.
- Removed redundant copy under the scanner checkboxes ("Defaults come from config.env. Selections here override that for this run only.").
- Updated the auto-refresh notice on the progress page to: *"This page refreshes every 1.5s - Don't close it! Results are stored in memory until the scan finishes."*
- Removed the underline on URL links inside `<h1>` page headings (e.g. *Scanning `…`*); hover still shows the underline as a normal-link affordance.

## [0.0.6] - 2026-05-02

### Changed
- **Renamed user-facing product to "Url Reporter"** (was "Url Reporter"). Header, footer, browser tab title, CLI banner, and `--version` all read `Url Reporter v0.0.6 | Made by Paolo Diomede`. The Python package, CLI command, and repo directory remain `urlreporter`.
- Simplified the URL-form helper note from two sentences to just *"Scans can take 1-3 minutes (SSL Labs is the slow one)."* The validation copy ("Only http(s) URLs are accepted; the scheme is added for you if you omit it") was redundant: the form already rejects bad URLs inline.

### Added
- **`LICENSE.md`** at the repo root (MIT, 2026 Paolo Diomede). README's License section links to it.
- **`gitUrlReporter.sh`** at the repo root: one-command stage / commit / push to `https://github.com/pdiomede/urlreporter`.
 - First-run init: `git init -b main`, adds `origin`, switches to `main`.
 - Default commit message is the current package version, e.g. `v0.0.6`, sourced from `pyproject.toml` with a fallback to `urlreporter/__init__.py`. Override with `./gitUrlReporter.sh "your message"`.
 - **Secret-file guard**: refuses to run if any of `.env`, `.env.*`, `pat.txt`, `*.pat`, `*.token`, `token.txt`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`, `secrets.*`, or `config.env.local` exists in the repo root *and* is not covered by `.gitignore`.
 - **PAT-aware push**: when `pat.txt` is present, the push uses a one-shot `GIT_ASKPASS` helper inside a sandboxed `HOME` (so cached macOS Keychain credentials, `~/.netrc`, `~/.gitconfig`, and `/etc/gitconfig` can't supply a stale credential). The PAT never enters argv, shell history, or git config; the askpass helper and sandbox `HOME` are removed when the push exits.

### Fixed (UI)
- **Select all / Deselect all buttons** on the index form rendered with the primary-blue style (inherited from `.scan-form button`) and went *invisible on hover* because the dark hover background combined with the inherited dark text color produced black-on-black. Fixed via `button.ghost-btn` selectors with `!important` overrides on color/background; the buttons are now compact outline pills with a subtle blue tint on hover.

## [0.0.5] - 2026-05-02

### Added
- **Shared retry helper** (`scanners/_retry.py`) wrapping every outbound HTTP call from the scanners. Retries on transient HTTP statuses (408, 429, 500, 502, 503, 504, 520-527, 529) and `httpx.RequestError` (timeouts, DNS failures, connection refused), with exponential backoff (3s, 8s, 20s) before giving up. Each retry is logged at WARNING level, so failed scans tell you exactly what was tried.
- **Per-scanner module loggers** - every scanner now emits to a `urlreporter.scanners.<name>` logger, which propagates to the package-level file handler. Retries, fallback paths, and supplementary-fetch failures are all captured in `logs/error_<timestamp>.log` automatically.
- **`describe_exc(e)` helper** - produces a human-readable error string even when `httpx`'s `__str__` returns empty. Avoids the previous "HTTP error: " (no detail) UX.
- **`treat_404_as_transient`** flag on the retry helper, used by crt.sh which serves 404s for valid queries when its DB is under load.

### Fixed (core logic)
- **Empty error messages** when `httpx.HTTPStatusError` (and a few other exceptions) had blank `__str__`. All scanners now use `describe_exc` so the user always sees an exception type at minimum.
- **No retries** on most scanners (only SSL Labs and crt.sh had them); now applied to Mozilla Observatory, securityheaders.com, hstspreload.org, CAA, DNSSEC, HTTP→HTTPS redirect, and DoS posture, in addition to the two that already had retries.
- **`config.py`**: `INTERNETNL_API_TOKEN` now `.strip()`s its value so users with surrounding whitespace get a clean token.
- **`config.py`**: `SCAN_TIMEOUT_SECONDS` is clamped to ≥ 10 to prevent SSL Labs polling from giving up before its first response.
- **`runner._safe_scan`** now lets `asyncio.CancelledError` propagate (so cooperative cancellation actually cancels) instead of trapping it in the broad `except Exception`.
- **`runner._emit`** wraps the user-supplied `on_event` callback in try/except so a buggy listener can no longer sink the entire scan; the failure is logged at WARNING.
- **Logger restructure**: handler is attached to the package logger (`urlreporter`) so every submodule's `logging.getLogger(__name__)` propagates to the per-run file. Previously only `urlreporter.cli` and `urlreporter.web` logged anything.

### Fixed (UI)
- **Initial bar caption inconsistency**: showed "0%" before the first poll then "(0%)" after; now consistently `(0%)` from page load.
- **Stuck shimmer animation**: the moving highlight on the progress bar kept animating after the scan finished or errored; now stops via a `stopShimmer()` call when the job is done or has failed.
- **Polling that never gives up**: `/scan/{id}/status` is polled forever on persistent server errors; now caps at 12 consecutive failures (~72 s of retries) and surfaces "Lost contact (gave up after N attempts)".
- **Reconnect counter**: while the JS is retrying after a server error, the bar caption now shows "Reconnecting (N/12)" instead of an opaque "Lost contact" that resets every poll.

## [0.0.4] - 2026-05-02

### Added
- **`dos_posture` scanner** - passive DoS / DDoS resilience check. Sends a single GET to the URL (zero load generated) and inspects response headers for: CDN/WAF fingerprints (Cloudflare, Akamai, Fastly, AWS CloudFront, Google GFE, Azure Front Door, Sucuri, Imperva, KeyCDN, StackPath, BunnyCDN, CDN77, Vercel, Netlify, GitHub Pages, Varnish), positive-`max-age` / `s-maxage` cache directives or `x-cache` HIT signals, and rate-limit advertisement headers (`x-ratelimit-*`, `ratelimit-*`, `retry-after`). Score weights: CDN presence 60, useful caching 25, rate-limit headers 15. Toggle via `SCANNER_DOS_POSTURE`.
- This is **not** a load test. Active DoS testing is out of scope (legality, blast radius, distributed-traffic requirements). Use dedicated tools (k6, Locust, gatling) against your own staging environment with explicit authorization for that.

## [0.0.3] - 2026-05-02

### Added
- **Four new scanners**, all free and key-free, raising the default count to nine:
 - **crt.sh (Certificate Transparency)** - surveys the last 90 days of certificates issued for the host. Grades by CA concentration: A+/A for ≤4 CAs, downgrades when many different CAs have signed for the same name (a classic mis-issuance smell). Includes retry-with-backoff for crt.sh's transient 404/5xx errors.
 - **CAA records** (via Cloudflare DNS-over-HTTPS) - verifies the domain pins which CAs may issue certs for it. Walks up the DNS tree to honor CAA inheritance. Decodes both presentation form (`0 issue "letsencrypt.org"`) and the generic `\# <length> <hex>` (RFC 3597) form some resolvers return. A+ when issuance is restricted, C when only iodef is set, D when no records exist.
 - **DNSSEC** (via Cloudflare DoH `AD` flag) - A+ when the resolver returns an authenticated response, F on SERVFAIL (broken chain), D when DNSSEC is simply absent.
 - **HTTP→HTTPS redirect** - calls `http://<host>` directly and walks the redirect chain. A+ for a clean direct redirect to HTTPS on the same host, B if there's an intermediate http hop, C if it crosses to a different host first, F if HTTPS is never reached. Treats "no HTTP listener at all" as A (HTTPS-only is fine).
- Each new scanner has its own `SCANNER_<KEY>=true` toggle in `config.env` (`SCANNER_CRTSH`, `SCANNER_CAA`, `SCANNER_DNSSEC`, `SCANNER_HTTPS_REDIRECT`), all enabled by default.
- Web UI: index form now lists every scanner in `REGISTRY` as a checkbox, pre-checked from `config.env`. `Select all` and `Deselect all` buttons toggle the whole list. Submission overrides the config for that one scan, so the user can drop slow scanners (e.g. SSL Labs) without editing the config file.

### Changed
- Renamed user-facing strings from "Url Reporter" to **Url Reporter**.

### Fixed
- `result.html` `<title>` tag still hard-coded `urlreporter - {{ url }}`; now uses `{{ app_name }}` like the other templates.
- `result.html` per-scanner row produced an empty `<a href="">` (linking back to the report page) when the scanner returned a `ScanResult` without a `link` attribute; the link is now conditional on `r.link` being truthy.
- `urlutil.normalize_url` raised `ValueError` (HTTP 500) when the URL contained an out-of-range port like `:99999`; it now reports a clean form error.

## [0.0.2] - 2026-05-02

### Changed
- Renamed product to **Url Reporter** (dropping "" from the user-facing name). Web footer, CLI banner, page titles, and version output now read `Url Reporter v0.0.2 | Made by Paolo Diomede`. The Python package, CLI command, and repo directory remain `urlreporter`.
- CLI reports now default to `./reports/<filename>.md` (matching the web app's output directory) instead of the current working directory. Pass `--out PATH` to override.

### Added
- **Live progress page** in the web UI. POST `/scan` now schedules a background job and redirects to `/scan/{job_id}`, which renders a real-time progress bar and per-scanner status table that polls `/scan/{job_id}/status`. Status icons: ⏳ waiting, 🏃 running, ✅ done, ❌ error. The bar has a moving shimmer while scanning so the user sees motion even at 0%.
- **Indeterminate "starting…" bar** on the index form the moment the user submits, before the redirect lands.
- **Per-scanner CLI progress** block on stderr that updates in place on a TTY (overwrites previous lines) and falls back to plain output when piped.
- **Copy-to-clipboard button** on the result page's *Raw text summary*, with hover tooltip "copy text", success state, and `execCommand` fallback for older browsers.
- **Auto-linkified URLs** in recommendations, findings, summary text, and per-scanner errors. URLs render as `<a target="_blank" rel="noopener noreferrer">`. The page heading URL is now clickable too.
- **Clickable "Open external scan ↗"** link in the result column of the progress page and the summary cell of the result page for link-out scanners (e.g. internet.nl).
- **Per-run error log** at `./logs/error_<YYYYMMDD-HHMMSS>.log`. CLI invocation gets one log file; web server gets one per startup. Scanner errors and unexpected exceptions are written there at WARNING+.
- **`./runUrlReporter.sh`** launcher for the web UI: `./runUrlReporter.sh [port] [host]` (defaults `127.0.0.1:8000`). Set `CH_RELOAD=1` for uvicorn auto-reload during development.
- **`./bin/fix-venv-launcher`**: one-shot helper that patches the pip-generated `urlreporter` console script to inject the project root into `sys.path`. Works around iCloud Drive auto-flagging pip's editable `.pth` files as hidden (Python 3.13+ silently skips hidden `.pth` files).
- **Strict URL validation** (`urlreporter/urlutil.py`): rejects schemes other than http/https (`javascript:`, `data:`, `file:`, `ftp:` …), control characters, embedded credentials, malformed hosts; auto-prepends `https://` when no scheme is present; strips fragment and userinfo; caps URL length at 2000. Bad URLs render an inline form error instead of a generic 400. Same validator is shared by CLI and web.
- **Index form hardening**: `maxlength`, `autocomplete=off`, `spellcheck=false`, server-side error rendering with the previously typed value preserved.
- **SSL Labs retries**: transient HTTP responses (429, 500, 502, 503, 504, 521-526, 529) and network errors are retried with exponential backoff (5s, 15s, 30s) before being reported. The retry counter resets between successful poll iterations.

### Fixed
- **Race condition** in `progress_status` where JSON serialization of `job["states"]` could collide with the runner coroutine mutating the same dict (`RuntimeError: dictionary changed size during iteration`). Status now serializes a `copy.deepcopy` snapshot.
- **`_cleanup_old_reports`** orphaned the matching `.name` sibling when expiring `.md` files; both are now removed together.
- **`asyncio.create_task(runner_task())`** result was not retained, so the GC could drop pending tasks per CPython docs. Tasks are now held in a `_running_tasks` set with a `discard` done-callback.
- **`@app.on_event("startup")`** is deprecated in FastAPI ≥ 0.110; migrated to the `lifespan` async context manager.
- **`{job_id}` path parameters** now require a 32-char hex pattern at the route level. Probes get 422 from the validator instead of falling through to a 404 lookup.
- **`result_page`** raised `KeyError` if the scan finished without producing a report; now it returns 500 with a clean message.
- **`download` endpoint** re-sanitizes the on-disk `.name` filename through the same character whitelist as the writer (defense in depth against CRLF / path separators in the `Content-Disposition` header).
- **`urlutil.normalize_url`** rebuilt IPv6 netlocs without brackets, so `[::1]:8080` became `::1:8080`. Brackets are now preserved when the host contains a colon.
- **`logs/`** added to `.gitignore`.

## [0.0.1] - 2026-05-02

Initial release of **Url Reporter** (`urlreporter`).

### Added
- CLI (`./bin/urlreporter scan <url>`) that runs configured scanners and writes a Markdown report to the current directory.
- Web UI (FastAPI + Jinja2) with a URL form, summary page, and downloadable Markdown report.
- Five built-in scanners, all toggleable via `config.env`:
 - SSL Labs (TLS / certificate grade, polling API)
 - Mozilla Observatory v2 (HTTP best-practices score & grade)
 - securityheaders.com (HTTP-headers grade with header-inference fallback when the public `X-Grade` is gated by an API key)
 - internet.nl (link-out - no free single-scan API)
 - hstspreload.org (Chrome HSTS preload status)
- Aggregate overall grade computed across scanners that returned a numeric score; link-out / failed scanners are excluded and noted.
- Prioritized recommendations list deduped by title and sorted by severity.
- Parallel async execution with per-scanner error isolation: one slow or failing scanner does not block the others.
- `config.env` + optional `config.env.local` override; process environment variables override file values.
- macOS / iCloud Drive workaround: bundled `./bin/urlreporter` launcher, `__main__.py`, and `PYTHONPATH=$PWD` instructions for cases where iCloud auto-flags pip's editable `.pth` files as hidden.
- Versioned banner on CLI runs and footer on every web page:
 *Url Reporter v0.0.1 | Made by [Paolo Diomede](https://pdiomede.com)*.

### Known limitations
- internet.nl runs as link-out only until an API token is wired in.
- securityheaders.com no longer exposes the letter grade to anonymous clients; the inference fallback only flags missing headers, not relative weight.
- SSL Labs scans can take 1–3 minutes the first time (cache miss).
