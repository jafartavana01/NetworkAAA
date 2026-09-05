# Changelog

All notable changes to NetworkAAA are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

Dates below reflect the actual work session boundaries as best they
can be reconstructed, not a promise of calendar-perfect precision —
where a feature's exact day is ambiguous, it's grouped with the work
it was built alongside.

---

## 2026-09-03

### Added — Scheduled Audits: a platform-owned service account for unattended daily device auditing

Direct request: give NetworkAAA its own account for reaching devices,
run Security Center audits against every device automatically once a
day, and gate this behind the same "trusted host" mental model
already used for TACACS+ users -- restricting where the credential
can actually be used to sign in to this platform's own management IP.
NCM (config change management) was explicitly deferred to its own
follow-up request and is NOT part of this entry.

**New `AuditScheduleSettings` model** -- a singleton settings row
(same convention as `AdSettings`) storing the SSH username, a
Fernet-encrypted password using the exact same
`encrypt_secret`/`decrypt_secret` mechanism already protecting device
shared secrets and the AD bind password (this credential is at least
as sensitive as either), a single daily run time, a free-text
"management IP note" field, and the last run's status/summary. The
IP note is deliberately admin-entered, not auto-detected -- this
platform may have multiple interfaces, and presenting a wrong guess
as authoritative would be worse than asking the admin to state it
themselves; it exists purely so the admin has something to allow-list
on each device's own SSH ACL, since NetworkAAA has no ability to
configure a device's own access control. Added to `init_db()`'s model
import list in the same edit that created the model -- the exact
mistake that caused the recent Security Center database outage, not
repeated here.

**New `app/services/scheduled_audit.py`**: `run_scheduled_audit()`
audits every enabled device in sequence (deliberately not in
parallel -- an unattended fleet-wide job has no one watching it fail,
so bounding total run time predictably and avoiding simultaneous
management-plane sessions against many devices at once matters more
here than raw speed), reusing the exact same SSH-execution and
audit-persistence pipeline the existing live-audit API endpoint
already uses, not a second implementation of it. Every device is
wrapped in its own try/except so one unreachable device can never
abort auditing the rest of the fleet.

**`should_run_now()`** -- the actual "is it time yet" decision,
deliberately pulled out as its own pure function specifically so it
could be verified independent of the database/SSH/asyncio machinery
around it. Verified with 5 real scenarios (before scheduled time,
after it, already run today, last run was yesterday, exactly at the
scheduled minute) -- then re-extracted directly from the real file
and re-tested against the same 5 cases a second time, specifically to
rule out any transcription drift between what was tested and what
actually shipped.

**`scheduler_loop()`** -- a plain asyncio background task, not a new
dependency: this project has zero existing scheduling infrastructure
(no APScheduler, no Celery, no cron integration), and a single
poll-every-5-minutes loop covers the one real requirement (a daily
fleet audit) without taking on a general-purpose job-scheduling
library for it. The actual audit always runs via `asyncio.to_thread`,
never directly in the loop's own coroutine, so a slow or hanging
device can never block the web server from handling ordinary requests
while a scheduled run is in progress. Wired into `app/main.py` as a
second, separate `@app.on_event("startup")` handler -- deliberately
not merged into the existing sync one, which does one-time setup, not
something meant to run for the process's entire lifetime.

**Three new API endpoints** (`GET`/`PUT /api/security/schedule`,
`POST /api/security/schedule/run-now`), gated to superadmin only --
matching the exact convention `app.api.routes_ad_settings` already
established for AD's own service-account credential, given the
identical risk profile (a shared credential capable of reaching
everything unattended).

**New `/security/schedule` page** -- toggle, username/password/
schedule-time/IP-note fields (all with the established field-icon
treatment), a Save button and a separate Run Now button for testing
the credential without waiting for the schedule, and a Last Run
status panel. Superadmin-gated at the web-route layer too (not just
the API), matching `app.web.routes_platform`'s own established
`require_superadmin` pattern for AD/platform settings pages -- added
that exact capability to Security Center's own `_render()`, which
didn't have it before since nothing in Security Center needed
superadmin-only gating until now. New nav entry added with
`requires_superadmin=True`, verified hidden for a non-superadmin and
visible for one via the same isolated logic test used throughout this
project's sidebar work.

**Verified**: every new/changed Python file compiles; every model
field reference and schema-construction call cross-checked against
the real field definitions via AST inspection; the new template
parses, has zero ID mismatches, and its script confirmed landing
inside `#view-scripts-container` by checking the actual rendered
HTML; a full project-wide sweep for the `view_scripts` placement bug
(the one that broke Security Center earlier this session) still finds
zero instances anywhere, including this new page; full project-wide
compile/template/CSS-balance checks all pass.

---

### Fixed — two real bugs: SPA navigation timing, and a misleading "100% success" chart

Direct report, with screenshots.

**"Device not found" when clicking into a device from the Security
Center list, despite the list itself showing devices correctly.**
Root cause traced to `spa.js` itself, not the Security Center --
`navigateTo()` was re-executing the newly-loaded page's own inline
scripts BEFORE calling `history.pushState()`. Any page whose own
script reads `window.location.pathname` to extract a dynamic URL
segment (a device ID, a job ID) would read the OLD url -- wherever
the user was navigating FROM, not TO -- every single time it was
reached via an in-app link click, and only work correctly on a hard
refresh or direct URL visit (which involve a real page load, where
the URL is already correct from the start). Confirmed this wasn't
isolated to Security Center by grepping the whole project for the
same `window.location.pathname` pattern -- `network_ops_job_detail.html`
has the identical latent bug, not yet reported but fixed by the same
change. Fixed by moving `history.pushState()` to run before the new
page's scripts execute, so `window.location` is already correct by
the time any page reads it. The back/forward-button path (`popstate`)
was already correct and is untouched by this change, since the
browser itself updates the URL before that handler ever fires,
independent of anything this file does.

**Dashboard's Authorization Results chart showed a full green ring
implying 100% success when there was actually zero data recorded.**
The chart's own "no data yet" fallback rendered `[1, 0]` using the
SAME green/red colors real data uses -- visually identical to "100%
permit," when the true state was "no requests recorded at all."
Fixed to render a single neutral-gray segment labeled "No data yet"
instead, and the center-label overlay (added earlier this session)
now shows "No Data" rather than "Success" underneath the dash in
that state, so every part of the panel agrees on what it's showing
instead of implying a real result. The percentage math underneath
this was re-verified with the same test cases as before, plus the
new label-agreement logic, all passing.

Verified: `spa.js` and `dashboard.html` both pass their syntax/parse
checks; full project-wide compile and template checks pass; ID
cross-check on `dashboard.html` returns zero mismatches.

**On the third part of the report** (scheduled daily device auditing,
a platform-owned service credential for reaching devices
unattended, and a Network Configuration/Change Management section):
investigated rather than guessed at scope before building anything --
confirmed this project has zero existing scheduling/background-task
infrastructure (no APScheduler, no Celery, no cron integration), and
that `AuditRun.raw_config`/`config_snapshot_hash` (built earlier this
session for Security Center) already stores a timestamped device
config snapshot on every audit, which is most of NCM's actual data
model already in place as a side effect. Given this touches new
scheduling architecture and a genuinely security-sensitive
shared-credential design, a concrete proposal is owed before writing
code, not a unilateral implementation -- see the conversation itself
for that proposal.

---

### Fixed — Security Center's own database tables were never created

Direct report, with screenshots: Overview showed every stat as a dash,
Devices and Findings both showed "Could not load...". All three
failing together, with nothing in common except the Security Center
API, pointed at something shared rather than three separate bugs.

Root cause: `app/database.py`'s `init_db()` -- the only place in this
project that creates database tables -- imports an explicit, hardcoded
list of model modules before calling `create_all()`, specifically so
SQLAlchemy knows to create their tables. `audit_run` (the module
holding `AuditRun`/`AuditFinding`/`AuditDomainScore`/
`AuditComplianceResult` -- the tables the entire Security Center reads
and writes) was never added to that list. `init_db()` itself is only
ever called once, from `setup.py`, during initial installation --
confirmed by grepping the entire project for every call site, not
assumed. The running application (`main.py`) never calls `create_all()`
itself; it relies entirely on setup having already created every
table. So the `security_audit_*` tables were never created in the
first place, and no amount of restarting the running app would ever
fix that, since the app was never the thing responsible for creating
them.

Fixed by adding `audit_run` to `init_db()`'s import list -- this
covers every fresh install going forward. This does NOT retroactively
fix an already-deployed database that was set up before this change,
since `init_db()` isn't called again on ordinary app restarts.
Confirmed `init_db()` is self-contained and safe to call in isolation
(it uses `get_settings().database_url`, the exact same configuration
the already-running app uses, and `create_all()` only ever creates
tables that don't already exist -- it never touches or recreates
existing ones): running `python3 -c "from app.database import
init_db; init_db()"` from the application's own directory/environment
will create just the missing Security Center tables, without invoking
any of `setup.py`'s other system-level steps (users, groups, certs,
systemd units).

Verified: `database.py` compiles; full project-wide compile check
passes; confirmed via direct code reading (not assumption) that no
other model added this session was missed from this same list.

---

### Continued — Dashboard chart panels, global panel rounding, Active Directory field icons

**`.panel-wide` now has rounded corners (8px) globally** -- checked
the scale first (18 files use this class) before changing it, and
deliberately left the base `.panel`/`.panel-grid` combination alone:
`.panel-grid` shares hairline borders between adjacent items via a
background-color trick, and rounding those individual items would
show odd corner gaps rather than a clean look, so only `.panel-wide`
(genuinely standalone, bordered panels) got the change.

**Dashboard's Authorization Results chart** now shows the real
success-rate percentage in its center, matching the reference
screenshot's circular-progress-with-center-label style -- this
already existed as a Chart.js doughnut chart (confirmed by reading
the actual chart config, not assumed), so no new charting component
was needed, just a center-label overlay computed from the same
permit/non-permit counts the chart itself already uses. The
percentage math (permit / total, rounded) was verified with 5 real
test cases including the zero-data and rounding edge cases -- the
one part of this addition I could verify programmatically. The
label's exact vertical centering relative to the doughnut (which sits
above a bottom-positioned legend, not centered in the full panel
height) is a reasonable approximation I could not visually confirm in
this environment; flagged here rather than presented as certain.

**Active Directory**: icons macro imported, field icons added to
Domain/Username/Password, and an icon added to the Save Settings
button. Checked "Test Connection" the same way as the Dashboard/
Security Center buttons before it and found the identical risk (its
own `.textContent` gets overwritten to "Testing…" during the
request) -- left it alone rather than ship an icon that would vanish
on click, consistent with every other button this pivot has
deliberately skipped for the same reason.

**Verified**: both templates parse; ID cross-checks return zero
mismatches on both; the new field-icon count on Active Directory
confirmed exactly 3 as expected; every extracted script passes Node
syntax checks; full project-wide compile/template/CSS-balance checks
pass after the global `.panel-wide` change specifically, given its
reach across 18 files.

---

### Continued — Devices page brought fully in line with the reference screenshot

Devices was named the most important page in the original request;
finished the remaining gap against its reference screenshot (device-
row icons, a real toggle switch for monitoring mode, and the
dashed-icon-circle Access Grants empty state).

**Device row icons** -- a small server icon next to each device name
in the table, using the same pre-rendered-icon-as-JS-constant
technique already established for Dashboard's status cards and
Security Center's per-row links (this table is built client-side, one
row per device, so a static Jinja icon call doesn't apply). Uses
`display: flex` directly on a `<td>` -- confirmed this is already a
proven pattern in this exact file (`.cell-actions` already does the
same for the actions column), not a new risk introduced here.

**New `.toggle-field`/`.toggle-switch` component** -- a real pill-
shaped switch with a sliding circle, for genuine binary settings like
"Enable monitoring mode", replacing what was previously the same
square checkbox used for "select this item" checkboxes elsewhere. A
real CSS cascade bug caught and fixed before it shipped: `.toggle-
field`'s `display: flex` alone wasn't enough to lay the switch and its
label out side-by-side, because `.field`'s own `flex-direction:
column` (declared earlier in the file, but for a property `.toggle-
field` didn't touch) would have kept applying and stacked them
vertically instead. Fixed by having `.toggle-field` explicitly
declare `flex-direction: row`, verified by checking both rules' exact
line numbers to confirm the override order, not just assumed correct.

**New `.empty-state-icon-circle`** -- a large dashed-border circle
around an icon, an opt-in addition to the existing empty-state
pattern (title/description/action are unchanged, this just adds the
icon above them). Applied to the Access Grants empty state, whose
action button reuses the real "Add access grant" button's own full
click logic (including its existing "create a group first" guard)
via a synthetic click, rather than duplicating that check in a second
place.

**Verified**: template parses; full ID cross-check (101 references,
zero mismatches); both new icon constants confirmed to contain real
rendered SVG via direct HTML inspection; extracted scripts pass Node
syntax checks; CSS brace-balanced with every new variable reference
confirmed defined.

---

### Completed — icon/modal redesign rolled out to every remaining page

Continuing the visual pivot: every modal in the entire project now has
the redesigned style (close button, icon-in-field, icon-on-primary-
button), and every Security Center page received icon treatment where
it was actually safe to add.

**Every modal in the project, closed out this pass**: Network Ops
Audits, Network Ops Job Detail (view-only output modal), Sessions
(view-only session detail modal), Accounting (Promote to Command Set),
and Config (view-only diff modal) -- each got the same treatment as
every other modal from this pivot: import, X close button wired to
that file's own existing close logic (never a new close mechanism),
icon on the primary button where one exists, field icons where
semantically clear. Combined with the previous pass, this is now
every single modal in the project, confirmed by having grepped for
`modal-backdrop` across every template rather than guessing which
pages had one. Also confirmed, by direct inspection rather than
assumption, that AAA Health, Diagnostics, Effective Access, Policy
Simulator, and Network Ops Checks have zero modals -- nothing skipped
there, there was simply nothing to change.

**Two real risks caught and fixed on Security Center pages, not just
assumed safe:**

1. `security_overview.html`'s and `security_device_detail.html`'s
   "Run Audit" buttons both overwrite their own `.textContent` during
   the audit ("Running audit…" / "Run Audit"), which would silently
   strip any icon added via static HTML the moment the button updates
   -- checked this before adding anything, and deliberately left both
   buttons alone rather than ship an icon that would vanish on first
   click.
2. `security_device_detail.html`'s Live-SSH/Paste-Config mode toggle
   buttons fully replace their own `className` on click
   (`'btn-primary btn-small'`, no `btn-with-icon`) -- adding icons
   without also fixing this would have made the icon's flex layout
   break the instant either button was clicked. Fixed by updating
   both `className` assignments to include `btn-with-icon`, not just
   adding the class to the initial markup and hoping.

**`security_devices.html`'s per-row "View" link** (built client-side,
one per device row) needed the same pre-rendered-icon-as-JS-constant
technique Dashboard's status cards already established, not a static
HTML edit -- confirmed the constant contains real rendered SVG via
direct inspection, not assumed from the pattern alone.

**`security_findings.html`**'s three filter dropdowns (Severity/
Status/Device) and **`security_device_detail.html`**'s SSH username/
password fields got the standard field-icon treatment.

**Verified, every page, no exceptions**: Jinja parse, full ID
cross-check (zero mismatches on every single page touched this
session), and Node syntax check on every extracted script. Final
full-project pass before packaging: all 31 top-level templates plus
both partials parse, CSS brace-balanced, `app.js`/`spa.js` both valid,
all 31 named icons re-confirmed as well-formed XML, and -- given how
severe that bug was earlier this session -- a full project-wide
re-sweep for the `view_scripts` placement bug across every template,
still zero instances found anywhere.

---

### Continued — global modal redesign, custom checkbox, comprehensive icon treatment

Explicitly asked to redesign every popup to match the "Add user"
reference screenshot specifically, plus continue Dashboard/Devices --
prioritized the modal redesign first since it's shared CSS: one
change to `.modal`/`.modal h2`/`.checkbox-field` automatically
upgrades every modal in the project, not just the one being directly
edited.

**`.modal`** -- rounded corners (14px, up from square), title enlarged
to 22px/700 weight with its own bottom divider (was 15px, no
divider), padding increased to match. **New `.modal-close-btn`** -- no
modal anywhere in this project had an X close button before this
(confirmed by checking every modal's markup first, not assumed);
every existing modal instead relied on a footer Cancel button and
backdrop-click alone. Added the pattern and wired it into the Add
User and Add Device modals specifically, calling each modal's own
already-existing `closeModal()` -- not a new close mechanism, the
same one Cancel already used.

**New custom checkbox** -- `.checkbox-field input[type="checkbox"]`
now renders as a filled signal-green square with a checkmark when
checked, replacing the native browser checkbox, using the exact same
background-image-data-URI technique this file's own `<select>` arrow
already used (not a new pattern). Verified the checkmark's SVG data
URI decodes to well-formed XML programmatically, the same way every
icon in the new icon set was verified. This one CSS change reached
all 10 files that use `.checkbox-field` -- checked each one's context
first to confirm none of them use it inside a cramped table cell
where the larger 20px size would misfit; all 10 are labeled form/
filter toggles, the context this sizing was designed for.

**New `.btn-with-icon` utility** -- deliberately not baked into
`.btn-primary` itself (used on many icon-less buttons project-wide);
an additive class instead, so only buttons that opt in get the
icon-gap flex layout.

**Add User modal** now comprehensively matches the reference: icons
in all 4 real fields (Authentication/Username/Group/Password), the X
close button, and an icon on the Save button. Add Device modal
brought to the same close-button/icon-button consistency.

**Verified**: full project-wide compile and template checks pass; ID
cross-checks on both modified pages (zero mismatches, including a new
100-reference check on `devices.html`); every icon confirmed present
as real rendered SVG via direct HTML inspection, not assumed from
markup alone; extracted scripts pass Node syntax checks; CSS
brace-balanced throughout.

**Honestly still ahead**: every other modal in the project (Groups,
Policies, Command Sets, Active Directory, and more) still needs its
own close button and field icons -- only Users and Devices have the
full treatment so far, though all of them already inherited the
rounded corners/bigger title/custom checkbox from the shared CSS
change. Dashboard's chart panels and Devices' table-row icons /
monitoring-toggle switch / Access-Grants dashed-border empty state
(all visible in the reference screenshots) haven't been touched yet.

---

### Started — full visual pivot: icon system, superseding the earlier "no icons" design spec

Explicit, confirmed direction change: shown 4 screenshots of an
icon-rich, glowing-card aesthetic and asked to adopt it everywhere,
overriding this same day's earlier detailed spec that had explicitly
said the opposite ("do NOT use emoji as UI icons," "not a generic
SaaS admin dashboard"). Confirmed directly before proceeding, given
the earlier spec was followed carefully across 7 pages this same day.

**New `partials/icons.html`** -- 32 hand-authored SVG icons. This
project has no network access to pull in a real icon library and no
build pipeline to add one as a dependency, so these are hand-authored
geometric SVG primitives (circle/rect/line/polyline/path) following
Lucide's own visual conventions (24x24 viewBox, stroke-based, round
caps/joins, currentColor) rather than copied library path data.
Verified two ways, not just visually assumed: every icon rendered
through Jinja and parsed as well-formed XML programmatically (all 32
passed), and every path command flagged by an automated "coordinates
outside 0-24" sanity check was individually traced by hand to confirm
they were valid relative-coordinate SVG path syntax (a real limitation
of that particular check, not real errors) rather than dismissed.

**Sidebar icons wired end-to-end** -- `NavEntry.icon` existed as
unused, dead data before this session (confirmed the first time this
came up); now actually rendered for Dashboard and all 5 accordion
section headers, via a new per-section icon assignment in
`app/modules/sidebar.py` (sections don't map 1:1 to any single
existing module, so there's no automatic source to derive one from).
A real risk caught during this change: the new markup nests the
section label in an inner `<span>`, which could have silently broken
Ctrl+K's label-reading `querySelector` -- fixed to target that inner
span explicitly rather than rely on SVG elements happening to
contribute nothing to `.textContent`.

**New `.status-card` component** (Dashboard's Management API/
tac_plus-ng/Database cards) -- built as its own class, not a `.panel`
variant, since `.panel` is used 100+ places elsewhere and this needed
its own layout (real gaps between rounded, glow-bordered cards, not
`.panel-grid`'s shared-hairline-via-background technique). Icon SVGs
are rendered once server-side via Jinja and passed into the page's
existing JS as constants, not regenerated client-side on every
15-second refresh.

**A real, confirmed Jinja bug caught and fixed**: a JS comment
referencing "the top-of-file `{% import %}`" literally contained
Jinja's own delimiter syntax -- Jinja parses `{% %}`/`{{ }}` anywhere
in a template file regardless of surrounding HTML/JS context, so this
broke the whole page with a template syntax error. Reworded the
comment to avoid the literal delimiter characters, then swept every
other template touched this pass for the same pattern -- clean.

**New `.field-icon-wrap` pattern** -- icon positioned inside a form
field, matching the reference screenshots' input style. A real
specificity conflict caught before it could silently fail: the
project's existing global `input[type="text"]`/`select` rules have
equal CSS specificity to a naive `.field-icon-wrap input` selector
and are declared later in the file, so cascade order alone would have
let the global padding silently win. Fixed with a properly
higher-specificity selector instead of relying on file ordering.
Applied to 3 fields in the Devices form (Name/IPv4/Shared secret) as
a verified demonstration of the pattern, not yet rolled out further.

**Verified throughout**: every icon confirmed as real rendered SVG
content (not just present-in-markup) in both the sidebar and the
Devices form; full project-wide template parse (31 top-level
templates + both partials); ID cross-checks on every touched file;
Node syntax checks on every extracted script; CSS brace-balanced.

**Honestly scoped**: this is the foundation (icon system, sidebar,
one status-card set, one form's worth of field icons) for a pivot the
reference screenshots show applied to every page, every card, and
every form field. That full scope -- glow-bordered panels everywhere,
icons in every remaining form across every remaining page, redesigned
tables/buttons/modals to match -- is still ahead.

---

### Continued — UI/UX design system pass: Dashboard, Users, Groups, Active Directory, Policies, Command Sets

Continuing the pass started earlier today (Devices was Phase 3's first
page) through the rest of the spec's own priority order.

**Dashboard** — a real bug fixed, not just cosmetic: `loadStatus()`'s
error handler only ever updated the health-status grid, never the
separate build-info panel, so a network failure while loading the
dashboard could leave that panel stuck on "Loading build
information…" forever. Fixed to update both. Reordered content to
match the spec's own 4-question framework (health → usage/
correctness → lowest-priority build/version info, which moved from
second-on-the-page to last) -- pure reordering of existing sections,
no data or logic changed.

**Users** — form restructured into Authentication / Identity / Access
/ Password / Restrictions sections. Done carefully around the
existing AD-vs-local conditional show/hide logic: `.form-section` was
added directly onto the already-toggled elements (`#user-ad-auth-fields`,
`#user-local-auth-fields`) rather than introducing new wrapper divs,
so the exact same three-line `.hidden = isAd` toggle in the existing
JS needed zero changes.

**Active Directory** — new connection-status summary at the top of
the page (status/directory/protocol/server), built entirely from
fields `/api/ad-settings` already returns -- no new backend endpoint,
no invented data. The manual "Run health check" button's own handler
now also updates this summary (one source of truth for "current known
status," not two independent displays), and it's auto-triggered on
page load, but only when AD is actually enabled -- otherwise a
never-configured environment would land on this page to an immediate,
alarming "failed" reading for settings nobody has filled in yet.

A real, serious editing mistake made and caught during this specific
change: an intermediate edit closed `loadSettings()`'s closing brace
too early, orphaning about a dozen lines of the original function
(domain/username field reconstruction) outside the function entirely.
Caught by reading the surrounding code after the edit rather than
trusting the diff alone, and fixed by merging the orphaned block back
inside before the real closing brace -- re-verified with a full parse,
ID cross-check, and Node syntax check afterward, not just assumed
fixed.

**Groups, Policies, Command Sets** — empty states upgraded to the
requested what's-missing/why-it-matters/action pattern; the two
larger pages' (Policies at 1118 lines, with its own condition-tree
builder; Command Sets) forms were deliberately left as-is beyond
that -- both already show conceptually sound information (Policies'
list already renders a compact, human-readable condition summary per
row rather than raw IDs; Command Sets already separates permit/deny
into two distinct lists) and restructuring 1000+ lines of existing,
working condition-builder logic under this pass's time constraints
carried more risk than the visual gain justified.

A pattern caught and fixed three separate times this pass: each new
empty-state edit's `old_str` matched only the single line being
replaced, and the original code already had its own `return;`
immediately after it -- so several of these edits initially produced
a duplicate `return;` statement (harmless dead code, but sloppy).
Caught each time by checking the surrounding lines after the edit
rather than assuming the diff was complete.

**Verified across all six pages**: every template parses; every
`getElementById` reference cross-checked against real IDs (zero
mismatches on any page, including 40 references on the largest,
`policies.html`); every extracted script passes Node syntax checks;
div-nesting balance confirmed on the two heavily-restructured forms
(Users: 33 opens/33 closes; Active Directory's `loadSettings()`
re-verified after the brace-mismatch fix); full project-wide compile
and template checks pass; CSS brace-balanced; and a project-wide
systematic re-scan for the `view_scripts` bug class (the one that
broke Security Center earlier this session) still finds zero
instances anywhere, confirming none of today's six pages
reintroduced it.

---

### Started — enterprise UI/UX design system pass (Phase 1-3, Devices page complete)

A large-scope request: make the whole application feel like a mature
network/security operations console rather than a collection of
individual admin pages, without introducing any frontend framework,
build pipeline, or architectural change -- FastAPI/Jinja2/vanilla JS/
the existing SPA shell all preserved, per explicit instruction.
Followed the requested process exactly: Phase 1 audit before touching
anything, Phase 2 design-system additions, Phase 3 applying them --
starting with Devices, the page the request itself named most
important.

**Phase 1 audit findings (evidence-based, not assumed):** the
foundation is better than the request anticipated -- `.badge`/
`.btn-primary`/`.btn-secondary`/`.btn-danger`/`.toolbar`/`.content-head`
are already used consistently project-wide (checked: every delete
button in `devices.html`/`command_sets.html` already uses
`.btn-danger`, not a mix). The real, confirmed gaps: no form-section
visual grouping exists anywhere (spec's own "DEVICE IDENTITY / NETWORK
/ PLATFORM / AAA" example has no equivalent today), and empty states
are uniformly a single bare sentence with no action ("No devices yet.
Add one to get started." -- text only, no button), never the
what's-missing/why-it-matters/action pattern requested.

**Phase 2 -- new reusable, additive CSS** (`app/static/css/app.css`):
`.form-section`/`.form-section-title` for visual grouping within
longer forms; `.empty-state-title`/`.empty-state-desc` as opt-in
richer sub-parts of the existing `.empty-state` (every current bare
`<div class="empty-state">text</div>` usage across the project is
completely unaffected); `.error-state` as a new, visually distinct
sibling for "something failed" or "not permitted," separate from
"nothing here yet." Every new CSS variable reference verified defined;
brace balance confirmed.

**Phase 3 -- Devices page** (`devices.html`), the page named most
important: the Add/Edit device form restructured into the requested
four `.form-section` groups (Identity, Network, Platform, AAA) --
every single `id`/`required`/`pattern`/`placeholder` attribute
preserved exactly, since the JS's own `getElementById` calls depend on
them unchanged; only grouping and field order changed (Description
moved into Identity, next to Name, matching the spec's own example).
The empty state upgraded to the requested pattern -- title,
explanation, and a working "+ Add device" button wired to the same
`openModal()` the header's own Add button already uses, not a second
implementation.

**Two real issues caught and fixed during this pass, not just
assumed correct:** field-hint spacing initially diverged from this
project's own established `margin-top:-10px;margin-bottom:14px;`
convention (confirmed via `grep` across `accounting.html`/
`admin_users.html`) -- reverted to match rather than introduce a third
variant; and a duplicated `return;` statement left over from an edit,
caught by reading the surrounding code after the change rather than
trusting the diff alone.

**Verified:** template parses; all 98 `getElementById` references in
`devices.html` cross-checked against real IDs with zero mismatches;
full render through Jinja with both extracted scripts passing Node
syntax checks; project-wide compile and template checks pass; CSS
brace-balanced.

**Honestly scoped, not claimed complete:** this is one page of the
roughly dozen the request names (Dashboard, Users, Groups, Active
Directory, Policies, Command Sets, Accounting, Sessions, AAA Health,
Network Operations, Security Center all still ahead), matching the
request's own "do this incrementally" instruction -- a project this
size isn't realistically finishable to this session's verification
standard in one pass, and claiming otherwise would be worse than
being direct about what's left.

---

### Added — Security Center "Findings": fleet-wide, filterable, across every device

`GET /api/security/findings` -- every finding from each device's own
LATEST completed audit only (never an older, superseded run, so a
fixed issue from three audits ago can't reappear just because it's
still sitting in an old run's rows), filterable server-side by
severity/status/device/domain. `/security/findings` is the page:
severity/status/device dropdowns, a real severity-priority sort (see
the real bug caught below), and each row links to its device's own
detail page.

A real bug caught before shipping: the first version sorted findings
with `.order_by(AuditFinding.severity.asc())` -- alphabetical, which
puts "info" and "low" ahead of "high" and "medium" (`critical` <
`high` < `info` < `low` < `medium` as plain strings). Fixed by sorting
in Python against an explicit severity-priority mapping instead.

Also refactored rather than adding a third copy of the same logic:
the "most recent completed audit run per device" query -- already
duplicated once between `/overview` and `/devices` -- is now one
shared `_latest_completed_runs_by_device()` helper, used by all three
endpoints including the new one, so the definition of "current fleet
posture" can't drift between them.

Learning directly from the view_scripts bug fixed just below in this
same day's log: verified the new template's script lands inside
`#view-scripts-container` by checking the actual rendered HTML, not
assumed from having written it correctly, and re-ran the project-wide
systematic scan for that exact bug class -- still zero instances found
anywhere, confirming both the earlier fix held and this new page
didn't reintroduce it. All 31 templates parse; zero ID mismatches;
extracted script passes Node syntax checks; every new/refactored field
reference re-verified against the real database schema; the new nav
entry confirmed appearing correctly under Security Center.

---

### Fixed — Security Center pages stuck on "Loading…" forever when reached via the sidebar

Direct report, with screenshots: Overview and Devices both hung
indefinitely with no error. Root cause, found by re-deriving the
actual mechanics rather than guessing: this project's shell
(`app_shell.html`) is an SPA loader (`spa.js`) that swaps page content
into `#view-root` via `innerHTML` on every in-app navigation --
**script elements inserted through `innerHTML` never execute**, a
standard browser behavior. Every other page in this project puts its
`<script>` in a separate `{% block view_scripts %}`, which lives
OUTSIDE `#view-root` in its own `#view-scripts-container` and is
specifically, individually re-executed by `spa.js` on each navigation
(via `createElement` + `appendChild`, which DOES run). All three new
Security Center pages (`security_overview.html`, `security_devices.html`,
`security_device_detail.html`) had their `<script>` inside
`{% block view_content %}` instead -- so on a hard refresh or direct
URL visit the script ran fine (the whole document loads and executes
normally), but navigating to any of them via a sidebar click meant the
script never ran at all: not a failure, simply nothing ever attempting
to fetch anything, which is exactly why nothing ever errored either --
matching the screenshots precisely.

Fixed by moving each page's `<script>` into its own `{% block
view_scripts %}`, matching the one correct pattern already used by
every other page in this project.

Given how severe and silent this bug class is (a page that renders
fine on direct load, with the identical HTML, silently does nothing at
all via the SPA -- a gap neither a Jinja parse check nor a Node syntax
check would ever catch, since both are blind to which Jinja block a
script sits in), searched the entire project for the same pattern
rather than trusting that only the reported pages were affected.
Confirmed zero further instances -- this was specific to the three
newest pages, not a pre-existing or widespread issue.

While in this code, also hardened three fetch call sites
(`loadOverview()`, `loadDeviceSummary()`, `loadDevices()`, `loadHistory()`)
that previously left their "Loading…" state on screen forever on any
API failure (`if (!res.ok) return;`, with no user-facing message) --
now show a real error, and a distinct message when the failure is a
403 (a role lacking the `security:view` permission, since that
permission is new and existing roles created before it existed
wouldn't have it granted automatically).

Verified: all 3 templates parse; block structure confirmed balanced
and the script now lands inside `#view-scripts-container` specifically
(checked directly against the rendered HTML, not assumed); zero ID
mismatches; every extracted script passes Node syntax checks; a
project-wide systematic scan (script-tag position vs. block
boundaries, run before and after the fix) confirms the bug is fully
resolved and doesn't recur elsewhere.

---

### Changed — sidebar sections now behave as a true accordion, collapsed by default

Direct request: every section collapsed on login, and expanding one
closes whichever other section was open, rather than each section
toggling independently.

The two requirements interact in a way worth spelling out: "collapsed
by default on login" and "auto-expand the section containing wherever
the user currently is" (an earlier requirement) are NOT in tension --
login lands on Dashboard, which was already rendered standalone,
outside every section, so it has no section to auto-expand and every
section is correctly collapsed as a direct consequence, not a special
case. Landing directly on a sub-page (a deep link or a refresh) still
opens that one page's own section, same as before -- now simply
`the` open one, since only one can be, ever.

Previously each section's collapsed state was tracked independently
and persisted to localStorage across page loads. That persistence
directly contradicted "collapsed by default on every login," so it's
removed rather than reconciled -- accordion state now lives only in
the current page's own DOM, reset fresh on every real page load
(`setOpenSection(activeKey)`, called with `null` -- collapsing
everything -- whenever the current page isn't inside any section).
Search remains a deliberate exception: matches can span several
sections, so search force-opens every section with a hit rather than
being constrained to the single accordion slot, and restores normal
accordion state the moment the query is cleared.

Verified: server-side rendering confirmed correct for both cases
(landing on Dashboard renders every section collapsed; landing on a
sub-page renders only its own section open, matching the no-JS
fallback principle this project already established for the original
sidebar). The accordion state machine itself was verified with 5
scenario tests (initial Dashboard landing, initial sub-page landing,
manual open-while-elsewhere-active, re-closing an open section,
SPA-navigating between sections) -- all passed. Full project-wide
template/compile checks and an ID cross-check confirm nothing else
regressed.

---

### Fixed — Ctrl+K palette permanently visible, blocking the entire page

Direct report, with a screenshot: the search palette showed on every
page load and blocked all clicks to the rest of the app. Root cause:
`.cmdk-backdrop` set `display: flex` with no `[hidden]` override --
the `hidden` HTML attribute and a class rule that also sets `display`
have EQUAL CSS specificity, so which one wins depends on cascade
order, not the attribute being present; my author stylesheet's rule
was overriding the browser's own default `[hidden] { display: none }`.
This project already had the correct, proven fix for this exact bug
class on `.modal-backdrop[hidden]` -- I'd simply failed to replicate
it for the new palette.

Given a report of one instance, searched the entire project
systematically rather than fixing only the reported case: every CSS
class with an explicit non-`none` `display` declaration, cross-
referenced against every element in every template that combines that
class with the `hidden` attribute. Found and fixed four more real,
previously-unnoticed instances of the identical bug -- `.panel-grid`
(this session's own new device-detail score grid), and, more
significantly, `.field`, `.field-row`, and `.badge`, three widely-used
foundational classes present across many pages, each now given the
same `[hidden] { display: none }` override. Re-ran the same systematic
search after the fixes and confirmed zero remaining instances anywhere
in the project.

---

### Added — Security Center "Devices" list and per-device detail page

The Overview page's audit trigger had nowhere for its results to
persist to beyond that one page. Added:

- `GET /api/security/devices` -- every NetworkAAA device (reusing the
  existing `NetworkDevice` inventory, not a second one) paired with its
  own most recent completed audit's score/risk/date if it has one, so
  this list is also where "which devices haven't been audited yet" is
  discoverable, not just already-audited ones.
- `/security/devices` -- the list page. Initially used an invented
  `.clickable-row` pattern; caught during review that this project
  already has an established list-to-detail pattern (a real `<a
  class="btn-secondary btn-small">` in a `.cell-actions` column, per
  `network_ops_jobs.html`), and switched to matching it instead of
  introducing a new one.
- `/security/devices/{id}` -- per-device detail: score/risk/last-
  audited summary, a live-SSH-or-paste-config audit trigger (SSH
  fields follow the exact `.field`/`.field-label` markup
  `devices.html`'s own "Apply AAA Configuration" dialog already
  established), the latest audit's domain scores/findings/compliance,
  and full audit history.
- `security_module.py`'s nav entries and `sidebar.py`'s path-to-
  section mapping both updated for the new `/security/devices` path.

Verified: all 30 templates (28 + 2 new) parse; both new templates'
extracted scripts pass Node syntax checks; zero ID mismatches; every
new API field reference cross-checked against the real model schema
(same AST-based verification used throughout this migration, given
SQLAlchemy still isn't installed in this sandbox); the new nav entry
confirmed appearing correctly under Security Center via the same
isolated-logic test used for the sidebar redesign itself.

---

### Redesigned — sidebar navigation: collapsible sections, search, Ctrl+K

The sidebar had grown to one long, flat list under 4 top-level
groups (23 items). Redesigned into 5 collapsible sections (Identity &
Access, TACACS+ / RADIUS, Network Operations, Security Center, System)
plus a standalone Dashboard link, following the exact information
architecture requested -- every existing route preserved unchanged,
zero fake/placeholder links added.

Inspected the existing architecture first, as instructed, and found a
mechanism that would have silently broken if missed: `spa.js` is a
persistent-shell SPA loader whose own `setActiveNav()` re-syncs the
sidebar's active-link highlighting on every client-side navigation
(not full page reloads) by querying `.nav-item` elements by `href` --
any redesign had to keep that exact contract. `spa.js` was extended
with one minimal addition (a `spa:navigated` custom event, dispatched
on both initial load and every SPA transition) rather than teaching it
about "sections," keeping it sidebar-agnostic; the new sidebar-specific
reactions (auto-expanding the active item's section) listen for that
event instead.

**New `app/modules/sidebar.py`**: regroups the nav entries every
module already contributes via `all_modules()` into the new sections
-- without moving a single `NavEntry` between `core_module.py`/
`tacacs_module.py`/`network_ops_module.py`/`security_module.py`, each
of which keeps owning its own nav entries exactly as before. Grouping-
for-display is a presentation concern, kept separate from which module
implements a feature. Superadmin gating (previously enforced only at
the whole-group level -- e.g. the old "Platform" group) is now
evaluated per item, a necessary change since the new Identity & Access
section mixes previously-separate gated and non-gated items; the
effective visibility of every existing item is unchanged. Verified
against data reconstructed exactly from the real module files (FastAPI
isn't installed in this sandbox, so tested with equivalent standalone
dataclasses): all 24 items present with zero loss for a superadmin,
correctly restricted to 19 for a non-admin.

**Search**: filters the already-rendered sidebar client-side (no API
call), matching against each item's own keyword aliases (e.g.
"device" -> Devices/Device Groups; "ad"/"ldap"/"directory" -> Active
Directory) plus its label. A matching section force-expands so results
are actually visible regardless of its stored collapse state.

**Ctrl+K / Cmd+K**: opens a command palette built by reading the
sidebar's own already-rendered DOM, grouped by section, with arrow-
key/Enter/Escape navigation. Deliberately reads from the DOM rather
than a separately-maintained list: an item hidden from a non-superadmin
was never rendered server-side in the first place, so it's structurally
impossible for Ctrl+K to surface a page that admin doesn't have.

**Collapsible sections**: state persisted per-section in localStorage;
a section containing the currently-active page always force-expands
regardless of stored state, "so the user is never left having to
manually discover where they currently are" -- re-evaluated on every
SPA navigation via the `spa:navigated` event, not only on first load.

**A real accessibility issue caught and fixed during review**: the new
search/Ctrl+K inputs' own `:focus` CSS initially overrode this
project's existing, better global `input:focus` style (a visible
signal-colored glow) with a dimmer, custom one -- removed entirely so
the existing convention applies untouched, rather than introducing a
weaker one.

**Deferred, per the requesting spec's own explicit priority order**:
Favorites, Recent pages, and a collapsed icon-only sidebar mode --
this project has no existing icon-rendering system to reuse (`NavEntry.icon`
was already-unused, dead data before this change), and introducing one
solely for a lower-priority, explicitly-conditional feature would risk
exactly the "different visual style" the spec asked to avoid.

**Testing performed**: every one of the 28 templates parses; the
5 real page-render tests (dashboard, devices, network-ops audits,
security overview, plus the sidebar/shell templates directly) all
render without error; every extracted `<script>` block (9 total across
those pages) passes Node.js syntax checking; every `getElementById`/
class-based `querySelector` in the new shell script cross-checked
against real IDs/classes in the rendered HTML; CSS brace balance and
every CSS variable used confirmed defined; full project-wide Python
compile check passed clean.

---

### Added — Security Center: Cisco device security auditing, migrated from two legacy projects

The two legacy repositories (`cisco-ios-security-auditor`,
`cisco-interface-security-audit`) were fully read as real source code
before any migration began -- not summarized from their READMEs --
including running each one's own tools/tests against their own real
sample configs to confirm documented behavior actually held. A
capability matrix and migration architecture were produced and agreed
before any NetworkAAA code was written, per explicit direction.

**Migrated, every domain individually verified byte-identical against
the real original source, not just "looks right":**

- The device-wide config parser (`app/security_center/parser/cisco_config.py`),
  preserving both real bugs the original project's README documents and
  fixes (a `re.MULTILINE` default, and a compiled-pattern/`flags`
  branch) -- verified identical output against a real sample config.
- The per-interface parser (`interface_config.py`) -- verified
  identical against both of the interface-security project's own
  bundled sample configs, run in a separate subprocess to work around
  a real namespace collision (both legacy projects use the top-level
  package name `app`).
- All 9 device-level check domains (`app/security_center/checks/`) --
  37 check functions, 593 individual findings verified byte-identical
  across 4 real sample configs. Extracted programmatically from source
  rather than retyped, specifically to eliminate transcription risk --
  retyping the first migrated domain (Management Plane) by hand had
  already produced one real bug (a lost double-space in one finding's
  evidence string), caught by an AST-level string-constant diff
  against the real source and fixed before moving on.
- The 10-rule correlation engine and all 4 compliance framework JSON
  files (byte-identical checksums confirmed against the originals,
  including the CIS Benchmark's deliberately sparse 2-control coverage
  and the DISA STIG's real V-IDs).
- The 33-rule interface security engine -- migrated via a direct,
  `diff`-confirmed file copy rather than retyping 605 lines of rule
  logic, given the size; verified end-to-end (parse -> assess -> unified
  finding) against real sample configs, 145 findings including scores,
  compliance, and maturity sub-scores all matching exactly.

**New, not a straight port of either original:** unified scoring
(`app/security_center/engine/scoring.py`), applying the interface
engine's self-normalizing `earned/applicable-weight` model consistently
to both device- and interface-level findings, rather than the device
auditor's own flat subtractive model (which doesn't account for how
many checks were actually applicable) or the interface engine's
unexplained 65/35 "maturity" blend (dropped -- an unjustified magic
constant doesn't meet this project's own "scoring must be explainable"
bar). Building this surfaced a real bug: the migrated `F()` helper
(correctly reproducing the original's own PASS/NA-severity-downgrade-
to-INFO behavior) silently zeroed out nearly every finding's
contribution to the new normalized model, since that model needs each
finding's TRUE severity to compute a fair denominator. Fixed by adding
a `true_severity` field to the unified `Finding` model, preserved from
before the downgrade, rather than changing the already-verified
`severity` field's behavior. Re-verified all ~750 previously-checked
findings still matched after the fix.

**API, persistence, and GUI (Phase 6, in progress):** new
`security_audit_runs`/`security_audit_findings`/
`security_audit_domain_scores`/`security_audit_compliance` tables
(purely additive); `app/api/routes_security.py` (upload-config and
live-SSH audit triggers -- the live path reuses Network Operations'
own `run_commands_on_device`, not a second SSH implementation --
plus get/list/compare/overview endpoints); a new `security` RBAC
permission set (`security:view`/`:audit`/`:remediate`, matching this
project's existing `<resource>:<action>` convention); a new,
non-mandatory `security_module.py` registered the same way
`network_ops_module.py` is; and a real, working Security Center
Overview page (live fleet stats, a paste-config-and-audit flow with
scored results, recent-audits table) -- not a placeholder. The
remaining planned pages (Devices, Interfaces, Findings, Compliance,
Remediation, Security Builder, Audit History) are deliberately not
stubbed in as dead nav links.

**Not yet done:** interface-level auditing isn't wired into the same
API/persistence flow as device-level auditing yet (a real, flagged
product decision -- see `orchestrator.py`'s own docstring on why
combining them wasn't decided silently), and remediation isn't yet
wired into the existing configuration Apply workflow.

### Fixed — session detail showed a literal `\n` instead of line breaks

Direct report, with a screenshot. Root cause: the session-detail
timeline was joined with `'\\n'` in the JS source -- a double
backslash, which JavaScript parses as the two-character string
`\n` (backslash, letter n), not an actual newline escape (`'\n'`,
single backslash). `.diff-view` already uses `white-space: pre`, so
fixing the escaping alone was sufficient -- reproduced the exact
broken output and confirmed the fix with a real test against
JavaScript's own string-escaping semantics.

### Added — admin-configurable SSH timeouts for Apply

Direct report that "Apply" could take too long with no way to adjust
it short of editing source code. `ssh_provision.py`'s previously
hard-coded 8s/10s constants are now parameters
(DEFAULT_CONNECT_TIMEOUT_SECONDS / DEFAULT_COMMAND_TIMEOUT_SECONDS),
resolved in order: a per-apply override in the GUI -> an admin's
saved default (new `AaaTemplateSettings.connect_timeout_seconds` /
`command_timeout_seconds`, editable on the AAA Command Template
section) -> the original built-in default. Wired through every apply
path: the single-device apply modal, the Network Scan & Provision
apply modal (single and bulk), and their underlying API endpoints.

### Added — live progress with a real progress bar, and "Continue in background"

Every apply endpoint (`/api/network-scan/apply`, `/apply-all`, and
`/api/devices/{id}/apply-aaa`) now runs as a background task and
returns a session id immediately instead of blocking the request --
`app.services.apply_progress` extended with `total`/`completed`
counters specifically to back a real percentage-based progress bar,
not just a scrolling log. Both apply modals now show a taller,
scrollable live output box with that progress bar above it, backed by
a single generalized `pollApplyProgress(prefix, sessionId,
description)` function shared by both rather than two separate
implementations.

"Continue in background": clicking it during an apply hands the
session off to a new shared `AAAPlatform.trackBackgroundOperation`
poller and closes the modal -- the operation keeps running
server-side regardless. A persistent notification widget in the
topbar (bell icon + badge + dropdown with its own progress bars),
added to `app_shell.html` specifically because that file persists
across SPA navigation (unlike a page's own script), so navigating
away from Devices doesn't lose track of an apply still in progress.
Shows a completion toast and clears itself once each tracked
operation finishes.

---

### Fixed — the real root cause of AD group authorization: `AD_GROUP_PREFIX` must be defined, not merely non-empty

Confirmed with a live, controlled before/after test against the real
AD server this session has been debugging against, using `mavistest`
directly rather than any documentation or secondhand example:

With `AD_GROUP_PREFIX` entirely absent from the generated config
(this platform's previous behavior whenever no specific prefix was
configured), a real `AUTH`-type request against a real AD user
returned `RESULT=ACK` -- fully successful authentication -- but
**zero** group attributes of any kind. Adding a single line,
`setenv AD_GROUP_PREFIX = ""` (empty, not a real prefix), with
nothing else changed, made `MEMBEROF` and `TACMEMBER` appear
immediately in the exact same request, correctly listing every group
the user actually belongs to, completely unstripped.

This means `mavis_tacplus_ads.pl`'s group-membership reporting
requires the variable to be *defined*, not merely for its value to be
non-empty -- a materially different requirement than assumed
previously, and the direct explanation for every group-based
authorization failure investigated this session: since no group
information was ever being returned at all, any policy checking
`member == X` was guaranteed to never match any AD user, regardless
of the condition or the user's real membership.

`_mavis_block()` now always emits `AD_GROUP_PREFIX` whenever memberOf
-based lookup is enabled -- using the admin's configured value if
set, or an empty string otherwise -- rather than omitting the
directive entirely when no prefix was configured. Verified with 4
real execution tests reproducing the exact confirmed live scenario
plus edge cases (a real prefix still passes through correctly;
nothing is emitted when memberOf itself is disabled). Also fixed,
along the way, three separate `mavistest` usage errors that
repeatedly produced misleading or empty output during this
investigation: the wrong config file path/extension, the wrong
`<type>` value (`TAC_PLUS` instead of the tool's actual `TACPLUS`),
and stdio buffering differences between a real terminal and a
redirected pipe -- none of which turned out to be the underlying bug,
but all of which cost real debugging time before being resolved.

### Added — read-only, live AD group membership on the Groups page

Direct request: since this platform's own local Members add/remove UI
has no effect on an AD group's real, authorization-relevant
membership (confirmed the hard way this session), an AD-linked group
now shows a genuinely read-only, live-fetched list of who Active
Directory itself currently reports as a member -- the add-user picker
and Remove buttons are hidden entirely for this group type, replaced
with a direct explanation of why. Backed by a new `get_ad_group_members`
lookup: an exact-CN search for the group's DN, then a single query for
every user whose memberOf includes it -- deliberately not one query
per listed member, regardless of group size. Local groups are
unaffected; their existing add/remove behavior is unchanged.

### Changed — installer now clones the administrator's own fork

`UPSTREAM_REPO_URL` now points at
`https://github.com/jafartavana01/GUi-event-driven-servers.git`
(a fork of the real upstream), per explicit request. Everything else
about the build process -- configure-flag discovery, commit-pinning
for reproducibility -- is unchanged, since this is still a real git
clone of a real source tree, just from a different remote.

### Fixed — two real bugs behind broken Sessions, Accounting, and AAA Health

Direct report, with screenshots, of the "device" column showing a
concatenated timestamp+IP, sessions never correlating to a closed
state, session detail never showing any commands, and AAA Health
reporting "28 distinct devices" for what is really a single device.

**Root cause 1**: `_parse_line`'s timestamp-prefix format was a wrong,
unconfirmed guess (`Jul 12 09:39:50`, no year) carried over from
generic research examples. This real deployment's actual prefix is
`2026-09-03 08:02:18 +0000` (full year, UTC offset) -- and critically,
it's followed by a SPACE before the real payload, not the `::` field
separator the old anchor-from-the-end parsing strategy depended on to
tell the two apart. With no delimiter between them, the entire
prefix silently fused onto the first real field's value (`nas`/
device) instead of being recognized as separate. Fixed by trying a
corrected, confirmed-format timestamp match from the START of the
line first, only falling back to the old (weaker) anchor-from-the-end
heuristic when that doesn't apply.

**Root cause 2**: `group_into_sessions` treated any `accttype=stop`
record as ending a session -- but per-command TACACS+ accounting is
itself sent as `stop`-type records too (a command executes
instantaneously, so there's no separate start/stop pair for it the
way there is for the session itself). This closed every session after
its very first command, discarding the rest and reporting zero
commands in the session that was actually still open. Fixed to
distinguish a per-command `stop` (has a `cmd` value: append it, keep
the session open) from the session's own closing `stop` (empty `cmd`:
actually end it).

Verified with real execution tests reproducing the exact reported
scenario end to end: a start record, three per-command `stop` records,
and a session-ending `stop`, correctly correlating into one closed
session with all three commands captured -- confirmed both bugs are
now fixed together, not just each in isolation. AAA Health's
"distinct devices" count needed no separate fix -- it reads directly
from the same `nas` field, so root cause 1's fix corrects it
automatically.

Also cleaned up, for display only (never touching the underlying
stored data): a trailing `<cr>` -- a standard, expected Cisco IOS
TACACS+ argument marking a complete submitted command line, not a
parsing artifact -- is now trimmed from commands shown on the
Accounting and Sessions pages, and from a command pre-filled into the
"Promote to Command Set" dialog.

### Added — Policy "Manual mode" definition, and a real, evidence-based finding about its limits for AD users

`Policy` gains two new fields: `requires_manual_approval` (a
deliberately separate flag from `default_action`, not a third value
crammed into it -- see the model's own docstring for why) and
`manual_default_command_set_id`, the command set applied to an
approved session unless overridden at approval time. Full schema
validation, API wiring, and a Manual-mode toggle in the Policy form
that reveals the default-command-set picker -- exactly the "CoreSwitch
+ Manual mode + pick a default set" flow requested.

Researched, rather than guessed at, how an approved login would
actually be granted: confirmed with new evidence (a direct reply from
tac_plus-ng's own author -- "user backend = mavis disables user
lookup") that a static `user {}` block is completely ignored for
group-membership purposes once MAVIS is the user backend, and that no
real config anywhere (including several independent AD/group
troubleshooting threads) uses a bare-username ruleset condition. This
project's own existing `DeviceAccessGrant` feature hit the identical
wall previously and works around it by scoping to a dedicated group --
a workaround that doesn't extend to AD users, since this platform
cannot inject AD group membership at all. The actual grant-application
mechanism (the compiler change, the pending-approval data model, and
the approval/queue GUI) is deliberately NOT built yet, rather than
build something that might silently not restrict access to the
specific approved individual.

### Added — shared right-click context menus (Devices, Users, Groups)

A single reusable `AAAPlatform.showContextMenu(x, y, items)` utility,
rather than three separate implementations -- positioned to stay
on-screen near window edges, dismissed on outside click, Escape, or
scroll. Wired into each page's existing row actions (Edit/Delete, plus
Members for Groups and Apply AAA config for Devices) rather than
introducing new, separate action implementations.

### Removed — Just-In-Time (JIT) access grants

Built partway (data model, compiler integration for group-scoped
grants, RBAC permissions), then explicitly requested to be removed
before the remaining pieces (API routes, GUI, cleanup task, tests)
were built. Fully reverted: `app/models/jit_grant.py` and
`app/services/jit_grants.py` deleted, the `jit_grants:view`/`write`
permissions removed from the catalog, and every JIT-specific addition
to `app/services/config_compiler.py` (four compiler functions and
their integration into `compile_candidate`) removed -- confirmed with
a project-wide search returning zero remaining references anywhere,
and the device-access-grant logic it had been woven alongside
confirmed, with a real test, to be back to its exact original,
pre-JIT behavior.

Worth recording for anyone reviewing this history: while building it,
a real, working discovery from earlier in this project (the
"dedicated synthetic group" workaround `DeviceAccessGrant` uses for
group-only targeting) turned out NOT to safely extend to an individual
JIT-granted user -- `TacacsUser.group_id` is a single column, one
group per user, with no membership join table in this project, so
moving a user into a synthetic grant-only group would have displaced
their real, standing group membership for the grant's duration, not
added to it. Caught before it reached the database layer. If a
JIT-style feature is revisited later, this is the specific pitfall to
design around from the start, not rediscover again.

---

## 2026-09-02

### Fixed — the actual root cause of AD login failures: missing Perl module

Real production log analysis. Every previous AD fix this session (LDAPS
TLS configuration, `UNLIMIT_AD_GROUP_MEMBERSHIP`) was correct but
could never have mattered on its own, because `mavis_tacplus_ads.pl`
was failing before it ever got that far:

```
Can't locate Net/LDAP.pm in @INC (you may need to install the Net::LDAP module)
BEGIN failed--compilation aborted at /usr/local/lib/mavis/mavis_tacplus_ldap.pl line 294.
external: /usr/local/lib/mavis/mavis_tacplus_ads.pl respawning too fast; throttling for 30 seconds.
```

- **`installer/apt_deps.py`**: now installs `libnet-ldap-perl`
  (confirmed, via multiple independent Debian package pages, as the
  correct Debian/Ubuntu package providing Perl's `Net::LDAP` module)
  and `libio-socket-ssl-perl` (LDAPS/StartTLS support within the Perl
  script itself — only a "Suggests" on the former, so not pulled in
  automatically, and had to be listed explicitly). An earlier version
  of this file deliberately deferred mavis's Perl dependencies with
  the reasoning "belong to a future LDAP/RADIUS module" — that future
  arrived when AD integration shipped, and this closes the gap.
- Without this fix, `mavis_tacplus_ads.pl` cannot even load on any
  login attempt, regardless of how correctly this platform's own AD
  settings, TLS configuration, or certificates are set up — the
  failure happens entirely upstream of any of that, at the Perl
  module loading stage.

### Improved — AD search is now live, auto-search as you type

On both the Users page (searching AD users) and the Groups page
(searching AD groups): removed the separate Search button and
Enter-key requirement entirely, per direct feedback that a plain
textbox that searches itself is the expected interaction. Typing now
triggers a debounced (400ms) search automatically.

Verified with a real, deliberately adversarial test: simulated typing
"j" then quickly "jd", with the network mocked to resolve the simpler
"j" query *after* the more specific "jd" one (a genuine race auto-search
implementations are prone to) — confirmed the correct, most recent
result always wins, never a stale one silently overwriting it. Also
clears any in-flight search when its modal closes.

### Clarified — AD users don't need to be pre-added to log in

Confirmed from `login backend = mavis` / `user backend = mavis` being
global settings, and directly from a real log line
(`looking for user u1 in MAVIS backend` for a user with no static
`user {}` block in the compiled config): any AD user who is a genuine
member of the correct AD group can authenticate and be authorized
without ever being manually added to this platform's own Users page
first. The Users page is for visibility and organization, not a
prerequisite gate.

### Added — a direct way to see why an AD login is "denied by ACL"

Real log analysis confirmed AD authentication itself was working
(`result for user u1 is ACK`) but authorization was failing (`denied
by ACL`) -- the expected result when a policy's group condition
doesn't match what the user is really a member of in AD. Rather than
requiring external LDAP tools to check, the Users page now has a
"Check real AD group membership" action (for an AD-linked user) that
performs a live `memberOf` lookup and shows exactly what group
name(s) `tac_plus-ng` itself would see for that identity -- applying
the same confirmed prefix-filter-and-strip transformation
`mavis_tacplus_ads.pl` applies, so what's shown is what a `member ==`
policy condition actually needs to reference, not the raw AD group
name.

Verified with 4 real execution tests against realistic `memberOf`
values, including reproducing the exact confirmed research example
(`GTC_ad-admins` → `ad-admins`) and the zero-groups case, which
surfaces a direct explanation rather than an empty result.

### Improved — Add Group dialog: Type-first, matching the Users dialog

Direct UX feedback: the previous "Linked AD group" field undersold how
much it actually mattered, presenting itself as an optional
cross-reference when getting it right is actually the entire
mechanism by which an AD group's real membership maps to a policy
condition. Redesigned with a Type selector (Local / Active Directory)
as the first field, matching the pattern already established on the
Users dialog. Selecting Active Directory surfaces AD search
immediately and shows an explicit warning that membership is
determined entirely by real AD group membership -- adding members via
the Members button has no effect for this type. Selecting Local shows
the reverse warning: local group membership drives authorization for
local users only, not AD ones.

Confirmed, with further research (a real, direct fix from tac_plus-ng's
own author mapping a backend-reported "groups" attribute to `member`
internally) that this project's existing guidance was correct: an AD
user's `member ==` match always comes from what the AD backend itself
reports at login time, never from a locally-assigned membership table
-- there is no way to make manually adding an AD-sourced user to a
platform-local group drive their real tac_plus-ng authorization.

### Clarified — why adding an AD user shows no pending Apply change

Real feedback against a live compiled config, confirming an AD-linked
user genuinely never gets a `user {}` block: adding one is not itself
a config change, because `login backend = mavis` being global means
tac_plus-ng will try MAVIS for any username it doesn't recognize --
including one never added to this platform at all. Added a clear note
on the Users page explaining this directly, rather than leaving an
admin to wonder why the Apply button never appears. Further research
into tac_plus-ng's own real-world configs also surfaced a
`mavis module = groups { }` block (regex-based `groups filter` /
`memberof filter`) as a more flexible alternative to the simpler
`AD_GROUP_PREFIX` approach already in use here -- noted for a future
increment, not built now without stronger confirmation it's needed.

### Fixed — AD search silently hid real failures behind "No matches"

Real, concrete bug report: a user's own memberOf correctly reported
membership in a group ("tacpalasGroup") via the group-membership
lookup tool, but searching for that exact same name on the Groups
page returned "No matches" -- a genuine inconsistency between two
tools hitting the same directory.

Root cause: `search_groups`/`search_users` had a blanket
`except Exception: return []` -- any real failure (a bad bind, a
malformed filter, or -- the likely culprit here -- a search_base that
doesn't cover the OU/container a group actually lives in, unlike a
memberOf lookup, which reads an attribute value directly off the user
and never needs the group to be within search_base at all) was
indistinguishable from a search that genuinely found nothing.

Both functions now return a real/empty/error three-way result
instead of a bare list, and the API and both GUIs (Groups, Users)
surface an actual error message when a search fails, rather than
silently presenting it as zero results. Verified with a real test
covering all three states: a genuine failure, a genuinely empty
result, and a successful one -- confirming each renders distinctly.

### Fixed — the real `search_groups` root cause, a CSS layout bug, and hardened the "Discard and close" button

Follow-up on the search-failure fix above, from a real, concrete error
the improved error-surfacing immediately revealed: `Search failed:
Search failed: attribute 'get' not found`. Root cause found and fixed:
`entry.get("distinguishedName", entry.entry_dn)` in `search_groups`
called `.get()` on an ldap3 `Entry` object, which isn't a dict --
ldap3 overrides attribute access so `.get` gets interpreted as "look
up an LDAP attribute literally named 'get'", which doesn't exist.
Reproduced the exact reported error string with a real test against
ldap3's actual attribute-access behavior, confirmed the fix resolves
it. Also fixed the resulting double "Search failed: Search failed:"
prefix (both the backend and frontend were independently adding the
same label).

**A real, project-wide CSS bug**, also from direct feedback ("text
description are in the textboxes"): `.field-hint`'s common
`margin-top:-10px` convention exists specifically to compensate for
`.modal .field { margin-bottom: 14px; }`, a rule scoped only to
`.modal`. Active Directory Settings (and part of the Devices page)
render their fields on a plain page, not inside a modal, so that
compensating margin had nothing to offset and pulled hint text up
into the input box above it. Found every instance project-wide with a
proper HTML-nesting-aware parser (not a text search, which cannot
distinguish "inside a modal" from "not"), confirmed zero remaining
instances after fixing both files.

**Hardened "Discard and close"**, from a report that clicking it
repeatedly did nothing. Extensive testing with a real, purpose-built
DOM simulation (using the actual, unmodified source from this file)
could not reproduce a failure in the core Escape-to-confirm flow, but
the fix removes an entire class of potential staleness bugs regardless:
the button previously closed whichever modal a `pendingCloseTarget`
closure variable had captured when Escape was first pressed; it now
re-queries for the currently-visible real modal at the moment of the
click itself, which is provably correct since the dirty modal stays
visible (just overlaid) for the entire time the confirm prompt is
showing. `pendingCloseTarget` removed entirely rather than kept
alongside the safer approach.

---

## 2026-09-01

### Fixed — Active Directory group authorization, and Add User UX

Real production debugging, working from a live `tacplas.local` AD
deployment and an actual authorization failure report ("AD user can't
login on switch or routers"):

- **`UNLIMIT_AD_GROUP_MEMBERSHIP = 1` now emitted whenever memberOf-
  based group evaluation is used.** Confirmed, by the actual author
  of the mavis LDAP integration scripts in a real support thread:
  without this flag, a user's reported group membership is silently
  limited to exactly ONE group, even if they're really a member of
  several — almost certainly the direct cause of AD users
  authenticating successfully but failing every authorization rule
  that checks a specific group. This was a genuine gap in the
  compiler's MAVIS block that existed since AD integration was first
  built.
- **Groups page**: picking an AD group from the search results now
  suggests the LOCAL group's Name field as the prefix-stripped CN
  (confirmed exact behavior: `AD_GROUP_PREFIX = GTC_` turns
  `CN=GTC_ad-admins` into `member == ad-admins`, prefix stripped, not
  the full CN) — verified against that exact real-world example.
  Never overwrites a name the admin already typed; never suggests an
  invalid tac_plus-ng identifier.
- **Add User dialog reordered**: Authentication is now the first
  field. Selecting Active Directory surfaces AD search immediately;
  picking a result now auto-fills Username, Full Name, and AD
  Identity together (previously only AD Identity was filled, still
  requiring the admin to separately retype the username by hand even
  after finding the exact right AD account). A new inline note
  clarifies that for an AD-linked user, the platform's own Group
  dropdown is local/display-only and does not drive tac_plus-ng's
  actual authorization for them — that requires real AD group
  membership instead, which is what the Groups page fix above makes
  practical to set up correctly.

### Added — Network Operations & Assurance Engine, Phase 1 (Command Jobs)

The first increment of a much larger, explicitly-phased capability
(the full design covers 12 phases: Command Jobs → Templates → a Check
engine → an Audit engine → integration of two existing standalone
Cisco security-auditor projects → remediation with an approval
workflow → compliance mapping → scheduling → a fleet-wide "Finder" →
visualization). Only Phase 1 is built here — see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full
architecture assessment and exactly what's deliberately deferred.

- **Command Jobs**: run commands against one or more devices, device
  groups, or a mix of both, with automatic deduplication — a device
  reachable through more than one selected group (or both
  individually and via a group) runs exactly once. Sequential or
  controlled-parallel execution with configurable concurrency and
  per-command/connection timeouts. Verified with a real executable
  test against every target-resolution scenario the design spec
  explicitly requires, including its own "device in two groups"
  example.
- **Live job dashboard**: per-device, per-command progress while a
  job runs, auto-refreshing every 2.5s and stopping once the job
  reaches a terminal state; full raw output retained and viewable for
  every command, on every device, permanently.
- **Command classification**: every executed command is tagged
  READ_ONLY / CONFIGURATION / DESTRUCTIVE / UNKNOWN — a heuristic aid
  for the confirmation UI, explicitly documented as such, never a
  guarantee. Verified against 13 realistic Cisco IOS commands across
  all four categories.
- **Command Templates**: reusable, named command lists, selectable
  when creating a job instead of typing commands from scratch.
- New RBAC permissions (`network_ops:view`, `network_ops:execute`,
  `network_ops:templates`), following the existing permission
  catalog's naming convention exactly.
- Registered as a genuinely optional module (not mandatory, unlike
  the TACACS+ core) — toggleable independently via the existing
  module enable/disable mechanism.

### Fixed (caught during Phase 1's own development, before shipping)

- The command classifier's `write memory` handling: reasoned about in
  a docstring as belonging in the CONFIGURATION category, but the
  actual prefix list was never updated to match, so it silently fell
  through to UNKNOWN. Found by the classification test failing, not
  by re-reading the code.
- A leftover, confusing placeholder (`if False else re.compile("(?!)")`)
  in the destructive-command pattern list, written while reasoning
  through whether `write memory` should be classified as destructive
  — cleaned up before it could confuse a future reader, once the
  actual decision (it shouldn't) was reached.

### Added — Network Operations & Assurance Engine, Phase 3 (Check Engine)

- **Checks**: a small, code-defined registry of Cisco IOS hardening
  evaluators (AAA new-model enabled, password encryption service,
  VTY SSH-only transport, HTTP management server disabled) — all
  well-documented, standard Cisco IOS checks chosen specifically for
  high confidence. Evaluates already-collected command output from a
  completed Command Job; running a check never triggers a new SSH
  connection.
- A small, independently-written Cisco IOS config-structure parser
  (`show running-config` stanza parsing) — verified with a real test
  against the exact `re.MULTILINE` bug class a referenced project's
  own README documents having hit, confirmed correct here from the
  start.
- **Honesty discipline, verified with real tests**: a device with no
  running-config output collected returns NOT_APPLICABLE, never a
  guessed PASS/FAIL. A fully-hardened sample config passes all 4
  checks; a weak one fails all 4; a mixed-VTY config correctly
  flags only the specific line range with the actual problem.
- Check results are append-only across re-runs — never overwritten,
  matching this project's established version-history discipline.
- New Job Detail page section (Run Checks + results with evidence and
  recommended fix inline) and a new Checks catalog page.

### Fixed (caught during Phase 3's own development, before shipping)

- A genuine type mismatch in the `Check` model: `enabled` was
  annotated `Mapped[bool]` but defined with a `String(8)` column, left
  behind from thinking through the design mid-write, with a comment
  that didn't describe real code. Caught by re-reading before the file
  was even submitted; fixed to a proper `Boolean` column.

---

## 2026-08-30

### Added — Device Secret Confirmation
- The Edit Device modal now shows the **last 4 characters** of the
  saved shared secret (e.g. "Currently ends in …7X9k") — the same
  confirmatory-without-exposing pattern used by AWS access keys and
  Stripe API keys. The full secret is still never displayed; this
  addresses repeated confusion where the earlier fixes (clearer hint
  text, then a plain "configured" badge) weren't concrete enough for
  admins to actually confirm which secret was saved.

### Changed — Policy Conditions: "User" Removed as a Selectable Type
- Individual users are no longer offered anywhere in the condition
  builder (the two-list picker or the Advanced tree builder) — only
  User Groups. Direct per-user conditions have no confirmed
  `tac_plus-ng` syntax and could never compile, so offering the option
  only ever produced a policy that saved successfully but silently
  contributed nothing to the real configuration. Deliberately *not*
  removed from the backend's accepted condition types, to avoid
  blocking a re-save of any already-existing policy that happens to
  still have one in its tree — existing data continues to load and
  display correctly; only the ability to create a new one is gone.

### Added — Active Directory / LDAP Integration
- New **Platform → Active Directory** page: Domain, Username, Password
  as the three primary fields, with host/port/TLS/search-base/user-
  filter/group-prefix/memberOf all auto-derived from the domain name
  and tucked into a collapsible Advanced section — editable, but not
  required for a working setup.
- **Test Connection** — a real, direct LDAP bind + search from the
  management plane itself, honestly scoped as testing platform-to-AD
  reachability, not a guarantee that tac_plus-ng's own separate MAVIS
  integration is configured identically.
- **AD Health check** — on-demand test of the currently saved settings.
- **Browse-and-select pickers** for AD groups (on the Groups page) and
  AD users (on the Users page), backed by real LDAP search endpoints,
  with manual entry still available as an alternative.
- tac_plus-ng MAVIS backend config generation (`mavis module =
  external { ... }`, `login backend = mavis`, `user backend = mavis`)
  — confirmed real syntax, sourced from the upstream project's own
  integration guide and a real tac_plus-ng-specific example. Purely
  additive: disabled or unconfigured AD compiles a byte-identical
  config to before this feature existed.
- `TacacsUser.auth_source` (local/ad) and `ad_identity`; `password_hash`
  is now nullable for AD-linked users. `TacacsGroup.ad_group_name` for
  cross-referencing a real AD group.

### Added — Monitoring Mode
- **Devices → Monitoring**: an enable/disable toggle that, once
  applied, makes an unrecognized device's connection attempt
  observable (a catch-all `host world { address = ::/0 }` block,
  always emitted *last*, after every specific device's host block —
  safe regardless of which host-matching precedence tac_plus-ng
  actually uses, since a specific block always gets first
  opportunity to match either way).
- A live-updating list of recently-seen unrecognized source IPs, with
  one-click **Add**, assigning the new device to a seeded "monitor"
  Device Group.
- The shared key is never shown (and never could be — TACACS+ doesn't
  transmit it over the wire, by protocol design).

### Added — Network Scan & Provision
- Scan an IP range for SSH-reachable hosts (a TCP port-22 check, no
  ICMP/root privileges needed), with results marked when an IP is
  already a configured device.
- **Apply AAA** (single) and **Apply AAA to all** (bulk), each with a
  confirmation step for Device Group selection (with inline
  create-new-group).
- Cisco IOS TACACS+ client AAA configuration pushed over SSH —
  `local` and `if-authenticated` fallbacks always included so a
  misconfigured push can't lock out device access; `aaa authorization
  config-commands` extends authorization to configuration-mode
  commands.
- **Editable command preview** before applying, and an **admin-wide,
  persistent default template** (Devices → Default AAA command
  template) for future scans — not just a one-off edit.
- **Live "Applying..." progress** during bulk apply: a 2-line,
  auto-updating, non-scrollable display of which device and step is
  currently running, color-coded pass/fail. Runs as a background task
  with a polled progress endpoint, since a single blocking request
  can't report partial progress mid-batch.
- SSH credentials are never persisted — used only for the duration of
  the scan/apply request. Each device gets its own randomly-generated
  shared secret; if commands are hand-edited, the *stored* secret is
  extracted directly from what's actually being sent, so it can never
  drift out of sync with a manual edit.
- **Device-overlap validation**: creating or updating a device whose
  network overlaps an already-configured device's network is now
  rejected outright, in either direction.

### Added — Platform-wide UX
- **Global "Apply Configuration" button** in the top bar, visible
  whenever changes are pending, from any page — opens a responsive
  diff popup and applies through the same flow the Config page itself
  uses.
- **ESC closes the open dialog**, project-wide, with unsaved-changes
  protection: a shared confirm prompt (defaulting to *keep editing*,
  never silently discarding real edits) appears before closing a
  modal with unsaved input.
- Modern scrollbar styling; textboxes and form edges now visually
  distinct from their surrounding panel; modals size to their content
  instead of always rendering at a fixed width.
- `setup.py`: `apt-get update` restored (deliberately `update` only,
  never `upgrade`).

### Fixed
- **Policy save error, "String should have at least 1 character"** —
  root-caused: the default condition builder correctly sends an empty
  placeholder value for database-backed conditions (the backend
  resolves the real value independently), but an overly strict
  backend validation rule rejected it anyway. Fixed at the source.
- Group quick-add (on the Network Scan Apply dialog) not appearing in
  the list or being selected after creation — the refresh callback
  was a no-op.
- A form-overflow layout issue in the quick-add panel.
- Group Membership: **Device Groups and TACACS+ Groups** now support
  viewing and adding/removing members directly from the group's own
  page, not only by editing each user/device individually.

### Changed
- Policy conditions: the old three-field "Simple" view is replaced by
  a two-list **Users & Groups / Devices & Device Groups** picker (per
  a provided wireframe), with **Simple / Advanced** now presented as a
  proper two-button tab pair instead of a one-way "switch" link.
- Condition builder nesting depth is now genuinely unlimited (was
  capped at one level as a prior scope decision) — "+ Add Condition
  Group" works at every level.
- AAA command template: `aaa new-model` now comes first, before the
  `tacacs-server host` line, matching conventional Cisco IOS practice
  (enable the AAA subsystem before configuring it).
- `setup.py`: `apt-get update` is now a yes/no prompt (default yes)
  rather than running automatically and unconditionally.

### Added — Network Scan & Provision: device info from `show version`
- A newly-provisioned device's **vendor**, **platform** (model
  number, e.g. `WS-C2960X-24TS-L` or `ISR4331/K9`), and
  **description** (the device's own `show version` output) are now
  populated automatically from a real SSH session — not left blank.
  Best-effort by design: if the platform can't be confidently
  extracted from a given device's output, it's left unset rather than
  guessed at, but the raw output is always preserved in the
  description regardless, so nothing observed is ever lost.
- Runs in the *same* SSH session that already reads the device's
  prompt for a hostname suggestion — one connection, not two.

### Fixed
- **Advanced policy condition builder layout**: the "no confirmed
  syntax" hint shown for a `user`-type condition was being appended as
  another flex child of the condition row itself, rendering as a
  column to the right instead of a line below it. Fixed by wrapping
  the row and hint in a separate stacked container — caught and fixed
  a second, more serious bug in the process of fixing the first: an
  early version of the fix moved the function's `return` statement
  ahead of where the row's own dropdown/input event listeners get
  attached, which would have silently broken every condition row's
  interactivity. Verified with a real executable test confirming both
  the corrected layout and that every listener still fires correctly.
- **Config page silently showing "Up to date" on a real error**: the
  candidate-check request's response was read as JSON without first
  checking whether the request had actually succeeded — a server-side
  failure while compiling the candidate would silently render as "no
  pending changes" instead of surfacing the real problem. Now shows
  the actual error.
- A regression in the `show version` platform-extraction regex, caught
  by testing against a realistic router output sample before shipping:
  the character class didn't include `/`, so model numbers like
  `ISR4331/K9` (the `/K9` suffix denoting a crypto-enabled image,
  common across Cisco router lines) failed to match at all.

### Added — Policy Priorities: Insert-and-Shift
- Priorities now start at 0. Creating or editing a policy at an
  already-used priority no longer rejects with a conflict — it inserts
  the policy there and shifts every other policy between the old and
  new position by exactly one slot to make room, the same way
  inserting into an ordered list works. Verified with a real
  simulation of the exact requested example (10 policies, insert at
  7 → 7 through 9 each shift up by one) plus both directions of moving
  an existing policy, checking for zero gaps or duplicates in every
  case. The drag-and-drop reorder endpoint now assigns sequential
  priorities from 0 too, for consistency with the same scheme.

### Added — A Second, Safer Root-Cause Fix for "New Policy Not Detected"
- `get_uncompilable_policies()` — which explains *why* a specific
  policy can't compile into the real config (e.g. a condition type
  with no confirmed tac_plus-ng syntax) — was previously checked only
  at the moment of an actual Apply. If the ONLY pending change was a
  policy that gets silently excluded from compilation, it contributes
  zero bytes to the candidate, so the admin never even saw an Apply
  button to click, let alone the recorded reason. This check is now
  surfaced directly in the candidate-status endpoint and shown from
  both the Config page and the global Apply button (with its own
  distinct warning state) — a silently-excluded policy is now visible
  from any page with a clear, specific reason, not an invisible
  non-event.

### Added — Dashboard: Live Activity
- A large **Active Sessions** count, computed from the same real
  session-correlation logic (a start with no matching stop = active)
  the Sessions page already uses — no separately-tracked metric.
- A table of every (device, user) pair with activity in the last 5
  minutes, most-recent first, with event counts — clicking a device
  opens its full time-sorted activity history in a modal.

### Added — Accounting → Policy: Promote a Command Directly
- The existing "Promote to Command Set" flow on the Accounting page
  now also supports targeting a **policy** directly: pick a policy
  instead of a command set, and the platform finds or creates the
  right command set automatically (creating and attaching a new one,
  named after the policy, if it doesn't have one yet — truncated so
  the generated name never exceeds the shared 64-character limit,
  verified at that exact boundary). A new, narrowly-scoped backend
  endpoint (`POST /policies/{id}/command-sets/{id}`) backs this
  specifically because the existing full-policy-update endpoint
  requires raw condition IDs that the policy list response never
  exposes (only their resolved display names) — reusing it here risked
  silently clearing a policy's conditions.

### Added — AAA Template: `aaa authorization console`
- Extends the same authorization method lists already in place to the
  console line specifically (which Cisco IOS otherwise exempts from
  authorization even with `aaa new-model` enabled) — doesn't define a
  separate method list, so the existing `local`/`if-authenticated`
  fallbacks still protect console access the same way they protect
  everything else.

### Added — Apply AAA Config to an Already-Existing Device
- Devices added manually (not just ones discovered by Network Scan)
  now have their own **Apply AAA config** action, using the device's
  own already-saved shared secret rather than generating a new one —
  keeping the device and the platform's record of it consistent. The
  real secret is never sent to or shown in the browser: the editable
  command preview uses a clearly-fake placeholder string that's
  substituted server-side at the moment of the actual SSH push: if the
  admin edits the commands and leaves the placeholder alone, the real
  secret is substituted in; if they replace it with a different value
  instead, the platform's stored secret for that device is updated to
  match what was actually sent, so the two can never drift apart.
- A **"✓ Configured"** badge now appears next to the Shared Secret
  field when editing a device, driven by the backend's real
  `has_secret` value — concrete visual confirmation that a secret
  really is saved, addressing repeated confusion over the (correct,
  intentional) fact that secrets are never displayed once set.

### Added — Bootstrap Script & Installer Prompt
- `bootstrap.sh`: a single self-contained bash script that detects
  Python 3 (installing it via apt if missing) and hands off to the
  existing `setup.py` unchanged — solves the chicken-and-egg problem
  of the real installer needing Python to even start. Verified with
  real execution of both branches (Python present, and Python missing
  → installed via apt) using an isolated fake PATH.
- `setup.py`'s `apt-get update` is now a yes/no prompt (default yes)
  instead of running automatically and unconditionally.

### Fixed
- **Command Set editor showing raw regex instead of the original plain
  text**: reconstructing a stored pattern's original match mode
  checked the *still-escaped* text for regex metacharacters — but the
  escaping backslash is itself one, so any command containing a
  literal "." (IP addresses, version numbers — extremely common)
  always failed the check and was shown as "Custom regex" with the raw
  escaped pattern visible in the box. Fixed with a round-trip check
  (un-escape, then re-escape, then compare to the original) that
  correctly recognizes a simple match regardless of what characters it
  contains, while still correctly leaving genuine hand-written regex
  identified as "Custom." Verified against 6 scenarios including the
  exact reported case and confirmation that real regex is never
  misidentified as simple text.
- Modals now size to their content instead of always rendering at a
  fixed width, with Save/Cancel buttons pinned via `position: sticky`
  so they stay visible regardless of how much content scrolls above
  them — fixed globally via CSS, without restructuring any modal's
  HTML.

---

## 2026-08-29

### Added — Policy Condition Engine (replaces the flat three-field model)
- A real condition **tree** (`PolicyConditionGroup` / `PolicyCondition`)
  supporting AND / OR / NOT logic across User, User Group, Device,
  Device Group, and Source IP (exact match or CIDR range) — evaluated
  by a new recursive engine and verified with real executable tests,
  including the exact nested AND/OR and CIDR examples from the design
  spec.
- **Compiler integration**: a migrated policy's condition tree compiles
  into real `tac_plus-ng` boolean expressions (`&&`, `||`, `==`, `!=`,
  and generated `acl {}` blocks for CIDR matching) — confirmed syntax,
  sourced from a real tac_plus-ng-specific working configuration.
  Anything that can't be safely compiled (a bare-username condition, a
  NOT group — no confirmed `!` operator) excludes just that one policy
  from the generated ruleset, with the reason recorded as an
  auditable event, never faked.
- Interactive GUI condition builder with a searchable value picker for
  every database-backed object type.
- Migrating a policy from the legacy model to the tree model is an
  explicit, lossless, one-way admin action — never automatic; an
  un-migrated policy's behavior is completely unchanged.

### Added — Device-level Access Grants
- Grant a user group unrestricted privilege-15 access to a device or
  device group, taking precedence over Policies — precedence achieved
  by *emission order* in the generated ruleset (grants always written
  first), not by priority-number juggling. Group-only, for the same
  reason direct per-user policy conditions aren't offered: no
  confirmed syntax exists for matching a bare username.

### Added — Granular RBAC
- `AdminRole` with a flat permission catalog (16 real permission keys
  across resources that actually exist in this project) and 3 starter
  role templates (Read-Only Auditor, Policy Manager, Device Operator).
- Strictly additive over the existing two-tier model: a superadmin
  bypasses role checks unconditionally; an account with no role
  assigned behaves exactly as it always did (full standard-admin
  access) — nothing about any existing account changes by this
  feature existing.
- Applied to Policies, Command Sets, Devices, and Device Groups this
  round; Accounting/Diagnostics/Config/TACACS+ user-and-group
  management remain on the original "any authenticated admin" or
  superadmin gate for now.

### Added — Command Sets, Policy Versioning, Simulator, Effective Access
- Command Sets: reusable, named permit/deny rule collections
  referenced by one or more policies, with a "Starts with / Contains /
  Exact / Custom regex" pattern builder instead of hand-written regex
  for the common cases, and a "promote to Command Set" action directly
  from the Accounting page.
- Every policy save creates a new version; diff against the current
  state and restore an old one (restoring creates a new version —
  history is never destroyed).
- **Policy Simulator**: test a hypothetical request and see the full
  step-by-step evaluation trace.
- **Effective Access**: "what can this user access?" / "who can access
  this device?", with the reasoning chain shown.

### Added — Accounting, Sessions, AAA Health, Dashboard
- Session view correlating accounting start/stop records by device and
  port; searchable/filterable accounting with CSV export.
- AAA Health: real permit/deny and failure-analysis breakdowns computed
  from parsed accounting data — no fabricated statistics.
- Dashboard charts (hourly activity, authorization-results breakdown).

### Added — Config Backup/Restore, Uninstaller
- Structured, version-tagged config export/import with compatibility
  checking and a diff shown before anything is touched.
- `sudo python3 setup.py -u`: removes everything the installer
  created, and only that — never Python, pip packages, or other
  system software (including the PostgreSQL *server* itself).

### Changed
- Installer no longer ran `apt-get update` automatically as of this
  point in the session (later reversed on 2026-08-30 — see above).
- Single-window GUI shell completed across every authenticated page.

### Fixed
- `${task_id}` removed from the accounting log format — confirmed
  invalid `tac_plus-ng` syntax against a real deployment failure.
- Config validation now blocks an `apply` outright on a daemon-
  confirmed definitive syntax error, rather than relying solely on the
  post-reload health check to catch it after the fact.
- A missing-function regression in `accounting_log.py` (an earlier
  edit had silently deleted `compute_health_and_failure_stats`,
  breaking the AAA Health page and Dashboard activity chart) — caught
  via `ast.walk()`, not just `py_compile`, which had missed it
  entirely since the leftover code was syntactically valid.
- A property-naming mismatch that made the Command Sets "Edit" button
  silently do nothing for any set with existing rules.

