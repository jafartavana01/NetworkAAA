# Changelog

All notable changes to NetworkAAA are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

Dates below reflect the actual work session boundaries as best they
can be reconstructed, not a promise of calendar-perfect precision —
where a feature's exact day is ambiguous, it's grouped with the work
it was built alongside.

---

## 2026-09-03

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

