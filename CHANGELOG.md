# Changelog

All notable changes to NetworkAAA are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

Dates below reflect the actual work session boundaries as best they
can be reconstructed, not a promise of calendar-perfect precision —
where a feature's exact day is ambiguous, it's grouped with the work
it was built alongside.

---

## 2026-09-03

### Fixed — three RADIUS routes pointed at templates that do not exist

Caught during verification, before it shipped. The previous pass moved
RADIUS into its own nav section and intended to drop the routes for
pages not yet built. The removal used a regex that silently matched
nothing, so `/radius/overview`, `/radius/policies` and
`/radius/accounting` remained registered with no template behind them
-- all three would have returned a 500.

Removed properly, and a check added to the verification pass: every
`_render(...)` template argument is now confirmed to exist on disk,
and every RADIUS nav entry is confirmed to resolve to a registered
route. A "the regex ran without error" result is not evidence the edit
happened.

### Added — RADIUS server probe, device node-type tabs, and AD support in the access tools

**RADIUS probe (`POST /api/radius/probe` + a Test panel on the Server
page).** Sends a real RFC 2865 Access-Request to the local listener
using a device's STORED shared secret, and reports whether the daemon
answers.

This exists because a NAS cannot tell these apart -- all of them show
as "requests sent, zero responses": listener down, client not defined,
secret mismatch, or a firewall eating the reply. The probe controls
the secret and the source, so its result is unambiguous.

The secret is never accepted from the request body; it is read from
the encrypted device record, so the endpoint cannot be used to test a
secret the caller does not already have, nor to discover one by trial.
Superadmin-only for the same reason.

**An Access-Reject is reported as SUCCESS**, with an explanation. It
proves the server received the packet, validated the shared secret and
evaluated policy -- showing that as a failure would perpetuate exactly
the confusion the tool exists to end.

Protocol verified against the RFC rather than assumed: password hiding
round-trips at six lengths including empty and 17 characters, the
length field matches the real packet, attributes parse back, and the
Response Authenticator check rejects both a forged reply and a wrong
secret. Then end-to-end against a simulated server across four
behaviours (accept, reject, silent, secret mismatch).

**Device node-type tabs.** The device form now has TACACS+ and RADIUS
tabs with only the relevant fields on each. Both panels remain in the
form and are always submitted -- the tabs control what is VISIBLE,
never what is saved, so switching tabs cannot silently discard a
secret already typed. Editing a RADIUS-only client opens on the RADIUS
tab rather than one that says nothing about it.

**Active Directory users now work in the access tools.** Reported and
confirmed: Policy Simulator and Effective Access both queried
`TacacsUser` only, so an AD-authenticated user always came back "not
found" -- for precisely the identities an administrator most needs to
check, and in disagreement with the authorization path those tools
exist to predict.

New `services/identity_resolver.py` resolves local first (matching the
daemon's own precedence), then AD, mapping AD groups onto platform
groups by `ad_group_name` and falling back to the group name, both
case-insensitively. Verified across seven cases including group names
with spaces.

Two things are surfaced rather than swallowed: **unmapped AD groups**
(an AD group with no counterpart here matches nothing, which is worth
seeing), and **multi-group membership** (all mapped groups are listed
and the first is used, because which one wins changes the answer).

For an AD user the simulator now reports "authenticates against Active
Directory, so no password can be verified here" instead of a failure
that reads like a broken account.

**Two bugs caught by verification before shipping:**
* The evaluation stand-in for an AD identity was missing `user.id`,
  which `condition_engine` reads for single-user policy conditions.
  `None` is the correct value -- an AD identity is not that specific
  local user -- but the attribute has to exist. Found by diffing the
  attributes the engine reads against those the stand-in provides.
* The new endpoint used `result.matched_policy_name`, which exists
  only in `to_dict()`, not on the dataclass. That would have raised
  `AttributeError` on the first device evaluated.

---

### Added — NCM Change Control page (Phases 6-9 GUI)

The candidate/approval/deployment backend was built and tested two
changes ago but had no pages. This is that GUI.

**One page, two tabs**: Changes (the candidate lifecycle) and
Deployments (what was actually pushed, and rollback).

**Refused commands are surfaced in the LIST, not at deploy time.** A
candidate containing `reload`, `no ip ssh` or similar shows the
refusal on its row and in the drawer, so a reviewer sees the problem
BEFORE approving. Discovering it at deployment would be too late to be
useful.

**"Verified" means what it says.** The deployments table reports
"Config changed" or "No change detected" from the post-deployment
backup being compared against the pre-deployment one -- not from the
commands having been accepted. A deployment that changed nothing says
so rather than reporting success.

**Both destructive actions confirm, and the confirmations state what
actually happens**: deploying explains that a backup is taken first
and the device is not touched if that fails; rollback states plainly
that replaying an archived configuration restores settings the change
MODIFIED but does not remove lines it ADDED. That limit is in the
service docstring and would have been invisible to the person clicking
the button.

The create form explains that `configure terminal` / `end` /
`write memory` are added automatically, so an operator does not add
them again, and that comment and blank lines are ignored.

Deployment transcripts are shown with a note that credentials are
redacted before storage -- the redaction already existed; saying so
means nobody assumes a transcript is a safe place to paste a secret.

**Verified**: 47 templates parse; the page renders with zero ID
mismatches; scripts pass syntax checks; undefined-name scan (179
modules), render-target check, `[hidden]` sweep and authorization
suite all clean.

---

### Changed — Configuration Diff page rebuilt against the reference design

Rebuilt on the structured backend from the previous change, so every
number, row and category comes from the real comparison rather than
from layout.

**Side-by-side workspace.** Two panes with line numbers, monospaced
text and change highlighting. A line present on only one side gets a
hatched spacer opposite it -- that is what keeps the panes aligned row
for row rather than drifting apart as soon as anything is added.
Scrolling is synchronised in both directions, with a guard flag so the
two panes cannot drive each other in a feedback loop.

**Controls that all do something:** side-by-side / unified toggle, and
"Show only changes" which keeps two lines of context around each
change so a lone changed line is not stripped of the block it belongs
to. No non-functional buttons were added -- fullscreen was left out
rather than stubbed.

**Changes table** with type, location, category and before/after
values, filtered by type, category and free text, paginated at 25.
**Export writes what is currently FILTERED**, so what you see is what
you get, with proper CSV quote escaping.

**Summary tab** groups changes by configuration area with a stacked
bar per category. Categories with no changes are not listed -- an
empty row implies something was checked and found clean, which would
be untrue.

**One claim from the reference deliberately not reproduced:** the
"No syntax errors" indicator. There is no syntax checker behind this
page, so asserting it would be a fabricated status on a screen whose
whole job is to report what actually changed. The card shows
"Identical" or "Configuration changed" instead, which is derivable.

**Colours integrate with the existing token set** (`--signal` /
`--red` / `--amber`) rather than introducing a second palette, and
every state also carries a `+` / `−` / `~` marker and a text label, so
nothing depends on colour alone.

Error state shows a plain sentence and a Retry button, never a raw
exception. Empty states are distinct for: no snapshots at all, no
device selected, same snapshot twice, no differences found, and no
rows matching the filters.

`/api/ncm/diff` is untouched, so nothing else that used it changed.

**Verified**: 46 templates parse; the page renders with zero ID
mismatches across 28 references; scripts pass Node syntax checks; CSS
brace-balanced with all ten new component classes present; project-wide
`[hidden]` sweep, undefined-name scan (179 modules), render-target
check and authorization suite all clean.

---

### Added — structured diff backend for the Configuration Diff redesign

The reference design needs three things the current `/api/ncm/diff`
cannot provide: side-by-side ALIGNED rows, a change table with
location and before/after values, and per-category counts. Built the
backend for those first, because a page that renders any of them from
guesswork would be a mockup.

**New `app/services/ncm_diff_detail.py`.** The raw text diff stays
authoritative -- this is a VIEW over difflib's opcodes, not a second
algorithm, and no line is shown as changed that difflib did not report
as changed. `/api/ncm/diff` is untouched, so the existing page and any
other caller keep working.

**Two derivations, both real rather than invented:**

*Location* (`interface GigabitEthernet0/1 - description`) comes from
the nearest preceding column-0 line plus the changed line's first
token. In IOS the indentation IS the hierarchy, so this is structure,
not a guess.

*Modified* comes from difflib's `replace` opcodes: within one such
block, a removal and an addition are paired as a modification when
they share the same parent context AND the same first token. Anything
unpaired stays a plain add or remove. The pairing is a presentation
choice and is documented as one -- add/remove counts are never altered
by it, and the summary reports all three so the numbers can always be
reconciled.

**Categories reuse `ncm_compare.CATEGORY_PATTERNS`** rather than
introducing a second taxonomy, so a line that is "Routing" on the
multi-device Compare page is "Routing" here too.

**A real bug caught and fixed during testing:** a top-level line was
treated as its own parent, producing the nonsense location
`version 17.9 - version` -- and worse, preventing it from pairing with
its replacement, since two different top-level lines never share a
context. A `version` bump therefore showed as an unrelated add plus
remove instead of one modification. Context search now starts ABOVE
the line: after the fix the same comparison reports three
modifications with correct locations.

Verified against a realistic IOS change: description edit, IP change,
OSPF network change and an added `transport input ssh` all classify
and locate correctly; categories populate Interfaces / Routing / SSH;
every aligned row has at least one populated side; and an identical
configuration returns `identical` with no changes.

**New endpoint** `POST /api/ncm/diff/detailed`, gated on the same
`ncm:diff` permission as the existing diff.

**Still to build**: the redesigned page itself -- side-by-side panels
with synchronised scrolling, the change table with search and export,
and the Summary tab. The data behind every one of those is now real
and tested, which is the part that had to come first.

---

### Fixed — Groups page reported 0 policies and 0 members for groups that had both

Two separate under-reporting bugs, both in the backend, both reported
from a real screen showing "none" and "0 members" for groups
demonstrably in use.

**1. Policy references missed the condition tree.**
`_referencing_policy_names` only looked at `Policy.condition_group_id`
-- the original single-condition field. Any policy built with the
condition BUILDER stores its group as a `user_group` condition inside
the condition tree instead, so those policies were invisible to the
reverse lookup: two policies targeting two groups reported "USED BY
POLICIES: 0" and "2 unreferenced".

Now checks both paths and de-duplicates, since one policy can
reference the same group in several conditions. A reverse lookup has
to cover every forward path or it quietly under-reports -- which is
worse than not showing the column at all, because it looks authoritative.

**2. Member counts ignored Active Directory.** `member_count` counts
local `TacacsUser` rows only. An AD-backed group with three members in
AD showed "0 members" -- while clicking Members listed all three,
because that modal already queried AD. The list and the detail
disagreed, and the list was wrong.

Fixed in the GUI rather than the list endpoint, deliberately: querying
LDAP once per group inside the list request would make the page slow
and would fail outright whenever AD is unreachable. AD counts are
fetched AFTER the table renders, one group at a time (a fleet of
AD-backed groups should not open a burst of LDAP searches), and merged
into both the cell and the KPI as they arrive.

The cell now distinguishes every state rather than collapsing them
into a number: `3 members (0 local, 3 AD)`, `0 local +AD…` while
pending, and `0 local (AD unreachable)` on failure. That last one
matters -- the endpoint deliberately distinguishes a failed search
from an empty one, and treating a bind failure as "0 members" is
exactly the bug being fixed.

Response shape was verified against the endpoint (`results`, plus an
`error` field) rather than assumed; my first draft guessed at
`entries` and would have silently counted zero for every group.

### Changed — removed Checks and Audits from Network Operations navigation

Requested: Security Center covers this ground more thoroughly, and
surfacing both invites confusion about which to trust.

Nav entries and Ctrl+K search keywords removed. **The routes,
templates, API and stored audit data are deliberately left intact** --
removing navigation is reversible and loses nothing, whereas deleting
the feature would destroy existing audit history that was never asked
to be deleted. A bookmarked URL still works.

---

### Fixed — web server stopped answering after ~10 minutes while the process stayed alive

Reported symptom: the service ran, the server was reachable, but no
page loaded. The journal was the clue -- it showed the app STILL making
its periodic `systemctl` status calls, so the process was alive and
working. A crash looks nothing like that. A blocked event loop looks
exactly like that.

**Two bugs, both mine, both in the scheduler loops.**

1. **Blocking database work ran directly on the event loop.** Both
   `ncm_scheduler.scheduler_loop` and
   `scheduled_audit.scheduler_loop` called `session_local()` and
   `db.query(...)` inside the coroutine, offloading only the SSH work
   to a thread. A synchronous query blocks the loop for its duration --
   and if the connection pool is exhausted, `session_local()` blocks
   INDEFINITELY. The process keeps running and answers nothing, which
   is precisely the reported symptom and why it appeared minutes after
   startup rather than at boot.

2. **A Session created on the event-loop thread was passed into
   `asyncio.to_thread`.** SQLAlchemy sessions are not thread-safe.
   `ncm_backup` deliberately avoids this by having its worker threads
   return plain dicts and doing all writes on one thread; the
   schedulers did the opposite. Undefined behaviour under concurrency,
   and a plausible route to the pool exhaustion in (1).

**Fix**: each loop's entire tick now lives in `_poll_once()`, executed
wholly inside `asyncio.to_thread`. The session is created, used and
closed on one thread, and the coroutine does nothing blocking at all --
only `await asyncio.to_thread(...)` and `await asyncio.sleep(...)`.

**Verified by measurement, not inspection.** A simulation of both
shapes under load: the old pattern produced a **1001 ms** worst-case
request stall, the new one **1 ms** -- a ~930x improvement, with an
assertion that the old shape demonstrably stalls so the test cannot
pass vacuously. Also asserted via AST that neither coroutine contains
`db.query`, `session_local()`, `db.commit` or `db.close` any more.

**On my verification generally.** This is the third runtime failure to
reach the server. Compilation, then import-time names, and now
event-loop behaviour -- each a category my checks did not cover.
Static checks cannot catch a blocked loop; only reasoning about what
runs where can. Both schedulers were written with a docstring claiming
the blocking work was offloaded, and that claim was true of the SSH
call and false of the database call in the same function. A comment
asserting a property is not evidence of it.

---

### Fixed — service failed to start: missing `BaseModel` import in routes_radius

`app/api/routes_radius.py` defined three Pydantic response models but
never imported `BaseModel`. The service raised `NameError` at import
time, exited 1, and systemd restart-looped it. My regression, from the
RADIUS attributes/clients work.

**Why my verification missed it, and what I did about that.**
`py_compile` COMPILES a module; it never IMPORTS one. A missing import
is not a syntax error, so the file compiled cleanly every time while
being guaranteed to fail the moment Python actually executed the class
definitions. Every "full project compiles" line in this changelog was
therefore weaker evidence than it appeared -- it proved the files were
parseable, not loadable.

Added `tests/check_undefined_names.py`, which walks each module's AST
and reports any name used by module-level code -- base classes,
decorators, default arguments, module-level assignments and
expressions -- that is not imported, defined, or a builtin. Function
BODIES are deliberately skipped: a name resolved at call time is a
different and far less fatal problem, and flagging those would make
the check noisy enough to ignore.

It cannot import the real modules (SQLAlchemy, FastAPI and Pydantic
are not installed in the build environment, which is precisely how the
gap arose), so it reasons statically instead. That is enough for this
class of bug.

**Verified it actually catches the failure**: reintroducing the exact
missing import produces three specific findings naming the file, line,
class and missing name -- while `py_compile` passes the same file
without complaint, demonstrating the gap directly rather than
asserting it.

Clean across all 178 modules. Also added a check that every template
referenced by a `_render(...)` call exists on disk, since a broken
render target is the same shape of failure: invisible to compilation,
fatal at runtime.

---

### Changed — progressive disclosure via a reusable feature gate (UI/UX pass, part 2)

Spec sections 8-10: a page whose configuration is meaningless until the
feature is switched on should not show that configuration. Active
Directory was the named example -- nine fields plus a connection-status
panel, all rendered whether or not AD was enabled.

**Built as a reusable component, not a one-off.** `.feature-gate` plus
`.gated-config` is the same markup shape for any on/off-gated
configuration screen, which is the point of section 26. Applied to
Active Directory AND the RADIUS server page in this pass; monitoring
and any future gated feature use the same two classes.

The gate itself carries the state rather than leaving it implied: a
title, a one-line description of what the feature does, and an explicit
state line that changes between "Disabled — enable it to configure
domain settings" and "Enabled — configure the domain and service
account below". The toggle is labelled On/Off in text as well as
position, so the state does not depend on reading a switch graphic.

**Two details that mattered:**
* When AD is disabled the connection-status and health panels are
  hidden too. Reporting "Not configured" for a feature an admin has
  deliberately turned off is noise, not information.
* A Save button remains available in the disabled state, in its own
  action row. Turning AD **off** and saving is a legitimate action, and
  hiding the only Save button behind the gate would have made it
  impossible -- a bug the obvious implementation walks straight into.

**A real CSS bug caught while wiring it:** `.modal-actions` sets
`display: flex`, so the bare `hidden` attribute on the disabled-state
action row would have had no effect and BOTH button rows would have
shown at once. Added `.modal-actions[hidden]` -- the same class of bug
this project already sweeps for, found by running that sweep rather
than by noticing it.

Active Directory keeps its existing Advanced-settings collapse, which
already implemented section 9 correctly; nothing there was rebuilt.

No backend, API, permission or business logic changed.

**Verified**: 46 templates parse; both gated pages render their gate
markup with zero ID mismatches and valid scripts; the project-wide
`[hidden]` sweep is clean after the fix; full project compiles;
authorization suite passes.

---

### Changed — modal sizing design system (UI/UX pass, part 1)

Audited the modal layer before changing anything, and the root cause
was systemic rather than per-page: the base `.modal` was capped at
**480px** with always-on `overflow-y: auto`. Every dialog therefore
inherited "narrow and scrolling", and **19 of 22 templates worked
around it with one-off inline widths** -- precisely the per-page
styling a design system exists to remove.

**Four content-driven sizes** replace the single cap:

    modal-sm   460px   confirmations, delete prompts, one or two fields
    modal-md   760px   ordinary forms -- device, user, credential editing
    modal-lg  1040px   multi-section forms, pickers, side-by-side content
    modal-xl  1320px   workspaces: execution output, large tables

All 19 inline overrides were replaced with these classes, and the
forced `max-height: 90vh; overflow-y: auto` they carried was dropped
-- the base rule already scrolls only when content genuinely exceeds
the viewport, so the scrollbars those overrides created were
unnecessary.

Sizes were then assigned by CONTENT rather than left uniform:
execution output and the generated-configuration viewer are `xl`;
the device form, policy editor, permission matrix and device pickers
are `lg`; the rest `md`. The resulting spread is 11 lg / 9 md / 2 xl,
which is the point -- one width for everything was the original
problem.

**Two supporting rules:**
* `.field-row` now collapses to a single column below 700px, instead
  of squeezing two inputs into ~150px each.
* New `.form-grid` flows fields into as many columns as fit, so a
  ten-field form fills a wide dialog rather than becoming a tall
  narrow column.

The device form already used `field-row` in nine places -- it did not
need restructuring, only the width to use it, which `modal-lg` now
provides.

No template markup beyond the modal class changed, and no backend,
API, or business logic was touched.

**Verified**: 46 templates parse; CSS brace-balanced with all six new
classes present; `[hidden]` sweep clean; authorization suite passes;
full project compiles.

---

### Added — RADIUS attribute dictionary (parsed from the real upstream file), plus a capability audit

First step of the RADIUS GUI redesign. Started with an end-to-end
audit of what tac_plus-ng can actually be made to do, page by page,
because two of the seven requested pages turn out to depend on things
that are not confirmed to exist. Recorded in
`docs/RADIUS_FINDINGS.md`.

**Attribute dictionary — built, and NOT hardcoded.**
`app/services/radius_dictionary.py` parses
`tac_plus-ng/sample/radius-dict.cfg` from the upstream checkout the
installer already clones. The attributes an operator can pick are then
exactly the attributes the daemon will accept; a hand-maintained list
would drift the moment upstream changed one, and the GUI would start
offering attributes that fail at config-compile time. Vendor
dictionaries (Cisco, Cisco-ASA, Fortinet, PaloAlto, Juniper, Microsoft,
APC, MikroTik) come with their real vendor IDs rather than being
transcribed.

Written as an explicit brace-depth scanner rather than independent
regexes, because an attribute's enumerated-value block
(`Login-User 1`) is only distinguishable from other tokens by its
nesting.

**When the file is absent it returns EMPTY and says so** -- no
fallback list. An attribute picker showing plausible attributes the
daemon may not accept is worse than one that admits it could not read
the dictionary.

Verified against the real dictionary content: 17 attributes across
standard and three vendor blocks; `Service-Type` enumerations parsed
(`Administrative-User` = 6); `Cisco-AVPair` qualifying to
`Cisco:Cisco-AVPair`, exactly the form the sample's scripts use;
MikroTik vendor id 14988; enumerated values correctly NOT leaking into
the attribute list; and a missing file returning unavailable.

**Capability audit — what will and will not be built:**

*Supported, syntax confirmed*: Server (listeners and log targets),
Clients (the device model already carries `radius_enabled` and
`radius_secret_encrypted`, so no duplicate inventory is needed),
Attributes, and Policies -- the sample confirms
`if (aaa.protocol == radius) { if (radius[Attr] == V) { set
radius[Vendor:Attr] = "..." permit } }`.

*NOT supported — CoA.* No evidence of any kind: not in the upstream
README (which lists RADIUS transports and auth methods but never CoA),
not in the confirmed samples, not in the RADIUS source filenames the
detector reported. CoA also requires the server to act as a CLIENT
originating UDP to port 3799, a role tac_plus-ng plays nowhere else
here. **A CoA page is deliberately not built** -- "View sessions /
Disconnect" controls that cannot work are exactly the fake
functionality the brief rules out. A one-line grep to settle it is in
the findings doc.

*Blocked, not unbuilt — statistics and accounting events.* Both logs
are real and produced; their LINE FORMAT is not confirmed. The sample
declares them with a `destination` only, so the default layout is
unknown, and whether `accounting format = "..."` is accepted inside a
`radius.accounting log` block has not been verified. A rejected
directive would break the entire generated configuration, so this is
blocked on one question rather than on effort.

---

### Added — Module Management page; corrected the installer's stale "next steps" message

Prompted by a question about the installer's closing line, which said:

    Next steps : Phase 8 (Module Management) adds a GUI page showing
                 installed/enabled/status per module -- the last phase.

Investigated rather than assuming it was just stale text, and it was
**half stale and half a real gap**. The module BACKEND was fully
wired: `ModuleState` rows are seeded at startup, and `app.main` only
mounts a module's router when `module.mandatory or key in enabled`. So
disabling a module already worked -- there was simply no way to see or
change it.

**New Module Management page** (`/platform/modules`), superadmin-gated
at both the API and the page route. Lists every registered module with
its description, route count, navigation paths, and an enable toggle.

Details that matter:
* A **mandatory** module reports enabled regardless of any stored row,
  because that is what `app.main` actually does when mounting.
  Reporting a stored `false` for a module the platform mounts anyway
  would be a lie the UI then repeats.
* Disabling is stated as **reversible and non-destructive**: routes
  are not mounted on the next boot, data is untouched. An admin should
  not have to guess whether they are about to lose anything.
* The page says plainly that **a restart is required** rather than
  implying the change is live.
* A rejected toggle is **reverted in the UI**, so the switch never
  shows a state the server refused.

**Installer message corrected.** It now lists what an operator should
actually do after installing -- change the initial password, add
devices, review modules, apply the configuration -- instead of
advertising an internal development phase. A post-install summary is
for the operator, not for the project's own roadmap.

**Verified**: 44 templates parse; the new page renders with zero ID
mismatches and valid scripts; `registry.get_module` confirmed to exist
before use; the API router is mounted in `core_module`; full project
compiles; the authorization regression suite still passes.

---

### Added — NCM Phases 6-9 backend: candidates, approval workflow, deployment, rollback

This is the first NCM feature that WRITES to devices, and it is built
around that fact rather than treating it as another CRUD surface.

**Reuses the existing proven push path.** Commands go through
`ssh_provision.apply_aaa_config`, which already runs an interactive
shell and returns the device's own transcript. No second SSH
implementation, exactly as with backup.

**Safety ordering, enforced in the service:**
1. Only an `approved` candidate is deployable.
2. A fresh backup is taken IMMEDIATELY BEFORE the change -- that
   snapshot, not the last scheduled one, is the rollback point.
   Rolling back to a stale backup would restore a state the device was
   never in at the moment of the change.
3. **If the pre-backup fails, the deployment aborts without touching
   the device.** Changing a device you cannot roll back is the one
   outcome worth refusing outright.
4. Commands are wrapped in `configure terminal` / `end` /
   `write memory`, so the sequence is balanced regardless of what the
   operator wrote.
5. A verification backup is taken after, and "did it change" is
   derived from comparing real archived snapshots -- never assumed
   from the commands having been accepted. A deployment that changed
   nothing says so.

**Dangerous commands are refused** (`reload`, `no aaa new-model`,
`no ip ssh`, `no username`, `no line vty`, `no interface`, `erase`,
`format`, `delete`) -- the ones that sever the platform's own access
or reboot the box. Documented as a backstop against a typo in a
reviewed change, NOT a security boundary: an operator with deploy
rights can still do harm, and the audit trail is what covers that.
Refused commands are surfaced on the candidate at READ time, so a
reviewer sees the problem before approving rather than at deployment.

**Self-approval is refused, superadmins included.** The point of a
separate `ncm:approve` permission is a second pair of eyes; letting
the author sign off their own change would make approval a formality
that records a name without adding review. An exemption is exactly the
path a rushed change would take.

**Transcripts are sanitised before storage.** A device echoes what it
is sent, so a candidate containing a key or password would otherwise
land in the database in clear text via the transcript -- the one path
by which this feature could leak a secret it was never given.

**Two limits stated plainly rather than implied:**
* A candidate stores the CHANGE (lines to apply), not a target
  configuration. Computing the command sequence that transforms one
  full Cisco config into another requires modelling negation, sub-mode
  context and per-platform ordering, which this platform cannot do
  safely.
* Rollback REPLAYS the pre-deployment configuration. That reliably
  restores settings a change MODIFIED, but does NOT remove lines it
  ADDED -- undoing an addition needs the `no` form. So rollback
  verifies against the pre-deployment snapshot and reports honestly
  whether the device byte-matches, instead of declaring success
  because commands were accepted.

**New**: `NcmCandidate` and `NcmDeployment` models, three permissions
(`ncm:propose` / `ncm:approve` / `ncm:deploy`, split so
separation-of-duty is possible at all), `app/services/ncm_deploy.py`,
and seven endpoints. Lifecycle transitions live in one
`ALLOWED_TRANSITIONS` table so the rules are inspectable and cannot
diverge across the API.

**Verified by execution**: dangerous-command matching across nine
cases including the near-misses that must NOT be blocked
(`no shutdown`, `interface Gi0/1`); comment and blank lines never
reaching a device; eight lifecycle transitions including
`draft -> approved` correctly refused; and transcript redaction of
keys and passwords. Both serializers cross-checked against real model
fields via AST; 43 templates parse; the authorization suite still
passes; full project compiles.

**No GUI yet.** The backend is complete and callable, but change
control deserves a properly designed review screen rather than a form
bolted on at the end of a long session -- the diff a reviewer sees
before approving is the whole safety mechanism.

---

### Added — NCM Phase 4: configuration baselines and drift detection

The architecture built in Phases 1-3 was designed to carry this without
alteration, and it did: `NcmBaseline` attaches to the existing
immutable snapshots by foreign key, and drift reuses the existing diff
engine. No Phase 1-3 code changed.

**A baseline is a POINTER to an archived snapshot, not a copy of its
text.** The snapshot is already immutable and SHA-256 hashed, so a
baseline can never silently disagree with the archive, and drift is a
comparison between two artifacts the platform actually holds -- rather
than between a device and a hand-maintained document that could itself
be wrong.

**Five drift statuses, deliberately not a boolean:**

    in_sync        latest snapshot is byte-identical to the baseline
    drifted        latest snapshot differs from the baseline
    no_baseline    has snapshots, none designated golden
    no_snapshot    never backed up
    baseline_gone  the designated snapshot was deleted from the archive

The last three are gaps in COVERAGE, not misbehaving devices.
Collapsing them into "drifted" would raise false alarms; collapsing
them into "in_sync" would hide real blind spots. They are counted and
displayed separately, so a fleet with no baselines set can never read
as healthy.

**Nothing contacts a device.** Drift describes what has been ARCHIVED.
A device that changed but has not been backed up since shows its real
coverage state rather than "in sync", which would be a false
all-clear.

**Correctness details worth naming:**
* Comparison is by SHA-256 first; line counts are computed only when
  hashes differ, so an in-sync fleet is not diffed line-by-line to
  prove it is unchanged.
* A snapshot belonging to a DIFFERENT device is rejected as a
  baseline. Accepting it would make every future comparison for that
  device meaningless.
* `ondelete="SET NULL"` on the baseline's snapshot reference: if the
  golden config is deleted from the archive the baseline becomes
  `baseline_gone` -- visible and fixable -- rather than silently
  vanishing along with the operator's intent.
* Clearing a baseline removes the designation only; the archived
  snapshot is untouched. Changing what counts as "correct" must never
  delete configuration history.
* Setting a baseline is gated on `ncm:schedule`, not `ncm:view`:
  declaring what "correct" means is a configuration-management
  decision, not a read.
* Fleet drift uses three queries total, not three per device.

**New**: `NcmBaseline` model, `app/services/ncm_drift.py`, four
endpoints (`GET /api/ncm/drift`, `GET /api/ncm/baselines`,
`PUT|DELETE /api/ncm/devices/{id}/baseline`), and a Drift Detection
page with per-status filtering, a baseline-designation modal driven by
the device's real archive history, and a direct link into the existing
diff view.

Thanks to the additive column migration added earlier this session,
the new table and columns are created automatically on upgrade -- the
exact failure that broke logins after the RADIUS change cannot recur
here.

**Verified**: drift status rules tested directly across all five
outcomes plus the summary split between drift and coverage gaps;
schema constructions and every `NcmBaseline` attribute reference
cross-checked via AST; 43 templates parse; the new page renders with
zero ID mismatches and valid scripts; the authorization regression
suite still passes; full project compiles.

**Phase 5+ (candidate config, deployment, approval, rollback) remains
unbuilt** -- deliberately. Those write TO devices, which is a
materially different risk class from reading and comparing, and they
deserve their own design pass rather than being appended here.

---

### Fixed — stale session cookie caused a silent login loop; RADIUS PAP delegation added

**The login loop, diagnosed from a real report.** A session cookie
signed with a PREVIOUS session secret (an upgrade, a restored install,
a rebuilt server) fails signature verification, so the page route
bounced to `/login` while leaving the bad cookie in place. The browser
then re-sent the same rejected token on every attempt: correct
credentials appeared to do nothing, while wrong ones correctly showed
an error — which points the user at their password rather than at the
cookie. The user found it themselves by clearing cookies manually,
which is not a diagnosis anyone should have to make.

New `web.auth_helpers.redirect_to_login()` deletes the session and
CSRF cookies on the way out whenever a token was present but did not
validate, so the loop breaks on the first bounce. Applied at all six
page-route modules; the root-path redirect for a genuinely logged-out
visitor is deliberately left alone, since there is no bad cookie to
clear there.

**RADIUS PAP delegation.** `password pap = login` is now emitted for
every user when RADIUS is enabled platform-wide, matching the upstream
sample where each RADIUS user carries both `password login = ...` and
`password pap = login`. That directive means "use the same credential
as the login password", so this adds a delegation and never a second
stored secret — no password is duplicated, re-encoded or weakened.

Emitted only when RADIUS is actually enabled: on a TACACS+-only
install the generated configuration stays byte-identical. Verified by
test in both states, including that the login password appears exactly
once.

**Documented rather than half-built:** profile `aaa.protocol == radius`
branching. The upstream sample sets vendor attributes like
`radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"`, but this project's
profiles are generated from Policies and Command Sets, which model
COMMANDS — there is no field in the policy model that maps to a RADIUS
AV-pair. Doing it properly means extending the policy model, not just
the compiler. The practical consequence is recorded in
`docs/RADIUS_FINDINGS.md`: RADIUS authentication works and devices get
their `radius.key`, but priv-lvl for a RADIUS session comes from the
device default rather than a NetOpsGuard policy.

**Verified**: full project compiles; 42 templates parse; the
authorization regression suite still passes; every consumer of the new
helper confirmed to import it; no unconverted login bounce remains
except the intended one.

---

### Fixed — TWO bugs: schema drift broke logins after upgrade; only_show denied shell authorization

**Bug 1 — logins broken after the RADIUS update. My regression.**

The RADIUS work added `radius_enabled` and `radius_secret_encrypted`
to the EXISTING `network_devices` table. `create_all()` creates missing
tables but cannot alter existing ones, so on an upgraded install those
columns were never created and every query selecting a device failed
with "column does not exist".

This is precisely the drift the installer's own
`check_schema_drift` was built to report two changes earlier -- and
reporting it was not enough, because the columns still had to be added
by hand before the application would run.

Fixed properly, in `app/database.py`: `init_db()` now runs
`_apply_additive_column_migrations()`, which compares model columns
against the live schema and adds what is missing. Scope is deliberately
narrow, because this runs unattended at startup against production
data:
* **ADD COLUMN only.** Never drops, never alters a type, never
  renames. A column in the database but no longer in the models is
  left exactly where it is -- removing it would destroy data nobody
  asked to lose.
* A NOT NULL column is added with its model default
  (`... NOT NULL DEFAULT false`). With no scalar default it is added
  NULLABLE and a warning logged, rather than failing: adding NOT NULL
  to a populated table without a default is an error that would take
  startup down.
* Every statement is `IF NOT EXISTS`, so re-running is a no-op.
* String defaults are quote-escaped.
* Any failure is logged, never raised -- a migration problem must not
  make the application unbootable.

**Bug 2 — `only_show` denied the initial shell authorization.**

Root cause exactly as diagnosed: `_policy_block` emitted

    if (cmd == "") { set priv-lvl = 15 }

with no `permit`. Setting a privilege level is not a decision, so the
empty `cmd` used for initial EXEC authorization matched none of the
`cmd =~` rules and fell through to the policy's `default_action` --
`deny` for any deny-by-default policy. Hence
`only_show deny shell` and "% Authorization failed." Reproduced
against the real generator before changing anything.

Fixed at the source (`app/services/config_compiler.py`), one line:
`permit` now closes the empty-cmd block. Emitted for EVERY policy
regardless of `default_action`, because denying the shell itself is
not something a command policy is meant to express -- a policy that
should not grant login is expressed by not applying it to that user,
not by silently failing their EXEC authorization.

**New `tests/test_policy_block_authorization.py`** -- the project had
no test suite at all. Written as a runnable script rather than pytest,
since neither pytest nor a suite exists here and a test that cannot be
run is worth nothing. It includes a small interpreter of the script
subset this compiler emits, so the tests assert on generated
BEHAVIOUR; string matching would pass just as happily on a config that
denies every login.

24 checks, all passing: initial EXEC permits with priv-lvl 15; six
allowed commands; eight forbidden commands; three prefix-confusion
cases (`showevil`, `exitnow`, `sshd_config` all denied); the
permit-inside-empty-block assertion; a permit-by-default policy; and
`service=ppp` not silently permitted.

**The test was verified to actually catch the bug** by reverting the
fix and re-running -- it reports `('deny', 15)` on initial EXEC,
reproducing the router's failure exactly.

**A bug in the TEST caught during the run**: the first interpreter
treated the `permit` inside the empty-cmd block as the trailing
default action -- they are textually identical lines -- and wrongly
permitted every forbidden command. Fixed by tracking brace depth. Worth
recording because a harness that permits everything would have
"passed" while proving nothing.

**Investigated, no change needed:** AD group names containing spaces.
Internal group names are already validated against
`^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$`, so a space cannot reach
`member == <group>` unquoted, and `ad_group_name` (which may contain
spaces) is never emitted into the configuration at all -- it is
resolved to an internal group before compilation. `ad_directory.py`
was correctly left untouched.

---

### Added — RADIUS GUI: device secrets and platform settings page

Completes the RADIUS feature end to end. Everything is driven by the
model and compiler built against the confirmed upstream sample; this
pass adds the surfaces to configure it.

**Device modal** gains a RADIUS section: a toggle and a secret field
that only appears when the toggle is on, so the form never implies it
will save something it won't. The secret field states plainly that it
is separate from the TACACS+ secret and never reused from it. On edit
it shows whether a secret is already stored without ever returning the
value -- the same treatment the TACACS+ secret already gets.

**Device API** carries `radius_enabled` and `radius_secret`.
`DeviceOut` exposes `has_radius_secret` as a boolean only; the secret
itself is never returned. Turning RADIUS off for a device CLEARS the
stored secret rather than leaving it encrypted at rest for a protocol
no longer in use.

**New RADIUS Settings page** (`/tacacs/radius`), superadmin-gated at
both the API and the page route -- enabling RADIUS opens daemon
listeners that did not previously exist, which is a platform change
rather than device administration. Verified that the nav entry is
hidden for a non-superadmin and shown for a superadmin.

It carries three things worth calling out:
* A **live preview** of the exact directives that will be added to the
  compiled configuration, mirroring `_radius_blocks` -- so an admin
  sees the real syntax before applying it, rather than trusting a
  checkbox.
* An explicit warning that **nothing changes on the daemon until the
  configuration is compiled and applied**, using the existing Apply
  workflow. The settings page does not pretend to open ports itself.
* A **"devices with RADIUS" count** that turns amber when RADIUS is
  enabled but no device uses it -- open listeners serving nothing is
  worth flagging rather than leaving to be discovered.

**Transport is UDP only**, and the page says why in plain terms:
upstream documents TCP, DTLS and TLS (RadSec), but their listener
syntax was not in the sample this was built against, so it is not
offered rather than guessed. Emitting a directive the daemon rejects
would take TACACS+ down with it.

Port validation rejects anything below 1025 (the daemon should not
need privileges it can do without) and rejects auth and accounting
sharing a port.

**Also added**: `require_superadmin` support to
`app.web.routes_tacacs._render`, which did not have it -- matching the
pattern already used in `routes_platform` and `routes_security`.
Sidebar search keywords for the new page.

**Verified**: 42 templates parse; both changed pages render with zero
ID mismatches; every extracted script passes Node syntax checks; nav
gating confirmed for both superadmin and standard admin; full project
compiles.

**Still deferred, unchanged**: RADIUS accounting parsing. The upstream
sample declares `log rad-acctlog` with no explicit `accounting
format`, so the default line layout remains unconfirmed and it gets
the same treatment as the TACACS+ authorization log -- not parsed
until the format is known from a real log.

---

### Added — RADIUS: real config generation (model + compiler), built against the confirmed sample

The full `tac_plus-ng-radius.cfg` sample from the real installation
answered every open question. Implemented against that syntax
verbatim, not inference.

**The key finding: `radius.key` lives in the SAME `host { }` block as
the TACACS+ `key`.**

    host world {
            address = 0.0.0.0/0
            key = demo
            radius.key = demo
    }

So one host block serves both protocols. No second device record, no
parallel host block, no separate realm -- which is why this needed
only two new columns on the existing device model rather than a new
device concept.

**Device model**: `radius_enabled` and `radius_secret_encrypted`
(nullable, reusing the existing Fernet mechanism). The RADIUS secret
is deliberately SEPARATE from the TACACS+ one: they are independent on
real equipment, and a device with RADIUS enabled but no secret stored
emits no `radius.key` at all rather than silently reusing the TACACS+
key -- that would put an existing secret on the wire over a protocol
the operator never chose for it.

**New `RadiusSettings` model** (singleton, matching AdSettings),
registered in `init_db()` in the same edit that created it. Disabled
by default: enabling opens listeners the operator did not previously
have, so it must be an explicit choice, never something an update
switches on.

**Compiler** now emits, all verbatim from the sample:

    listen = { port = 1812 protocol = UDP }
    listen = { port = 1813 protocol = UDP flag = accounting }
    log rad-accesslog { destination = ... }
    log rad-acctlog   { destination = ... }
    radius.access log = rad-accesslog
    radius.accounting log = rad-acctlog
    include = "$CONFDIR/radius-dict.cfg"

`flag = accounting` on the 1813 listener is in the sample and easy to
miss; without it the daemon cannot distinguish the accounting listener
from the auth one. Only `protocol = UDP` is offered -- upstream
documents TCP/DTLS/TLS, but their listen syntax was not in the sample
that was read, so it is left out under the same rule already applied
to IPv6 host addresses.

**When RADIUS is disabled every fragment is EMPTY**, so the generated
file is byte-identical to what this compiler produced before RADIUS
existed. An operator who never enables it sees no change whatsoever --
verified by test, not assumed.

**Verified by execution, asserted against the real sample syntax**:
disabled and no-settings-row both produce entirely empty output;
enabled produces every confirmed directive including
`flag = accounting`; dictionaries can be turned off; custom ports are
honoured; a TACACS+-only device is unchanged; a dual-protocol device
gets both keys in ONE host block; and a RADIUS-enabled device with no
stored secret correctly emits no `radius.key` rather than falling back
to the TACACS+ key.

**Also resolved and recorded** in `docs/RADIUS_FINDINGS.md`: one
daemon instance serves both protocols; existing users and profiles
apply unchanged, branching on `aaa.protocol == radius`; RADIUS PAP
needs `password pap = login` on the user.

**Still to build**: the per-device and settings GUI, `password pap`
emission, and profile `aaa.protocol` branches. **RADIUS accounting
parsing remains deferred** -- the sample declares `log rad-acctlog`
with no explicit `accounting format`, so the default line layout is
still unconfirmed, and it gets the same treatment as the TACACS+
authorization log: not parsed until the format is known.

---

### Confirmed — RADIUS capability verified on a real installation; findings recorded

The detector was run on a real server and returned confirmed evidence:
RADIUS is genuinely implemented (`config_radius.c`, `config_radius.h`,
`protocol_radius.h`), four daemon-side sample configurations ship with
the distribution, and real syntax was extracted verbatim.

**Confirmed syntax** now recorded in `docs/RADIUS_FINDINGS.md`:
RADIUS listeners (`listen { port = 1812 protocol = UDP }` and 1813 for
accounting), dedicated log targets (`radius.access log` /
`radius.accounting log`, distinct from the TACACS+ ones this project
already emits), and vendor dictionaries included via
`include = "$CONFDIR/radius-dict.cfg"` with `radius.dictionary`
blocks for Cisco, Fortinet, PaloAlto, Juniper, Microsoft, APC and
MikroTik.

**One finding worth flagging, because acting on it would have broken
things.** The keyword scan also returned `radius server radius-udp`,
`aaa group server radius radius-udp` and `server name radius-udp`.
Those are **Cisco IOS device-side configuration** -- what you put on a
switch to point it at this daemon -- not tac_plus-ng syntax. The
sample directory legitimately contains both. Emitting them into the
daemon's own config would produce a file it rejects, taking working
TACACS+ down. The sample-file list used for generation is therefore
restricted to the four daemon-side files by name, and the distinction
is documented rather than left as a trap.

**Still blocked on one thing, and it is the important one:** the
per-device RADIUS shared-secret directive. TACACS+ device blocks in
this project emit `key = ...`; the RADIUS equivalent inside a `device`
block was not in the extracted lines. Since this platform's entire
device model is built around per-device secrets, generation cannot
proceed correctly without it -- and inferring it from the TACACS+ form
is exactly the guess that has been avoided throughout.

Added `--dump` mode, which prints the four daemon-side sample
configurations in full. Isolated keyword lines proved capability but
cannot show block structure or distinguish daemon from device config;
reading the files whole settles all four remaining open questions at
once.

`docs/RADIUS_FINDINGS.md` records what is proven, what is explicitly
NOT daemon syntax, and the four open questions -- so the eventual
implementation is written against evidence rather than inference.

---

### Improved — RADIUS syntax discovery now reads the shipped docs and sample configs

The upstream README (supplied directly, since every relevant host --
github.com, raw.githubusercontent.com, projects.pro-bono-publico.de and
www.pro-bono-publico.de -- is blocked by this environment's egress
allowlist) confirms two things that change what is possible here:

1. tac_plus-ng really does implement RADIUS (UDP, TCP, DTLS, TLS) with
   PAP/CHAP/MSCHAPv1/MSCHAPv2 and downloadable ACLs.
2. **The distribution ships its own documentation in the top-level
   `doc/` directory, and sample configurations under
   `tac_plus-ng/sample/`.**

The second point is the useful one: the installer already clones that
repository to `/opt/aaa-platform/upstream/event-driven-servers` and
keeps it, so the authoritative RADIUS syntax is sitting on the
operator's disk. It never needed to come over the network.

`installer/radius_support.py` now reads those locations in priority
order -- shipped samples first, then `doc/` -- and QUOTES THE MATCHING
CONFIGURATION LINES VERBATIM rather than summarising them. A sample
config line is working syntax; a paraphrase of it is not, and would
reintroduce exactly the guesswork this module exists to avoid.

**Evidence is now graded, not pooled.** C-source string literals are
still searched, but only as a fallback, and a keyword found only there
sets `keywords_from_source_only`, which forces `syntax_confirmed` to
stay False. An internal C token is not proof of user-facing config
syntax, and treating the two as equivalent is how a plausible-looking
wrong directive would end up in a generated config.

Added a runnable entrypoint -- `sudo python3 -m installer.radius_support`
-- so the report can be produced on a real server in one command.

**Verified against a simulated checkout** containing a realistic
sample config, an HTML doc page and a C file: real syntax
(`radius.key = ...`, `protocol = radius-udp`,
`attr set RADIUS:Service-Type`) is extracted verbatim and
`syntax_confirmed` is True. And against a C-literals-only checkout:
support is correctly reported while `syntax_confirmed` stays False and
the weaker evidence is labelled as a lead to verify.

**Still not implemented**: config generation, per-device RADIUS
secrets, RADIUS accounting parsing and GUI. The gate has not moved --
it now just resolves itself the moment the report runs against a real
checkout.

---

### Added — RADIUS capability discovery (groundwork only; config generation deliberately NOT implemented)

Asked to implement RADIUS by reading the upstream repository's
documentation. **Network egress is blocked in this environment** --
both `github.com` and `raw.githubusercontent.com` return
"Host not in allowlist" -- so I could not read that documentation, and
therefore do not know tac_plus-ng's real RADIUS configuration syntax.

That matters more here than it would in most features. This project
generates a SINGLE configuration file that the running daemon loads.
Emitting invented RADIUS directives into it would not merely fail to
enable RADIUS: it would make the whole file unparseable and take
working TACACS+ authentication down with it. A guess here is a
production outage, not a cosmetic defect.

It is also against this codebase's own established practice.
`upstream_build` discovers build flags by running `./configure --help`
against the real checkout rather than hard-coding them, and
`config_compiler`'s comments record that the `host NAME { }` convention
was confirmed against real upstream examples before being emitted. I
applied the same rule rather than making an exception for a feature I
was asked for.

**What was built: `installer/radius_support.py`.** The installer
already clones the real upstream source to
`/opt/aaa-platform/upstream/event-driven-servers` and keeps it, so
capability can be established from the actual code on the operator's
machine instead of from assumption. It inspects, in order of
authority: `./configure --help` for real RADIUS build flags; the built
binary; RADIUS-related source files; and config-parser/documentation
keywords.

Two deliberate distinctions in the result:
* `supported` requires real RADIUS source files or parser keywords. A
  configure flag ALONE does not set it -- a flag can exist for a
  feature that is absent or partial in a given checkout.
* `syntax_confirmed` requires actual configuration keywords to have
  been extracted, and is the gate on emitting anything. Without it the
  correct report is "RADIUS present, syntax unconfirmed", not a
  generated config.

Verified across four cases including the two that matter: a configure
flag alone correctly does NOT report support, and real source files
correctly report support while still withholding
`syntax_confirmed`.

**Not implemented, and not stubbed:** RADIUS config generation,
per-device RADIUS secrets, RADIUS accounting parsing, and any GUI. All
of them depend on the syntax I cannot currently verify. Building the
data model and UI first would produce a feature that looks finished
and cannot work.

---

### Added — browser icon (favicon)

The app had no favicon at all, which is why Chrome showed a blank page
icon on every tab. Added `app/static/favicon.svg`, linked from
`base.html` so every page inherits it through the single shared head.

Deliberately the same shape and palette as the in-app brand mark: the
hexagon from `.brand-mark`, filled with the same signal-green
gradient. Colours are hard coded rather than referencing CSS custom
properties, because a favicon is fetched standalone by the browser
outside any stylesheet -- a `var()` reference would resolve to nothing
and render an invisible icon. A shield-and-check glyph sits inside the
hexagon: the bare mark is not recognisable at tab size, and the check
is stroked rather than filled so it survives downscaling to 16px
without its interior closing up.

Also added `apple-touch-icon` and a `theme-color` meta matching the
app background, so a mobile browser's UI chrome matches the app
instead of defaulting to white.

**Two XML bugs caught and fixed during validation**, both in the
explanatory comment rather than the artwork: an `-->` sequence
terminated the comment early, and `--signal-dim` contains a double
hyphen, which is illegal inside an XML comment. Either would have made
the file unparseable and the icon silently absent. Found by actually
parsing the SVG rather than eyeballing it.

**Verified**: the SVG parses as well-formed XML; no attribute contains
a `var()` reference (checked per-attribute, not by text search, since
the word legitimately appears in the comment); the gradient id is
correctly referenced; `/static` is confirmed mounted in `main.py`; the
installer copies the whole `app/` tree so the icon ships automatically;
and the link renders on dashboard, login, Security Center and NCM
pages.

---

### Fixed — literal "\\u2019" in dashboard text; Authorization Results now points at the right log

**Two bugs, one of them mine.** The dashboard was rendering a literal
`don\\u2019t` instead of an apostrophe. Cause: writing that template
through a Python heredoc double-escaped the sequence, so the browser
received the escape as text rather than a character. Fixed, then swept
EVERY template's rendered output for the same pattern -- zero other
instances.

**Authorization Results: investigated properly rather than trusting my
earlier conclusion.** I previously reported this as "not a bug -- the
counter correctly counts only records carrying a result field." That
was true but incomplete, and the incompleteness is what made the panel
useless.

Tracing the actual log configuration: `tac_plus-ng` is configured with
THREE log targets, and permit/deny decisions go to
`tac_plus-ng-authorization.log` -- a SEPARATE file. The accounting
log's `${result}` field is populated only on authorization accounting
events; session start/stop records leave it empty. So this chart was
reading the right field in the wrong file for what it claimed to show,
and on a deployment whose traffic is session accounting it will always
be empty no matter how much AAA activity there is.

The authorization log is deliberately NOT parsed by this project (its
exact file format was never independently confirmed -- see
`routes_tacacs_logs.py`'s own docstring), so the honest fix is not to
invent a parser to fill the chart. Instead the empty state now
explains that permit/deny decisions live in a separate log and links
to **Diagnostics**, which already serves that log's live tail.

Route verified before linking: an earlier draft pointed at
`/tacacs/logs`, which does not exist -- that would have shipped a dead
link. The real page is `/tacacs/diagnostics`, confirmed in
`tacacs_module.py` before use.

**Verified**: rendered output confirmed free of double-escaped
sequences across all templates; both link targets confirmed to exist;
the JS escapes confirmed to produce real em-dash and apostrophe
characters when executed; dashboard parses with zero ID mismatches;
scripts pass Node syntax checks; 41 templates and the full project
compile.

**Still open, honestly**: parsing the authorization log would let this
chart show real permit/deny counts. That needs a confirmed sample of
the file's actual line format from a live deployment -- guessing at it
risks silently mis-counting security decisions, which is worse than an
empty chart that explains itself.

---

### Changed — rebranded to NetOpsGuard; compliance control drill-down; README rewritten

**Rebranded to "NetOpsGuard — Network Operations & Security"** across
the sidebar, login page, all 41 page titles, in-app prose, README and
`docs/ARCHITECTURE.md`. Zero stale "NetworkAAA" or "AAA Platform"
references remain in the UI. As before, no Python module, database
table, API path or variable was renamed -- branding only.

**Compliance control drill-down.** Clicking any control in Security
Center → Compliance now opens a drawer showing the control's real
title from the framework mapping, per-device pass/fail/manual counts,
and every actual audit finding that determines its status -- grouped
as what is failing, what needs manual verification, and what passes.

The important part: **the descriptions and remediation shown are the
audit engine's OWN output for each check** -- its `why`,
`recommendation` and `fix_command` fields, already stored per finding.
Nothing is generated for the compliance view, and where a check has no
recommendation, nothing is invented in its place. Writing plausible-
sounding remediation text would have looked more complete and been
worth less than nothing on a compliance screen.

The mapping file is `check_id -> [controls]`, so the endpoint inverts
it to find which checks feed a given control. Verified against the
real ISO 27002 mapping: control 8.5 ("Secure authentication") resolves
to 16 real checks including AAA-02, PWD-04 and BOOT-08. Findings sort
failing-first, then manual review -- the order an operator works in.
Checks whose mapping marks them `supporting` rather than `direct` are
labelled as such, so a control failing on a supporting check isn't
mistaken for a direct violation.

Control rows are keyboard-operable (`tabindex`, `role="button"`,
Enter/Space) with a visible focus state, matching the finding rows
elsewhere in Security Center.

**README rewritten** with a new header, a capability table covering
all six areas the platform now spans (AAA, Identity, Security Center,
NCM, Network Operations, Operations), and an explicit note that it
runs on one host with no cloud service, external dependency or
telemetry.

**Verified**: new endpoint's schema constructions and every
`AuditFinding` field reference cross-checked via AST; mapping
inversion tested against the real ISO 27002 file; compliance page
parses with zero ID mismatches and valid scripts; branding confirmed
rendered with no stale references; README structure checked (20
sections, no duplicates, balanced markup); 41 templates parse; full
project compiles; CSS balanced and `[hidden]` sweep clean.

---

### Added — upgrade-aware installer: re-run detection, config preservation, schema drift reporting

Traced every install phase before writing anything, and the finding
was better than expected: `setup.py` was ALREADY largely re-runnable.
PostgreSQL provisioning checks whether the role exists and keeps its
password; the admin phase skips creation when accounts exist and
records a `reinstall` InstallEvent; the TLS and platform-settings
phases both guard on file existence; and `create_all()` never touches
existing tables or their data. AAA data, audit history, the NCM
archive, users, policies and devices all already survived a re-run.

Two real gaps closed, plus the missing signal to the operator.

**1. The one genuinely destructive step, fixed.**
`write_bootstrap_config()` called `write_text()` with no existence
check. On a re-run that file is almost certainly NOT the bootstrap
template any more -- it is the live configuration the compiler
produced from the operator's own devices, users and policies
(`config_compiler.apply_candidate` writes to the same path).
Overwriting it would silently discard a production AAA configuration
during what the operator asked to be an install, and the loss would
only surface when devices stopped authenticating. Now guarded by the
same existence check the TLS and settings phases already use, with a
new `--force-config` flag as the explicit opt-out for genuinely
wanting to reset a broken configuration.

Verified with a real temp file across all three paths: a fresh install
writes the template; a re-run PRESERVES a live config and warns; and
`--force-config` resets it.

**2. Schema drift reporting.** `create_all()` creates missing TABLES
but cannot alter existing ones -- so a new column on an existing table
(exactly like `AuditRun.batch_id`) is silently skipped on an upgrade,
and the application then fails at runtime with an obscure
"column does not exist" deep inside an unrelated query. The installer
now compares every model column against `information_schema` after
`create_all()`, names the exact tables and columns, and prints the
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements that would fix
it.

Deliberately REPORTS rather than APPLIES. Silently mutating a
production schema during an install is a bigger risk than telling the
operator plainly what needs to change, and the generated columns are
emitted as nullable regardless of how the model declares them --
adding a NOT NULL column to a table with existing rows fails without a
default, and inventing a default for someone else's production data is
not a decision an installer should make. Only additive drift is
reported: a column in the database but no longer in the models is left
alone, because dropping it would destroy data nobody asked to lose.

**3. Mode banner.** The installer now states up front whether this is
a "fresh install" or an "upgrade", and on an upgrade lists exactly
what is preserved. Detection is filesystem-only (the database
credentials file is the deciding signal) because this runs before the
app's dependencies are guaranteed installed; database-derived detail
is filled in later, and failure to query it is non-fatal.

**Verified**: install-state detection and drift reporting tested
directly; the `--force-config` flag traced through all seven links
from argparse to the file write; the config guard tested against a
simulated live configuration; full project compiles; 41 templates
parse.

**Not done, deliberately**: automatic migration execution. That is the
piece that actually needs care, and it belongs in its own reviewed
change rather than being bundled into an installer improvement. The
drift report is what makes the need visible in the meantime.

---

### Added — Score Explanation and Manual Review breakdown (closing the last Security Center gaps)

Re-checked the Security Center spec against what is actually built.
Sections 1-14 and 17-21 were already implemented across the earlier
phased work (gauge, KPIs, severity donut, domain chart, trend,
heatmap, risky devices, top risks, timeline, compliance, findings
workspace, detail drawer, device page, interface view, responsive
grid). Two sections had genuinely never been built, and those are what
this change adds -- rather than rebuilding what already works.

**§16 Score Explanation — "Why is the score what it is?"** Attributes
the gap between a perfect score and the actual one across domains:
each domain's shortfall (100 − its own score) weighted by its share of
all domains, so the parts sum to the real gap. Sorted worst-first,
each row deep-linking into that domain's findings.

Stated plainly in the panel and in code: this is an ATTRIBUTION of the
engine's own domain scores, **not a second scoring algorithm**. It
cannot be an exact deduction breakdown, because the engine's real
denominator (`applicable_weight`) is not persisted per domain, so
exact weighted deductions cannot be reconstructed from stored rows.
The API carries `is_approximate: true` and the UI says so in the
panel. Presenting the approximation as exact would have been the
easier and more impressive-looking option, and the wrong one.

Verified the attribution arithmetic: with real domain scores the parts
sum to the actual gap (100 − total deduction lands within 0.05 of the
mean domain score), all-perfect domains produce a zero deduction, and
all-zero domains produce exactly 100.

**§15 Manual Review breakdown.** A dedicated panel with the total and
a per-domain breakdown, each row deep-linking to
`?status=manual_review&domain=...`. Categories come from the domains
of REAL manual-review findings, never a fixed list. The panel states
outright that these are never counted as passing -- the spec's
explicit requirement that manual review must not visually read as
PASS.

**A forward-reference problem caught and fixed properly.** The new
schemas were initially appended AFTER `SecurityDashboardOut`, which
references them. With `from __future__ import annotations` that may
resolve at import -- but pydantic is not installed in this
environment, so I could not prove it does. Rather than ship something
unverifiable, the definitions were moved above their consumer, which
is unambiguously correct either way. Confirmed by index comparison and
a duplicate-definition check.

**Verified**: both `SecurityDashboardOut` construction sites (the
populated branch and the no-data branch) cross-checked via AST with no
missing or unknown fields; the Findings page confirmed to already read
both `status` and `domain` query parameters, so the new combined
deep-link genuinely filters rather than landing unfiltered; template
parses and renders both panels; zero ID mismatches; scripts pass Node
syntax checks; 41 templates and the full project compile.

---

### Added — NCM Configuration Compare: multi-device comparison, matrix and outlier detection

A new `/ncm/compare` page plus the real backend behind it. Every value
shown is computed from the ACTUAL stored configuration text of each
device's latest snapshot -- no sampling, no placeholder categories, no
demo data anywhere in the implementation.

**New `app/services/ncm_compare.py`.** A "category" (AAA, SSH, SNMP,
Logging, NTP, HTTP, Interfaces, Routing, ACL, Services) is a named set
of real Cisco IOS line patterns. For each device the matching lines are
extracted, normalised (trailing whitespace only -- LEADING whitespace
is significant in IOS, it marks sub-mode) and hashed. Devices sharing a
hash are running byte-identical configuration for that category.

That is a claim the code can prove. What it deliberately does NOT claim
is semantic equivalence: two different configurations that happen to
behave identically are reported as different, because proving otherwise
means modelling device behaviour. The UI says "identical", not
"equivalent", for exactly that reason.

**Deliberate correctness decisions, each a case where the easy
implementation would have lied:**
* Comparison is against the MAJORITY per category, not against
  whichever device was clicked first -- otherwise the answer to "which
  is the odd one out" would depend on click order.
* With no majority (two devices that differ, or an all-different set)
  NO outlier is named. Calling an arbitrary side "correct" would be a
  guess presented as a finding.
* An outlier is only named when it is UNIQUELY worst. On a tie there is
  no single odd one out.
* A category no device uses at all is dropped from the matrix rather
  than shown as an empty row -- an empty row implies something was
  checked and found absent, when nothing was checked.
* Fewer than two devices with snapshots returns "nothing was compared",
  NOT a 100%- or 0%-consistent result. A single device cannot be
  consistent with anything.
* Devices without a snapshot are returned explicitly in
  `devices_without_snapshot`, never silently dropped or counted as
  matching -- "we have never backed this up" is a finding.
* A line may belong to several categories (an interface ACL is
  arguably both). Categories are views over the configuration, not a
  partition, because forcing exclusivity would hide a line from a
  category an operator expects to find it in.

**New `POST /api/ncm/compare`**, gated on `ncm:diff` (the same
permission the two-version diff uses -- the same capability across
devices) with CSRF on the mutating call, capped at 50 devices so a
mis-click on "select all" cannot ask the server to diff a whole fleet
at once. Latest snapshots are fetched in ONE query, not one per device.

**The page**: device explorer with live search, group and
backup-status filters; multi-select by checkbox AND drag-and-drop into
the workspace (checkboxes are the accessible, keyboard-operable route
-- drag is an addition, never the only way to select); removable
device chips showing each device's archived version; consistency /
matching / differing / no-snapshot KPIs; the configuration matrix; an
outlier callout; and a raw diff pane that calls the EXISTING
`/api/ncm/diff` endpoint rather than adding a second diff
implementation. Matrix cells carry a text label ("match" / "differs" /
"absent") as well as colour -- a matrix read only by hue is unusable
for a colour-blind operator.

**Empty and failure states, each distinct**: no devices at all; no
device matching the filters; fewer than two selected; fewer than two
with an archived snapshot (naming which devices are missing one); a
403 stating it is a permission problem; and a general comparison
failure. Large selections show progress on the button and in the
results area rather than appearing frozen.

**Tested by execution — 8 comparison cases**: three identical devices
(100%, no outlier); a genuine outlier correctly identified with its
differing-category count and the HTTP category appearing only because
one device has it; two differing devices producing NO outlier; a
device with no snapshot excluded but reported; a single device
returning nothing-compared rather than a false 100%; an empty
selection; unused categories dropped; and a baseline selected from a
MATCHING device so "diff against baseline" doesn't compare one outlier
against another.

**Verified**: 41 templates parse; every existing NCM page (Overview,
Archive, Diff, Jobs, Schedules) and the Dashboard re-rendered and
re-syntax-checked to confirm nothing regressed; zero ID mismatches
across 22 references on the new page; all icon constants render real
SVG; new CSS classes present and brace-balanced; project-wide compile
and `[hidden]` sweeps clean; branding confirmed as NetworkAAA.

**Limitations**: categories cover common Cisco IOS syntax -- a line
outside those patterns still appears in the raw diff but not in the
matrix. Comparison reads archived snapshots only; it never contacts a
device, so an unreachable device simply has no newer snapshot rather
than failing the comparison.

---

### Fixed — "Building configuration..." truncation, product branding, Authorization Results

**Bug 1 root cause — SSH read loop, not the archive layer.**
`network_ops_execution._read_until_idle` stopped after 1.5 seconds of
silence. A Cisco device answers `show running-config` by printing
"Building configuration..." IMMEDIATELY, then going quiet for several
seconds while it renders the configuration. The reader returned during
that pause, so the banner WAS the entire captured output -- everything
downstream (cleanup, hashing, archive, diff) then faithfully stored and
compared a 25-byte string. Reproduced deterministically with a fake
shell replaying real IOS timing before changing anything.

**Fix: prompt-based completion detection.** New `_read_until_prompt`
returns when the device's own prompt reappears at the END of the
stream -- the device telling us it is finished. Silence is not that
signal. Specifics:
* The prompt regex is anchored to the tail, because a prompt-looking
  string can legitimately appear INSIDE a configuration (a banner, a
  description). Verified: a config containing `banner motd ^R2#^` is
  no longer truncated at that line.
* `--More--` is detected and answered with a space, so a device that
  ignores `terminal length 0` yields output instead of hanging.
* The idle window is kept only as a FALLBACK for prompts this regex
  cannot match, raised to 8s for configuration commands and left at
  1.5s otherwise -- so ordinary interactive commands stay responsive
  and a config dump is never truncated. Config commands are matched
  loosely (`sh run`, `show run`, `show startup-config`) since
  operators abbreviate.
* `_read_until_idle` is retained as an alias, so existing command
  execution keeps working unchanged.

**Driver cleanup improved**: strips the echoed command, the
"Building configuration"/"Current configuration : N bytes" chatter,
and the trailing prompt -- but never truncates on an unexpected line.
Losing real configuration is far worse than carrying one odd line into
the archive.

**Tested** (7 SSH-reader cases + 6 cleanup assertions, all executed):
the exact bug scenario now captures 15 lines where it previously
captured 1; the reader returns immediately on prompt rather than
waiting out the grace; the pager is stripped and answered; an
unmatchable prompt still returns via fallback instead of hanging;
prompt-like text inside a config is preserved; and abbreviation
matching is correct. A real device could not be reached from this
environment -- the fake shell replays real IOS output and timing,
which is what makes the root cause and fix demonstrable here.

**Bug 3 — Authorization Results was NOT a bug.** Traced it: the
counter only counts records carrying a `result` field, which is
correct. TACACS+ accounting records a permit/deny result on
authorization events; a log holding only session start/stop records
legitimately yields zero. The panel simply explained this badly. It
now states how many accounting records WERE read, that session
start/stop records don't carry an authorization result, and links to
AAA Health -- rather than showing an unexplained empty donut. No
counting logic was changed, because none was wrong.

**Bug 2 — branding.** Sidebar now shows "NetworkAAA" with the
subtitle "Network Security Operations Platform"; the login page
matches; 38 page titles rebranded from "AAA Management Platform" to
"NetworkAAA". Confirmed zero remaining product-name occurrences in
the UI. Per instruction, no Python module, database table, API path
or variable was renamed -- this was branding only.

**Verified**: all 40 templates parse; project compiles; dashboard and
sidebar render with the new branding and no stale name; extracted
scripts pass Node syntax checks; CSS brace-balanced with the new
brand classes present; `[hidden]` sweep clean.

---

### Completed — NCM device panel + docs; Dashboard rebuilt in the modern layout

**NCM device-page panel.** Added to `/security/devices/{id}` -- which,
confirmed by checking the routes rather than assuming, is the ONLY
real per-device detail page in this project. It uses the same device
id the rest of that page already has, so NCM references the existing
device record with no second lookup and no NCM-specific device table.
Shows status (healthy / never backed up / last backup failed), current
version, stored version count, last backup time and source, plus
Backup Now, View Configuration, History and Diff. The Diff link
appears only when the device actually has two versions, with a line
explaining why when it doesn't. After a backup it reports whether a
new version was archived or the configuration was unchanged.

**Documentation.** `docs/ARCHITECTURE.md` gains a full NCM section:
relationship to Network Operations and AAA, an explicit table of what
infrastructure is reused rather than duplicated, the data model, the
backup lifecycle including deduplication and failure isolation, the
driver abstraction, why the diff is text-based, how scheduling works,
the security model, RBAC, and a candid limitations list (Cisco-only,
retention stored but NOT yet enforced, no platform-wide audit-event
log, text diff only, single daily run time). README gains an NCM entry
in the feature table.

**Dashboard rebuilt** in the attached reference's layout: a hero
header, a five-card KPI row (devices, users, active sessions,
authorization success rate, and config-backup coverage), an AAA
Activity area chart, an Authorization Results donut with a centred
total and a clickable legend, live "active in the last 5 minutes",
service health, a Configuration Posture panel driven by NCM, quick
actions, and core build information.

`.dash-kpi` is its own component rather than a reuse of
`.status-card`: these are larger, carry a sub-line and are the first
thing read on the page -- reusing the compact card would have meant
either shrinking these or bloating every other page's cards.

**Three real field-name bugs caught by checking the API instead of
trusting the field names I'd written:**
1. Hourly activity returns `{hour: <ISO>, count: n}` -- I had written
   `hour_label`/`label`, which would have produced a chart with blank
   x-axis labels. Now parsed and formatted as a local time.
2. Recent activity returns `event_count` and `last_seen` (ISO) -- I
   had written `events` and a non-existent `last_seen_human`, which
   would have shown "—" in both columns for every row.
3. `/api/system/status` returns `database` as a plain STRING
   ("connected") and each service with systemd's own `active_state`,
   not booleans. My original code would have reported every service
   and the database as down even when perfectly healthy.

All three were found by reading the actual endpoints and service
functions rather than assuming, and every remaining key used
(`distinct_devices`, `distinct_users`, `permit_count`,
`non_permit_count`, `sessions`, `build_info`, `os`) was verified the
same way.

The Authorization donut keeps the no-data behaviour fixed earlier: one
neutral-grey segment labelled "No data yet", never a full green ring
that would read as 100% permit when nothing was recorded. Service
health carries a text state as well as a colour dot. The NCM posture
panel distinguishes "no permission" from "error" -- a 403 is a
permission outcome, not a failure.

**Verified**: dashboard parses, zero ID mismatches, all nine icon
constants render real SVG, scripts pass Node syntax checks; NCM device
panel renders and passes the same checks (zero mismatches across 34
references); project-wide compile, 40 templates, `view_scripts` and
`[hidden]` sweeps all clean; CSS brace-balanced with every new class
confirmed present.

---

### Completed — NCM GUI: Overview, Archive with viewer, Diff, Jobs, Schedules

NCM is now usable end-to-end from the browser. Five pages, all built
on the platform's existing shell, modal, drawer, table, KPI-card and
toast conventions -- NCM reads as a native section, not a bolted-on
app.

**Overview** -- six KPI cards (managed devices, recent backup, failed,
never backed up, stored versions, last successful backup), recent
configuration changes, recent jobs, and a per-device backup status
table. "Backup Now" opens a device picker with search and
select-all-shown, and a configuration-type choice (running, startup,
or both).

**Configuration Archive + viewer** -- filterable by device, type and
free text (device name or hash). The viewer opens in a drawer with
line numbers, in-configuration search that reports a match count,
copy, and download. Content is fetched ONCE per snapshot and held for
search/copy/download, so searching a large configuration does not
re-request it. Line numbers are `user-select: none`, so copying the
configuration doesn't drag them along with it.

**Diff** -- device plus from/to version selectors, defaulting to
previous -> current (the comparison actually asked for most often),
plus an explicit "Current vs Previous" action. Added/removed counts as
KPI cards and a unified diff where every changed line carries a `+`/`-`
marker as well as colour, so the change is readable without relying on
hue. With fewer than two versions it states "No previous configuration
available" rather than fabricating a comparison against nothing.

**Backup Jobs** -- job list with status KPIs, and a detail drawer with
per-device results. Failures report connection and retrieval
separately ("could not reach the device" vs "connected but no config
came back" are different problems with different fixes), and successes
distinguish "new version archived" from "unchanged — nothing
archived".

**Schedules** -- full create/edit/delete with device AND device-group
target pickers, daily run time, configuration types, retention, and an
enabled toggle. Delete asks for confirmation and states plainly that
archived configurations are not affected.

**Verified**: all five templates parse with correct block structure
and balanced `<main>` tags; zero ID mismatches across 60 references;
every extracted script passes Node syntax checks; the
`/api/device-groups` endpoint the schedules page calls confirmed to
exist rather than assumed; new CSS classes confirmed present and
brace-balanced; project-wide compile, template (40), `view_scripts`
and `[hidden]` sweeps all clean.

One check flagged `ncm_schedules` as having "no rendered SVG" -- that
was my own check looking for the JS-constant icon pattern, which that
page legitimately doesn't need since it builds no icons client-side.
Confirmed by direct inspection: 12 real SVGs render inline.

**Remaining NCM work**: the device-page NCM panel, and
README/ARCHITECTURE documentation.

---

### Added — NCM API layer, module registration and navigation

Builds on the NCM backend foundation below. The subsystem is now
registered as a first-class platform module and reachable over HTTP;
the GUI templates are the remaining piece.

**15 endpoints** (`app/api/routes_ncm.py`), following this project's
existing conventions -- `require_permission` on every endpoint,
`verify_csrf` on every mutating one, Pydantic response models, safe
error messages:
overview, device status, configuration list/detail/download/delete,
per-device history, backup, diff, job list/detail, and schedule
list/create/update/delete.

**Deliberate API design choices:**
* List responses NEVER include `configuration_content`. Shipping
  hundreds of full device configurations to render an archive table
  would be slow and needless; content is fetched per snapshot.
* `ncm:download` is a separate permission from `ncm:view` -- taking a
  full device configuration off the platform as a file is a
  higher-trust action than reading it in the UI.
* The download filename is built by stripping the admin-supplied
  device name to alphanumerics, hyphens and underscores, so a device
  name cannot inject header content or path separators.
* Backup with no targets is rejected rather than defaulting to the
  whole fleet -- an accidental empty selection SSHing into every
  device would be an expensive surprise.
* Schedule target ids are validated at create/update time, so a
  malformed id surfaces immediately rather than at 02:00 when the
  schedule runs.

**A bug caught in review before it shipped:** the diff endpoint's
lookup was written as `{c.id: c in rows and c for c in rows}` -- a
convoluted way of writing `{c.id: c}` that would also have misbehaved
when comparing a version against ITSELF, since the query returns a
single row for a repeated id. Simplified to a plain dict, which
handles that case correctly.

**Module registration** (`app/modules/ncm_module.py`, `web/routes_ncm.py`)
mirrors the Security Center module exactly, so NCM gets navigation,
module state and RBAC through existing machinery rather than as a
bolted-on section. New sidebar section "Config Management" with five
entries, plus Ctrl+K search keywords for each path.

The spec's suggested "Templates" and "Compliance" nav entries are
deliberately NOT registered: nav leading to an empty page is the fake
UI the brief rules out, and they belong with the phases that
implement them.

**Two wrong assumptions caught by checking rather than trusting:** the
web route module initially imported `current_admin_or_none` from
`..services.admin_session` and a shared `..templating.templates`.
Neither exists -- this project puts the first in `web.auth_helpers`
and constructs `Jinja2Templates` per web-route module. Corrected to
the real structure, then every imported name verified to exist.

**Verified**: full project compiles; all 15 routes registered; every
model attribute reference and schema construction cross-checked
against the real definitions via AST (including inherited schema
fields and `**spread` constructions); the NCM nav section confirmed to
build with all five entries via the isolated sidebar test.

**Still not built**: the five GUI templates (Overview, Archive with
configuration viewer, Diff, Jobs, Schedules), device-page NCM panel,
and README/architecture documentation. The API is complete and
callable but has no pages yet.

---

### Added — NCM backend foundation (models, drivers, archive, diff, backup engine, scheduler, RBAC)

Per the spec's own instruction, inspected the real repository before
writing anything. What that found, and what is therefore REUSED rather
than rebuilt:

* **SSH execution** -- `network_ops_execution.run_commands_on_device`
  already handles connection, interactive shell, paging, prompt and
  timeouts. NCM's driver layer wraps it; there is no second paramiko
  implementation anywhere in NCM.
* **Bounded concurrency** -- `ThreadPoolExecutor`, the same mechanism
  `run_job` already uses, not one thread per device.
* **Device groups** -- resolved through the existing
  `NetworkDevice.device_group_id`; no NCM-specific grouping table.
* **Credentials** -- the existing encrypted service account
  (`AuditScheduleSettings` + `app.security` Fernet helpers). No second
  credential vault, and no credential is stored in, logged by, or
  returned from any NCM table or code path.
* **Scheduling** -- the asyncio background-loop pattern already
  established for scheduled security audits. No Celery/Redis/broker
  introduced.

One finding worth stating plainly: **there is no generic audit-event
model in this project.** Rather than invent one as a side effect of
NCM, the audit trail lives in the NCM job and target records
themselves (who, what device, what type, when, result, changed-or-not,
sanitised error). A platform-wide event log is a real piece of work
that deserves its own change, not a half-version smuggled in here.

**New models** (`app/models/ncm.py`, all additive, registered in
`init_db()` in the same edit that created them): `NcmConfiguration`
(immutable snapshot: version, type, content, sha256, size, source,
created_by, job_id), `NcmBackupSchedule`, `NcmBackupJob`,
`NcmBackupJobTarget`.

**Deduplication design.** A snapshot is written only when its SHA-256
differs from that device's most recent snapshot OF THE SAME type --
but a `NcmBackupJobTarget` row is written every time regardless, with
a `configuration_changed` flag. That is what keeps "backup executed,
configuration unchanged" distinct from "configuration changed"
without accumulating an identical row nightly, and without losing
backup history. Comparison is against the latest snapshot only, not
all history: a config that changes and reverts is a real event that
must not be silently swallowed.

**Version numbers are per device AND per configuration type**, so
running-config and startup-config each have their own sequence --
otherwise "version #184" is ambiguous about what it versions.

**Driver abstraction** (`ncm_drivers.py`) owns only the vendor-specific
part: which command retrieves which config, and output cleanup. Only
`CiscoIOSDriver` is implemented; empty subclasses for untestable
vendors would be fake structure, not architecture. A driver simply
omits a type it does not support, which is how "not every device has
both" is represented without a flag.

**Diff is honest text diff.** No semantic network meaning is claimed,
because this implementation cannot prove it. "Changed" is not reported
as a third count: in a line diff a modification genuinely is a removal
plus an addition, and pairing them up would be a heuristic presented
as fact.

**Six RBAC permissions** (`ncm:view/backup/download/diff/schedule/
delete`), split finely because reading an archive, downloading raw
config, opening an SSH session and deleting history are different
levels of trust. Deliberately NOT auto-granted to existing roles.

**Verified by execution, not inspection**: driver tested against four
paths (success with echoed-command stripping and paging preamble,
connection failure, connected-but-empty, unsupported type) using a
stubbed SSH layer; SHA-256 correctness and stability; diff across
seven cases the spec names (changed line, identical, empty-to-content,
content-to-empty, empty-vs-empty, pure addition); deduplication across
four cases including a device selected directly and via two groups;
job status rollup across five cases including partial success and a
device that succeeds on one config type but fails another; scheduler
timing across six cases including an unparseable time; and
comma-separated id parsing including malformed entries. Every model
field reference and constructor kwarg cross-checked against the real
schemas via AST. Full project compiles.

**Not yet built** (next step, not claimed as done): NCM API routes,
schemas, GUI pages (Overview, Archive, Viewer, History, Diff, Backup
Jobs, Schedules), device-page integration, nav registration, and
README/architecture documentation. The backend is complete and tested
but is not yet reachable from the browser.

---

### Completed — dashboard visual language now on every remaining section

Finished converting the pages listed as outstanding last pass. Every
one uses the shared `AAAPlatform.kpiCard` helper rather than its own
copy, so the cards stay identical across sections by construction.

**AAA Health** -- five cards (records in tail, last hour, devices,
users, permit rate) added ABOVE the existing detail panels rather
than replacing them: those readouts carry breakdowns (parsed vs
unparsed, by accounting type) that a card row genuinely can't, so
replacing them would have lost real information. The permit-rate card
colours itself by threshold and reads "—" with a "no authorization
records" sub-label when there is nothing to divide by, rather than
showing a misleading 0%.

**Network Operations → Jobs** -- total / completed / in-flight /
failed-or-partial, counted using the exact status vocabulary
`statusBadge()` already maps (COMPLETED, PARTIAL, FAILED, RUNNING,
PENDING, CANCELLED) rather than a parallel guess at what the API
returns.

**Users** -- total, enabled, disabled, and an Active Directory count
with the local count as its sub-label.

**Groups** -- total groups, total memberships (summed from
`member_count`), and how many are referenced by a policy with the
unreferenced count alongside, which is the number worth noticing.

**Devices** -- total, enabled, disabled, and device groups with the
distinct vendor count as a sub-label.

**Policies** -- total, enabled, disabled, and default-permit count
with "with conditions" alongside.

Every field used was confirmed against what each page's own row
rendering already reads (`enabled`, `auth_source`, `vendor`,
`member_count`, `has_condition_tree`, and so on) rather than assumed
from the field name.

**The stale-KPI bug found in Accounting last pass was checked for on
every page converted here**, and fixed in the two that had it: AAA
Health and Network Ops Jobs both replace their content with an error
message on failure, which would have left the previous load's counts
sitting above it describing data no longer on screen.

**Verified**: all eight converted pages parse, render with both a KPI
grid and real rendered SVG icons present in the output, and have zero
ID mismatches (248 references checked across them); every extracted
script passes Node syntax checks; the permit-rate maths tested
separately across 6 explicit cases plus a 961-combination range check
confirming it never leaves 0-100 or mis-thresholds; and project-wide
compile, template, `view_scripts` and `[hidden]` sweeps are all
clean.

**Remaining pages deliberately not converted**: Diagnostics,
Effective Access, Policy Simulator, Command Sets/Categories, Network
Ops Templates/Checks/Audits and Config. These are input-driven tools
and editors rather than status views -- a KPI row above a form or a
one-shot diagnostic would be decoration, not information. Export
Report remains unimplemented per instruction.

---

### Started — extending the dashboard visual language across the whole platform

Request: bring the card/chart/visualisation language the Security
Center now uses to every section of the platform. Started with the
shared foundation plus two pages, rather than touching a dozen
templates in one unverified sweep.

**Generalised the shared visual primitives.** The bar-row and
inline-bar components were named `.sec-*` because they were built for
Security Center. Rather than leave every other section using
Security-Center-prefixed classes (or duplicating the CSS under new
names), each rule now carries a neutral alias alongside its original
selector -- `.bar-row, .sec-bar-row { ... }` and so on. Existing
Security Center templates keep working untouched; new pages use the
neutral name.

**New shared helpers in `app.js`**: `kpiCard`, `kpiGrid`, `barRow`,
`scoreColor`, plus `escapeHtml`/`cssVar`. Every page adding KPI cards
was otherwise going to redefine the same helpers inline, which makes
the visual language "consistent until someone tweaks one copy".
Defining them once means a change to card markup lands everywhere at
once. `kpiCard` takes the same `is-signal`/`is-amber`/`is-red` state
classes `.status-card` already defines rather than inventing a
parallel vocabulary, and renders as a link when given an `href` --
which is how the Security Center KPIs deep-link into filtered views.

**Sessions** now leads with five KPI cards (active sessions, total,
unique users, devices seen, commands logged), all counted from the
sessions actually loaded, so the summary can never disagree with the
table beneath it.

**Accounting** leads with four (matching records with the in-log
total as a sub-label, unique users, devices seen, commands), counted
from the records returned for the current filter rather than a wider
unfiltered set.

**A real bug caught while wiring Accounting:** its load path replaces
the table with a "Loading…" or error message, but the KPI row would
have kept displaying the *previous* query's numbers -- counts sitting
above a table that no longer contains them, which is worse than
showing nothing. The KPI row is now cleared on the same path.

**Verified**: the shared helpers tested directly against 13 cases --
state classes applied, link-vs-div rendering, HTML escaping of both
label and value (including a `<script>` payload), optional sub-label
present/absent, grid wrapping, distinct score thresholds, and bar
percentages clamped above 100, floored at 2% so a zero bar stays
visible, and NaN-safe. Both templates parse, zero ID mismatches, icon
constants confirmed to render real SVG, scripts pass Node syntax
checks, CSS brace-balanced, and project-wide compile / template /
`[hidden]` sweeps clean. The `[hidden]` sweep was also fixed to
handle multi-selector rules, which the new comma-separated aliases
introduced.

**Still to convert**: AAA Health, Diagnostics, Network Operations
(jobs/templates/checks/audits), Users, Groups, Devices, Policies and
Effective Access. Export Report remains deliberately unimplemented
per instruction.

---

### Changed — audit by device selection; Devices page rebuilt with filters and bulk audit

Direct request with reference screenshots: make "Run Security Audit"
pick devices/groups rather than take pasted config, give the Devices
page filters and multi-select so an admin can audit a chosen set as
one job, and bring both closer to the attached designs.

**New `POST /api/security/audit/bulk`** audits a chosen set of
devices as one job, producing a single numbered Audit Report through
the same pipeline and batch model the scheduled fleet job already
uses -- a narrower device list, not a second implementation. Gated on
`security:audit` rather than `security:view`, since it reaches out and
touches real devices. It uses the platform's stored audit service
account for SSH rather than prompting per run (that account exists
precisely so bulk auditing needs no per-device credentials), and if
none is configured it fails with a message pointing at where to set
one up instead of silently auditing nothing.

**`run_scheduled_audit` gained optional device selection.**
`device_ids=None` keeps the daily job's existing fleet-wide behaviour
untouched; a supplied list narrows it. The list is still filtered by
`enabled`, so a selection containing a disabled device audits the
rest rather than failing the whole job -- the caller chose devices,
not a guarantee every one is currently auditable. An empty selection
is rejected at the schema rather than silently meaning "everything":
an accidental empty list auditing the entire fleet would be a
genuinely surprising and expensive outcome.

**Fixed a concurrency bug while wiring this up.** The bulk endpoint
first reported its report number by querying for "the most recent
batch" -- which is wrong the moment anything runs concurrently, since
a scheduled run finishing mid-request would hand the caller someone
else's report number. `ScheduledAuditResult` now carries the number
of the batch it actually created, so the endpoint reports its own
result rather than whatever happens to be newest.

**Devices page rebuilt**: four summary cards (total / healthy / at
risk / not audited), four filters (search across name and IP, group,
audit status, risk level), per-row and select-all-visible checkboxes,
a selection bar that appears only when something is selected, and a
"Run Audit on Selected" action. Rows now carry a device icon, group,
a status badge and an inline score bar, matching the attached
reference. Risk classification uses the six values
`scoring.risk_level()` genuinely returns -- Critical/Severe/High
count as at-risk -- not the usual three.

**Run Security Audit is now a device picker.** The modal lists real
devices with search and group filtering, select-all-shown and clear
actions, a live selection count, and a scrolling list so a large
fleet can't push the Run button off screen. The old paste-config
textarea is gone from the Overview; pasting a config by hand remains
available on each device's own page, and the modal says so rather
than leaving that capability seemingly removed.

**Verified**: device filter logic tested across 10 cases (each filter
alone, search by name and by IP prefix, combinations, and a
contradictory combination expecting zero) plus the summary counts;
schema constructions cross-checked via AST (no missing or unknown
fields); the permission name confirmed to exist in the permissions
registry rather than assumed; zero stale references to the removed
textarea fields; templates parse with correct block structure and
zero ID mismatches across 28 and 10 references respectively; all icon
constants confirmed to render real SVG; every new CSS class and
variable confirmed to exist; scripts pass Node syntax checks; and
project-wide compile / template / `[hidden]` sweeps all clean.

**Not done in this pass**: the reference dashboard's Findings Trend
multi-series chart and Export Report menu. Export remains the one
unimplemented item from the earlier brief.

---

### Added — Audit Activity timeline (Phase 9) and accessibility/responsive pass (Phase 10)

This completes the 10-phase Security Center redesign.

**Phase 9 — Audit Activity timeline.** New
`GET /api/security/activity` returns recent audit runs, newest first,
one event per real stored `AuditRun` -- the timeline never synthesizes
entries. `score_delta` compares each run against that SAME device's
own chronologically-previous completed run, so "+8" means the device
improved by 8 since its last audit, not that it differs from a fleet
average. Runs with no comparison point (a device's first audit, or a
failed run with no score) get a null delta and the GUI renders no
arrow rather than implying a trend that doesn't exist. Deltas are
computed in one pass over all runs rather than a per-row lookup,
avoiding the N+1 pattern.

Rendered on the Overview as a real `<ol>` so the sequence is conveyed
to screen readers, not only visually by the connecting line. Fetched
in its own request rather than bolted onto the dashboard payload: it
is a different shape of data (a time-ordered log, not current
posture), has its own limit, and keeping it separate means a slow or
empty activity query can't delay the posture widgets from rendering.

**Phase 10 — audited rather than assumed.** Checked responsive
behaviour and accessibility against what the stylesheet actually
contains:
- Dashboard grids already collapse to one column at 1100px, tables
  already scroll horizontally at 640px, and the drawer already sizes
  to `min(94vw, 540px)` -- all verified in the CSS, no change needed.
- Clickable finding rows already carry `tabindex` and `role="button"`
  with Enter/Space handlers; icons are already `aria-hidden`;
  icon-only close buttons already carry `aria-label`. Confirmed by
  scanning every template, not assumed from memory.

**One real, app-wide accessibility bug found and fixed:** inputs,
textareas and selects had `:focus` styling, but **buttons and links
had no focus indicator anywhere in the stylesheet**. A keyboard user
tabbing through any page in the entire application -- not just
Security Center -- had no visible indication of where they were.
Fixed with a single global `:focus-visible` rule covering `button`,
`a`, `[role="button"]` and `summary`, declared once so it also covers
components added later. `:focus-visible` rather than `:focus` so the
outline appears for keyboard navigation without ringing every mouse
click.

**Verified**: the per-device delta logic tested against 5 real cases
covering a device's first audit (null), a genuine improvement, a
decline where an intervening failed run is correctly skipped, a
single-audit device, and a scoreless run -- plus explicit
confirmation that one device is never compared against another.
Schema construction cross-checked via AST (no missing or unknown
fields). Template parses, zero ID mismatches across 24 references,
timeline markup confirmed present in rendered output, scripts pass
Node syntax checks, CSS brace-balanced with every new class
confirmed to exist, and full project-wide compile / template /
`view_scripts` / `[hidden]` sweeps all clean.

**All 10 phases are now complete.** Findings export (CSV/PDF/JSON)
remains the one item from the original brief that was never
implemented -- it was listed as optional there and is genuinely not
started, not partially built.

---

### Added — fleet-wide Compliance page (Phase 8)

**New `GET /api/security/compliance`** aggregates every stored
per-control result across each device's own most recent completed
audit -- built on the same `_latest_completed_runs_by_device` basis
every other Security Center view uses, so compliance posture can't
disagree with what the Overview or Findings pages report.

**Worst-status-wins per control**, deliberately: a control that fails
on any audited device is a failing control for the fleet, regardless
of how many devices pass it. Reporting it any other way would let a
real gap disappear behind an average. `devices_passing` /
`devices_failing` / `devices_manual` count DEVICES rather than
findings, since "this control fails on 3 devices" is the number an
auditor actually asks about.

**Framework display names come from the mapping files' own
`framework_name` field** ("NIST SP 800-53 Rev. 5", "ISO/IEC
27002:2022", "CIS Cisco IOS XE 17.x Benchmark v2.1.0", "DISA STIG --
Cisco IOS Switch L2S / Router RTR") rather than a hardcoded lookup in
the API layer, so adding or renaming a framework needs no change
here. Verified those names by reading the four mapping files
directly, not assumed.

**Frameworks with no stored results are omitted entirely** rather
than rendered at 0%. "Not assessed" and "assessed and failing" are
genuinely different states, and showing the former as the latter
would be a real misstatement of posture -- exactly the kind of
fabricated-looking data the redesign brief rules out.

**The page** shows each framework as a card with its percentage,
progress bar and control counts, expanding on demand into a
per-control table (control ID, status badge, and device counts for
failing/passing/manual). Controls are sorted worst-first, so failing
controls are the first thing visible without scrolling. Status is
carried by a labelled badge, never colour alone.

**Verified**: the worst-status-wins classifier tested against 6 real
cases including the two orderings that matter (a single failing
device outranks five passing ones; a failing device outranks manual
review), and the percentage math against 5 cases plus a
900-combination range check confirming it can never fall outside
0-100. Schema constructions cross-checked against their definitions
via AST (no missing or unknown fields), every referenced name
confirmed resolvable at module level, the new nav entry confirmed to
render in the right position, template parses with correct block
structure and zero ID mismatches, scripts pass Node syntax checks,
and project-wide compile / template / `view_scripts` / `[hidden]`
sweeps all clean.

**Remaining (Phases 9-10)**: audit activity timeline, and the final
responsive/performance/accessibility polish pass. Findings export
remains unimplemented.

---

### Wired the interface engine into the audit run — Phase 7 now real, not deferred

Explicit product decision given: interface results belong in the SAME
audit run. That was the exact question `run_device_audit`'s own
docstring had been holding open, so this closes it rather than
working around it.

**On the two GitHub repositories referenced**: no network access is
available in this environment, so neither could be fetched -- but
neither needed to be. Both engines were migrated into this project in
earlier sessions and verified byte-identical against their originals
(`cisco-ios-security-auditor` -> `security_center/checks/*` +
`parser/cisco_config.py`; `cisco-interface-security-audit` ->
`checks/interfaces.py` + `parser/interface_config.py`). The work here
was never "port the repos" -- it was wiring the already-migrated
interface engine into the audit flow and building the GUI over its
real output.

**`run_device_audit` now runs both engines** over the same raw config
and merges their findings. Interface findings flow through the
existing `to_unified_findings()` adapter, so they arrive as the same
unified `Finding` type and need no special-casing anywhere
downstream -- scoring, correlation, compliance mapping and
persistence all just work. They carry an `Interface Security / *`
domain prefix and a non-null `interface_name`, which is what lets the
GUI separate per-port results from device-wide ones without a second
query or a parallel storage path. `interface_name` was already
persisted, so no migration was needed for the findings themselves.

**New `run_interface_checks()` helper** with deliberate failure
isolation at two levels: a config the interface parser chokes on
degrades to "no interface findings" rather than failing the whole
audit and losing the device-level results the user actually asked
for, and one bad interface doesn't drop every other interface's
results. Both failures are logged, not silently swallowed.

**Phase 7 GUI is now real.** The Device Security page's Interface
Security section shows Interfaces / Secure / Warning / At Risk
counts and a clickable port grid; each port displays its name and
failing-check count as text (never colour alone), and clicking one
opens that port's own findings in the same drawer component every
other finding uses -- so evidence and remediation read identically
wherever the user arrived from. Ports are real `<button>` elements
with hover and focus-visible states, so the grid is keyboard-operable.

**Verified by actually running the pipeline, not by inspection:**
- End-to-end against a real multi-interface config: 125 device-level
  findings + 14 interface-level findings, correct `Interface
  Security /` domain prefixes, correct per-interface attribution.
- Graceful degradation confirmed against three hostile inputs -- a
  config with no interfaces at all, a completely empty config, and
  non-Cisco garbage text. All three still return a full device-level
  audit rather than raising.
- Interface grouping logic tested independently: per-interface
  fail/warn/pass tallies, worst-failing-severity selection (a
  critical correctly outranks a medium on the same port), and the
  secure/warning/at-risk classification.
- Plus the usual: templates parse, zero ID mismatches across 32
  references, scripts pass Node syntax checks, CSS brace-balanced,
  and project-wide compile / `view_scripts` / `[hidden]` sweeps all
  clean.

**Still not started (Phases 8-10)**: expanded Compliance page, audit
activity timeline, and the final responsive/performance polish pass.
Findings export remains unimplemented.

One consequence worth stating plainly: because interface findings now
join the scored denominator, device scores will shift for
interface-heavy configs compared with audits run before this change.
That is correct -- the score now reflects interface posture too --
but historical runs were scored without them, so a score drop
immediately after this change may be the new coverage, not a
regression in the device.

---

### Redesigned — Device Security page (Phase 6); Phase 7 investigated and deliberately not built

**Phase 6 done.** The Device Security page is now graphical: a radial
score gauge (same verified arc math as the Overview), seven KPI cards
(critical/high/medium/low/manual-review/passing/total checks computed
from that device's own findings), horizontal domain-score bars sorted
weakest-first with per-domain failing/passing/manual counts beneath,
a compliance panel, and a findings table wired to the same Finding
Detail Drawer built in Phase 5 -- so a finding opens identically
whether reached from the fleet-wide Findings page or a single device.

**The Run Audit form moved into a modal**, matching what the Overview
already does. All submit logic is preserved verbatim -- same two
endpoints (live SSH and paste-config), same payloads, same validation
and error handling, same Live-SSH/Paste-Config mode toggle including
the `btn-with-icon` class-reapplication those buttons need because
they replace their own className wholesale.

**Compliance percentage** is derived from the `total`/`fail` the
backend already computes (share of referenced controls not failing),
not a second scoring rule invented in the browser. Verified with 6
explicit cases plus a 210-combination range check confirming it can
never fall outside 0-100.

**Phase 7 (graphical switch/interface view): investigated, and
deliberately NOT built.** The spec scopes this to "where the backend
data supports it" and forbids fabricating data. It does not:
`app.security_center.engine.orchestrator` explicitly does not run the
interface engine (its own docstring documents that as a deferred
product decision), and `to_unified_findings()` -- the only path that
converts interface checks into storable findings -- is never called
anywhere in the application; grepping the whole codebase returns only
comments mentioning it. So no interface-level finding is ever
persisted, and a switch/port panel today could only show invented
ports. Instead the page renders a real per-interface summary
(interface count, how many have findings, and a port grid with each
port's failing-check count) that appears ONLY when findings carrying
an `interface_name` actually exist, and stays hidden entirely
otherwise. When the interface engine is wired into the audit flow,
that section will populate itself with no further frontend work.

**Two real bugs caught by the project-wide `[hidden]` sweep, in code
written this same pass:** the new "Run New Audit" button
(`.btn-with-icon`) and both dashboard rows (`.sec-grid`) are hidden
until their data loads, but both classes set a `display` value, which
beats the browser's own `[hidden] { display: none }`. All three would
have flashed visible and empty on every page load. This is the third
time this bug class has appeared in this project; the sweep is now
part of the standard verification run precisely because it keeps
catching real instances. Fixed at the CSS level and re-swept: zero
problems project-wide.

**Verified**: template parses with correct block structure; zero ID
mismatches across 32 references; all four icon constants confirmed to
render real SVG; every new CSS class confirmed to exist; scripts pass
Node syntax checks; full project-wide compile, template,
`view_scripts` and `[hidden]` sweeps all clean.

**Still not started (Phases 8-10)**: expanded Compliance page, audit
activity timeline, and the final responsive/performance/accessibility
polish pass. Findings export remains unimplemented.

---

### Redesigned — Findings page as an investigation workspace, plus the Finding Detail Drawer (Phase 4-5)

Continuing the Security Center redesign in its own specified phase
order. Phases 4 and 5 are now done; Phases 6-10 remain untouched and
are listed honestly at the end.

**Closed the seam flagged last pass.** The Overview's donut segments,
severity legend, KPI cards and domain bars all emit real deep links
(`?severity=`, `?status=`, `?domain=`, `?device_id=`). The Findings
page now actually READS those query parameters on load and applies
them to its own filter controls, so those links filter instead of
landing on an unfiltered list. That was the one visible seam left
open by the previous pass, and closing it was the first thing done
here rather than a later cleanup.

**`FleetFindingOut` extended** with `detail`, `why`, `risk`,
`evidence`, `evidence_label` and `compliance_refs`. These come from
the same already-loaded `AuditFinding` row the endpoint reads anyway,
so the drawer opens instantly from data already in the browser --
deliberately one wider response instead of one extra request per
finding the user clicks, which is exactly the N+1 pattern this
redesign exists to avoid.

**Findings page rebuilt** as a filtering workspace: a summary card
row (total / critical / high / medium / manual review), five filter
controls (severity, status, device, domain, free-text search), and
client-side pagination with 25/50/100 per page. The device and domain
dropdowns are populated from the findings actually returned, not a
hardcoded list, so they always reflect real data. Long text is out of
the table entirely, per the redesign's own rule against giant text
blocks in cells -- rows now carry only severity, status, device,
domain, title and check ID.

**Finding Detail Drawer** -- a right-side panel (not a centred modal:
the user is scanning a table and opening findings one after another,
so keeping the list visible alongside matters more here than the
focus a modal enforces). Shows why-this-matters, risk, detail,
evidence under its own real label, recommendation, proposed fix, and
compliance mappings -- each section rendered only when that finding
actually has that content, so no empty headers. Reuses the existing
`.modal-close-btn`, `.readout` and `.diff-view` conventions rather
than defining parallel ones. Closable by its X, backdrop click, or
Escape.

**Accessibility**: finding rows are real keyboard targets --
`tabindex`/`role="button"`, activated by Enter or Space, with a
visible `:focus-visible` outline. Severity is carried by a labelled
badge, never colour alone.

**A real bug caught by a project-wide sweep, not shipped:** the
Findings pager uses `class="toolbar"` with the `hidden` attribute,
but `.toolbar` sets `display: flex`, which beats the browser's own
`[hidden] { display: none }`. The pager would have stayed visible on
an empty result set, showing "Showing 1-0 of 0". This is the exact
`[hidden]` override bug class this project hit before (already
handled for `.cmdk-backdrop`, `.panel-grid`, `.field`, `.field-row`
and `.badge`), and `.toolbar` had simply never been used with
`hidden` until now. Fixed at the CSS level, then swept every template
in the project for any other element carrying `hidden` whose class
sets a display value without a matching override -- zero remaining
instances.

**Verified**: filter matching tested with 9 real cases (each filter
individually, case-insensitive search, search by check ID, combined
filters, and a deliberately contradictory combination expecting zero
results); pagination tested with 7 cases including empty data, exact
page boundaries, and a page-overflow case confirming it clamps to the
last page rather than producing a negative slice. Plus the usual:
template parses with correct block structure, zero ID mismatches
(including the dynamically-referenced IDs checked separately), icon
constants confirmed to render real SVG, every CSS class confirmed to
exist, scripts pass Node syntax checks, `FleetFindingOut`'s
construction cross-checked against its schema via AST (no missing or
unknown fields), and project-wide compile/template/`view_scripts`
checks all clean.

**Still not started (Phases 6-10)**, deliberately not stubbed: Device
Security page redesign, graphical switch/interface view, expanded
Compliance page, audit activity timeline, and the final
responsive/performance polish pass. Export from the Findings page is
also not implemented.

---

### Redesigned — Security Center Overview as a visual security posture dashboard (Phase 1-3)

Detailed spec with a 10-phase implementation order. Followed that
order rather than touching everything at once: Phases 1-3 (Overview
redesign, gauge/KPIs/donut/domain chart/trend, plus device risk, top
risks and heatmap) are done; Phases 4-10 are not started and are
listed honestly below rather than half-built.

**One aggregated endpoint, `GET /api/security/dashboard`** -- score,
severity breakdown, domain scores, trend, compliance, risky devices,
top risks and the device x domain heatmap in a single call. Built as
one endpoint deliberately, per the spec's own performance
requirement: the Overview firing one request per widget is exactly
the N+1 pattern the redesign exists to avoid. Reuses the existing
`_latest_completed_runs_by_device` helper so "current posture" can't
drift between this and the older endpoints, and calls the engine's
own `risk_level()` rather than reimplementing any scoring in the API
or the browser.

**Data integrity, per the spec's strongest requirement**: every
section derives from real stored rows, and sections with no data come
back EMPTY rather than zero-filled, so the GUI renders a truthful
empty state instead of a chart implying data that doesn't exist. The
trend specifically returns one point per real completed audit run,
never interpolated -- and with fewer than two points the GUI shows
"Not enough historical audit data" instead of drawing a line.

**The Overview itself** is now a dashboard: an SVG radial score gauge
(arc math verified against the circle's own radius, not eyeballed)
with a real "since previous audit" delta computed from each device's
own second-most-recent completed run; seven clickable KPI cards; a
severity donut whose segments and text legend both deep-link into
filtered Findings; horizontal domain-score bars; the score trend; a
compliance posture panel; highest-risk devices with inline score
bars; top security risks as compact cards; and the device x domain
heatmap. The sidebar, shell, icon system and existing panel/status-
card/rail conventions are untouched -- this reads as the same
application, as the spec explicitly required.

**Run Audit moved into a modal.** The permanent textarea no longer
dominates the page; the submit logic itself is preserved verbatim
(same endpoint, payload, validation and error handling), just
relocated behind a "Run Security Audit" button.

**Three real bugs caught during verification, none shipped:**

1. `Status.MANUAL_REVIEW` does not exist -- the enum member is
   `Status.MANUAL`. This would have crashed the whole dashboard
   endpoint with an AttributeError on the first request. Found by
   reading the enum's real members rather than assuming the name
   matched its string value ("manual_review").
2. `--orange` was referenced for High severity but is not defined
   anywhere in the stylesheet, so High would have silently fallen
   back to grey -- collapsing the Critical/High/Medium distinction
   the spec explicitly requires. Added as a real variable sitting
   between amber and red.
3. The heatmap and domain chart were written assuming domains might
   be short keys (`mgmt`, `l2`). Traced the value through the check
   functions to `F()` and confirmed they are already full labels
   ("Management Plane / AAA"), so no translation layer was needed --
   verified rather than guessed in either direction.

**Accessibility**: severity and score are never carried by colour
alone -- the donut has a text legend with labels and counts, heatmap
cells show their numeric score as text with a descriptive hover
title, and every bar shows its value.

**Verified**: every changed Python file compiles; every enum member,
model field and schema-construction call in the new endpoint
cross-checked against real definitions via AST (all complete, no
unknown or missing fields); template parses with correct block
structure; zero ID mismatches including the dynamically-referenced
ones checked separately; all five icon constants confirmed to render
real SVG; every new CSS class and variable confirmed to exist;
extracted scripts pass Node syntax checks; project-wide
`view_scripts` sweep still clean.

**Not started (Phases 4-10)**, deliberately not stubbed as dead UI:
Findings page redesign with advanced filtering, the Finding Detail
Drawer, Device Security page redesign, graphical switch/interface
view, expanded Compliance page, and the audit activity timeline. The
Findings deep-links this Overview emits (`?severity=`, `?domain=`,
`?status=`) are real URLs but the Findings page does not yet read
those query parameters -- that is Phase 4's job and is the one place
where this pass leaves a visible seam.

---

### Added — fleet-wide Audit Report dashboard (Security Audit → Device View redesign)

Detailed spec plus a reference screenshot. Per its own instruction,
inspected the existing implementation before writing anything --
which surfaced a real architectural gap rather than a pure
presentation task.

**The gap, confirmed not assumed**: `AuditRun` is strictly one row per
device per audit, with no concept tying "these N devices were audited
together" under one numbered report. The requested dashboard is
inherently fleet-wide ("Audit Report #100", 39 devices scanned), so
this grouping had to exist before any of it could show real data.
Adding it was necessary, not a rewrite of working audit logic -- the
audit engine, scoring, findings, and per-device flows are all
untouched.

**New `AuditBatch` model** -- groups multiple `AuditRun` rows under
one sequential, human-readable `display_number`. First drafted using
a PostgreSQL `Sequence` object, then reverted: this sandbox has no
way to confirm `create_all()` provisions a sequence correctly for a
fresh install, so it now uses the `MAX(column) + 1` pattern this
project's own `ConfigVersion.version_number` already proves works
(app.services.config_compiler._next_version_number). A verified
existing convention over an unverifiable new one.

**`AuditRun.batch_id`** added as nullable -- single-device audits run
from a device's own page are completely unaffected and keep working
exactly as before. Both new models added to `init_db()`'s import list
in the same edits that created them (the omission that caused the
recent Security Center outage, deliberately not repeated).

**Two new aggregate endpoints** (`GET /api/security/batches`,
`GET /api/security/batches/{display_number}`) returning the executive
summary, risk distribution, category breakdown, top critical findings
(grouped by check across devices, sorted by severity then device
count), and the per-device risk table -- all from real audit rows,
aggregated server-side in one call per the spec's own note about
avoiding N+1 queries and client-side recalculation.

**Two new pages**: `/security/reports` (the report list) and
`/security/reports/{n}` (the dashboard itself) -- executive summary
cards, a Chart.js donut for risk distribution with a real total in
the center, category breakdown bars, top critical findings, quick
actions wired only to real destinations, and a filterable/searchable
device risk table. The existing sidebar is untouched, as the spec
explicitly required; both pages use the shell, icon system, panel,
status-card, and rail conventions already established in this
project, so they read as the same application rather than a
bolted-on dashboard.

**Two real bugs caught during verification, not shipped:**

1. `.is-active` (used for the selected device-risk filter) had NO
   button styling anywhere in the stylesheet -- the selected filter
   would have been visually indistinguishable from the unselected
   ones. Found by grepping for the class rather than assuming it
   existed; added a proper style distinct from `.btn-primary`, which
   stays reserved for a page's actual primary action.
2. The risk filters were drafted as All/High/Medium/Low, but
   `scoring.risk_level()` actually returns SIX values --
   Minimal/Low/Medium/High/Severe/Critical. Devices scoring
   `Minimal`, `Severe`, or `Critical` would have been silently
   invisible under every single filter, including the most dangerous
   ones. Found by reading that function's real return values instead
   of assuming the obvious three, then fixed and verified with a test
   confirming all six values are each reachable by exactly one filter
   and all are matched by "All".

**Verified**: every new/changed Python file compiles; every model
field, constructor kwarg, and schema-construction call cross-checked
against real definitions via AST inspection (one flagged mismatch
investigated and confirmed a false positive from two same-named
variables in different scopes, not a real error); both templates
parse with correct block structure and zero ID mismatches; every
icon constant confirmed to contain real rendered SVG; every CSS class
and variable used confirmed to exist; extracted scripts pass Node
syntax checks; project-wide `view_scripts` sweep still finds zero
instances.

**Not built this pass**, and deliberately not stubbed as dead UI: the
Findings Trend chart (needs multiple historical batches to be
meaningful -- the spec itself says not to fabricate a trend), the
paginated All Findings table, export (PDF/CSV/JSON), and the finding
detail modal.

---

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

