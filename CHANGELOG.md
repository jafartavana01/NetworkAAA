# Changelog

All notable changes to NetworkAAA are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

Dates below reflect the actual work session boundaries as best they
can be reconstructed, not a promise of calendar-perfect precision —
where a feature's exact day is ambiguous, it's grouped with the work
it was built alongside.

---

## 2026-08-30

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

