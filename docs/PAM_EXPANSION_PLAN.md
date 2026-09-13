# AAA / Privileged Access Management Platform — Expansion Plan

Status: **planning document, no code changes yet**. This is the
increment-by-increment plan for evolving the platform from a
TACACS+ management GUI into the AAA/PAM control plane described in
the product direction doc, per that doc's own §37 ("create an
implementation plan" before code) and §38 (phase/priority order).

Nothing in this document is committed code. Each increment below
ends with a review point before moving to the next.

---

## 0. Principles carried forward, unchanged

These already hold true in the existing codebase and this plan does
not weaken any of them (product doc §30):

- **Verified vs. reasoned-unverified.** Every tac_plus-ng syntax claim
  in this plan is tagged. Where research hasn't happened yet, it says
  so explicitly rather than assuming.
- **Additive migrations only.** No existing table is dropped or
  destructively altered. New shapes are introduced alongside old ones,
  existing data is migrated forward automatically and losslessly, and
  every migration is idempotent (safe to re-run).
- **Config-plane, not device-plane.** No SSH, NETCONF, RESTCONF, SNMP,
  or remote command execution is introduced anywhere in this plan
  (product doc §36, §39). The platform only ever talks to devices via
  TACACS+/RADIUS as a server, never as a client to them.
- **Security properties held constant.** CSRF, secret encryption,
  trusted-host restriction, RBAC, HTTPS, systemd hardening, scoped
  sudo, config validation, audit logging, config-injection defense —
  every new mutating endpoint gets the same treatment the existing
  ones already have, not a lighter version.
- **One evaluation engine, not two.** This is the single most
  important new architectural rule this plan introduces — see §1.3.

---

## 1. Phase 1: Policy Engine Foundation

This is the foundation everything else (Sessions, Accounting,
Reviews, JIT, RADIUS) eventually reads from, so it gets the most
detailed treatment here. Later phases stay more directional until
Phase 1 is actually built and its real shape is known.

### 1.1 What exists today, and what has to change

Today: `Policy` owns `CommandRule` rows directly (one policy → many
rules, split into permit/deny lists in the GUI). `TacacsGroup` has a
single nullable `policy_id`. That's the entire targeting model — a
policy applies to one group, everywhere, always.

The product doc's model (§4) is richer:

```
Policy
 ├── Name, Description, Enabled, Priority
 ├── Conditions   (who/where/when this policy applies)
 ├── Authentication
 ├── Authorization  (priv-lvl + Command Sets, permit/deny, default action)
 └── Accounting
```

Re-reading §4 closely: **conditions live directly on the Policy**, not
in a separate assignment table. A Policy is self-contained — it
declares both "when do I match" and "what do I grant." Multiple
policies with different conditions and priorities coexist; the engine
walks them in priority order and the first full match wins. This is
simpler than a separate join table and is what this plan builds.

### 1.2 Schema changes

**New: `CommandCategory`**
`id, name, vendor, description`. Seeded with the product doc's Cisco
IOS-oriented list (§6): SHOW, INTERFACE, ROUTING, BGP, OSPF, SECURITY,
AAA, SYSTEM, CONFIGURATION, DANGEROUS. Vendor-scoped from the start
(`vendor` column) so a second vendor's categories can be added later
without restructuring — per §6's explicit vendor-neutrality
requirement.

**New: `CommandSet`**
`id, name, description, enabled, vendor`. A named, reusable, versioned
collection of command rules (§5) — e.g. `READ_ONLY`,
`BGP_OPERATOR`.

**Changed: `CommandRule`**
Currently `policy_id` (required FK to Policy). Becomes `command_set_id`
(required FK to CommandSet) + optional `category_id` (FK to
CommandCategory, for filtering/reporting only — never changes
authorization behavior on its own, matching §11's explicit
requirement that risk/category metadata must stay purely
observational unless a policy deliberately references it).

**New: `PolicyCommandSet`** (join table)
`policy_id, command_set_id, order`. A policy can reference multiple
command sets (§5's example: `Network-Engineer` = `READ_ONLY` +
`ROUTING_OPERATOR` + `BGP_OPERATOR`). Order matters for the same
deny-overrides-first evaluation rule already established in the
existing engine (Phase 5/7's permit/deny split) — see §1.4.

**Changed: `Policy`**
Adds:
- `priority` (int, required, unique-ish but not enforced unique —
  ties broken by creation order)
- `condition_user_id` (nullable FK → TacacsUser)
- `condition_group_id` (nullable FK → TacacsGroup)
- `condition_device_id` (nullable FK → NetworkDevice)
- `condition_device_group_id` (nullable FK → DeviceGroup)
- `condition_source_cidr` (nullable text — IP/CIDR, reusing the exact
  validation already built for `AdminUser.allowed_source_ips`)
- `condition_service` (nullable string, e.g. `shell`)
- `condition_protocol` (nullable string — `tacacs+` today,
  `radius` from Phase 4 onward)
- `condition_time_start`, `condition_time_end` (nullable, `HH:MM`)
- `condition_days_of_week` (nullable, e.g. `1,2,3,4,5` for weekdays)

Every condition field is nullable; null means "matches anything" for
that dimension. `default_priv_lvl` and `default_action` stay as they
are today.

**Retired, not deleted:** `TacacsGroup.policy_id` and the direct
`Policy → CommandRule` relationship stop being written to by new code,
but the columns are NOT dropped in this phase — see the migration
strategy below. A future cleanup phase can drop them once every
existing installation has confirmed-migrated, per §31's "do not
rewrite the schema unnecessarily" alongside "never destroy data";
dropping a column is a stronger, less reversible action than adding
one, and doesn't need to happen in the same increment as the
additive change.

### 1.3 The single-evaluation-engine rule

The product doc requires (§7) that the Simulator evaluate requests
"using the exact same policy engine used by production AAA." If the
simulator and the config compiler are two independently-written
pieces of matching logic, they can silently disagree — the simulator
says PERMIT while the real compiled tac_plus-ng script says DENY (or
the reverse), which is a dangerous inconsistency for a security tool
to have.

The fix: a single Python module, `app/services/policy_engine.py`,
becomes the one source of truth for "given this user/device/context,
which policy matches, and what does it grant." Two things consume it:

1. **The config compiler** — walks the same policies in the same
   priority order and translates the engine's own condition-matching
   logic into tac_plus-ng `ruleset`/`profile` blocks (still emitting
   real, confirmed syntax — this changes what generates the script,
   not the confirmed script grammar itself).
2. **The Simulator** (§7, Phase 1 item 3) — calls the engine directly
   with a hypothetical request and gets back a decision plus the
   evaluation trace, with **no config generation or device contact
   involved at all**.

This is the one piece of this plan I'd call architecturally
load-bearing: getting it right here means the Simulator's answer is
*provably* what production would do, not a best-effort approximation.

### 1.4 What's confirmed vs. what needs research before building

Carried forward from Phase 5's research, already confirmed real:
- `if (member == <group>) { profile = <policy> permit }` — group
  targeting.
- `if (device == <hostname>) { ... }` — confirmed in the official
  upstream sample (`device == localhost && client == private`).
- Source-IP/CIDR matching via ACL blocks — confirmed:
  `acl <name> { if (nac == 10.27.64.0/21) permit deny }` then
  `if (acl == <name>) { ... }`, from a real mailing-list example.
  `nac` is also confirmed elsewhere as the source-address variable
  (used in the Phase 6 accounting format).

**Not yet confirmed, needs research before Phase 1 ships (not before
Phase 1 starts — this can happen in parallel with schema/API work)**:
- Direct per-user targeting (as opposed to per-group) — every
  confirmed example matches on `member ==`, not a bare username.
  Needs a real example or a documented fallback (e.g., auto-create a
  single-member group when a policy targets one user directly).
- Time-of-day / day-of-week conditions. No confirmed evidence
  tac_plus-ng's script language has time-aware variables. If it
  doesn't, time conditions become **engine-only** (real for the
  Simulator and Effective Access, but not compilable into a always-
  current static config) — this would need either a scheduled config
  regeneration or an honest GUI note that time conditions aren't yet
  reflected in the live daemon between applies. This gets flagged
  plainly rather than silently built as if it works identically in
  both places.
- Device-*group* targeting still expands to an OR-chain of individual
  `device ==` checks at compile time (established reasoning from the
  earlier device/group-targeting discussion) — real, but generated,
  not a native tac_plus-ng concept.

### 1.5 Migration strategy (product doc §31's explicit requirements)

Run once, automatically, on first startup after upgrade — idempotent,
tested against a populated database before release:

1. Create the new tables (`command_categories`, `command_sets`,
   `policy_command_sets`) and new nullable columns on `policies` via
   `ADD COLUMN IF NOT EXISTS` (same pattern already used for
   `AdminUser.allowed_source_ips`).
2. For every existing `Policy` row: create a `CommandSet` named
   `<policy-name>-legacy-ruleset`, move its existing `CommandRule`
   rows to point at that new CommandSet (updating the FK, not copying
   — no duplication), and link it to the policy via
   `PolicyCommandSet`.
3. For every `TacacsGroup` with a non-null `policy_id`: set that
   policy's `condition_group_id` to the group's id (if not already
   set by an admin), so existing group→policy assignments keep working
   with identical behavior under the new condition-based model.
4. Assign a default `priority` to every existing policy (e.g. by
   creation order) so priority-based evaluation has a deterministic
   starting point identical to today's single-match behavior.
5. Re-run the config compiler once (as a dry validation, not an
   auto-apply) to confirm the newly-migrated policies compile to
   byte-identical output as before migration, for every existing
   installation's data. Any mismatch blocks the migration from being
   marked complete and surfaces a clear diagnostic rather than
   silently applying a behavior change during an upgrade.

### 1.6 API & GUI (this increment)

- `app/api/routes_command_sets.py` — CRUD, matching the existing
  pattern (validated names, CSRF, superadmin not required — command
  sets are TACACS+ data, same permission tier as Devices/Users/Groups
  today). Delete is blocked with a clear "referenced by N policies"
  message when in use (§5's explicit requirement), not silently
  cascaded.
- `app/api/routes_command_categories.py` — simpler CRUD, mostly
  read-heavy (seeded set, admins can extend it).
- `Policy` API/schema updated for the new condition fields and
  `PolicyCommandSet` list (replacing the old flat `command_rules`
  list in the request/response shape — this is a breaking API change
  for that one endpoint, called out explicitly rather than silently
  shipped).
- GUI: Command Sets page (list/add/edit, usage count, category
  filter). Policies page gains a Conditions section and a
  multi-select for Command Sets in place of the current inline
  permit/deny editor (which moves to live on the Command Set's own
  edit form instead).

### 1.7 Policy Simulator + Evaluation Trace (Phase 1 items 3-5)

New page, new read-only endpoint
(`POST /api/policy-simulator/evaluate`), calling
`policy_engine.evaluate()` directly — no config compilation, no
device contact, exactly per §7's explicit constraint. Input: the
fields in §7's example (username, password *optional* — see below,
device, source IP, protocol, service, privilege, command). Output:
the decision plus the full step-by-step trace shown in §7's example
(user lookup → group matching → device lookup → device-group matching
→ source-IP condition → policy matched → command-set matched →
result), each step marked PASS/FAIL/SKIP.

One deliberate scope note: password verification in the simulator
checks against the real stored hash if a password is supplied (so
"does this password work" can be tested), but the simulator never
needs a password to evaluate authorization — a common real use is
"would this user be authorized here" without them needing to supply
their live credential to an admin running the test.

### 1.8 Effective Access (Phase 1 item 4)

Two read-only query modes over the same engine (§8):
`GET /api/effective-access/user/{id}` (every device this user can
reach, at what privilege, via which policy) and
`GET /api/effective-access/device/{id}` (every user who can reach
this device). Both return the full inheritance chain
(User → Group → Policy → Device Group → Device → Privilege →
Command Sets) for each result, not just the final answer — this is
the same trace machinery as the Simulator, run in bulk across every
user or device instead of one hypothetical request.

---

## 2. Phase 2 (directional — detailed plan written once Phase 1 ships)

- **Session Monitoring (§9)**: active/historical session views and a
  per-session event timeline, built strictly from what the (already
  real, Phase 6) accounting log actually contains. If session
  start/stop correlation needs a session/task identifier this
  project's accounting format doesn't currently capture, that's a
  research-and-possibly-reopen-Phase-6 item, not something to fake —
  matching the explicit instruction not to claim a session is active
  without accounting data supporting it.
- **Advanced Command Accounting (§10)**: extends the existing Phase 6
  parser's field set (already real, self-defined format) rather than
  replacing it; malformed-record handling already exists (Phase 6's
  `parsed: false` fallback) and extends naturally to "record a parsing
  error," not silently discard.
- **Command Risk Classification (§11)**: a static field on
  `CommandCategory` or `CommandRule` (LOW/MEDIUM/HIGH/CRITICAL),
  reporting/filtering only, never consulted by the authorization path
  unless a policy explicitly references it — enforced by simply not
  wiring it into `policy_engine.py`'s decision logic at all in this
  phase.
- **AAA Health Dashboard (§16) / Failure Analysis (§17)**: extends the
  existing Diagnostics page (Phase 7) rather than replacing it —
  same reused-not-duplicated principle Phase 7 already established.

## 3. Phase 3 (directional)

Policy Versioning (§22, parallels the existing Configuration
versioning pattern from Phase 2 almost exactly — same
backup/diff/restore shape, applied to policy rows instead of the
compiled config file), Impact/What-If Analysis (§23, a pure
`policy_engine.py` query, no device contact), Access Graph (§24, a
visualization over the same Effective Access data from §1.8), Access
Reviews (§14), Approval Workflow (§13), Break-Glass (§15), and JIT/
Temporary Authorization (§12) — the last four share a common shape
(request → approval/expiry state machine → time-bounded Policy or
PolicyCommandSet grant → automatic expiry) worth designing as one
underlying model rather than four separate ones once this phase
starts.

## 4. Phase 4 (directional)

LDAP/AD identity source abstraction (§18), MFA architecture (§19),
RADIUS (§20-21). RADIUS specifically: tac_plus-ng's own RADIUS support
(confirmed present in the daemon, per Phase 1's research) needs the
same verified-vs-unverified research treatment every TACACS+ feature
in this project has already gotten — no RADIUS syntax gets used
without a confirmed real example, per §20's explicit instruction.

## 5. Phase 5 (directional)

REST API expansion/consistency pass (§27), API service accounts
(§28), granular RBAC permissions (§29, additive on top of the
existing two-tier model — never breaking it), Compliance Reports
(§25), Audit Evidence packages (§26).

---

## 6. Testing (product doc §32, applies to every phase above)

Unit tests for `policy_engine.py`'s matching logic (every condition
type, priority ordering, permit/deny/default-deny) become possible
for the first time in this project in a real, automated way — Phase
1 is also the natural point to introduce the automated test suite
that's been an acknowledged gap since Phase 7. Integration tests
against the real tac_plus-ng binary, and end-to-end tests via a real
or lab TACACS+ client, follow the same phased approach as everything
else — not deferred to the very end.

---

## Review checkpoint

This plan is written to be read and pushed back on before any code
changes happen. Specific things worth confirming before Increment 1
(schema refactor + migration) starts:

1. Conditions-on-Policy (this plan) vs. a separate PolicyAssignment
   join table (the alternative considered and rejected in §1.1) —
   agree with that call?
2. OK with per-user targeting falling back to an auto-created
   single-member group if direct-user matching in tac_plus-ng scripts
   turns out not to be confirmable?
3. OK with time-of-day conditions potentially being engine-only
   (Simulator/Effective-Access-accurate) but not live-compilable, if
   that's what the research turns up?

---

## Increment 1 status: schema — DONE (simplified after a scope
## clarification: clean installs only, no upgrade path needed)

Built: `CommandCategory`, `CommandSet`, `PolicyCommandSet` models;
`CommandRule` refactored to belong to a `CommandSet`
(`command_set_id`) instead of directly to a `Policy`; `Policy` gained
`enabled`, `priority`, and three condition fields
(`condition_group_id`, `condition_device_id`,
`condition_device_group_id` — user/source-IP/service/protocol/time
conditions deliberately deferred, per §1.4's confirmed-vs-unconfirmed
reasoning).

**Scope simplification**: this increment originally also included a
real, idempotent data-migration path (wrapping existing Policies'
CommandRules into auto-created legacy CommandSets, backfilling
condition_group_id from the old TacacsGroup.policy_id link,
column-by-column ADD COLUMN IF NOT EXISTS migrations) — verified as
far as a sandbox with no database access allowed (a pure-Python
simulation of the control flow, covering first-run, idempotent
re-run, and name-collision cases). Once it was confirmed every
install targets a fresh VM rather than an existing populated
database, that entire migration path — genuinely the highest-risk
code in this project up to that point, since it transformed real data
and couldn't be tested end-to-end at all — was removed outright rather
than kept unused. `app/database.py`'s `init_db()` is now a single
`Base.metadata.create_all()` call. See that file's own docstring and
`docs/ARCHITECTURE.md`'s "Clean install only" section for the full
reasoning.

**Not yet built (next increments)**: `app/services/policy_engine.py`
(the single source of truth for evaluation — nothing reads the new
schema yet), the Command Sets CRUD API/GUI, the Policy API/GUI update
to expose conditions and CommandSet references, the config compiler
rewrite to consume the engine's decisions, and the Simulator/Effective
Access pages that depend on all of the above existing first.


