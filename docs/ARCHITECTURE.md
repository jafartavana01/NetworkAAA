# Architecture

## Two planes

**Data plane** -- `tac_plus-ng`, built unmodified from upstream
(https://github.com/MarcJHuber/event-driven-servers) and run as its
own systemd service. It is never edited; it is only configured,
started, stopped, and reloaded.

**Management plane** -- this application (FastAPI + PostgreSQL +
server-rendered GUI), running as its own systemd service. It owns
every piece of administrative state and is the only thing that writes
`tac_plus-ng.conf`.

```
Browser
   |
Web GUI (Jinja2, server-rendered, /app/templates)
   |
Management API (FastAPI, /app/api)
   |
   +---------------------+
   |                      |
PostgreSQL          Configuration Compiler
(source of truth)          |
                    Candidate tac_plus-ng.conf
                            |
                        Validation
                            |
                          Diff (vs. what's live on disk)
                            |
                [administrator confirms]
                            |
                    Backup -> Apply -> Reload
                            |
                       Health check
                       /          \
                  healthy      auto-rollback
                     |               |
                ConfigVersion   restore backup
                  recorded        + reload
                            |
                       tac_plus-ng  (TCP/49)
                            |
                     Network Devices
```

## Why the database is the source of truth

`tac_plus-ng.conf` is a *derived artifact*. Every device (and, in
later phases, every user, group, and policy) lives in PostgreSQL
first; the configuration compiler turns that state into a candidate
config file, validates it, and only then applies it. The GUI never
edits the running config file directly. This is what makes "change a
device's IP in the GUI" safe to do without recompiling or hand-editing
anything -- see "Configuration lifecycle" below.

## Module system

`app/modules/registry.py` defines a `Module` as: a key, a FastAPI
router, GUI nav entries, and a `mandatory` flag. `ModuleState` in
PostgreSQL persists which modules are enabled. At startup,
`app/main.py` only mounts a module's router if it's mandatory or
enabled -- a disabled module contributes no routes, no nav entries,
and (once later phases add background workers) no background tasks.
This is the extension point future RADIUS, LDAP, Active Directory, and
HA modules register against without changing `app/main.py`'s mount
loop or the registry itself (spec sections 27-29, 46-47).

Two modules exist so far:
- `core` (Phase 1) -- system dashboard, mandatory, always enabled.
- `tacacs` (Phase 2) -- Devices, Device Groups, Users, Groups, Policies,
  and Configuration pages today (Phases 2-5 all landed in this module,
  growing its nav children each time); Accounting (Phase 6) and
  Diagnostics (Phase 7) will register as additional children the same
  way. Mandatory, per spec section 29 -- TACACS+ itself is not
  optional.

## Configuration lifecycle (spec sections 13-15)

Implemented end-to-end in `app/services/config_compiler.py`:

```
Database (NetworkDevice rows)
        |
compile_candidate()            pure function: same DB state -> same config text, every time
        |
Candidate tac_plus-ng.conf
        |
validate_candidate()           best-effort `-P` syntax check -- INCONCLUSIVE on failure, not blocking
        |
compute_diff()                 vs. get_active_config(), which always reads the real file on disk
        |
   [administrator confirms in the GUI]
        |
apply_candidate()
   1. back up the currently-active file to /opt/aaa-platform/backups/
   2. write the candidate to /opt/aaa-platform/generated/tac_plus-ng.conf
   3. reload tac_plus-ng (SIGHUP via `systemctl reload`), falling back to a full restart
   4. wait, then check `systemctl is-active`
   5a. active     -> record a new ConfigVersion row (this IS the version history)
   5b. not active -> restore the backed-up file, reload again, raise an error with the journal attached
```

Diffs are always computed against whatever is *actually deployed on
disk* (`get_active_config()`), not against the database's idea of the
last-applied version. This matters because Phase 1's installer writes
the very first config directly (`installer/bootstrap_config.py`,
before any `ConfigVersion` row exists) and because an administrator
could in principle hand-edit the live file despite the header
comment's advice not to -- either way, the diff the GUI shows stays
accurate.

"Restore" (spec section 15) is implemented as re-applying an old
version's stored content through the exact same pipeline above, as a
brand-new version -- like a git revert, not a history rewrite. The
version log stays an honest, append-only record of what was actually
deployed and when.

## Privilege model

The management API runs as the unprivileged `aaa-platform` system
account (spec section 33), separate from root, with `ProtectSystem=strict`
and other systemd hardening applied to its unit. It legitimately needs
to start/stop/restart/reload the tac_plus-ng service and read its
journal (spec section 34) -- which an unprivileged user cannot do
against system units by default.

Rather than running the whole API as root, `installer/sudoers_setup.py`
installs a single sudoers rule, validated with `visudo -c` before it's
ever put in place, that grants the `aaa-platform` account exactly six
verbs (`start`/`stop`/`restart`/`reload`/`is-active`/`is-enabled`) plus
one `show` and one `journalctl` invocation, against exactly the two
unit names this platform owns -- no wildcards, nothing else. This is
why the management unit's systemd hardening deliberately omits
`NoNewPrivileges=true` (present on the tac_plus-ng unit): that flag
blocks the setuid escalation `sudo` depends on, and setting it here
would silently break service control rather than produce an obvious
error.

`/etc/aaa-platform` itself is intentionally root-owned and NOT
group-writable (`0750`), even though the service reads from and
(for two lazily-generated secrets) would otherwise want to write to
it -- the runtime service shouldn't be able to modify its own
credentials or build record. This creates a real chicken-and-egg
problem for `session_secret.key` and `secret_encryption.key`, which
`app/config.py` will happily generate on first use, but only has
permission to do if something already gave it write access. The fix
is `installer/app_install.py`'s `provision_secret_files()`: the
installer (running as root) generates both files up front and hands
ownership to the `aaa-platform` account with `0600`, so the runtime
service only ever needs to *read* them. `fix_etc_file_ownership()`
does the equivalent for `db_credentials.json` and `build_info.json`,
which are written earlier in the install by root-run code, before
`chown`ing them to the service account that actually needs to read
them at runtime. Both of these were caught by a real failed install --
`aaa-platform.service` exiting immediately on every start with no
more specific signal than a generic Python exit code -- not designed
in from the start.

## Config-injection defense

The device `name` field becomes a bare identifier inside a generated
`host {}` block. Rather than trying to escape arbitrary strings into
that position (no confirmed quoting mechanism exists for it), it's
restricted at input time to a conservative safe charset
(`app/schemas/device.py`). IP addresses are parsed and re-serialized
through Python's `ipaddress` module, which rejects anything that isn't
a real, unambiguous address -- so what reaches the compiler is always
already-normalized, never raw user text. Shared secrets, which *can*
legitimately contain arbitrary characters, are the one value actually
placed into the config as a quoted string, with backslashes and quotes
escaped.

## Directory layout

```
/opt/aaa-platform/
    app/                      management application source (installed copy)
    upstream/event-driven-servers/   tac_plus-ng source checkout
    generated/                tac_plus-ng.conf (the live, deployed config)
    backups/                  one file per applied version, written just before each Apply

/etc/aaa-platform/
    build_info.json           exact tac_plus-ng build record
    db_credentials.json       PostgreSQL credentials (root:aaa-platform, 0640)
    session_secret.key        session-signing secret (aaa-platform:aaa-platform, 0600)
    secret_encryption.key     Fernet key protecting device shared secrets at rest (aaa-platform:aaa-platform, 0600)
    build_info.json           tac_plus-ng build record (root:aaa-platform, 0640)

/etc/sudoers.d/aaa-platform  scoped systemctl/journalctl grant (see "Privilege model")
/var/lib/aaa-platform/data/  non-database persistent state
/var/log/aaa-platform/       application.log, tac_plus-ng logs
```

## Data model conventions

Every table uses a UUID primary key, not an auto-increment integer.
This is a spec section 45 requirement: a future HA version may run
multiple management-plane nodes against a shared/clustered PostgreSQL,
and auto-increment IDs generated independently on two nodes would
collide. Starting with UUIDs now avoids a primary-key migration later.

## What's implemented so far

**Phase 1:** installer, tac_plus-ng build pipeline, Web GUI shell,
authentication, live system dashboard.

**Phase 2:** Network Devices (full CRUD, encrypted shared secrets) and
the configuration compiler described above -- candidate generation,
diff, validation, apply, versioned history, and automatic rollback on
a failed apply.

**Phase 3:** TACACS+ Users (full CRUD, bcrypt-hashed passwords). The
config compiler emits `user <name> { password login = crypt <hash> }`
blocks -- syntax confirmed against a real working tac_plus-ng config
posted on the project's own support forum, not the legacy `tac_plus`
syntax (the two are explicitly documented by the maintainer as
"different and incompatible" beyond basic host configuration). The
Users page shows a raw tail of the tac_plus-ng access log to satisfy
spec section 52's "GUI must display the authentication event" --
deliberately unparsed, since the exact line format for a file-based
access log target (as opposed to syslog) wasn't independently
confirmed, and a wrong parser would be worse than no parser.

**What Phase 3 proves, and what it doesn't:** a user saved here and
applied can *authenticate* against tac_plus-ng -- the daemon can
verify a username/password pair. It does NOT yet mean that user can
actually get an interactive shell session on a device. TACACS+
authentication (AUTHEN) and authorization (AUTHOR) are separate
protocol exchanges; a NAS checks authentication first, then makes a
separate authorization request asking "is this user allowed to do
X". Answering that requires `profile {}` / `ruleset {}` blocks, which
don't exist yet -- that's Phase 5. A user can prove their password is
correct; what they're allowed to do once verified is still Phase 3
scope's Devices/Users only, not command authorization.

**Phase 4:** TACACS+ Groups and Device Groups. TacacsGroup is
tac_plus-ng's own native grouping concept -- confirmed against the
same real working config found for Phase 3, which showed `group
admins { }` as a valid, empty block, with users joining via `member =
admins`. The config compiler now emits both: a `group <name> { }`
block per group, and a `member = <group>` line inside any user's
block who belongs to one. DeviceGroup, by contrast, has no tac_plus-ng
config counterpart -- there's no confirmed "device group" concept in
the daemon's config language, so it's implemented as a management-
plane-only organizational feature (grouping in the GUI, a real target
for Phase 5's authorization engine to eventually match against) rather
than inventing config syntax that doesn't correspond to anything the
daemon actually supports.

**What Phase 4 proves, and what it doesn't:** group membership is now
real, generated config -- a user's `member = <group>` line actually
reaches tac_plus-ng. What it doesn't yet do is anything WITH that
membership: no permissions are inherited, no commands are
permitted/denied based on group. That's what makes group membership
useful, and it's exactly Phase 5's job (`profile {}` / `ruleset {}`
matching on `if (member == ...)`). Phase 4 is the structural
prerequisite -- users correctly sorted into named, real groups --
not the policy engine itself.

**Phase 5:** Authorization policies. This is the phase spec section 20
warns hardest about ("do not implement a fake policy system that does
not translate correctly to the core"), so it got the deepest research
pass of any phase -- four independent real tac_plus-ng configs
(the official upstream sample, two mailing-list threads, and a
tactrace.pl debug example) all confirmed the identical structure:

```
profile <name> {
    script {
        if (service == shell) {
            if (cmd == "") { set priv-lvl = <N> }
            <command-rules-in-order>
            <default-action>
        }
    }
}

ruleset {
    rule <group> {
        enabled = yes
        script {
            if (member == <group>) { profile = <name> permit }
        }
    }
}
```

A `Policy` maps to a `profile`; each `TacacsGroup` optionally gets a
`policy_id`, and every group-with-a-policy becomes one `rule` inside a
single shared `ruleset {}` block. One policy per group, not a list --
tac_plus-ng's own rules already have an order/first-match-wins
structure, and exposing that ordering complexity in the GUI for a case
the spec's own example doesn't call for would be complexity without
a clear benefit yet.

**What's confirmed vs. reasoned:** the privilege-level and permit/deny
mechanics above are confirmed, verbatim, across all four sources.
Matching a SPECIFIC command name (`CommandRule.command_pattern`, the
"ALLOW show *, DENY configure terminal" part of spec section 20's own
example) uses `cmd =~ /pattern/` -- and that specific combination was
NOT found directly demonstrated anywhere during research. What IS
confirmed: `cmd` is a real script variable (compared with `==`
everywhere), and `=~` is a real regex operator used elsewhere in this
exact language against other string variables (`nas-name`, `user`,
`$PASSWORD`). Extending the confirmed operator to the confirmed
variable is a reasoned inference from consistent language mechanics --
not the same thing as observing it work, and it's flagged as such
directly in the GUI (a note on the Policies page) and in
`app/models/command_rule.py`. This is the single most likely thing in
the whole project so far to need a small correction once tested
against a real command-authorization request from an actual NAS.

**Not yet implemented:** Accounting, Diagnostics, RADIUS/LDAP/AD
backends, HA, and Module Management UI (Phases 6-8). Every page that
exists is fully real for what it covers; there's no placeholder/fake
functionality standing in for the rest -- it simply doesn't exist yet.

**Phase 6:** Accounting (spec section 23). Rather than reverse-engineer
tac_plus-ng's undocumented default accounting log format, the config
compiler defines its own explicit `accounting format = "..."` string
using `${var}` placeholders confirmed real via a maintainer-answered
GitHub Discussion (`${nas}`, `${user}`, `${port}`, `${nac}`,
`${accttype}`, `${result}`, `${service}`, `${cmd}`, joined by a
self-chosen `::` delimiter). Both the writer (the generated config)
and the reader (`app/services/accounting_log.py`) are this project's
own code, so the 8 data fields parse reliably by construction rather
than by guesswork -- a meaningfully different, lower-risk situation
than Phase 3's raw/unparsed access-log viewer.

What's still best-effort: whether tac_plus-ng prepends a timestamp
before that custom format on each line. Every real-world example
found during research had one (syslog convention, `MMM DD HH:MM:SS`,
no year), but this was independently confirmed for syslog-routed and
legacy-tac_plus file output, not tac_plus-ng's own file destination
specifically. The parser looks for that pattern and stores it
separately as `parsed_at` when it matches; a line where it doesn't is
still fully parsed and shown, just excluded from date-range filtering
rather than guessed at. The GUI states this plainly rather than
implying more precision than the data supports.

**Not yet implemented:** Diagnostics, RADIUS/LDAP/AD backends, HA, and
Module Management UI (Phases 7-8).

**Phase 7:** Diagnostics (spec section 56) -- server status, recent
requests, authentication/authorization log tails, on-demand
configuration validation, service logs, and build information,
consolidated onto one page. Deliberately not a new subsystem: every
section reuses an existing service module or reads an audit trail
earlier phases were already writing (`InstallEvent` has recorded every
config apply/validation/rollback since Phase 2, but had no GUI to view
it until now). The authorization log (`authorlog`, configured since
Phase 1) is surfaced for the first time here too, following the same
raw-text, admin-supplied-search pattern as Phase 3's access-log viewer
-- not the safely-parseable pattern Phase 6 used for accounting,
since (like the access log) its line format wasn't independently
confirmed the way the accounting format is, because this project
defines that one itself.

**Not yet implemented:** RADIUS/LDAP/AD backends, HA, and Module
Management UI (Phase 8). CLI (spec section 32) and an automated test
suite (spec section 48) also remain outstanding, outside the 8-phase
numbering.

**Post-Phase-7 GUI/UX enhancements** (user-requested, not from the
original phase plan): inline "create new" quick-add popups on
Devices/Users/Groups (a Device Group, TACACS+ Group, or Policy can be
created without leaving the form that needs one), and a rework of
Policy command rules from one ordered mixed permit/deny list into two
separately-labeled lists (Denied / Permitted). The two-list UI needed
a real semantic decision, not just a layout change: what happens when
a command matches both a permit and a deny pattern? The compiler now
emits ALL deny rules before ALL permit rules regardless of GUI
insertion order (deny-overrides) -- the safer default, verified with a
test asserting a broad `permit ^show` and a narrow `deny ^show
running-config` coexist correctly, with the specific deny still
winning. Three Cisco IOS starter policy templates (Admin,
Network-Manager, Auditor) were added as one-click starting points in
the Add Policy modal -- reasonable defaults based on standard Cisco
AAA conventions, not a definitive security stance for any given
environment, and fully editable before saving. The Network-Manager
template's compiled output was verified end-to-end against the real
compiler code.

## Platform self-management (Admin RBAC, trusted hosts, HTTPS)

User-requested, built after Phase 7: this project had no way to manage
*itself* -- who can log into its own GUI, or how it's reached. Three
related pieces, all superadmin-only:

**Two-tier RBAC.** `AdminUser.is_superadmin` existed since Phase 1 but
was never actually checked anywhere. It now gates a real dependency
(`app.api.deps.get_current_superadmin`) covering admin-account
management and network/TLS settings; a standard admin can do
everything else. Enforced at three independent layers -- the API
dependency, the page route (a non-superadmin is redirected away from
`/platform/*`), and the nav itself (`NavEntry.requires_superadmin`
hides the section from the sidebar entirely, not just after clicking)
-- deliberately redundant, so a bug in any one layer still leaves the
other two holding.

**Trusted-host restriction.** `AdminUser.allowed_source_ips` (comma-
separated IPs/CIDRs) is checked at login against `Request.client.host`
-- the real TCP peer address for a direct uvicorn bind, not spoofable
by the client. If a reverse proxy is ever added in front of this app,
this check needs to switch to trusting `X-Forwarded-For` only from
that specific proxy, or the restriction becomes trivially bypassable.
(This column originally needed an explicit `ADD COLUMN IF NOT EXISTS`
migration to reach installations from before this feature existed --
see the "clean install only" note below for why that migration
machinery was later removed entirely rather than kept around.)

Several self-lockout guardrails live in `app/api/routes_admin_users.py`,
enforced in the API layer since nothing about them is a database
constraint: an admin can never delete or deactivate their own account
(their session would die on their very next request --
`get_current_admin` checks `is_active` on every request, not just
login), the last active superadmin can never be removed or demoted,
and changing your OWN trusted-host list is checked against your
current request's source IP before being accepted.

**HTTPS.** Self-signed by default (generated at install time,
`installer` phase `phase_tls_and_settings`), with GUI-driven
regeneration (custom CN/org/validity/key size) and custom
certificate upload, all built on the `cryptography` library --
already a project dependency since Phase 2 (Fernet secret encryption)
-- rather than shelling out to `openssl`. No new system or pip package
was needed for any of this. Caught and fixed a real correctness bug
during development: the first draft of the self-signed cert generator
set `BasicConstraints(ca=True)`, which would have marked every
generated certificate as a Certificate Authority rather than a normal
server certificate -- some strict TLS clients reject or warn on that.
Verified with an actual generate-and-validate round trip (not just a
syntax check) including a deliberate mismatched-cert/key test to
confirm the validator actually rejects what it should.

Making the port/host/HTTPS toggle genuinely configurable at runtime
required a real structural change: the systemd unit no longer invokes
`uvicorn app.main:app --host X --port Y` as a fixed CLI command --
that can't reflect a setting change without rewriting the unit file
itself. `app/run.py` is now the fixed `ExecStart` target; it reads
`app/platform_settings.py` (a JSON file, not a database table --
needed before the process can even know PostgreSQL is reachable) at
process start and calls `uvicorn.run()` programmatically. A settings
change takes effect on the next restart of `aaa-platform.service`, not
instantly -- true of virtually all server software's bind-address/
port/TLS settings, and the Settings page says so directly rather than
implying otherwise. Restarting is a deliberately separate, explicit
action from saving settings: the HTTP response confirming the save
needs to actually reach the browser before the process sending it
dies, especially if the admin is about to need a different port or
protocol to reconnect afterward.

`/etc/aaa-platform/config/` and `/etc/aaa-platform/tls/` are owned by
the `aaa-platform` service account specifically (unlike `/etc/aaa-platform`
itself, which stays root-owned/group-read-only so the service can't
modify its own credentials or build record) -- the running service
needs to write to both at runtime for this feature to work at all.

## Clean install only -- no in-place upgrade path

This project targets fresh installs on a new VM, not upgrading an
existing populated installation. This is an explicit product decision,
not a gap: `app/database.py`'s `init_db()` is a single
`Base.metadata.create_all()` call and nothing else. An earlier draft
carried real ALTER TABLE / data-migration logic (the PAM Expansion
Plan's Increment 1 originally included wrapping legacy `CommandRule`
rows into auto-created `CommandSet`s, backfilling new `Policy`
condition columns from old direct links, and column-by-column
`ADD COLUMN IF NOT EXISTS` migrations) specifically to support
upgrading an existing database -- that entire category of code was
removed once install scope was confirmed, rather than kept "just in
case." It was also the single highest-risk code in this project up to
that point: real data transformation that could not be tested against
a live PostgreSQL instance in the development sandbox (no network
access at all, confirmed by `apt-get install postgresql` failing on
403s against Ubuntu's own package mirrors), verified only by
extracting its control flow into a pure-Python simulation against
mocked table data. Removing it removed that risk along with the
complexity.

The upstream repository has no tagged releases, so there is no
"stable version" to pin to. `setup.py` still records the exact commit
hash resolved at clone time to `build_info.json` -- useful for knowing
exactly what's running and for reproducing a specific build, not for
an upgrade-in-place flow, since none is planned.

## Single-window GUI shell (all pages converted)

Every authenticated page (13 of them) now extends `app_shell.html`
instead of duplicating sidebar/topbar markup itself -- the shell
renders once per real page load, and `app/static/js/spa.js`
progressively enhances in-app navigation into fetch-and-swap
transitions with no new backend routes and no frontend framework.
`login.html` deliberately stays on the plain `base.html` pattern
forever -- it's pre-authentication and outside the shell by design,
not an unconverted leftover.

Two real bugs were caught during this conversion by actually tracing
through the runtime behavior rather than just reading the code:
orphaned `setInterval` timers surviving a view swap (fixed with
`app.js`'s `onViewLeave`/`runViewCleanup` lifecycle), and the
script-re-execution selector initially being broad enough to
re-trigger the shell-level status poller on every single navigation,
which would have caused the exact same leak via a different path
(fixed by scoping re-execution to a precise `#view-scripts-container`
query target rather than an exclude-list). `partials/header.html` was
removed once genuinely orphaned -- every page's topbar now renders
from `app_shell.html` itself.

## PAM Expansion Plan Increment 1 (Policy Engine foundation)

Completed: `CommandCategory`, `CommandSet`, and `PolicyCommandSet`
replace the old direct `Policy` -> `CommandRule` relationship from
Phase 5 -- a `Policy` now references one or more reusable Command
Sets instead of owning an inline rule list. `Policy` gained real
conditions (`condition_group_id`, `condition_device_id`,
`condition_device_group_id`, all nullable = "matches anything" on
that dimension) and `priority` (ascending, first full match wins),
per the "conditions live directly on Policy, not a separate
assignment table" decision recorded in `docs/PAM_EXPANSION_PLAN.md`
§1.1.

`app/services/policy_engine.py` is the single evaluation engine
(§1.3 of the plan): `get_ordered_policies()`,
`get_ordered_rules_for_policy()`, and `evaluate()` are shared by both
`config_compiler.py` (translates decisions into real tac_plus-ng
`profile`/`ruleset` blocks) and, in a follow-up increment, the Policy
Simulator -- so what the config actually does and what any future
tool predicts can never independently drift apart.

Two real, dangerous inconsistencies were caught and fixed during this
increment, both by inspecting actual runtime behavior rather than
trusting that existing code still matched the new model:

- `config_compiler.py` still referenced `CommandRule.policy_id`, a
  column that no longer existed on that model after the refactor --
  a guaranteed `AttributeError` the moment that code path ran. Fixed
  by rewriting policy/ruleset generation to consume
  `policy_engine.py`'s shared functions, verified with real executable
  tests (not just compiles) including a multi-condition scenario
  proving `group && device-group` conditions compile to a correctly
  parenthesized `&&`/`||` expression.
- `TacacsGroup.policy_id` still existed and the Groups page still let
  an admin "assign a policy" through it, but the compiler no longer
  read that field at all -- the GUI would have shown success while
  silently doing nothing. Removed the field outright (clean-install
  only, so no migration concern) and replaced it with a read-only
  reverse lookup (which policies currently target this group).

`condition_device_group_id` compiles to a generated OR-chain of
individual `device == <name>` checks (confirmed real syntax, same
reasoning as Phase 4's Device Groups -- no native tac_plus-ng concept
for a group of devices). Direct per-user targeting and time-of-day
conditions remain deferred, exactly as scoped in the plan -- no
confirmed tac_plus-ng syntax exists for either yet.

**Now built:** Policy Simulator (`/tacacs/policy-simulator`,
`POST /api/policy-simulator/evaluate`) and Effective Access
(`/tacacs/effective-access`, `GET /api/effective-access/user/{id}`
and `/device/{id}`) -- both call `policy_engine.evaluate()` directly,
the same function `config_compiler.py` uses, per §1.3's single-engine
principle. Effective Access runs that evaluation across every device
(or every user) in the database with no command supplied
(session-establishment only: "can this user reach this device, and at
what privilege" rather than "can they run this specific command"),
grouping results by granted privilege level. Neither feature contacts
a device, per §7/§8/§23's explicit constraint -- every lookup is a
database read.

Source IP, protocol, and service are accepted as Simulator input
fields (matching §7's requested form) but are not yet evaluated
against any policy condition -- `Policy` only implements group/
device/device-group conditions so far. The Simulator says so directly
in its result rather than silently ignoring what was typed in.

Three real gaps were caught and fixed while wiring this up, all by
systematically cross-checking nav entries against actual page routes
rather than assuming earlier work was complete: the Command Sets and
Command Categories pages had templates and API routers but **no page
route at all** (clicking those nav links would 404), and this was
only caught by grep-diffing every `nav_entries` path against every
`@router.get` path across both modules -- not by memory or spot-check.

## Session Monitoring & extended Accounting filters (PAM Expansion Plan §9-10)

`task_id` added to the accounting format string (now first field:
`${task_id}::${nas}::${user}::...`). Confirmed real by tac_plus-ng's
own documentation ("start and stop records for the same event must
have matching (unique) task_id numbers") -- what's *not* independently
confirmed is whether `${task_id}` specifically works inside a *custom*
`accounting format = "..."` string the way the other eight fields are
(each seen in a real maintainer-provided example). This is flagged
directly in `app/services/accounting_log.py`'s docstring and in the
Sessions page itself, not just in a code comment nobody reads --
and if the inference is wrong, `config_compiler.validate_candidate()`
catches it before it's ever applied to the live daemon, the same
safety net every other reasoned-not-confirmed piece of this project
relies on.

`accounting_log.group_into_sessions()` groups parsed records by
`task_id`: a session with an observed start and no observed stop is
shown as active -- a genuine, data-backed observation, not an
assumption, per §9's explicit "do not claim a session is active
unless the data supports it." Verified with a real executable test
(not just a compile check): a closed session with a start/stop pair
correctly reports `is_active=False` with both commands in
chronological order, and a session with only a start record correctly
reports `is_active=True`.

Accounting filters extended per §10: `source_ip` (already-captured
`nac` field, just newly exposed as a filter) and `device_group_id`
(resolves to member device names via a DB lookup in the API layer,
since the log itself only ever records device names, not ids --
`accounting_log.filter_records()` stays a pure function over
already-resolved names, matching every other filter it already had).
Still not implemented from §10: a command-category filter (would
require matching free-text accounting `cmd` values against
`CommandRule` patterns to infer a category -- not yet built).

## AAA Health & Failure Analysis (PAM Expansion Plan §16-17)

Before building this, confirmed a real semantic question rather than
assume: does the accounting `result` field mean "was the accounting
record itself logged successfully" or "was the associated command
authorized"? A genuine deployed tac_plus-ng syslog export (found
during research) settled it -- a real command/config-type accounting
line showed `result=permit`, confirming the field carries actual
authorization outcomes for that record type, not just a logging
acknowledgment. Building Failure Analysis on non-"permit" `result`
values is grounded in an observed real example, not a guess about
what the field means.

`accounting_log.compute_health_and_failure_stats()` is data-driven
throughout -- it doesn't assume a fixed `result` vocabulary (only
"permit"/"deny" ever appearing), and a record with an empty `result`
(typical for a bare `start` accounting event, which hasn't reached a
command decision yet) is excluded from the permit/non-permit
breakdown entirely rather than silently counted as a success either
way. Verified with a real executable test: a synthetic mix of
permit/deny/unparsed records produces exactly the expected
top-non-permit-device and top-non-permit-user rankings.

Per §16's own "do not create fake statistics" instruction,
Authentication Requests/Success/Failure and RADIUS cards from the
spec's suggested dashboard are deliberately omitted -- the access log
stays raw/unparsed (its format was never independently confirmed the
way the accounting format is, since this project defines that one
itself), so there is no real data to back those specific numbers with
yet. Only cards backed by genuinely parsed, structured accounting data
appear on the AAA Health page.

## Policy Versioning (PAM Expansion Plan §22)

Every Policy create/update now records a version (`PolicyVersion`,
scoped per-policy: "policy CORE-ADMIN v1, v2, v3, v4" reads as a
per-policy sequence, not a shared counter). Snapshots capture NAMES
for referenced group/device/device-group/command-sets rather than raw
ids, so a version stays meaningfully readable even after the thing it
referenced is renamed or deleted. Restore re-resolves those names back
to current ids; a name that no longer exists is dropped from the
restored policy with a warning returned to the caller, rather than
failing the whole restore or silently pointing at nothing. Restoring
creates a new version -- history only grows, matching Config
versioning's (Phase 2) established restore pattern and §22's explicit
"do not destroy historical versions."

Caught a real bug before it shipped: the model's first draft set
`ondelete="CASCADE"` on `PolicyVersion.policy_id`, meaning deleting a
policy would have destroyed all its version history -- directly
contradicting both this feature's own stated purpose and the spec's
explicit instruction. Fixed to `ondelete="SET NULL"` (with `policy_id`
made nullable): a deleted policy's versions become orphaned but
remain in the database, fully preserved. There's currently no
dedicated GUI for browsing orphaned versions (only "view versions for
this still-existing policy" is built) -- the data is preserved as
required; browsing it after the policy's own page is gone is a
reasonable future addition, not yet built.

Verified with a real executable test of the diff logic (not just
review): a synthetic old/current snapshot pair with five real
differences produces exactly those five changed fields and nothing
else, confirming unchanged fields are correctly excluded from the
diff output.

## Production incident: `${task_id}` was invalid, and the safety net didn't block it

A real deployment hit `log variable 'task_id' is not recognized` --
tac_plus-ng crash-looping via systemd's restart policy, confirmed by
install logs and journal output. Two real problems, both fixed:

**1. The core claim was wrong.** `${task_id}` (added for PAM Expansion
Plan §9's Session Monitoring, flagged at the time as "reasoned, not
directly confirmed") is not valid syntax inside a custom `accounting
format` string. Removed from both `config_compiler.py` and
`installer/bootstrap_config.py`. Session Monitoring now correlates on
`(device, port)` instead -- a heuristic (assumes at most one open
session per device+port at a time, true for the large majority of
real deployments), not a protocol-level guarantee, and the Sessions
page says so directly. Verified with a real executable test covering
four edge cases: a clean start/stop pair, an orphan stop with no
preceding start (correctly produces no session), an unclosed session
superseded by a new start on the same device+port (correctly flushed
as inactive), and a still-open session (correctly marked active).

**2. The bigger problem: the safety net didn't actually work.** The
platform's own config validation (`validate_candidate()`, via
tac_plus-ng's `-P` flag) correctly caught the bad config and printed
an unambiguous "Detected fatal configuration error. Exiting." -- but
`apply_candidate()` only *logged* a failed validation and proceeded
to write the config and reload the live daemon anyway, relying on the
post-reload health check to catch it after the fact. And separately,
the GUI labeled that failure "Inconclusive" regardless of how clear
the underlying error was. Both fixed:

- `validate_candidate()` now returns a `ValidationResult` with a new
  `definitively_failed` flag, set when the daemon's own output
  contains an unambiguous marker (`"fatal configuration error"`,
  `"is not recognized"` -- confirmed against the exact real failure
  text, not invented). `apply_candidate()` now genuinely BLOCKS on
  `definitively_failed`, raising `ApplyFailedError` before writing
  anything to disk or touching the live daemon -- upgraded from the
  original design's "we don't block on -P, only the post-reload
  health check blocks" specifically because this incident is now
  direct, confirmed evidence that -P's fatal-error reporting is
  trustworthy, not merely convenient to assume. A non-zero exit
  *without* one of those markers still doesn't block -- that remains
  the genuinely ambiguous case (binary missing, permissions, timeout)
  the original design was written for.
- The Diagnostics page now shows "FAILED — would not be applied" for
  a definitive failure, distinct from "Inconclusive" for a genuinely
  unexplained nonzero exit -- verified with the exact real error text
  from this incident, confirming the fix actually catches it.

## Policy drag-to-reorder and Dashboard charts

**Policy priority reordering**: native HTML5 drag-and-drop on the
Policies table, reassigning clean sequential priorities (multiples of
10) matching the new visual order rather than computing fractional
"insert between" values. Only policies whose priority value actually
changed get a PUT sent -- verified with a real test: an adjacent swap
of 4 policies correctly identifies only 2 as needing an update, not
all 4.

**Dashboard charts**: Chart.js 4.5.1 via a confirmed-real cdnjs URL
(verified by fetching cdnjs's own listing before using it, not
assumed), loaded on-demand rather than as a shell-level script since
only this page needs it. This surfaced a real architectural
consideration specific to this project's SPA shell: `spa.js` only
re-executes INLINE scripts on navigation (a plain `<script src>` tag
would render fine on a full page load but silently never re-fire on
an in-app SPA navigation *to* the dashboard, leaving `Chart`
undefined). Fixed by loading the library dynamically from inline JS
(`ensureChartJsLoaded()`), checking `window.Chart` first so repeat
visits in the same session don't re-fetch anything. Verified by
rendering the actual page and IIFE-wrapping each extracted script
exactly as `spa.js` does on real re-navigation, then syntax-checking
all three (including the shell's own daemon-poller script, confirming
the whole page's script boundaries are sound, not just the new code).

New backend piece: `accounting_log.compute_hourly_activity()`, a real
time series (not a point-in-time aggregate) bucketing parsed records
into hourly windows over a configurable lookback, with zero-count
hours included so the chart's x-axis stays a continuous timeline
rather than skipping quiet periods. Verified with a real test:
out-of-window and unparsed records are correctly excluded from every
bucket.

## Policy priority uniqueness, and Command Set "starts with / contains" UX

**Priority uniqueness**: `Policy.priority` now has a real unique
constraint -- deliberately `DEFERRABLE INITIALLY DEFERRED`, not a
plain one, because the drag-reorder feature (built two turns prior)
sends priority values that transiently collide mid-sequence when
reassigning positions. A plain constraint would have broken that
feature the moment this was added. Fixed properly: reorder now goes
through a dedicated `POST /api/policies/reorder` endpoint that
reassigns every affected policy's priority within ONE transaction, so
only the final, fully-unique arrangement is ever actually checked --
not each individual row update. Single-policy create/update still get
an explicit, friendly pre-check (`_check_priority_available`) so a
manual typo produces a clear "already used by policy X" message
instead of a raw constraint violation. Since this project is
clean-install-only by deliberate prior decision, no migration code
was reintroduced for this -- `create_all()` covers fresh installs
automatically; an already-existing deployment needs a manual
`ALTER TABLE` (see chat) or a fresh reinstall, consistent with that
decision.

**Command Set pattern UX**: replaced the raw-regex-only input with a
friendly Starts with / Contains / Exact match / Custom regex picker,
purely client-side (the stored `command_pattern` is still a plain
regex string; nothing in the schema or API changed). Editing an
EXISTING rule reverse-engineers a friendly (mode, value) pair from its
stored pattern where possible, falling back to "Custom regex" (showing
the raw pattern unmodified) for anything that doesn't cleanly fit --
never silently reinterpreting real data. Plain-text values are
regex-escaped for the three simple modes (so a literal "." in a
command name is matched as itself, not as regex "any character");
"Custom regex" passes the value straight through, since there the
admin is deliberately writing regex. Verified with real Node.js
execution of the actual extracted functions from the rendered page --
not a reimplementation -- including a concrete before/after
demonstration of the exact problem that motivated this: the raw regex
`show*` matches even the bare string "sho" (a real, confusing false
positive), while the new "Starts with: show" correctly produces
`^show` with no such issue.

## Two severe bugs caught from real deployment reports, both fixed

**1. Command Sets "Edit" silently did nothing.** Root cause: the
"starts with / contains / exact / custom" rule editor (added prior
turn) had a property-naming mismatch. `patternToModeAndValue()`
returned `{mode, value}`, but every consumer (`renderRuleList`,
`modeAndValueToPattern`) expected `{match_mode, match_value}`. Adding
a *new* blank rule worked (that code path built the object with the
right names directly); loading an *existing* rule or applying a Cisco
template did not -- both went through `patternToModeAndValue()`,
producing wrongly-named properties, which made
`modeAndValueToPattern()` call `.replace()` on `undefined`, throwing
inside the synchronous `openModal()` before it ever reached the line
that un-hides the modal. No visible error, modal just never opened --
exactly "not work, not show anything." Confirmed with a real Node.js
reproduction of the crash before fixing, and a second real run
confirming the fix. Fixed at the source (`patternToModeAndValue()`
itself now returns the correctly-named keys), not patched at each of
the three call sites, so the same class of bug can't recur at a future
call site either.

**2. The entire AAA Health page, and the Dashboard's activity chart,
have been broken since `compute_hourly_activity` was added.** Root
cause: inserting that function via a `str_replace` whose `old_str`
was just `compute_health_and_failure_stats`'s `def` line, without
re-adding that same `def` line in the replacement text -- the
function's docstring and full body survived as unreachable dead code
trapped inside `compute_hourly_activity`'s own scope (after its
`return`), but `compute_health_and_failure_stats` itself no longer
existed as a callable function anywhere. `py_compile` never caught
this: dead code after a `return` is syntactically valid Python, not a
syntax error -- the same class of gap that let the missing `BaseModel`
import through earlier. Confirmed absent with `ast.walk()` (searched
for a `FunctionDef` named `compute_health_and_failure_stats` -- none
existed), fixed by restoring the missing `def` line, and reconfirmed
present the same way. Then verified with a real end-to-end execution
test reproducing the exact `/health` endpoint code path (both
functions called in sequence against synthetic records), not just a
structural check. Given this exact class of bug had now appeared
twice, also ran a project-wide cross-module reference sweep
afterward -- the two other modules edited with the same risky
insert-before-existing-function pattern (`policy_engine.py`) were
confirmed clean the same way.

