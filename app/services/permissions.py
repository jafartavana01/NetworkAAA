"""
app.services.permissions
==========================
The finite catalog of permission keys granular RBAC (PAM Expansion
Plan §29) actually checks, plus a handful of starter role templates.

Every key here corresponds to a resource category that genuinely
exists in this project today -- deliberately NOT including keys for
features the original spec mentioned but that aren't built
(§29's own example list included "Reports: view/export" and
"Approvals: approve", neither of which exist as real features in this
project; a permission that doesn't actually gate anything would be
misleading, not useful). Extending this catalog when a new feature
ships is the intended way to grow it -- adding a key here and a
matching `Depends(require_permission("..."))` on the relevant routes,
not a schema change.

Each permission is `"<resource>:<action>"`. `view` and `write` are the
only actions used for most resources (matching how this project's
routes are actually structured -- GET-only vs everything else),
except where a resource has a genuinely distinct, more sensitive
action worth separating (`config:apply` is meaningfully riskier than
`config:view`, so it's its own key rather than folded into `write`).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Permission:
    key: str
    label: str
    description: str


PERMISSION_CATALOG: list[Permission] = [
    Permission("tacacs_users:view", "View TACACS+ Users", "See TACACS+ end-user accounts and their group membership."),
    Permission("tacacs_users:write", "Manage TACACS+ Users", "Create, edit, and delete TACACS+ end-user accounts."),
    Permission("groups:view", "View Groups", "See TACACS+ groups."),
    Permission("groups:write", "Manage Groups", "Create, edit, and delete TACACS+ groups."),
    Permission("devices:view", "View Devices", "See network devices and device groups."),
    Permission("devices:write", "Manage Devices", "Create, edit, and delete devices, device groups, and device-level access grants."),
    Permission("policies:view", "View Policies", "See authorization policies, command sets, and their version history."),
    Permission("policies:write", "Manage Policies", "Create, edit, delete, and reorder policies and command sets; restore old versions."),
    Permission("accounting:view", "View Accounting", "See accounting records, sessions, and AAA Health."),
    Permission("accounting:export", "Export Accounting", "Export accounting records to CSV."),
    Permission("diagnostics:view", "View Diagnostics", "See service status, logs, and the configuration audit trail."),
    Permission("config:view", "View Configuration", "See the compiled candidate configuration and version history."),
    Permission("config:apply", "Apply Configuration", "Apply a new configuration to the live tac_plus-ng daemon, or restore/import one."),
    Permission("admin_users:view", "View Admin Users", "See other platform administrator accounts."),
    Permission("admin_users:write", "Manage Admin Users", "Create, edit, and delete platform administrator accounts and roles."),
    Permission("platform_settings:write", "Manage Platform Settings", "Change network/HTTPS settings and certificates."),
    Permission("network_ops:view", "View Network Operations", "See command jobs, their targets, and raw command output."),
    Permission("network_ops:execute", "Run Command Jobs", "Create and run command jobs against devices and device groups."),
    Permission("network_ops:templates", "Manage Command Templates", "Create, edit, and delete reusable command templates."),
    Permission("security:view", "View Security Center", "See security audit findings, scores, compliance results, and audit history."),
    Permission("security:audit", "Run Security Audits", "Trigger a device or interface security audit (live SSH, uploaded config, or stored snapshot)."),
    Permission("security:remediate", "Apply Security Remediation", "Send a security finding's recommended fix through the configuration Apply workflow."),
]

PERMISSION_KEYS = {p.key for p in PERMISSION_CATALOG}


def _all_view_permissions() -> list[str]:
    return [p.key for p in PERMISSION_CATALOG if p.key.endswith(":view")]


ROLE_TEMPLATES: list[dict] = [
    {
        "name": "Read-Only Auditor",
        "description": "Can see everything -- users, devices, policies, accounting, diagnostics, configuration -- and change nothing.",
        "permissions": _all_view_permissions() + ["accounting:export"],
    },
    {
        "name": "Policy Manager",
        "description": "Full control over authorization policies and command sets, plus the view access needed to build and test them (users, groups, devices). Cannot touch devices, admin accounts, or apply configuration.",
        "permissions": [
            "policies:view", "policies:write",
            "tacacs_users:view", "groups:view", "devices:view",
            "accounting:view", "diagnostics:view", "config:view",
        ],
    },
    {
        "name": "Device Operator",
        "description": "Full control over devices and device groups, plus the view access needed for day-to-day network operations. Cannot manage policies, admin accounts, or platform settings.",
        "permissions": [
            "devices:view", "devices:write",
            "tacacs_users:view", "groups:view", "policies:view",
            "accounting:view", "accounting:export", "diagnostics:view",
        ],
    },
]
