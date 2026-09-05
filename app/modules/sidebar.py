"""
app.modules.sidebar
======================
Regroups the flat nav entries every app.modules.*_module.py already
contributes (via all_modules()) into the sidebar's presentation-layer
sections (Identity & Access / TACACS+ / Network Operations / Security
Center / System) -- WITHOUT moving any NavEntry between modules or
changing what module "owns" a given page. Grouping-for-display is a
presentation concern; which module implements a feature is not, and
keeping the two separate means this file is the ONLY thing that needs
to change if the sidebar's information architecture changes again,
while core_module.py/tacacs_module.py/network_ops_module.py/
security_module.py keep their own encapsulated nav_entries exactly as
before (same reasoning app.modules.registry's own docstring gives for
why each module owns its router independently).

Every path below was cross-checked against the real, current
nav_entries in all four module files at the time this was written --
not guessed. _SECTION_BY_PATH intentionally covers every existing nav
path; _uncategorized_fallback() exists only so a FUTURE module that
forgets to update this file still shows up somewhere sane (under its
own module name) rather than silently vanishing from the sidebar.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .registry import Module, NavEntry


@dataclass
class SidebarItem:
    label: str
    path: str
    icon: str
    keywords: list[str]
    requires_superadmin: bool = False


@dataclass
class SidebarSection:
    key: str
    label: str
    icon: str = "circle"
    items: list[SidebarItem] = field(default_factory=list)


# Display order, section labels, and each section's own icon --
# sections don't map 1:1 to any single existing module (e.g. Identity
# & Access draws items from both core_module.py and tacacs_module.py),
# so there's no single canonical icon to derive automatically the way
# individual item icons could theoretically come from their owning
# module; assigned directly here instead. "dashboard" is handled
# separately (rendered standalone, above every collapsible section)
# -- see build_sidebar_sections()'s own docstring.
_SECTION_ORDER: list[tuple[str, str, str]] = [
    ("identity", "Identity & Access", "users"),
    ("tacacs", "TACACS+ / RADIUS", "shield"),
    ("network_ops", "Network Operations", "terminal"),
    ("security", "Security Center", "shield-check"),
    ("system", "System", "settings"),
]

# path -> (section_key, search keywords). One entry per real nav path
# that exists today across core_module.py, tacacs_module.py,
# network_ops_module.py, and security_module.py.
_SECTION_BY_PATH: dict[str, tuple[str, list[str]]] = {
    # ---- Identity & Access ----
    "/tacacs/users": ("identity", ["user", "users", "account", "tacacs user"]),
    "/tacacs/groups": ("identity", ["group", "groups", "tacacs group"]),
    "/platform/admin-users": ("identity", ["admin", "admin user", "administrator", "platform user"]),
    "/platform/admin-roles": ("identity", ["role", "roles", "permission", "permissions", "rbac"]),
    "/platform/active-directory": ("identity", ["ad", "active directory", "ldap", "directory"]),

    # ---- TACACS+ / RADIUS ----
    "/tacacs/devices": ("tacacs", ["device", "devices", "switch", "router", "network device"]),
    "/tacacs/device-groups": ("tacacs", ["device group", "device groups"]),
    "/tacacs/policies": ("tacacs", ["policy", "policies", "authorization", "access policy"]),
    "/tacacs/command-sets": ("tacacs", ["command", "commands", "command set", "command sets"]),
    "/tacacs/command-categories": ("tacacs", ["command category", "command categories"]),
    "/tacacs/policy-simulator": ("tacacs", ["policy simulator", "simulate", "simulation"]),
    "/tacacs/effective-access": ("tacacs", ["effective access", "access lookup", "who can"]),
    "/tacacs/sessions": ("tacacs", ["session", "sessions", "active sessions"]),
    "/tacacs/accounting": ("tacacs", ["accounting", "logs", "aaa accounting", "audit log"]),
    "/tacacs/aaa-health": ("tacacs", ["aaa health", "health"]),
    "/tacacs/diagnostics": ("tacacs", ["diagnostics", "diagnose", "troubleshoot"]),

    # ---- Network Operations ----
    "/network-ops/jobs": ("network_ops", ["command job", "command jobs", "job", "jobs"]),
    "/network-ops/templates": ("network_ops", ["template", "templates", "command template"]),
    "/network-ops/checks": ("network_ops", ["check", "checks"]),
    "/network-ops/audits": ("network_ops", ["audit", "audits", "network ops audit"]),

    # ---- Security Center ----
    "/security/overview": ("security", ["security", "security center", "overview", "audit", "findings", "compliance"]),
    "/security/devices": ("security", ["security devices", "device security", "device audit", "audit device"]),
    "/security/findings": ("security", ["findings", "security findings", "vulnerabilities", "issues", "gaps"]),
    "/security/schedule": ("security", ["schedule", "scheduled audit", "automatic audit", "daily audit", "service account"]),

    # ---- System ----
    "/tacacs/config": ("system", ["configuration", "config", "tac_plus", "compile"]),
    "/platform/settings": ("system", ["settings", "network settings", "tls", "https", "certificate"]),
}


def _uncategorized_fallback(module: Module) -> tuple[str, str]:
    """A path this file hasn't been updated to categorize yet falls
    back to its own module's name as its own section, rather than
    disappearing -- see module docstring."""
    return module.key, module.name


def build_sidebar_sections(modules: list[Module], *, is_superadmin: bool) -> tuple[SidebarItem | None, list[SidebarSection]]:
    """
    Returns (dashboard_item, sections) -- Dashboard is pulled out and
    returned separately since it's rendered standalone, above every
    collapsible section, exactly as it is in the current sidebar and
    as spec section 19's own mockup shows.

    Superadmin-gating is now evaluated PER ITEM (via each leaf
    NavEntry's own requires_superadmin), not only per top-level group
    the way the current single-level sidebar.html does today -- a
    necessary change, since the new Identity & Access section mixes
    superadmin-only items (Admin Users, Roles, Active Directory) with
    non-gated ones (Users, Groups) that used to live in entirely
    separate top-level groups. The effective visibility rule for every
    existing item is unchanged: an item that was superadmin-only
    before (because its whole parent group was) is still
    superadmin-only now.
    """
    sections: dict[str, SidebarSection] = {
        key: SidebarSection(key=key, label=label, icon=icon) for key, label, icon in _SECTION_ORDER
    }
    dashboard_item: SidebarItem | None = None

    for module in modules:
        for entry in module.nav_entries:
            leaves: list[NavEntry] = entry.children if entry.children else [entry]
            # A top-level group's OWN requires_superadmin (e.g. core's
            # "Platform" group) applies to every child that doesn't
            # already set its own -- preserving today's effective
            # behavior (Admin Users/Roles/Active Directory/Settings
            # were only ever reachable because their PARENT group was
            # gated; none of them sets requires_superadmin itself).
            group_gate = entry.requires_superadmin

            for leaf in leaves:
                if not entry.children and leaf is entry:
                    # A standalone, childless top-level entry (e.g.
                    # Dashboard) -- not part of any section.
                    if leaf.path == "/dashboard":
                        dashboard_item = SidebarItem(
                            label=leaf.label, path=leaf.path, icon=leaf.icon,
                            keywords=["dashboard", "home", "overview"],
                            requires_superadmin=leaf.requires_superadmin or group_gate,
                        )
                        continue

                gated = leaf.requires_superadmin or group_gate
                if gated and not is_superadmin:
                    continue

                section_key, keywords = _SECTION_BY_PATH.get(leaf.path, (None, None))
                if section_key is None:
                    fallback_key, fallback_label = _uncategorized_fallback(module)
                    if fallback_key not in sections:
                        sections[fallback_key] = SidebarSection(key=fallback_key, label=fallback_label)
                    section_key = fallback_key
                    keywords = [leaf.label.lower()]

                sections[section_key].items.append(SidebarItem(
                    label=leaf.label, path=leaf.path, icon=leaf.icon,
                    keywords=keywords, requires_superadmin=gated,
                ))

    ordered_sections = [sections[key] for key, _, _ in _SECTION_ORDER if sections[key].items]
    # Any fallback sections (not in _SECTION_ORDER) come last, in
    # whatever order they were first encountered.
    ordered_keys = {key for key, _, _ in _SECTION_ORDER}
    for key, section in sections.items():
        if key not in ordered_keys and section.items:
            ordered_sections.append(section)

    return dashboard_item, ordered_sections
