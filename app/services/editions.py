"""
app.services.editions
========================
The business model, in one place.

Everything about editions -- limits, which features they include, how
they are named -- lives here and nowhere else. A module never asks
"are we Community?"; it asks the entitlement service whether a feature
is available. That means changing the commercial model later is a data
change in this file, not a hunt through the codebase.

`FEATURES` is the vocabulary. A feature key appears here once, and is
referenced by key everywhere else, so a typo in a module fails loudly
rather than silently granting access.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- Feature keys -----------------------------------------------------
#
# Keys are stable identifiers written into signed licenses, so renaming
# one breaks every license already issued. Add new keys; do not rename
# existing ones.
FEATURE_TACACS = "tacacs"
FEATURE_RADIUS = "radius"
FEATURE_ACCOUNTING = "accounting"
FEATURE_NCM = "ncm"
FEATURE_SECURITY_CENTER = "security_center"
FEATURE_NETWORK_OPS = "network_ops"
# Deliberately NOT defined: HA, multi-site, SSO and metered API access.
# None of them exist in the product today, and a licence tier that
# gates a capability the software does not have is selling something
# that cannot be delivered. Add the key here when the capability
# ships, not before.


@dataclass(frozen=True)
class Feature:
    key: str
    name: str
    description: str
    #: The module key this feature gates, when it gates one. Used to
    #: hide a whole module's navigation and routes; a feature with no
    #: module is enforced at its own call sites instead.
    module_key: str | None = None


FEATURES: tuple = (
    Feature(FEATURE_TACACS, "TACACS+",
            "Device administration AAA: authentication, command authorization and accounting.",
            module_key="tacacs"),
    Feature(FEATURE_RADIUS, "RADIUS",
            "RADIUS authentication and authorization for devices that do not speak TACACS+.",
            module_key="radius"),
    Feature(FEATURE_ACCOUNTING, "Accounting & Reporting",
            "Session history, command accounting, access events and AAA health."),
    Feature(FEATURE_NETWORK_OPS, "Network Operations",
            "Run command jobs against devices from templates.",
            module_key="network_ops"),
    Feature(FEATURE_SECURITY_CENTER, "Security Center",
            "Configuration auditing, findings, compliance mapping and remediation guidance.",
            module_key="security_center"),
    Feature(FEATURE_NCM, "Configuration Management",
            "Configuration backup, archive, diff, drift detection and change control.",
            module_key="ncm"),
)

FEATURES_BY_KEY = {f.key: f for f in FEATURES}


@dataclass(frozen=True)
class Edition:
    key: str
    name: str
    device_limit: int | None          # None means unlimited
    admin_limit: int | None
    features: frozenset
    description: str = ""

    def allows(self, feature_key: str) -> bool:
        return feature_key in self.features


#: ---------------------------------------------------------------------
#: Editions
#: ---------------------------------------------------------------------
#:
#: Tiers differ by DEVICE COUNT and nothing else. Every edition gets
#: every feature the product has.
#:
#: This is deliberate. Gating a capability the software does not yet
#: have would be selling something undeliverable, and gating one it
#: does have makes a security product weaker for the people least able
#: to pay. Device count is an honest meter: it tracks the value the
#: customer gets and the cost of supporting them.
#:
#: `admin_limit` is None everywhere. An administrator account is not a
#: cost driver, and capping it would break workflows that need a second
#: person -- NCM Change Control refuses self-approval, so a one-admin
#: cap would silently disable it. Kept as a field so a future edition
#: could set it without reworking the model.
COMMUNITY = Edition(
    key="community", name="Community",
    device_limit=5, admin_limit=None,
    features=frozenset(FEATURES_BY_KEY),
    description="Free forever. The complete platform, for a small network.",
)

STARTER = Edition(
    key="starter", name="Starter",
    device_limit=15, admin_limit=None,
    features=frozenset(FEATURES_BY_KEY),
    description="For a small site or a lab.",
)

PROFESSIONAL = Edition(
    key="professional", name="Professional",
    device_limit=50, admin_limit=None,
    features=frozenset(FEATURES_BY_KEY),
    description="For a single campus or branch network.",
)

BUSINESS = Edition(
    key="business", name="Business",
    device_limit=100, admin_limit=None,
    features=frozenset(FEATURES_BY_KEY),
    description="For a multi-site network.",
)

ENTERPRISE = Edition(
    key="enterprise", name="Enterprise",
    device_limit=300, admin_limit=None,
    features=frozenset(FEATURES_BY_KEY),
    description="For a large estate.",
)

UNLIMITED = Edition(
    key="unlimited", name="Unlimited",
    device_limit=None, admin_limit=None,
    features=frozenset(FEATURES_BY_KEY),
    description="No device limit.",
)

EDITIONS = {e.key: e for e in (COMMUNITY, STARTER, PROFESSIONAL, BUSINESS, ENTERPRISE, UNLIMITED)}

#: The edition an installation runs with when it holds no licence. Not
#: an error state -- Community is a supported, permanent configuration.
DEFAULT_EDITION = COMMUNITY


def get_edition(key: str | None):
    """Unknown edition keys fall back to Community rather than raising.

    A licence naming an edition this build does not know about is
    likelier to be a NEWER licence than an attack -- and downgrading to
    Community is both safe and visible, whereas crashing on startup
    would take a working installation offline over a label."""
    return EDITIONS.get((key or "").lower(), DEFAULT_EDITION)
