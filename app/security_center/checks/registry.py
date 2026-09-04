"""
app.security_center.checks.registry
======================================
Maps each of the 9 device-level domains to its check function list and
CLI-flag-equivalent key, mirroring cisco-ios-security-auditor's own
DOMAIN_REGISTRY structure and keys exactly (mgmt/l2/l3/cp/vpn/zbfw/
pki/physical/misc) so anything that already reasons in terms of those
keys (the compliance mapping JSON files, migrated verbatim, reference
domains by these same names) needs no translation layer.
"""
from __future__ import annotations

from .copp import COPP_CHECKS
from .layer2 import LAYER2_CHECKS
from .layer3 import LAYER3_CHECKS
from .management import MANAGEMENT_CHECKS
from .misc import MISC_CHECKS
from .physical import PHYSICAL_CHECKS
from .pki import PKI_CHECKS
from .vpn import VPN_CHECKS
from .zbfw import ZBFW_CHECKS

DOMAIN_REGISTRY: dict[str, dict] = {
    "mgmt": {"label": "Management Plane", "funcs": MANAGEMENT_CHECKS},
    "l2": {"label": "Layer 2 Security", "funcs": LAYER2_CHECKS},
    "l3": {"label": "Layer 3 Security", "funcs": LAYER3_CHECKS},
    "cp": {"label": "Control Plane / CoPP", "funcs": COPP_CHECKS},
    "vpn": {"label": "IPsec / VPN", "funcs": VPN_CHECKS},
    "zbfw": {"label": "Zone-Based Firewall", "funcs": ZBFW_CHECKS},
    "pki": {"label": "Cryptography / PKI", "funcs": PKI_CHECKS},
    "physical": {"label": "Physical / Boot Security", "funcs": PHYSICAL_CHECKS},
    "misc": {"label": "Unnecessary Services / Misc", "funcs": MISC_CHECKS},
}


def run_all_device_checks(cfg, policy, ctx) -> list:
    """Runs every domain's checks in registry order and returns the
    combined finding list -- the device-level equivalent of
    cisco_audit.py's own --all CLI flag."""
    findings = []
    for domain in DOMAIN_REGISTRY.values():
        for func in domain["funcs"]:
            findings.extend(func(cfg, policy, ctx))
    return findings
