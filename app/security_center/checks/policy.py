"""
app.security_center.checks.policy
====================================
Default check thresholds, migrated verbatim from cisco-ios-security-
auditor's `DEFAULT_POLICY`. The original supports a `--policy some.json`
CLI override; this project's equivalent is a future admin-editable
settings row (not built yet -- every check function below takes a
`policy: dict` parameter specifically so that hook can be added later
without changing a single check's signature, the same reason the
original made it a parameter rather than a set of module constants).
"""
from __future__ import annotations

DEFAULT_POLICY: dict = {
    "port_security_max_hosts_data": 1,
    "port_security_max_hosts_voice": 2,
    "dhcp_snooping_rate_limit_min": 5,
    "dhcp_snooping_rate_limit_recommended_max": 10,
    "dhcp_snooping_rate_limit_hard_max": 15,
    "arp_inspection_rate_limit_hard_max": 20,
    "ssh_timeout_max_seconds": 60,
    "ssh_auth_retries_max": 3,
    "console_exec_timeout_max_minutes": 15,
    "vty_exec_timeout_max_minutes": 15,
    "min_rsa_key_bits": 2048,
    "tacacs_radius_key_min_length": 12,
    "eem_applet_count_warn_threshold": 5,
    "weak_shared_secrets": ["cisco", "password", "secret", "admin", "changeme", "key"],
    "generic_usernames": ["admin", "cisco", "test", "guest", "user", "root"],
}
