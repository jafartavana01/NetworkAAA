"""
app.services.ad_directory
============================
Direct LDAP connectivity FROM this management plane to Active
Directory -- genuinely distinct from configuring tac_plus-ng's OWN
separate MAVIS-based AD backend (see app.services.config_compiler's
AD integration section). This module is a real, standard LDAP client
using `ldap3` (a pure-Python implementation, no OpenLDAP system
library dependency): it performs an actual bind and search against
the configured server, using the actual stored credentials.

WHY THIS IS A SEPARATE CLAIM FROM "tac_plus-ng's AD authentication
works": a successful bind/search here proves this platform can reach
AD with these settings -- useful for testing connectivity, running a
health check, and letting an admin browse real AD users/groups rather
than typing names blind. It does NOT prove tac_plus-ng's own,
completely separate Perl-based mavis_tacplus_ads.pl integration is
configured identically and will also succeed -- that's a different
process, reading the same settings from the generated config file,
which this module has no way to directly observe succeeding or
failing. The GUI says this distinction directly, not just this
docstring.

Every function is read-only and defensive: a connection failure,
timeout, or bad credential produces a clear (success=False, message)
result, never a raised exception the caller has to know to catch, and
never a partial/ambiguous result.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import security
from ..models.ad_settings import AdSettings


@dataclass
class AdTestResult:
    success: bool
    message: str
    detail: dict = field(default_factory=dict)


def _get_connection(settings: AdSettings, *, bind_password: str | None = None):
    """
    Builds a real ldap3 Connection object from the given settings.
    `bind_password` overrides the stored (encrypted) one -- used when
    testing a password the admin just typed but hasn't saved yet, so
    "Test Connection" can validate credentials before committing them.
    Raises normal ldap3/socket exceptions on failure -- callers in
    this module catch them; this is the one internal helper that
    doesn't itself return an AdTestResult.
    """
    import ldap3

    password = bind_password
    if password is None and settings.bind_password_encrypted:
        password = security.decrypt_secret(settings.bind_password_encrypted)

    server = ldap3.Server(settings.host, port=settings.port, use_ssl=settings.use_tls, get_info=ldap3.NONE)
    conn = ldap3.Connection(
        server,
        user=settings.bind_dn or None,
        password=password or None,
        auto_bind=False,
        receive_timeout=10,
    )
    return conn


def test_connection(settings: AdSettings, *, bind_password: str | None = None) -> AdTestResult:
    """
    A real LDAP bind, followed by a real (limited, count-only) search
    against the configured search base -- confirms both "the server is
    reachable and these credentials are accepted" AND "the search base
    is valid and readable by this account," which a bind alone would
    not catch (a wrong search_base is a common, otherwise-silent
    misconfiguration).
    """
    if not settings.host:
        return AdTestResult(False, "No AD server host configured.")

    try:
        conn = _get_connection(settings, bind_password=bind_password)
    except Exception as exc:  # pragma: no cover - defensive, ldap3 construction rarely fails
        return AdTestResult(False, f"Could not construct LDAP connection: {exc}")

    try:
        if not conn.bind():
            return AdTestResult(False, f"Bind failed: {conn.result.get('description', 'unknown error')}")
    except Exception as exc:
        return AdTestResult(False, f"Could not connect to {settings.host}:{settings.port} -- {exc}")

    detail = {"bind_result": conn.result.get("description", "success")}

    if settings.search_base:
        try:
            import ldap3
            found = conn.search(
                search_base=settings.search_base,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=[],
            )
            if not found:
                conn.unbind()
                return AdTestResult(
                    False,
                    f"Bind succeeded, but the search base '{settings.search_base}' could not be read: "
                    f"{conn.result.get('description', 'unknown error')}",
                    detail=detail,
                )
            detail["search_base_readable"] = True
        except Exception as exc:
            conn.unbind()
            return AdTestResult(False, f"Bind succeeded, but searching the search base failed: {exc}", detail=detail)

    conn.unbind()
    return AdTestResult(True, "Connected and bound successfully.", detail=detail)


def search_groups(settings: AdSettings, query: str, *, limit: int = 25) -> list[dict]:
    """Real LDAP search for group objects whose CN contains `query`
    (case-insensitive substring, via a wildcard filter) -- returns
    [] on ANY failure (bad credentials, unreachable server, bad
    search base) rather than raising, since this backs a live-search
    GUI picker where a transient failure should just show "no
    results," not crash the page."""
    if not settings.host or not settings.search_base:
        return []
    try:
        conn = _get_connection(settings)
        if not conn.bind():
            return []
        import ldap3
        safe_query = query.replace("*", "").replace("(", "").replace(")", "").replace("\\", "")
        conn.search(
            search_base=settings.search_base,
            search_filter=f"(&(objectClass=group)(cn=*{safe_query}*))",
            search_scope=ldap3.SUBTREE,
            attributes=["cn", "distinguishedName"],
            size_limit=limit,
        )
        results = [
            {"cn": str(entry["cn"]), "dn": str(entry.get("distinguishedName", entry.entry_dn))}
            for entry in conn.entries
        ]
        conn.unbind()
        return results
    except Exception:
        return []


def search_users(settings: AdSettings, query: str, *, limit: int = 25) -> list[dict]:
    """Real LDAP search for user objects whose sAMAccountName or
    displayName contains `query`. Same fail-quiet-to-empty-list
    behavior as search_groups, for the same reason."""
    if not settings.host or not settings.search_base:
        return []
    try:
        conn = _get_connection(settings)
        if not conn.bind():
            return []
        import ldap3
        safe_query = query.replace("*", "").replace("(", "").replace(")", "").replace("\\", "")
        conn.search(
            search_base=settings.search_base,
            search_filter=f"(&(objectClass=user)(|(sAMAccountName=*{safe_query}*)(displayName=*{safe_query}*)))",
            search_scope=ldap3.SUBTREE,
            attributes=["sAMAccountName", "displayName", "userPrincipalName"],
            size_limit=limit,
        )
        results = []
        for entry in conn.entries:
            sam = str(entry["sAMAccountName"]) if "sAMAccountName" in entry else ""
            upn = str(entry["userPrincipalName"]) if "userPrincipalName" in entry else ""
            display = str(entry["displayName"]) if "displayName" in entry else ""
            results.append({"sam_account_name": sam, "upn": upn, "display_name": display})
        conn.unbind()
        return results
    except Exception:
        return []
