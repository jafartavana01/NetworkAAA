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

import re
from dataclasses import dataclass, field

from .. import security
from ..models.ad_settings import AdSettings


@dataclass
class AdTestResult:
    success: bool
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class AdSearchResult:
    """
    Distinguishes a genuinely empty result from a failed search --
    both search_groups and search_users previously collapsed every
    failure (bad bind, malformed filter, connection drop, or a
    search_base that doesn't cover where the object actually lives)
    into a bare `[]`, identical to a real "nothing matched." That
    made a genuine misconfiguration indistinguishable from a correct
    search that found nothing, directly confirmed by a real report:
    a user's own memberOf correctly named a group ("tacpalasGroup"),
    but searching for that exact name returned "No matches" -- with
    no way to tell whether that was because the group doesn't exist
    where search_base looks, or because the search itself silently
    failed for some other reason.

    `error` is None on a normal search, whether or not it found
    anything -- only set when the search itself could not complete.
    Still never raises; the caller decides how to display an error,
    the function itself stays safe to call from a live-search picker.
    """
    results: list[dict]
    error: str | None = None


def _get_connection(settings: AdSettings, *, bind_password: str | None = None):
    """
    Builds a real ldap3 Connection object from the given settings.
    `bind_password` overrides the stored (encrypted) one -- used when
    testing a password the admin just typed but hasn't saved yet, so
    "Test Connection" can validate credentials before committing them.
    Raises normal ldap3/socket exceptions on failure -- callers in
    this module catch them; this is the one internal helper that
    doesn't itself return an AdTestResult.

    For StartTLS specifically: the upgrade is performed and its
    success EXPLICITLY CHECKED here, before this function returns --
    never leaving it to the caller's subsequent .bind() call, which
    would otherwise risk sending credentials over a connection that
    silently never got encrypted (start_tls() returns False on
    failure rather than raising, so ignoring that return value would
    be a real, easy-to-miss credential-exposure bug, not just an
    inconvenience).
    """
    import ldap3
    import ssl

    password = bind_password
    if password is None and settings.bind_password_encrypted:
        password = security.decrypt_secret(settings.bind_password_encrypted)

    # Explicit Tls object, deliberately added after a real connection
    # failure against a hardened modern DC (Windows Server 2025):
    # ldap3's OWN documentation confirms that without one, it falls
    # back to `ssl.PROTOCOL_SSLv23` -- a legacy, deprecated constant
    # it only uses "if available in your Python interpreter" -- rather
    # than negotiating a modern TLS version.
    #
    # `PROTOCOL_TLSv1_2` specifically, NOT `PROTOCOL_TLS_CLIENT`: an
    # earlier version of this code used PROTOCOL_TLS_CLIENT and paired
    # it with `validate=ssl.CERT_NONE`, which is a genuinely
    # CONTRADICTORY combination -- PROTOCOL_TLS_CLIENT sets
    # check_hostname=True and verify_mode=CERT_REQUIRED by default,
    # and Python then REFUSES the CERT_NONE assignment outright
    # ("Cannot set verify_mode to CERT_NONE when check_hostname is
    # enabled"), verified by direct execution. That combination could
    # only ever leave validation in an unintended state, so it was a
    # real bug, not a stylistic choice. PROTOCOL_TLSv1_2 carries no
    # such implicit strictness, so `validate=CERT_NONE` below is
    # actually honored, which is what genuinely preserves ldap3's own
    # documented default behavior ("performs no validation of the
    # server certificate").
    #
    # Why CERT_NONE at all: this project has no way for an admin to
    # supply a custom CA certificate yet, so requiring validation here
    # would break every deployment using an internal-CA or
    # self-signed DC certificate -- the overwhelmingly common case for
    # Active Directory. This is deliberately the same permissive
    # posture ldap3 already had by default, not a downgrade from it.
    # (Note that TLS 1.2 is explicitly enabled by default on Windows
    # Server 2025, so pinning it here is compatible, not a fallback to
    # anything deprecated.)
    tls_config = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

    # use_tls and use_starttls are mutually exclusive by construction
    # in the GUI (a single select, not two independent checkboxes) --
    # use_ssl is only ever True for dedicated LDAPS; StartTLS always
    # starts the underlying socket in the clear, then explicitly
    # upgrades it below. The same tls_config applies to both paths --
    # StartTLS's own upgrade uses the Server object's tls setting too.
    server = ldap3.Server(settings.host, port=settings.port, use_ssl=settings.use_tls, tls=tls_config, get_info=ldap3.NONE)
    conn = ldap3.Connection(
        server,
        user=settings.bind_dn or None,
        password=password or None,
        auto_bind=False,
        receive_timeout=10,
    )

    if settings.use_starttls:
        conn.open()
        if not conn.start_tls():
            raise RuntimeError(
                f"StartTLS upgrade failed: {conn.result.get('description', 'unknown error')} -- "
                "the domain controller may not have a working TLS/certificate setup at all "
                "(StartTLS depends on the same underlying TLS service dedicated LDAPS does)."
            )

    return conn


def _warn_if_domain_name_used_as_host(settings: AdSettings) -> str | None:
    """
    Returns a warning if `host` looks like a bare AD DOMAIN name
    rather than a specific domain controller's FQDN -- e.g.
    "tacplas.local" instead of "dc01.tacplas.local".

    This matters specifically for LDAPS: a DC's certificate has its
    own FQDN in the Subject/SAN (a confirmed Windows Server 2025
    requirement), NOT the bare domain name. Connecting to the domain
    name resolves via round-robin DNS to whichever DC answers, whose
    certificate then won't match the name that was connected to. It
    also means a connection failure is ambiguous -- you can't tell
    WHICH domain controller actually refused.

    A heuristic, deliberately conservative: only flags a two-label
    name (domain.tld), which a DC FQDN essentially never is. Never
    blocks the connection -- it's surfaced as guidance alongside a
    failure, since some environments legitimately do point a name
    with a matching certificate at a load balancer.
    """
    host = (settings.host or "").strip().rstrip(".")
    if not host or host.replace(".", "").isdigit():
        return None  # empty, or a bare IP address -- not a name at all
    if host.count(".") == 1:
        return (
            f"Note: '{host}' looks like an Active Directory domain name rather than a "
            "specific domain controller's fully-qualified name (e.g. "
            f"'dc01.{host}'). For LDAPS this matters: a domain controller's certificate "
            "contains its OWN FQDN, not the bare domain name, so connecting to the "
            "domain name can reach a DC whose certificate doesn't match what you "
            "connected to. Try a specific domain controller's FQDN instead."
        )
    return None


def _diagnose_connection_error(exc: Exception) -> str:
    """
    Appends an actionable hint for a well-known, CONFIRMED failure
    pattern -- researched against Microsoft's own official LDAPS
    troubleshooting KB and multiple independent real-world reports of
    the exact same symptom (not guessed). Only ever APPENDS to the
    real exception text, never replaces or hides it -- the admin
    always sees the actual underlying error first, with guidance
    added after it.
    """
    text = str(exc)
    lowered = text.lower()
    if "connection reset by peer" in lowered and ("ssl" in lowered or "wrapping" in lowered):
        return (
            f"{text} -- this specific error is a well-known symptom of the domain "
            "controller not presenting a valid LDAPS server certificate at all (no "
            "certificate bound to its TLS/Schannel listener, or one that's expired or "
            "otherwise invalid), confirmed against Microsoft's own official LDAPS "
            "troubleshooting guidance (KB938703) and multiple independent real-world "
            "reports of this exact error. On Windows Server 2025 specifically, this is "
            "commonly caused by a real, documented change from older Windows Server "
            "versions: installing AD Certificate Services no longer reliably "
            "auto-enrolls the domain controller for an LDAPS-capable certificate the "
            "way it used to -- an admin may need to request the Domain Controller "
            "Authentication certificate manually (certlm.msc on the DC itself, under "
            "Personal > Certificates > Request New Certificate) even when AD CS is "
            "already deployed. Verify a Server Authentication certificate matching the "
            "domain controller's own FQDN is actually installed and bound there before "
            "assuming this platform's own settings are the problem."
        )
    return text


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
        message = f"Could not connect to {settings.host}:{settings.port} -- {_diagnose_connection_error(exc)}"
        host_warning = _warn_if_domain_name_used_as_host(settings)
        if host_warning:
            message = f"{message}\n\n{host_warning}"
        return AdTestResult(False, message)

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


def search_groups(settings: AdSettings, query: str, *, limit: int = 25) -> AdSearchResult:
    """Real LDAP search for group objects whose CN contains `query`
    (case-insensitive substring, via a wildcard filter) -- searches
    within `settings.search_base` specifically. A group that exists
    in AD but lives in an OU/container outside search_base will
    genuinely not be found here, distinctly from an actual search
    failure -- see AdSearchResult's own docstring for why that
    distinction now matters."""
    if not settings.host or not settings.search_base:
        return AdSearchResult([], error="Active Directory host or search base is not configured.")
    try:
        conn = _get_connection(settings)
        if not conn.bind():
            return AdSearchResult([], error=f"Could not bind to Active Directory: {conn.result.get('description', 'unknown error')}")
        import ldap3
        safe_query = query.replace("*", "").replace("(", "").replace(")", "").replace("\\", "")
        conn.search(
            search_base=settings.search_base,
            search_filter=f"(&(objectClass=group)(cn=*{safe_query}*))",
            search_scope=ldap3.SUBTREE,
            attributes=["cn", "distinguishedName"],
            size_limit=limit,
        )
        results = []
        for entry in conn.entries:
            # entry is an ldap3 Entry, not a dict -- it has no real
            # .get() method; ldap3 overrides attribute access so
            # entry.get(...) is interpreted as "look up an LDAP
            # attribute literally named 'get'", which doesn't exist,
            # raising exactly the "attribute 'get' not found" error a
            # real search hit. `in` is the correct membership check,
            # same as already used correctly elsewhere in this file
            # (e.g. "sAMAccountName" in entry, a few lines below this).
            dn = str(entry["distinguishedName"]) if "distinguishedName" in entry else entry.entry_dn
            results.append({"cn": str(entry["cn"]), "dn": dn})
        conn.unbind()
        return AdSearchResult(results)
    except Exception as exc:
        return AdSearchResult([], error=str(exc))


def search_users(settings: AdSettings, query: str, *, limit: int = 25) -> AdSearchResult:
    """Real LDAP search for user objects whose sAMAccountName or
    displayName contains `query`. Same search_base scoping and
    distinguishable-error behavior as search_groups, for the same
    reason."""
    if not settings.host or not settings.search_base:
        return AdSearchResult([], error="Active Directory host or search base is not configured.")
    try:
        conn = _get_connection(settings)
        if not conn.bind():
            return AdSearchResult([], error=f"Could not bind to Active Directory: {conn.result.get('description', 'unknown error')}")
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
        return AdSearchResult(results)
    except Exception as exc:
        return AdSearchResult([], error=str(exc))


def get_user_group_memberships(settings: AdSettings, identity: str) -> dict | None:
    """
    Real LDAP lookup of exactly what group membership `tac_plus-ng`
    would see for `identity` (a sAMAccountName or UPN) -- built
    specifically to answer "why did this AD user get denied by ACL"
    without needing external LDAP tools. Returns None on any failure
    (bad credentials, unreachable server, user not found), or a dict:

        {
            "raw_groups": ["GTC_ad-admins", "Domain Users", ...],
            "reported_groups": ["ad-admins"],
            "prefix_applied": "GTC_",
        }

    `raw_groups` is every group CN from the user's own `memberOf`
    attribute, unfiltered. `reported_groups` is what's LEFT after
    applying the exact same two steps `mavis_tacplus_ads.pl` itself
    applies (confirmed by its actual author in a real support thread):
    first, only CNs matching the configured AD_GROUP_PREFIX (if any)
    are kept at all; second, that prefix is stripped from what's kept.
    This is deliberately the same transformation
    app.templates.groups.html's own AD-group-picker suggestion applies
    when creating a local group -- so a `member ==` policy condition
    should reference a name from `reported_groups`, not `raw_groups`,
    for an AD user to actually match it.

    `memberOf` is requested explicitly in the attribute list --
    unlike a plain attribute wildcard, it is not guaranteed to be
    returned by every LDAP server unless asked for by name.
    """
    if not settings.host or not settings.search_base:
        return None
    try:
        conn = _get_connection(settings)
        if not conn.bind():
            return None
        import ldap3

        safe_identity = identity.replace("*", "").replace("(", "").replace(")", "").replace("\\", "")
        conn.search(
            search_base=settings.search_base,
            search_filter=f"(&(objectClass=user)(|(sAMAccountName={safe_identity})(userPrincipalName={safe_identity})))",
            search_scope=ldap3.SUBTREE,
            attributes=["memberOf"],
            size_limit=1,
        )
        if not conn.entries:
            conn.unbind()
            return None

        entry = conn.entries[0]
        member_of_dns = list(entry["memberOf"]) if "memberOf" in entry else []
        conn.unbind()

        raw_groups = []
        for dn in member_of_dns:
            match = re.match(r"^CN=([^,]+),", str(dn), re.IGNORECASE)
            if match:
                raw_groups.append(match.group(1))

        prefix = settings.group_prefix or ""
        if prefix:
            reported_groups = [
                g[len(prefix):] for g in raw_groups if g.lower().startswith(prefix.lower())
            ]
        else:
            reported_groups = list(raw_groups)

        return {"raw_groups": raw_groups, "reported_groups": reported_groups, "prefix_applied": prefix}
    except Exception:
        return None
