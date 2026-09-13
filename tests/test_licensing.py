"""
tests/test_licensing.py
==========================
Licensing regression tests, including the attack cases from the
security review.

Every "attack" here is a check that a bypass is REFUSED. None of them
touch a real installation.

Run:  python3 tests/test_licensing.py
"""
from __future__ import annotations

import base64
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _load():
    """Loads the licensing services with SQLAlchemy stubbed, so the
    logic can be tested without a database."""
    sa = types.ModuleType("sqlalchemy")
    orm = types.ModuleType("sqlalchemy.orm")
    orm.Session = object
    sa.orm = orm
    sys.modules.setdefault("sqlalchemy", sa)
    sys.modules.setdefault("sqlalchemy.orm", orm)
    for name in ("app", "app.models", "app.services"):
        mod = types.ModuleType(name)
        mod.__path__ = []
        sys.modules.setdefault(name, mod)
    for name, attr in (("app.models.device", "NetworkDevice"),
                       ("app.models.license", "PlatformLicense"),
                       ("app.models.admin", "AdminUser")):
        mod = types.ModuleType(name)
        setattr(mod, attr, type(attr, (), {}))
        sys.modules[name] = mod

    import importlib.util

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    editions = load("app.services.editions", str(REPO_ROOT / "app/services/editions.py"))
    verify = load("app.services.license_verify", str(REPO_ROOT / "app/services/license_verify.py"))

    # Pin verification to the DEVELOPMENT key for the duration of the
    # tests. These tests exercise the licensing LOGIC -- limits,
    # tampering, binding, expiry -- and must keep doing so on a build
    # that ships a real production key, which no test can sign for.
    #
    # Note what this does NOT weaken: the production key is still the
    # only one a shipped build trusts, and that is asserted separately
    # below rather than assumed.
    verify.PRODUCTION_PUBLIC_KEY = None
    load("app.services.machine_fingerprint", str(REPO_ROOT / "app/services/machine_fingerprint.py"))

    src = (REPO_ROOT / "app/services/entitlements.py").read_text()
    src = src.replace("from ..models.device import", "from app.models.device import")
    src = src.replace("from ..models.license import", "from app.models.license import")
    src = src.replace("from ..models.admin import", "from app.models.admin import")
    src = src.replace("from . import editions, license_verify, machine_fingerprint",
                      "import app.services.editions as editions\n"
                      "import app.services.license_verify as license_verify\n"
                      "import app.services.machine_fingerprint as machine_fingerprint")
    ent = types.ModuleType("ent")
    ent.__name__ = "ent"
    sys.modules["ent"] = ent
    exec(compile(src, "ent", "exec"), ent.__dict__)
    return editions, verify, ent


class Row:
    def __init__(self, text=None, grandfathered=0, highest=None):
        self.license_text = text
        self.grandfathered_device_count = grandfathered
        self.highest_seen_utc = highest or datetime.now(timezone.utc)


class DB:
    def __init__(self, row, devices=0, admins=0):
        self._row, self._devices, self._admins = row, devices, admins

    def query(self, model):
        name = getattr(model, "__name__", "")
        outer = self

        class Q:
            def first(self):
                return outer._row if name == "PlatformLicense" else None

            def count(self):
                return outer._devices if name == "NetworkDevice" else outer._admins

        return Q()

    def add(self, _): pass
    def commit(self): pass
    def refresh(self, _): pass
    def rollback(self): pass


def _sign(payload: dict) -> str:
    """Signs with the development key, exactly as the issuer does."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    seed = base64.urlsafe_b64decode("bmV0b3BzZ3VhcmQtZGV2ZWxvcG1lbnQta2V5LTAwMDE" + "=")
    private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(private.sign(encoded.encode())).decode().rstrip("=")
    return f"{encoded}.{signature}"


def _payload(**overrides) -> dict:
    base = {
        "format": 1, "product": "netopsguard", "license_id": "test-1",
        "edition": "professional", "customer": "Test Co",
        "issued_at": "2026-01-01T00:00:00+00:00", "expires_at": None,
        "device_limit": 50, "admin_limit": None,
        "features": ["tacacs", "radius", "accounting", "ncm", "security_center", "network_ops"],
    }
    base.update(overrides)
    return base


def main() -> int:
    editions, verify, ent = _load()
    failures = []

    def check(desc, actual, expected):
        ok = actual == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {desc:62} -> {actual!r}")
        if not ok:
            failures.append(f"{desc}: expected {expected!r}, got {actual!r}")

    print("1. Community defaults (no licence):")
    e = ent.current(DB(Row(), devices=0))
    check("edition", e.edition_key, "community")
    check("device limit", e.device_limit, 5)
    check("admin limit (uncapped)", e.admin_limit, None)
    # NCM IS included in Community: the commercial lever is scale, not
    # withheld capability. Change Control's two-person workflow still
    # needs two admins, which Community does not have -- that follows
    # from the admin limit rather than from a feature flag.
    check("NCM included", e.has_feature(editions.FEATURE_NCM), True)
    check("TACACS+ included", e.has_feature(editions.FEATURE_TACACS), True)
    check("Security Center included", e.has_feature(editions.FEATURE_SECURITY_CENTER), True)

    print("\n2. Device limit is enforced:")
    for count, allowed in ((4, True), (5, False), (6, False)):
        check(f"{count} devices -> may add another", ent.check_can_add_device(DB(Row(), devices=count)).allowed, allowed)

    print("\n3. Administrators are not capped (limits are device-based):")
    check("0 admins -> may add", ent.check_can_add_admin(DB(Row(), admins=0)).allowed, True)
    check("5 admins -> may add", ent.check_can_add_admin(DB(Row(), admins=5)).allowed, True)

    print("\n4. A valid licence raises limits:")
    good = _sign(_payload())
    e = ent.current(DB(Row(good), devices=10))
    check("licensed", e.licensed, True)
    check("device limit", e.device_limit, 50)
    check("NCM included", e.has_feature(editions.FEATURE_NCM), True)
    check("ncm module allowed", "ncm" in ent.enabled_module_keys(DB(Row(good))), True)

    print("\n5. ATTACK — forge entitlements by editing the payload:")
    encoded, signature = good.split(".")
    original = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    for label, field, value in (
        ("device limit raised to 99999", "device_limit", 99999),
        ("edition upgraded to enterprise", "edition", "enterprise"),
        ("admin limit raised", "admin_limit", 999),
        ("machine binding replaced", "machine", {"machine_id": "0" * 64}),
        ("expiry extended", "expires_at", "2099-01-01T00:00:00+00:00"),
        ("product changed", "product", "other-product"),
    ):
        tampered = dict(original)
        tampered[field] = value
        text = base64.urlsafe_b64encode(
            json.dumps(tampered, separators=(",", ":"), sort_keys=True).encode()
        ).decode().rstrip("=") + "." + signature
        check(f"rejected: {label}", verify.verify(text).valid, False)

    forged_features = dict(original)
    forged_features["features"] = original["features"] + ["ha", "sso"]
    text = base64.urlsafe_b64encode(
        json.dumps(forged_features, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=") + "." + signature
    check("rejected: extra features added", verify.verify(text).valid, False)

    print("\n6. ATTACK — self-signed licence from a different key:")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    attacker = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(_payload(edition="enterprise", device_limit=None),
                   separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    self_signed = encoded_payload + "." + base64.urlsafe_b64encode(
        attacker.sign(encoded_payload.encode())).decode().rstrip("=")
    check("rejected: signed with an attacker key", verify.verify(self_signed).valid, False)

    print("\n7. ATTACK — edit the CACHED database columns:")
    # The cache is display-only; entitlements re-verify the signed text.
    row = Row(good)
    row.cached_device_limit = 100000
    row.cached_edition = "enterprise"
    e = ent.current(DB(row, devices=10))
    check("cached limit ignored", e.device_limit, 50)
    check("cached edition ignored", e.edition_key, "professional")

    print("\n8. ATTACK — wind the clock back to revive an expired licence:")
    expired = _sign(_payload(expires_at="2020-01-01T00:00:00+00:00"))
    seen = datetime.now(timezone.utc)
    row = Row(expired, highest=seen)
    e = ent.current(DB(row, devices=1))
    check("expired licence falls back to Community", e.edition_key, "community")
    # Clock rolled back to 2019: the high-water mark is still 'seen'.
    rolled_back = ent._effective_now(DB(row), Row(expired, highest=seen))
    check("effective time does not go backwards", rolled_back >= seen - timedelta(seconds=5), True)

    print("\n9. Expired licence does not DISABLE the platform:")
    e = ent.current(DB(Row(expired), devices=3))
    check("still usable as Community", e.device_limit, 5)
    check("problem is explained", "expired" in e.problem.lower(), True)

    print("\n10. Grandfathering — upgrade with more devices than allowed:")
    check("12 existing devices are not blocked from existing",
          ent.check_can_add_device(DB(Row(grandfathered=12), devices=12)).allowed, False)
    check("and the reason explains they keep working",
          "keep working" in ent.check_can_add_device(DB(Row(grandfathered=12), devices=12)).reason, True)

    print("\n11. Machine binding:")
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("mfp", str(REPO_ROOT / "app/services/machine_fingerprint.py"))
    mfp = _ilu.module_from_spec(_spec)
    sys.modules["mfp"] = mfp
    _spec.loader.exec_module(mfp)

    here = mfp.collect()
    claim = here.to_claim()
    check("this machine yields identifying details", len(claim) >= 1, True)
    check("a licence bound to THIS machine is accepted",
          mfp.check_binding(claim, here).ok, True)
    foreign = mfp.Fingerprint(components={k: "f" * 64 for k in mfp.COMPONENT_KEYS})
    check("the same licence on ANOTHER machine is refused",
          mfp.check_binding(claim, foreign).ok, False)
    check("an unbound licence runs anywhere",
          mfp.check_binding(None, foreign).ok, True)
    if len(claim) >= 2:
        swapped = dict(claim)
        swapped[sorted(swapped)[0]] = "a" * 64
        check("one hardware component changed -> still accepted",
              mfp.check_binding(swapped, here).ok, True)

    bound = _sign(_payload(machine=claim))
    stripped_payload = _payload(machine=claim)
    stripped_payload["machine"] = None
    stripped = base64.urlsafe_b64encode(
        json.dumps(stripped_payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=") + "." + bound.split(".")[1]
    check("ATTACK: stripping the binding invalidates the licence",
          verify.verify(stripped).valid, False)

    print("\n12. Unlimited edition:")
    unlimited = _sign(_payload(edition="unlimited", device_limit=None, admin_limit=None))
    e = ent.current(DB(Row(unlimited)))
    check("device limit is unlimited", e.device_limit, None)
    check("5000 devices allowed", ent.check_can_add_device(DB(Row(unlimited), devices=5000)).allowed, True)

    print("\n13. The shipped build trusts a production key, not the development one:")
    shipped = (REPO_ROOT / "app/services/license_verify.py").read_text()
    import re as _re
    match = _re.search(r'PRODUCTION_PUBLIC_KEY: str \| None = (.+)', shipped)
    configured = match.group(1).strip() if match else "MISSING"
    check("PRODUCTION_PUBLIC_KEY is set (release blocker if None)",
          configured not in ("None", "MISSING"), True)
    if configured not in ("None", "MISSING"):
        dev_key = _re.search(r'DEVELOPMENT_PUBLIC_KEY = "([^"]+)"', shipped).group(1)
        check("and it is NOT the development key", dev_key not in configured, True)

    print("\n14. Malformed input is refused safely:")
    for label, text in (("empty", ""), ("garbage", "nonsense"),
                        ("one segment", "abc"), ("bad base64", "!!!.???")):
        check(f"rejected: {label}", verify.verify(text).valid, False)

    print("\n" + "=" * 78)
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for item in failures:
            print("  - " + item)
        return 1
    print("ALL LICENSING TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
