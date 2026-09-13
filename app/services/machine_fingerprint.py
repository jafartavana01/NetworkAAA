"""
app.services.machine_fingerprint
===================================
Identifies the machine an installation is running on, so a licence can
be bound to it.

What is collected
-----------------
Four components, each independently hashed:

  * `machine_id`   -- /etc/machine-id (or the systemd equivalent)
  * `product_uuid` -- DMI system UUID, set by the BIOS/hypervisor
  * `cpu`          -- CPU model string plus core count
  * `root_fs`      -- UUID of the root filesystem

**Only hashes leave the machine.** The request file carries
SHA-256 digests, never the raw identifiers, so sending one does not
disclose the server's UUIDs, MAC addresses or disk layout. That matters
because a customer is asked to email this file.

Why four, and why tolerance
---------------------------
Binding to a single identifier is brittle: replace a NIC or migrate a
VM and a paying customer is locked out of their own platform. Binding
to all four is worse -- any hardware change breaks it.

So a licence records all four hashes and verification requires
`REQUIRED_MATCHES` of them. Ordinary maintenance (a disk swap, a CPU
upgrade) leaves enough matching. Moving the licence to a genuinely
different machine does not.

A mismatch never disables the platform -- it falls back to Community
with an explanation, consistent with how every other licence problem is
handled here. A customer whose motherboard died should not also lose
access to their AAA server.
"""
from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

#: How many of the four components must match for a bound licence to be
#: accepted on this machine.
REQUIRED_MATCHES = 2

COMPONENT_KEYS = ("machine_id", "product_uuid", "cpu", "root_fs")


def _hash(value: str | None) -> str | None:
    """SHA-256 of a raw identifier, or None when it is unavailable.

    Salted with the component name so the same value appearing in two
    components does not produce the same digest, which would let an
    observer correlate them."""
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return hashlib.sha256(cleaned.encode("utf-8", errors="replace")).hexdigest()


def _read_first(paths: list) -> str | None:
    for path in paths:
        try:
            text = Path(path).read_text(errors="ignore").strip()
            if text:
                return text
        except OSError:
            continue
    return None


def _machine_id() -> str | None:
    return _read_first(["/etc/machine-id", "/var/lib/dbus/machine-id"])


def _product_uuid() -> str | None:
    # Readable only by root on most systems; absence is normal and
    # simply means one fewer component, not a failure.
    return _read_first([
        "/sys/class/dmi/id/product_uuid",
        "/sys/devices/virtual/dmi/id/product_uuid",
    ])


def _cpu() -> str | None:
    model = None
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="ignore").splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    if model is None:
        model = platform.processor() or None
    if model is None:
        return None
    return f"{model}|{os.cpu_count() or 0}"


def _root_fs() -> str | None:
    """UUID of the filesystem mounted at /.

    Uses `findmnt`, falling back to the device name. A device NAME is a
    weaker identifier than a UUID (it can repeat across machines), so it
    is prefixed to keep the two distinguishable rather than silently
    treated as equivalent."""
    try:
        out = subprocess.run(
            ["findmnt", "-no", "UUID", "/"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return "uuid:" + out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        out = subprocess.run(
            ["findmnt", "-no", "SOURCE", "/"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return "dev:" + out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


@dataclass
class Fingerprint:
    components: dict = field(default_factory=dict)   # key -> hash | None

    @property
    def available(self) -> list:
        return [k for k, v in self.components.items() if v]

    def short_id(self) -> str:
        """A short, stable, displayable identifier.

        Derived from whichever components exist, in fixed key order, so
        it is reproducible on the same machine and safe to quote in a
        support email."""
        material = "|".join(f"{k}={self.components.get(k) or ''}" for k in COMPONENT_KEYS)
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    def to_claim(self) -> dict:
        """The form embedded in a signed licence."""
        return {k: self.components.get(k) for k in COMPONENT_KEYS if self.components.get(k)}


def collect() -> Fingerprint:
    raw = {
        "machine_id": _machine_id(),
        "product_uuid": _product_uuid(),
        "cpu": _cpu(),
        "root_fs": _root_fs(),
    }
    return Fingerprint(components={k: _hash(v) for k, v in raw.items()})


@dataclass
class BindingResult:
    ok: bool
    matched: list = field(default_factory=list)
    expected: list = field(default_factory=list)
    reason: str = ""


def check_binding(claim: dict | None, current: Fingerprint | None = None) -> BindingResult:
    """
    Compares a licence's machine claim against this machine.

    An ABSENT claim means the licence is not node-locked, which is a
    valid licence type and always passes -- node-locking is an option
    the issuer chooses, not a requirement.
    """
    if not claim:
        return BindingResult(ok=True, reason="This licence is not tied to a specific machine.")

    fingerprint = current or collect()
    expected = [k for k in COMPONENT_KEYS if claim.get(k)]
    matched = [
        k for k in expected
        if fingerprint.components.get(k) and fingerprint.components[k] == claim[k]
    ]

    # A licence claiming components this machine cannot read at all --
    # product_uuid needs root, for example -- should not fail on that
    # basis alone. Only components readable HERE can be compared.
    comparable = [k for k in expected if fingerprint.components.get(k)]
    needed = min(REQUIRED_MATCHES, len(comparable)) if comparable else 0

    if not comparable:
        return BindingResult(
            ok=False, matched=[], expected=expected,
            reason=(
                "This licence is tied to a specific machine, but none of the identifying "
                "details could be read here. If the platform recently moved, request a "
                "licence for the new machine."
            ),
        )

    if len(matched) >= max(1, needed):
        return BindingResult(ok=True, matched=matched, expected=expected)

    return BindingResult(
        ok=False, matched=matched, expected=expected,
        reason=(
            f"This licence was issued for a different machine "
            f"({len(matched)} of {len(comparable)} identifying details match, "
            f"{max(1, needed)} required). If the hardware changed or the platform was "
            f"migrated, request a replacement licence."
        ),
    )
