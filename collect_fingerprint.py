#!/usr/bin/env python3
"""
collect_fingerprint.py
=========================
Produces a licence request file for this machine.

Run this on the server where NetOpsGuard is installed, then send the
resulting `.request` file to your vendor. They return a licence bound
to this machine.

    sudo python3 collect_fingerprint.py

Why sudo: one of the four identifying details (the system UUID set by
your BIOS or hypervisor) is readable only by root. It works without
sudo, just with one fewer detail.

What is in the file
-------------------
**Only hashes.** The file contains SHA-256 digests of four identifiers,
never the identifiers themselves. Your machine's UUIDs, disk layout and
hardware details are not disclosed by sending it. You can read the file
yourself -- it is plain text -- and confirm that.

A note on encryption, stated honestly
-------------------------------------
This file is ENCODED and checksummed, not encrypted. Encrypting it
would need a key shipped alongside the software, which anyone holding a
copy could extract -- so it would look like protection without being
any. The file needs integrity (has it been altered or truncated in
transit?) and that is what the checksum provides.

The security of the licensing system does not rest on this file being
secret. It rests on the licence you receive being signed with a private
key that never leaves the vendor. Someone who intercepts this file
learns four hashes and gains nothing.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
for candidate in (REPO_ROOT, REPO_ROOT.parent):
    if (candidate / "app" / "services" / "machine_fingerprint.py").exists():
        sys.path.insert(0, str(candidate))
        break

try:
    from app.services import machine_fingerprint
except ImportError:
    print("Could not find the platform's modules.", file=sys.stderr)
    print("Run this script from the NetOpsGuard installation directory.", file=sys.stderr)
    raise SystemExit(1)

REQUEST_FORMAT = 1


def build_request(contact: str, note: str) -> dict:
    fingerprint = machine_fingerprint.collect()
    body = {
        "format": REQUEST_FORMAT,
        "kind": "netopsguard-license-request",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "short_id": fingerprint.short_id(),
        # Hashes only -- see the module docstring.
        "machine": fingerprint.to_claim(),
        "components_available": fingerprint.available,
        # Context for the vendor; none of it identifies the hardware.
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "contact": contact,
        "note": note,
    }
    return body


def encode(body: dict) -> str:
    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    checksum = hashlib.sha256(payload).hexdigest()[:16]
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"NETOPSGUARD-REQUEST-1.{checksum}.{encoded}"


def decode(text: str) -> dict:
    """Used by the vendor's issuing tool. Kept here so the request
    format has exactly one definition, rather than one on each side that
    can drift apart."""
    parts = text.strip().split(".")
    if len(parts) != 3 or parts[0] != "NETOPSGUARD-REQUEST-1":
        raise ValueError("This does not look like a NetOpsGuard licence request.")
    _, checksum, encoded = parts
    payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if hashlib.sha256(payload).hexdigest()[:16] != checksum:
        raise ValueError("The request file is corrupt or was altered in transit.")
    return json.loads(payload.decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a NetOpsGuard licence request.")
    parser.add_argument("--contact", default="", help="Your email, so the vendor can reply.")
    parser.add_argument("--note", default="", help="Anything the vendor should know (site, order number).")
    parser.add_argument("--out", default="netopsguard.request", help="Output file.")
    parser.add_argument("--show", action="store_true", help="Print the readable contents and exit.")
    args = parser.parse_args()

    body = build_request(args.contact, args.note)

    if args.show:
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0

    text = encode(body)
    Path(args.out).write_text(text + "\n")

    print("Licence request written to:", args.out)
    print()
    print("  machine id :", body["short_id"])
    print("  details    :", ", ".join(body["components_available"]) or "none readable")
    print("  os         :", body["os"])
    print()
    if len(body["components_available"]) < 2:
        # Below two components a bound licence cannot be verified
        # reliably, so warn BEFORE the customer sends the file rather
        # than after the licence fails to work.
        print("  WARNING: fewer than two identifying details could be read.")
        print("  Re-run with sudo so the system UUID can be included, otherwise")
        print("  a machine-bound licence may not verify on this host.")
        print()
    print("Send this file to your vendor. It contains hashes only -- no")
    print("hardware identifiers, addresses or disk details are disclosed.")
    print("Run with --show to read exactly what it contains.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
