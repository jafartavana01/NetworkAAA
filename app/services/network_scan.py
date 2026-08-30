"""
app.services.network_scan
============================
Scans an IP range for hosts with an open SSH port (22) -- used as the
"is this a live, manageable device" check rather than ICMP ping, since
a TCP connect to the port we're about to actually use (SSH) is both
more relevant (a host that doesn't accept SSH can't be provisioned
regardless of whether it answers ping) and doesn't need raw-socket/
root privileges the way ICMP typically does.

Every scan cross-references against already-configured devices (by
IP) so the caller can mark a hit as "already exists" rather than
presenting it as a fresh discovery.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy.orm import Session

from ..models.device import NetworkDevice

SSH_PORT = 22
_CONNECT_TIMEOUT_SECONDS = 1.5
_MAX_HOSTS_PER_SCAN = 1024  # a /22 -- large enough for real use, small enough to stay responsive


def _configured_ips(db: Session) -> dict[str, str]:
    """IP (bare, no CIDR suffix) -> device id, for every configured device."""
    devices = db.query(NetworkDevice).all()
    return {d.ip_address.split("/")[0].strip(): str(d.id) for d in devices}


def get_platform_addresses() -> list[str]:
    """
    This platform's own non-loopback IPv4 addresses -- lets the admin
    pick which one newly-provisioned devices should be told to send
    TACACS+ requests to, rather than guessing from a single browser-
    reported hostname (which may not even be an IP, and is wrong
    whenever the admin is reached via a hostname/proxy/NAT that
    differs from the address actually reachable from the device side).

    Uses `hostname -I` (standard on Ubuntu, the only OS this project
    targets) rather than a new Python dependency for something this
    simple -- returns [] on any failure rather than raising, since an
    empty list just means the admin falls back to typing an address
    manually, not a broken page.
    """
    import subprocess

    try:
        result = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        if result.returncode != 0:
            return []
        return [ip for ip in result.stdout.split() if ip.strip()]
    except Exception:
        return []


def _check_host(ip: str) -> bool:
    try:
        with socket.create_connection((ip, SSH_PORT), timeout=_CONNECT_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def scan_range(db: Session, cidr: str) -> list[dict]:
    """
    Returns one entry per HOST address in `cidr` (network and
    broadcast addresses excluded for anything larger than a /31) that
    answers on SSH, each as {ip_address, already_exists (device id or
    None)}. Raises ValueError for an invalid CIDR or one wider than
    _MAX_HOSTS_PER_SCAN -- surfaced by the API as a clear 400, not a
    silent truncation.
    """
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"'{cidr}' is not a valid IP range.") from exc

    hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
    if len(hosts) > _MAX_HOSTS_PER_SCAN:
        raise ValueError(
            f"That range has {len(hosts)} addresses -- scanning is limited to {_MAX_HOSTS_PER_SCAN} at a time. "
            "Use a smaller range."
        )

    known = _configured_ips(db)
    results = []
    with ThreadPoolExecutor(max_workers=min(64, max(1, len(hosts)))) as pool:
        future_to_ip = {pool.submit(_check_host, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                results.append({"ip_address": ip, "already_exists": known.get(ip)})

    results.sort(key=lambda r: tuple(int(p) for p in r["ip_address"].split(".")))
    return results
