"""
app.services.radius_probe
============================
Sends a real RADIUS Access-Request to this platform's own listener and
reports whether the daemon answers.

Why this exists: a RADIUS server that receives a packet it cannot
authenticate does not reply -- RFC 2865 says a request with a bad
Message-Authenticator or an unknown client is silently DISCARDED. From
the NAS side that is indistinguishable from "server down", "wrong
port", "firewall", or "wrong shared secret": the counter shows requests
sent and zero responses in every case.

This probe removes that ambiguity by controlling the one variable a
NAS cannot: it sends from a known client with a known secret, so a
timeout here means something quite different from a timeout at the
MikroTik.

Implemented against the RFC rather than with a library because this
project ships no RADIUS client dependency, and the packet is small:
a 20-byte header (code, id, length, 16-byte authenticator) followed by
type-length-value attributes.

It never asserts more than it can prove. A reply that is an
Access-Reject still proves the SERVER IS WORKING -- it received the
packet, validated the shared secret, evaluated policy and answered.
Reporting a reject as failure would be wrong, and is exactly the
confusion this tool exists to end.
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import time
from dataclasses import dataclass

# RADIUS packet codes (RFC 2865 section 3).
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11

CODE_NAMES = {
    ACCESS_ACCEPT: "Access-Accept",
    ACCESS_REJECT: "Access-Reject",
    ACCESS_CHALLENGE: "Access-Challenge",
}

# Attribute types used here.
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
ATTR_NAS_IDENTIFIER = 32

SERVICE_TYPE_AUTHENTICATE_ONLY = 8


@dataclass
class ProbeResult:
    reachable: bool          # a well-formed RADIUS reply came back
    code: int | None = None
    code_name: str = ""
    round_trip_ms: int = 0
    detail: str = ""
    #: What the operator should do next, when there is something useful
    #: to say. Empty when the result needs no action.
    guidance: str = ""


def _encode_password(password: str, secret: str, authenticator: bytes) -> bytes:
    """
    User-Password hiding, RFC 2865 section 5.2.

    b1 = MD5(secret + Request Authenticator); c1 = p1 XOR b1
    b2 = MD5(secret + c1);                    c2 = p2 XOR b2  ... and so on.
    The plaintext is padded with NULs to a multiple of 16.
    """
    raw = password.encode("utf-8")
    if len(raw) % 16:
        raw += b"\x00" * (16 - len(raw) % 16)

    secret_bytes = secret.encode("utf-8")
    out = b""
    previous = authenticator
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]
        digest = hashlib.md5(secret_bytes + previous).digest()
        encrypted = bytes(a ^ b for a, b in zip(chunk, digest))
        out += encrypted
        previous = encrypted
    return out


def _attribute(attr_type: int, value: bytes) -> bytes:
    # length covers type + length + value, and the field is one byte,
    # so a value longer than 253 cannot be represented.
    return struct.pack("!BB", attr_type, len(value) + 2) + value[:253]


def build_access_request(
    username: str, password: str, secret: str, *, nas_identifier: str = "netopsguard-probe",
) -> tuple[bytes, int, bytes]:
    """Returns (packet, identifier, request_authenticator)."""
    identifier = os.urandom(1)[0]
    authenticator = os.urandom(16)

    attributes = b"".join([
        _attribute(ATTR_USER_NAME, username.encode("utf-8")),
        _attribute(ATTR_USER_PASSWORD, _encode_password(password, secret, authenticator)),
        _attribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
        _attribute(ATTR_NAS_PORT, struct.pack("!I", 0)),
        _attribute(ATTR_SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_AUTHENTICATE_ONLY)),
        _attribute(ATTR_NAS_IDENTIFIER, nas_identifier.encode("utf-8")),
    ])

    length = 20 + len(attributes)
    header = struct.pack("!BBH", ACCESS_REQUEST, identifier, length)
    return header + authenticator + attributes, identifier, authenticator


def verify_response_authenticator(
    packet: bytes, request_authenticator: bytes, secret: str,
) -> bool:
    """
    Response Authenticator = MD5(Code + ID + Length + RequestAuth +
    Attributes + Secret), RFC 2865 section 3.

    Checking it proves the reply came from something that knows the
    shared secret, not merely that a UDP packet arrived -- which is the
    difference between "the server answered" and "something answered".
    """
    if len(packet) < 20:
        return False
    expected = hashlib.md5(
        packet[0:4] + request_authenticator + packet[20:] + secret.encode("utf-8")
    ).digest()
    return expected == packet[4:20]


def probe(
    host: str, port: int, secret: str, username: str, password: str,
    *, timeout_seconds: float = 12.0,
) -> ProbeResult:
    """
    One Access-Request, one wait. No retry: a retry would mask the
    intermittent case, and "answered on the second try" is itself worth
    seeing rather than smoothing over.

    The default timeout is deliberately generous. When users come from
    a directory, the daemon performs an LDAP lookup before it can
    answer -- and a username that does NOT exist still costs a full
    round-trip. A short timeout turns "the directory is slow" into
    "RADIUS is broken", which is the opposite of what this tool is for.
    """
    packet, identifier, authenticator = build_access_request(username, password, secret)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_seconds)
    started = time.perf_counter()
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return ProbeResult(
            reachable=False,
            detail=f"No reply within {timeout_seconds:.0f}s.",
            guidance=(
                "The port is open but nothing came back in time. In order of likelihood:\n"
                "1. If users are backed by Active Directory, the daemon asks LDAP before it can "
                "answer. A username that does not exist still costs a full directory round-trip, "
                "so a slow or unreachable directory shows up here as silence rather than a reject.\n"
                "2. The shared secret does not match, or this source address is not defined as a "
                "RADIUS client -- a RADIUS server silently DISCARDS such requests.\n"
                "3. The configuration has not been compiled and applied since RADIUS was enabled.\n"
                "Check the RADIUS access log for whether the request arrived at all: that separates "
                "'never got there' from 'got there and could not answer'."
            ),
        )
    except OSError as exc:
        return ProbeResult(
            reachable=False,
            detail=f"Could not send the request: {exc}",
            guidance="Check that the RADIUS listener is running and reachable from this host.",
        )
    finally:
        sock.close()

    elapsed_ms = int((time.perf_counter() - started) * 1000)

    if len(data) < 20:
        return ProbeResult(reachable=False, round_trip_ms=elapsed_ms,
                           detail="A reply arrived but was too short to be a RADIUS packet.")

    code, reply_id = data[0], data[1]
    if reply_id != identifier:
        return ProbeResult(
            reachable=False, round_trip_ms=elapsed_ms,
            detail="A reply arrived but its identifier did not match the request.",
            guidance="Something other than the expected server may be answering on this port.",
        )

    authentic = verify_response_authenticator(data, authenticator, secret)
    name = CODE_NAMES.get(code, f"code {code}")

    if not authentic:
        return ProbeResult(
            reachable=False, code=code, code_name=name, round_trip_ms=elapsed_ms,
            detail="A reply arrived but its Response Authenticator did not validate.",
            guidance=(
                "The shared secret used for this probe does not match the one the server has for "
                "this client. That is the single most common cause of a NAS counting requests with "
                "zero responses."
            ),
        )

    # An Access-Reject is a SUCCESSFUL probe: the server received the
    # packet, accepted the shared secret, evaluated policy and answered.
    if code == ACCESS_REJECT:
        return ProbeResult(
            reachable=True, code=code, code_name=name, round_trip_ms=elapsed_ms,
            detail="The server answered with Access-Reject.",
            guidance=(
                "RADIUS is working: the request was received, the shared secret validated, and "
                "policy was evaluated. The reject just means these test credentials were not "
                "accepted, which is expected unless you probed with a real user."
            ),
        )

    return ProbeResult(
        reachable=True, code=code, code_name=name, round_trip_ms=elapsed_ms,
        detail=f"The server answered with {name}.",
    )


@dataclass
class ListenerStatus:
    listening: bool
    addresses: list          # e.g. ["0.0.0.0:1812", "127.0.0.1:1812"]
    all_interfaces: bool     # bound to 0.0.0.0 / :: rather than loopback only
    loopback_only: bool
    detail: str
    guidance: str = ""


def _parse_proc_udp(path: str, port: int) -> list:
    """
    Reads listening UDP sockets straight from /proc/net/udp{,6}.

    Parsed from /proc rather than shelling out to `ss`, because this
    runs as an unprivileged service account: `ss` may not be on PATH,
    and adding a sudo rule for a read-only diagnostic would widen the
    service's privileges for no good reason. /proc/net is world
    readable.

    Address and port are little-endian hex in these files.
    """
    found = []
    try:
        with open(path, "r") as handle:
            lines = handle.readlines()[1:]
    except OSError:
        return found

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        local = parts[1]
        if ":" not in local:
            continue
        hex_addr, hex_port = local.rsplit(":", 1)
        try:
            if int(hex_port, 16) != port:
                continue
        except ValueError:
            continue

        if len(hex_addr) == 8:  # IPv4
            value = int(hex_addr, 16)
            octets = [(value >> (8 * i)) & 0xFF for i in range(4)]
            found.append(".".join(str(o) for o in octets))
        else:  # IPv6, including v4-mapped
            found.append(hex_addr.lower())
    return found


def listener_status(port: int) -> ListenerStatus:
    """
    Reports whether anything is listening on `port`, and on which
    address.

    This distinguishes the case a NAS cannot see: a daemon bound only
    to LOOPBACK accepts a local probe perfectly while being completely
    unreachable from the network. "The probe works but my switch gets
    nothing" is exactly that shape, and no amount of RADIUS
    configuration will fix it.
    """
    v4 = _parse_proc_udp("/proc/net/udp", port)
    v6 = _parse_proc_udp("/proc/net/udp6", port)

    if not v4 and not v6:
        return ListenerStatus(
            listening=False, addresses=[], all_interfaces=False, loopback_only=False,
            detail=f"Nothing is listening on UDP {port}.",
            guidance=(
                "The daemon is not bound to this port. Check that the configuration has been "
                "compiled and applied since RADIUS was enabled, and that tac_plus-ng restarted "
                "afterwards."
            ),
        )

    addresses = [f"{a}:{port}" for a in v4] + [f"[{a}]:{port}" for a in v6]

    # 0.0.0.0 and the all-zero IPv6 address both mean "every interface".
    wildcard_v4 = "0.0.0.0" in v4
    wildcard_v6 = any(set(a) == {"0"} for a in v6)
    all_interfaces = wildcard_v4 or wildcard_v6

    loopback_v4 = all(a.startswith("127.") for a in v4) if v4 else True
    # v4-mapped loopback appears as ...7F000001 in the v6 table.
    loopback_v6 = all(a.endswith("0100007f") or a.endswith("00000001") for a in v6) if v6 else True
    loopback_only = (not all_interfaces) and loopback_v4 and loopback_v6

    if loopback_only:
        return ListenerStatus(
            listening=True, addresses=addresses, all_interfaces=False, loopback_only=True,
            detail=f"UDP {port} is bound to loopback only.",
            guidance=(
                "A loopback-only listener answers a local test perfectly while being unreachable "
                "from every other host, so a NAS on the network will never get a reply -- and its "
                "packets will not even appear in a capture on this server. This is a bind-address "
                "problem, not a RADIUS configuration problem."
            ),
        )

    return ListenerStatus(
        listening=True, addresses=addresses, all_interfaces=all_interfaces, loopback_only=False,
        detail=f"UDP {port} is listening on {', '.join(addresses)}.",
        guidance=(
            "" if all_interfaces else
            "Bound to a specific address rather than all interfaces -- confirm it is the address "
            "your devices send to."
        ),
    )
