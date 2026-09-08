"""
app.services.radius_dictionary
=================================
Parses tac_plus-ng's RADIUS attribute dictionary.

The dictionary is NOT hardcoded here. It is read from the file the
distribution actually ships and the daemon actually loads --
`tac_plus-ng/sample/radius-dict.cfg` in the upstream checkout the
installer clones. That matters for two reasons:

  * The attributes an operator can pick in the GUI are then exactly the
    attributes the daemon will accept. A hand-maintained list would
    drift the moment upstream added or renamed one, and the GUI would
    start offering attributes that fail at config-compile time.
  * Vendor dictionaries (Cisco, Cisco-ASA, Fortinet, PaloAlto, Juniper,
    Microsoft, APC, MikroTik) come along for free, with their real
    vendor IDs, rather than needing to be transcribed.

The grammar parsed is the one in that file:

    radius.dictionary {
            attribute User-Name         1   string
            attribute Service-Type      6   integer
            {
                    Login-User          1
                    Administrative-User 6
            }
    }
    radius.dictionary Cisco 9 {
            attribute Cisco-AVPair      1   string
    }

If the file is not present (the checkout was removed, or this is a
development machine), `load_dictionary` returns an EMPTY result and
says so. It does not fall back to an invented list: an attribute
picker showing plausible-looking attributes the daemon may not accept
is worse than one that says the dictionary could not be read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: Where the installer clones the upstream source.
DEFAULT_DICT_PATHS = [
    Path("/opt/aaa-platform/upstream/event-driven-servers/tac_plus-ng/sample/radius-dict.cfg"),
    Path("/etc/aaa-platform/radius-dict.cfg"),
]

#: Attribute value types the dictionary uses. Exposed so the GUI can
#: render an appropriate input (a number field for `integer`, a
#: dropdown when the attribute has enumerated values, and so on)
#: instead of a free-text box for everything.
KNOWN_TYPES = ("string", "integer", "ipaddr", "ipv4addr", "ipv6addr", "octets", "time", "vsa")


@dataclass
class RadiusAttribute:
    name: str
    code: int
    value_type: str
    vendor: str | None = None
    vendor_id: int | None = None
    #: Enumerated values, e.g. Service-Type -> {"Login-User": 1, ...}.
    #: Present only for attributes the dictionary enumerates.
    values: dict = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        """How the attribute is referenced in a tac_plus-ng script:
        `radius[Service-Type]` for standard attributes,
        `radius[Cisco:Cisco-AVPair]` for vendor ones -- the exact form
        the upstream sample uses."""
        return f"{self.vendor}:{self.name}" if self.vendor else self.name


@dataclass
class DictionaryLoadResult:
    attributes: list = field(default_factory=list)
    source_path: str | None = None
    available: bool = False
    note: str = ""


_ATTR_RE = re.compile(
    r"^\s*attribute\s+([\w.\-]+)\s+(\d+)\s+(\w+)\s*$", re.IGNORECASE
)
_DICT_HEADER_RE = re.compile(
    r"^\s*radius\.dictionary(?:\s+([\w\-]+)\s+(\d+))?\s*\{\s*$", re.IGNORECASE
)
_VALUE_RE = re.compile(r"^\s*([\w.\-]+)\s+(\d+)\s*$")


def parse_dictionary(text: str) -> list:
    """
    Parses the dictionary grammar above.

    Written as an explicit brace-depth scanner rather than a set of
    independent regexes because the enumerated-value block that follows
    an attribute is only distinguishable from an attribute line by its
    nesting -- `Login-User 1` and a stray token look identical without
    knowing which block you are inside.
    """
    attributes: list = []
    vendor: str | None = None
    vendor_id: int | None = None
    depth = 0
    pending: RadiusAttribute | None = None
    in_values = False

    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        header = _DICT_HEADER_RE.match(line)
        if header:
            vendor = header.group(1)
            vendor_id = int(header.group(2)) if header.group(2) else None
            depth += 1
            continue

        stripped = line.strip()

        if stripped == "{":
            # An enumerated-value block belonging to the attribute just
            # parsed.
            depth += 1
            if pending is not None:
                in_values = True
            continue

        if stripped == "}":
            depth -= 1
            if in_values:
                in_values = False
                pending = None
            elif depth <= 0:
                vendor, vendor_id = None, None
                depth = 0
            continue

        if in_values and pending is not None:
            value = _VALUE_RE.match(stripped)
            if value:
                pending.values[value.group(1)] = int(value.group(2))
            continue

        attr = _ATTR_RE.match(line)
        if attr:
            pending = RadiusAttribute(
                name=attr.group(1), code=int(attr.group(2)),
                value_type=attr.group(3).lower(), vendor=vendor, vendor_id=vendor_id,
            )
            attributes.append(pending)
            continue

    return attributes


def load_dictionary(paths: list | None = None) -> DictionaryLoadResult:
    for path in (paths or DEFAULT_DICT_PATHS):
        if not path.exists():
            continue
        try:
            attributes = parse_dictionary(path.read_text(errors="ignore"))
        except Exception as exc:  # noqa: BLE001 - a bad dictionary must not 500 the page
            return DictionaryLoadResult(
                source_path=str(path), available=False,
                note=f"The dictionary file could not be parsed ({exc}).",
            )
        if attributes:
            return DictionaryLoadResult(
                attributes=attributes, source_path=str(path), available=True,
                note=f"{len(attributes)} attributes loaded from the dictionary tac_plus-ng itself uses.",
            )

    return DictionaryLoadResult(
        available=False,
        note=(
            "The RADIUS dictionary shipped with tac_plus-ng was not found. "
            "It is normally at "
            "/opt/aaa-platform/upstream/event-driven-servers/tac_plus-ng/sample/radius-dict.cfg "
            "after the installer runs. No attribute list is shown rather than an invented one, "
            "because an attribute the daemon does not know would fail when the configuration is compiled."
        ),
    )
