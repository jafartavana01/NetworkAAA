"""
app.security_center.parser.cisco_config
==========================================
Device-wide Cisco IOS/IOS-XE running-config parser. Migrated from the
legacy `cisco-ios-security-auditor` project's `CiscoConfig`/`ConfigBlock`
(verified against the real, complete 2919-line source, not a summary of
it), preserved verbatim in structure and behavior -- this is the parser
every device-level security check in app.security_center.checks is
built against, and those checks were themselves migrated expecting
this exact contract (`get_blocks`, `search`, `search_lines`,
`physical_interfaces`, `is_access_port`, etc.).

Two real bugs the original project's own README documents, both
preserved as fixed here (not reintroduced):

1. `re.search()`'s default flags must include `re.MULTILINE` wherever
   the full multi-line config text is searched with a `^`/`$`-anchored
   pattern -- without it, `^` only matches byte offset 0 of the whole
   file, not the start of each line, and presence checks like
   `^aaa new-model` silently fail even when the line is clearly
   present. The original bug was only caught by running the tool
   against a real test config and observing a known-present line
   reported missing.
2. `re.search()` raises `ValueError` if given a `flags` argument
   alongside an already-*compiled* `re.Pattern` object. Some callers
   pass a precompiled pattern (shared across many checks); `has()`/
   `find()` below branch on `isinstance(pattern, re.Pattern)` and skip
   the `flags` argument entirely in that case, exactly as the fix in
   the original project does.

This module intentionally does NOT parse per-interface security
attributes -- that's app.security_center.parser.interface_config,
migrated separately from cisco-interface-security-audit's own parser,
which tracks a much richer, interface-specific feature set. This
module's `physical_interfaces()`/`is_access_port()`/etc. exist only
because the device-wide checks (Layer 2, Layer 3, ...) need to reason
about interfaces in aggregate (e.g. "how many access ports lack BPDU
Guard") without needing the interface engine's full feature model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ConfigBlock:
    header: str
    lines: list[str] = field(default_factory=list)
    block_type: str = "other"

    def body(self) -> str:
        return "\n".join(self.lines)

    def has(self, pattern, flags=re.IGNORECASE | re.MULTILINE) -> bool:
        # body() is multi-line, so MULTILINE is included by default for
        # consistency with CiscoConfig.search(), even though most
        # block-level patterns are unanchored. See module docstring for
        # why the isinstance branch exists.
        if isinstance(pattern, re.Pattern):
            return bool(pattern.search(self.header) or pattern.search(self.body()))
        if re.search(pattern, self.header, flags):
            return True
        return re.search(pattern, self.body(), flags) is not None

    def find(self, pattern, flags=re.IGNORECASE | re.MULTILINE):
        if isinstance(pattern, re.Pattern):
            return pattern.search(self.header) or pattern.search(self.body())
        m = re.search(pattern, self.header, flags)
        if m:
            return m
        return re.search(pattern, self.body(), flags)

    def matching_lines(self, pattern: str, flags=re.IGNORECASE) -> list[str]:
        rx = re.compile(pattern, flags)
        return [l for l in ([self.header] + self.lines) if rx.search(l)]

    def name(self) -> str:
        """Best-effort extraction of the block's identifying name (2nd+ token)."""
        parts = self.header.split(None, 1)
        return parts[1] if len(parts) > 1 else self.header


def ifname(header: str) -> str:
    """Strip the leading 'interface ' keyword for cleaner display in report evidence lists."""
    return re.sub(r"^interface\s+", "", header, flags=re.I)


def _classify(header: str) -> str:
    h = header.lower()
    for prefix in ("interface", "line", "router", "crypto", "class-map", "policy-map",
                   "track", "ip access-list", "ipv6 access-list", "mac access-list",
                   "control-plane", "zone security", "zone-pair", "key chain",
                   "aaa group server", "banner", "event manager applet", "vlan"):
        if h.startswith(prefix):
            return prefix
    return "global"


class CiscoConfig:
    """
    Lightweight hierarchical parser for Cisco IOS/IOS-XE running-config text.
    Not a full CLI grammar parser -- relies on the fact that IOS config stanzas
    are column-0 header lines followed by indented child lines, which holds
    true for the vast majority of real-world running-config exports.
    """

    def __init__(self, raw_text: str):
        self.raw_text = raw_text
        self.banners: dict[str, str] = {}
        self.text = ""
        self.blocks: list[ConfigBlock] = []
        self._parse()

    # ---- parsing --------------------------------------------------------
    def _parse(self) -> None:
        text = self.raw_text.replace("\r\n", "\n").replace("\r", "\n")

        # Extract banners first -- their body lines are NOT indented and would
        # otherwise be misread as top-level commands by the indentation parser.
        banner_pattern = re.compile(
            r"^banner (motd|login|exec|incoming|slip-ppp)\s+(\S)(.*?)\2",
            re.DOTALL | re.MULTILINE,
        )

        def _extract(m: re.Match) -> str:
            btype, _delim, body = m.group(1), m.group(2), m.group(3)
            self.banners[btype] = body.strip("\n")
            return f"banner {btype} <extracted-see-context>"

        text = banner_pattern.sub(_extract, text)

        # Strip common terminal-capture artifacts (paging prompts, backspace).
        cleaned_lines = []
        for raw_line in text.split("\n"):
            if "--More--" in raw_line or "---- More ----" in raw_line:
                continue
            cleaned_lines.append(raw_line.replace("\x08", "").rstrip())
        text = "\n".join(cleaned_lines)
        self.text = text

        blocks: list[ConfigBlock] = []
        current: Optional[ConfigBlock] = None
        for raw_line in text.split("\n"):
            if not raw_line.strip() or raw_line.strip() == "!":
                continue
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            stripped = raw_line.strip()
            if indent == 0:
                if current is not None:
                    blocks.append(current)
                current = ConfigBlock(header=stripped, lines=[], block_type=_classify(stripped))
            else:
                if current is None:
                    current = ConfigBlock(header="<global>", lines=[], block_type="global")
                current.lines.append(stripped)
        if current is not None:
            blocks.append(current)
        self.blocks = blocks

    # ---- convenience accessors ------------------------------------------
    def get_blocks(self, *prefixes: str) -> list[ConfigBlock]:
        low = tuple(p.lower() for p in prefixes)
        return [b for b in self.blocks if b.header.lower().startswith(low)]

    def search(self, pattern: str, flags=re.IGNORECASE | re.MULTILINE) -> bool:
        # NOTE: defaults include re.MULTILINE because self.text is the full,
        # multi-line config -- every '^'/'$' anchored check depends on this.
        # See module docstring, bug #1.
        return re.search(pattern, self.text, flags) is not None

    def findall(self, pattern: str, flags=re.IGNORECASE | re.MULTILINE) -> list:
        return re.findall(pattern, self.text, flags)

    def search_lines(self, pattern: str, flags=re.IGNORECASE) -> list[str]:
        rx = re.compile(pattern, flags)
        return [l for l in self.text.split("\n") if rx.search(l)]

    def get_hostname(self) -> str:
        m = re.search(r"^hostname (\S+)", self.text, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else "unknown-host"

    def get_version(self) -> str:
        m = re.search(r"^version (\S+)", self.text, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else "unknown"

    def interfaces(self) -> list[ConfigBlock]:
        return self.get_blocks("interface ")

    def physical_interfaces(self) -> list[ConfigBlock]:
        rx = re.compile(
            r"^interface (GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
            r"FortyGigabitEthernet|HundredGigE|FastEthernet)",
            re.IGNORECASE,
        )
        return [b for b in self.interfaces() if rx.match(b.header)]

    def is_access_port(self, block: ConfigBlock) -> bool:
        if block.has(r"switchport mode trunk"):
            return False
        if block.has(r"no switchport"):
            return False
        if block.has(r"switchport mode access") or block.has(r"switchport"):
            return True
        return False

    def is_trunk_port(self, block: ConfigBlock) -> bool:
        return block.has(r"switchport mode trunk")

    def looks_like_uplink(self, block: ConfigBlock) -> bool:
        desc = block.find(r"description (.+)")
        if desc:
            d = desc.group(1).lower() if desc.lastindex else ""
            if any(k in d for k in ("uplink", "trunk", "core", "backbone")):
                return True
        return False
