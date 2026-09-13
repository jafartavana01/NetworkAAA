"""
app.services.cisco_config_parser
===================================
Network Operations & Assurance Engine, Phase 3 (Check engine).

A small, independently-written structural parser for Cisco IOS/IOS-XE
`show running-config` text -- built from the same well-documented
structural property the referenced standalone
`cisco-ios-security-auditor` project's own parser relies on (inspected
in detail via its public README before writing this, per this
project's "understand before reusing" discipline): every config
stanza is a column-0 header line followed by indented child lines,
terminated by the next column-0 line. `interface`, `line vty`,
`router ospf` all follow this shape.

DELIBERATELY NOT a copy of that project's parser -- this is a fresh,
independent implementation of the same well-known structural pattern,
scoped down to what this platform's Phase 3 checks actually need
(interface and line stanzas, plus flat top-level directive presence
checks). No banner-body extraction, no multi-encoding file reading --
this parser operates on already-collected `CommandExecution.raw_output`
text already decoded by paramiko, not a file on disk.

Every check built on this parser must be honest about what it can and
cannot determine -- a config with zero interface stanzas is not
evidence of a "PASS", it's evidence the platform never ran a
config-revealing command at all (see app.services.network_ops_checks
for how that distinction is enforced).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ConfigBlock:
    header: str
    lines: list[str] = field(default_factory=list)

    def has(self, pattern: str) -> bool:
        """Case-insensitive substring/regex search across the header
        and every child line of this block."""
        combined = self.header + "\n" + "\n".join(self.lines)
        return re.search(pattern, combined, re.IGNORECASE) is not None

    def name(self) -> str:
        """The stanza's own identifier -- e.g. "GigabitEthernet1/0/1"
        from "interface GigabitEthernet1/0/1", "vty 0 4" from "line
        vty 0 4". Just the header with its keyword prefix stripped."""
        parts = self.header.split(None, 1)
        return parts[1].strip() if len(parts) > 1 else self.header.strip()


class ParsedConfig:
    """The result of parsing one `show running-config` text blob."""

    def __init__(self, raw_text: str):
        self.raw_text = raw_text
        self._blocks: list[ConfigBlock] = _parse_blocks(raw_text)

    def get_blocks(self, header_prefix: str) -> list[ConfigBlock]:
        """Every stanza whose header starts with `header_prefix`
        (case-insensitive) -- e.g. get_blocks("interface ") for every
        interface stanza, get_blocks("line vty") for VTY line
        stanzas."""
        prefix_lower = header_prefix.lower()
        return [b for b in self._blocks if b.header.lower().startswith(prefix_lower)]

    def has_toplevel(self, pattern: str) -> bool:
        """Whether `pattern` (regex, case-insensitive, MULTILINE so
        `^`/`$` mean line boundaries -- not string boundaries, a real
        bug class the referenced auditor project's own README
        documents having hit and fixed) appears ANYWHERE in the raw
        config text -- for simple presence/absence directives like
        `aaa new-model` that aren't stanza-scoped."""
        return re.search(pattern, self.raw_text, re.IGNORECASE | re.MULTILINE) is not None


def _parse_blocks(raw_text: str) -> list[ConfigBlock]:
    """
    Column-0 header + indented children, per-stanza, terminated by the
    next column-0 line. A line is a "header" (starts a new block) if
    it has no leading whitespace and is non-blank; every subsequent
    line that DOES have leading whitespace belongs to that block.
    A non-indented, non-blank line always starts a NEW block (even a
    single bare top-level line with no children, e.g. `aaa new-model`
    alone, which becomes a zero-line-body block).
    """
    blocks: list[ConfigBlock] = []
    current: ConfigBlock | None = None

    for raw_line in raw_text.splitlines():
        if not raw_line.strip():
            continue
        is_indented = raw_line[0] in (" ", "\t")
        if is_indented and current is not None:
            current.lines.append(raw_line.strip())
        else:
            current = ConfigBlock(header=raw_line.strip())
            blocks.append(current)

    return blocks
