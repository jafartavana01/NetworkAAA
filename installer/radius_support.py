"""
installer.radius_support
===========================
Discovers whether the tac_plus-ng build on THIS machine supports
RADIUS, and extracts the real RADIUS configuration keywords from the
checked-out upstream source.

Why discovery instead of hard-coded syntax
------------------------------------------
This installer already refuses to hard-code upstream build flags --
`upstream_build` runs `./configure --help` against the real checkout
rather than guessing (see its module docstring). And
`config_compiler`'s own comments record that the `host NAME { }` block
convention was confirmed against real upstream examples before being
emitted, precisely because a wrong guess produces a config the daemon
rejects.

RADIUS gets the same treatment, and it matters more here: this project
generates a SINGLE configuration file that the running TACACS+ daemon
loads. Emitting invented RADIUS syntax into it would not just fail to
enable RADIUS -- it would make the whole file unparseable and take
working TACACS+ authentication down with it. That is a production
outage caused by a guess.

So this module reads the upstream source that `upstream_build` already
clones to disk and reports what is actually there. Nothing is emitted
into a device configuration on the strength of an assumption.

What it inspects, in order of authority:
  1. `./configure --help` in the checkout -- names the real build flags.
  2. The built binary's own `-v` / usage output.
  3. The source tree's RADIUS-related files and config-parser keywords.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

UPSTREAM_SRC_DIR = Path("/opt/aaa-platform/upstream/event-driven-servers")

#: Where the daemon binary normally lands. Only used as a fallback when
#: the caller does not supply an explicit path.
DEFAULT_BINARY_PATHS = [
    Path("/usr/local/sbin/tac_plus-ng"),
    Path("/usr/local/bin/tac_plus-ng"),
    Path("/usr/sbin/tac_plus-ng"),
]


@dataclass
class RadiusCapability:
    source_present: bool = False
    binary_path: str | None = None

    #: Build flags mentioning RADIUS, verbatim from `./configure --help`.
    configure_flags: list[str] = field(default_factory=list)
    #: Source files whose names indicate RADIUS handling.
    source_files: list[str] = field(default_factory=list)
    #: Configuration keywords found in the upstream config parser.
    config_keywords: list[str] = field(default_factory=list)
    #: Documentation / sample files that mentioned RADIUS.
    doc_sources: list[str] = field(default_factory=list)
    #: Verbatim RADIUS lines from shipped samples and docs -- the real
    #: syntax, quoted rather than summarised.
    sample_lines: list[str] = field(default_factory=list)
    #: True when keywords came only from C literals, which is weaker
    #: evidence than a shipped sample configuration.
    keywords_from_source_only: bool = False
    #: Anything that stopped a check from running.
    notes: list[str] = field(default_factory=list)

    @property
    def supported(self) -> bool:
        """True only when the SOURCE shows real RADIUS handling.

        A configure flag alone is not enough -- a flag can exist for a
        feature that is disabled or partial in a given checkout. Actual
        RADIUS source files or parser keywords are the evidence that
        matters.
        """
        return bool(self.source_files or self.config_keywords)

    @property
    def syntax_confirmed(self) -> bool:
        """True only when real configuration keywords were extracted.

        This is the gate on emitting anything into a device
        configuration. Without it, the correct behaviour is to report
        RADIUS as available-but-unconfigured rather than to write
        guessed directives into a file the running daemon loads.
        """
        return bool(self.config_keywords) and not self.keywords_from_source_only

    def summary_lines(self) -> list[str]:
        lines: list[str] = []
        if not self.source_present:
            lines.append(
                f"Upstream source not found at {UPSTREAM_SRC_DIR} -- "
                "RADIUS support cannot be determined."
            )
            return lines
        lines.append(
            "RADIUS handling found in the upstream source."
            if self.supported
            else "No RADIUS handling found in the upstream source."
        )
        if self.configure_flags:
            lines.append("Build flags mentioning RADIUS: " + ", ".join(self.configure_flags))
        if self.source_files:
            lines.append(f"RADIUS source files: {len(self.source_files)} "
                         f"(e.g. {', '.join(self.source_files[:4])})")
        if self.config_keywords:
            lines.append("Configuration keywords found: " + ", ".join(self.config_keywords))
        else:
            lines.append(
                "No RADIUS configuration keywords could be extracted, so the exact "
                "directive syntax is NOT confirmed. Nothing will be emitted into the "
                "generated configuration until it is."
            )
        if self.doc_sources:
            lines.append("Documentation / samples read: " + ", ".join(self.doc_sources[:6]))
        if self.sample_lines:
            lines.append("Real configuration lines found (verbatim):")
            lines.extend("    " + l for l in self.sample_lines[:25])
        lines.extend(self.notes)
        return lines


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:
        return ""


def _find_binary(explicit: str | None = None) -> str | None:
    if explicit and Path(explicit).exists():
        return explicit
    for p in DEFAULT_BINARY_PATHS:
        if p.exists():
            return str(p)
    return None


def detect_radius_capability(
    src_dir: Path = UPSTREAM_SRC_DIR, binary_path: str | None = None,
) -> RadiusCapability:
    cap = RadiusCapability()
    cap.binary_path = _find_binary(binary_path)

    if not src_dir.exists():
        cap.notes.append(
            "Run the installer at least once so the upstream source is cloned, "
            "then re-check."
        )
        return cap
    cap.source_present = True

    # 1. Build flags, from the real configure script.
    configure = src_dir / "configure"
    if configure.exists():
        help_text = _run(["./configure", "--help"], cwd=src_dir)
        cap.configure_flags = sorted({
            m.group(0) for m in re.finditer(r"--[\w-]*radius[\w-]*", help_text, re.IGNORECASE)
        })
    else:
        cap.notes.append("No ./configure script in the checkout; skipped build-flag discovery.")

    # 2. Source files that indicate RADIUS handling.
    try:
        for path in src_dir.rglob("*radius*"):
            if path.is_file() and path.suffix in (".c", ".h", ".cfg", ".conf", ".md", ".txt", ""):
                cap.source_files.append(str(path.relative_to(src_dir)))
        cap.source_files = sorted(cap.source_files)[:40]
    except Exception as exc:  # noqa: BLE001 - discovery must never abort an install
        cap.notes.append(f"Could not scan the source tree ({exc}).")

    # 3. Configuration syntax, taken from the two places upstream
    #    actually documents it. The project README states that the
    #    distribution ships its documentation in the top-level `doc/`
    #    directory and sample configurations under
    #    `tac_plus-ng/sample/` -- both land on disk when the installer
    #    clones the repo, so the authoritative syntax is available
    #    locally without needing network access to the project website.
    #
    #    These are searched IN PRIORITY ORDER, because a line in a
    #    shipped sample configuration is real, working syntax, whereas
    #    a string literal in C source may be an internal token that
    #    never appears in a config file.
    cap.config_keywords = _extract_config_keywords(src_dir, cap)

    if cap.supported and not cap.syntax_confirmed:
        cap.notes.append(
            "RADIUS appears to be present, but no directive syntax was extracted. "
            "Confirm the exact configuration syntax from the upstream documentation "
            "before enabling generation."
        )

    return cap


#: Directories the upstream distribution documents itself in, per its
#: own README. Ordered most-authoritative first.
_DOC_DIRS = ("tac_plus-ng/sample", "doc", "tac_plus-ng/doc")


def _extract_config_keywords(src_dir: Path, cap: "RadiusCapability") -> list[str]:
    """
    Pulls RADIUS configuration keywords from shipped sample configs and
    documentation, and records the sample lines verbatim so an operator
    can read the real syntax rather than a summary of it.
    """
    keywords: set[str] = set()

    for rel in _DOC_DIRS:
        root = src_dir / rel
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() in (".png", ".gif", ".jpg", ".o", ".so"):
                continue
            try:
                text = path.read_text(errors="ignore")
            except Exception:
                continue
            if "radius" not in text.lower():
                continue

            cap.doc_sources.append(str(path.relative_to(src_dir)))
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", "//", "*")):
                    continue
                if "radius" not in line.lower():
                    continue
                # Keep the line verbatim -- this is the actual syntax,
                # and paraphrasing it would defeat the purpose.
                if len(cap.sample_lines) < 60:
                    cap.sample_lines.append(line)
                m = re.match(r"([A-Za-z][\w-]*(?:\s+[\w-]+)?)", line)
                if m and "radius" in m.group(1).lower():
                    keywords.add(m.group(1).strip().lower())

    if not keywords:
        # Fall back to C string literals only if the documentation
        # yielded nothing. Explicitly noted, because this evidence is
        # weaker: an internal token is not proof of config syntax.
        for path in list((src_dir / "tac_plus-ng").rglob("*.c"))[:400]:
            try:
                text = path.read_text(errors="ignore")
            except Exception:
                continue
            for m in re.finditer(r'"(radius[\w-]*(?:\s+[\w-]+)?)"', text, re.IGNORECASE):
                keywords.add(m.group(1).strip().lower())
        if keywords:
            cap.notes.append(
                "Keywords below came from C source literals, not shipped docs or samples -- "
                "treat them as a lead to verify, not confirmed configuration syntax."
            )
            cap.keywords_from_source_only = True

    return sorted(keywords)[:40]


#: Sample files that define tac_plus-ng's OWN RADIUS configuration.
#: Named explicitly because the sample directory also contains Cisco
#: DEVICE-side configuration (`radius server ...`, `aaa group server
#: radius ...`), which is what you configure on a switch pointing AT
#: this daemon -- not syntax for the daemon's own config file. Mixing
#: the two up would produce a config the daemon rejects.
_DAEMON_SAMPLE_FILES = (
    "tac_plus-ng/sample/tac_plus-ng-radius.cfg",
    "tac_plus-ng/sample/tac_plus-ng-radius-mavis.cfg",
    "tac_plus-ng/sample/tac_plus-ng-radsec.cfg",
    "tac_plus-ng/sample/radius-dict.cfg",
)


def dump_samples(src_dir: Path = UPSTREAM_SRC_DIR, max_lines: int = 400) -> int:
    """
    Prints the upstream RADIUS sample configurations in full.

    The keyword report is enough to prove RADIUS exists, but not enough
    to generate a configuration: it shows isolated lines without the
    blocks they belong to, and cannot distinguish daemon config from
    the Cisco device-side config that also lives in that directory.
    Reading the files whole is what settles that.
    """
    found = False
    for rel in _DAEMON_SAMPLE_FILES:
        path = src_dir / rel
        if not path.exists():
            continue
        found = True
        print("=" * 68)
        print(f"FILE: {rel}")
        print("=" * 68)
        try:
            for i, line in enumerate(path.read_text(errors="ignore").splitlines()):
                if i >= max_lines:
                    print(f"... (truncated at {max_lines} lines)")
                    break
                print(line)
        except Exception as exc:  # noqa: BLE001
            print(f"(could not read: {exc})")
        print()

    if not found:
        print(f"No RADIUS sample configurations found under {src_dir}.")
        print("Looked for:")
        for rel in _DAEMON_SAMPLE_FILES:
            print(f"  {rel}")
        return 1
    return 0


def main() -> int:
    """
    Runnable directly on an installed server:

        sudo python3 -m installer.radius_support
        sudo python3 -m installer.radius_support --dump

    The first prints what RADIUS support and configuration syntax exist
    in the upstream checkout on this machine. `--dump` prints the
    upstream RADIUS sample configurations in full, which is what is
    needed to write a generator against real syntax rather than
    inferred fragments.
    """
    import sys as _sys
    if "--dump" in _sys.argv:
        return dump_samples()

    cap = detect_radius_capability()
    print("=" * 68)
    print("NetOpsGuard -- RADIUS capability report")
    print("=" * 68)
    for line in cap.summary_lines():
        print(line)
    print("-" * 68)
    print(f"supported        : {cap.supported}")
    print(f"syntax confirmed : {cap.syntax_confirmed}")
    if cap.binary_path:
        print(f"binary           : {cap.binary_path}")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
