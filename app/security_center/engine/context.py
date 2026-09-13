"""
app.security_center.engine.context
=====================================
Shared fact-sheet populated by device-level domain check functions as
a side effect, migrated verbatim from cisco-ios-security-auditor's
`Context` class. The correlation engine (app.security_center.engine.
correlation) reads these facts to reason across domains without each
domain module needing to know about any other domain's internals. If
only a subset of domains ran (e.g. only Layer 2), a correlation rule
needing a fact from a domain that didn't run simply sees `None` via
`get()`'s default -- no crash, no false positive, the rule just
doesn't fire because its precondition was never populated.
"""
from __future__ import annotations


class Context:
    def __init__(self):
        self.facts: dict[str, object] = {}

    def set(self, key: str, value) -> None:
        self.facts[key] = value

    def get(self, key: str, default=None):
        return self.facts.get(key, default)
