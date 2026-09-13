"""
tests/check_undefined_names.py
=================================
Catches names that are USED at module level but never imported or
defined -- the class of bug `py_compile` cannot see.

Why this exists: `py_compile` only compiles. A missing import is not a
syntax error, so a file referencing an unimported `BaseModel` compiles
cleanly and then raises `NameError` the moment the module is imported.
That shipped once and took the service down at startup, restart-looping
under systemd. Compiling is not importing, and this closes the gap
without needing the real dependencies installed.

Scope, deliberately narrow to stay useful rather than noisy:
  * Module-level code only -- base classes, decorators, default
    arguments, annotations that are evaluated, and module-level calls.
    Names inside function bodies resolve at call time and are a
    different (much less fatal) problem.
  * Reports a name only when it is absent from imports, module-level
    assignments, defs/classes, and builtins.

Run:  python3 tests/check_undefined_names.py
"""
from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = ["app", "installer"]

BUILTINS = set(dir(builtins)) | {"__name__", "__file__", "__doc__", "__package__"}


def _module_level_bindings(tree: ast.Module) -> set:
    """Everything a module-level expression could legally reference."""
    names: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, (ast.For, ast.comprehension)):
            target = getattr(node, "target", None)
            if target is not None:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for sub in ast.walk(item.optional_vars):
                        if isinstance(sub, ast.Name):
                            names.add(sub.id)
        elif isinstance(node, ast.Lambda):
            for arg in list(node.args.args) + list(node.args.kwonlyargs):
                names.add(arg.arg)
    return names


def _module_level_used(tree: ast.Module) -> list:
    """
    Names referenced by module-level constructs that are evaluated at
    import time. Function BODIES are skipped -- a name resolved at call
    time is not what takes a service down on boot.
    """
    used: list = []

    def record(node, context):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                used.append((sub.id, getattr(sub, "lineno", 0), context))

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                record(base, f"base class of {node.name}")
            for dec in node.decorator_list:
                record(dec, f"decorator on {node.name}")
            # Evaluated annotations/defaults inside the class body.
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and item.value is not None:
                    record(item.value, f"{node.name} field default")
                elif isinstance(item, ast.Assign):
                    record(item.value, f"{node.name} attribute")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                record(dec, f"decorator on {node.name}")
            for default in node.args.defaults + [d for d in node.args.kw_defaults if d]:
                record(default, f"default argument of {node.name}")
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if getattr(node, "value", None) is not None:
                record(node.value, "module-level assignment")
        elif isinstance(node, ast.Expr):
            record(node.value, "module-level expression")

    return used


def check_file(path: Path) -> list:
    try:
        tree = ast.parse(path.read_text(errors="ignore"))
    except SyntaxError as exc:
        return [f"{path}: SYNTAX ERROR {exc}"]

    bound = _module_level_bindings(tree) | BUILTINS
    problems = []
    for name, lineno, context in _module_level_used(tree):
        if name not in bound:
            problems.append(
                f"{path.relative_to(REPO_ROOT)}:{lineno}: '{name}' used as {context} "
                f"but never imported or defined"
            )
    return problems


def main() -> int:
    problems = []
    scanned = 0
    for directory in SCAN_DIRS:
        root = REPO_ROOT / directory
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in str(path):
                continue
            scanned += 1
            problems.extend(check_file(path))

    print(f"Scanned {scanned} modules for module-level undefined names.")
    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems:
            print("  " + p)
        return 1
    print("No undefined module-level names found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
