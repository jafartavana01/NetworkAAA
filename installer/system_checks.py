"""
installer.system_checks
========================
Detects the environment the installer is running in (spec section 5):
Ubuntu version, CPU architecture, Python version, root/non-root
privileges, available compiler, package manager, disk space, memory,
and Internet connectivity. Fails gracefully with a clear message when
the OS is unsupported rather than plowing ahead.
"""
from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
from dataclasses import dataclass

from . import utils

# Ubuntu LTS releases this installer is validated against. Anything else
# is reported as unsupported rather than silently attempted -- per spec
# section 5, "do not pretend to support every Ubuntu version."
SUPPORTED_UBUNTU_VERSIONS = {"22.04", "24.04", "26.04"}
MIN_PYTHON = (3, 10)
MIN_DISK_GB = 5
MIN_MEM_MB = 1024


@dataclass
class SystemReport:
    is_linux: bool
    distro_id: str
    distro_version: str
    ubuntu_supported: bool
    architecture: str
    python_version: str
    python_ok: bool
    is_root: bool
    compiler: str | None
    package_manager: str | None
    disk_free_gb: float
    mem_total_mb: int
    internet_available: bool

    @property
    def fatal_problems(self) -> list[str]:
        problems = []
        if not self.is_linux:
            problems.append("This installer only supports Linux (Ubuntu Server).")
        elif self.distro_id != "ubuntu":
            problems.append(
                f"Detected distro '{self.distro_id}', but this installer targets Ubuntu Server."
            )
        elif not self.ubuntu_supported:
            problems.append(
                f"Ubuntu {self.distro_version} is not in the supported list "
                f"({', '.join(sorted(SUPPORTED_UBUNTU_VERSIONS))}). "
                "Installation will not proceed automatically."
            )
        if not self.python_ok:
            problems.append(
                f"Python {'.'.join(map(str, MIN_PYTHON))}+ is required, found {self.python_version}."
            )
        if not self.is_root:
            problems.append("This installer must be run as root (or via sudo).")
        if self.compiler is None:
            problems.append(
                "No C compiler found (clang or gcc). Install one before continuing "
                "or let the installer install build-essential/clang."
            )
        if self.disk_free_gb < MIN_DISK_GB:
            problems.append(
                f"At least {MIN_DISK_GB} GB free disk space is recommended, "
                f"found {self.disk_free_gb:.1f} GB."
            )
        return problems


def _read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    path = "/etc/os-release"
    if not os.path.exists(path):
        return data
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key] = value.strip().strip('"')
    return data


def _detect_compiler() -> str | None:
    for candidate in ("clang", "cc", "gcc"):
        path = utils.which(candidate)
        if path:
            return candidate
    return None


def _detect_package_manager() -> str | None:
    return "apt" if utils.which("apt-get") else None


def _detect_internet(timeout: float = 3.0) -> bool:
    # Low-level TCP probe rather than shelling out to curl/ping, and no
    # dependency on DNS behaving in restrictive environments.
    targets = [("github.com", 443), ("archive.ubuntu.com", 80)]
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _disk_free_gb(path: str = "/opt") -> float:
    probe = path if os.path.exists(path) else "/"
    usage = shutil.disk_usage(probe)
    return usage.free / (1024 ** 3)


def _mem_total_mb() -> int:
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return kb // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def gather() -> SystemReport:
    os_release = _read_os_release()
    distro_id = os_release.get("ID", "unknown")
    distro_version = os_release.get("VERSION_ID", "unknown")

    py_ok = sys.version_info[:2] >= MIN_PYTHON

    return SystemReport(
        is_linux=(platform.system() == "Linux"),
        distro_id=distro_id,
        distro_version=distro_version,
        ubuntu_supported=(distro_id == "ubuntu" and distro_version in SUPPORTED_UBUNTU_VERSIONS),
        architecture=platform.machine(),
        python_version=platform.python_version(),
        python_ok=py_ok,
        is_root=(os.geteuid() == 0),
        compiler=_detect_compiler(),
        package_manager=_detect_package_manager(),
        disk_free_gb=_disk_free_gb(),
        mem_total_mb=_mem_total_mb(),
        internet_available=_detect_internet(),
    )


def print_report(report: SystemReport) -> None:
    utils.section("System Detection")
    utils.info(f"Operating System : {report.distro_id} {report.distro_version}")
    utils.info(f"Architecture     : {report.architecture}")
    utils.info(f"Python           : {report.python_version}")
    utils.info(f"Privileges       : {'root' if report.is_root else 'non-root'}")
    utils.info(f"Compiler         : {report.compiler or 'NOT FOUND'}")
    utils.info(f"Package manager  : {report.package_manager or 'NOT FOUND'}")
    utils.info(f"Disk free (/opt) : {report.disk_free_gb:.1f} GB")
    utils.info(f"Memory total     : {report.mem_total_mb} MB")
    utils.info(f"Internet         : {'available' if report.internet_available else 'unavailable'}")

    if report.mem_total_mb and report.mem_total_mb < MIN_MEM_MB:
        utils.warn(
            f"Less than {MIN_MEM_MB} MB RAM detected -- PostgreSQL + the "
            "management API may perform poorly."
        )
