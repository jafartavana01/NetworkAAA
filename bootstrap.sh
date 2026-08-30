#!/usr/bin/env bash
#
# bootstrap.sh -- solves the one problem setup.py can't solve for
# itself: it needs Python 3 to even start. This script's ONLY job is
# to make sure Python 3 is available (installing it via apt if it
# isn't), then hand off immediately to the real installer, setup.py,
# which does everything else exactly as it already did. Nothing here
# duplicates or replaces any of setup.py's own logic -- this is a
# thin bootstrap, not a second installer.
#
# Run as:  sudo bash bootstrap.sh
# (or: sudo ./bootstrap.sh, after chmod +x)
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This must be run as root (try: sudo bash bootstrap.sh)" >&2
  exit 1
fi

# Resolves correctly whether invoked as ./bootstrap.sh, bash bootstrap.sh,
# or via a relative/absolute path from elsewhere -- setup.py and the
# installer/ and app/ directories it needs must be alongside this
# script (same requirement setup.py's own docstring already states).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_PY="${SCRIPT_DIR}/setup.py"

if [ ! -f "$SETUP_PY" ]; then
  echo "Could not find setup.py next to this script (looked in: ${SCRIPT_DIR})." >&2
  echo "Run this from the full cloned project -- setup.py, installer/, and app/ must all be present." >&2
  exit 1
fi

echo "=================================================="
echo " NetworkAAA -- bootstrap"
echo "=================================================="

if command -v python3 >/dev/null 2>&1; then
  echo "Python 3 already installed: $(python3 --version 2>&1)"
else
  echo "Python 3 not found on this system -- installing via apt..."
  apt-get update
  apt-get install -y python3
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 still not found after installation attempt -- something went wrong." >&2
    exit 1
  fi
  echo "Python 3 installed: $(python3 --version 2>&1)"
fi

echo "Handing off to the real installer (setup.py)..."
echo "=================================================="
echo

# exec replaces this bash process with the python one entirely --
# setup.py's own exit code becomes this script's exit code, and any
# arguments this script was given (e.g. -u to uninstall) pass straight
# through untouched.
exec python3 "$SETUP_PY" "$@"
