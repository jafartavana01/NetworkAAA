"""
app.services.build_info_service
=================================
Exposes the installer-recorded tac_plus-ng build metadata to the GUI
(spec section 11: "System -> Core Information").
"""
from __future__ import annotations

from ..config import load_build_info


def get_build_info() -> dict:
    info = load_build_info()
    if not info:
        return {
            "status": "unavailable",
            "message": "No build_info.json found -- tac_plus-ng may not have been built yet.",
        }
    info["status"] = "recorded"
    return info
