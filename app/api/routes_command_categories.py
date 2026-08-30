"""
app.api.routes_command_categories
====================================
PAM Expansion Plan §6. Mostly read-heavy: the platform seeds a
starting Cisco IOS taxonomy at first use (see `ensure_seeded()`,
called once from app.main's startup, matching the "vendor-neutral,
extensible" requirement -- a second vendor's categories are just more
rows, not a schema or code change). Admins can still add their own.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.command_category import CommandCategory
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/command-categories", tags=["command-categories"])

_VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL", None}

# name, vendor, risk_level, description
_SEED_CATEGORIES = [
    ("SHOW", "cisco_ios", "LOW", "Read-only display commands (show ...)."),
    ("INTERFACE", "cisco_ios", "MEDIUM", "Interface configuration."),
    ("ROUTING", "cisco_ios", "MEDIUM", "General routing configuration."),
    ("BGP", "cisco_ios", "HIGH", "BGP-specific configuration."),
    ("OSPF", "cisco_ios", "HIGH", "OSPF-specific configuration."),
    ("SECURITY", "cisco_ios", "HIGH", "ACLs, AAA, and other security-relevant configuration."),
    ("AAA", "cisco_ios", "CRITICAL", "AAA configuration itself -- changes here affect this platform's own control."),
    ("SYSTEM", "cisco_ios", "HIGH", "System-level settings (hostname, clock, NTP, logging)."),
    ("CONFIGURATION", "cisco_ios", "MEDIUM", "Entering/exiting configuration mode and general config commands."),
    ("DANGEROUS", "cisco_ios", "CRITICAL", "Reload, erase, format, and other destructive or disruptive commands."),
]


def ensure_seeded(db: Session) -> None:
    """Called once at app startup (app.main). A no-op if categories
    already exist -- this seeds a STARTING taxonomy, it doesn't
    enforce or reset it on every boot, so admin edits/additions are
    never overwritten."""
    if db.query(CommandCategory).first() is not None:
        return
    for name, vendor, risk_level, description in _SEED_CATEGORIES:
        db.add(CommandCategory(name=name, vendor=vendor, risk_level=risk_level, description=description))
    db.commit()


def _to_dict(c: CommandCategory) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "vendor": c.vendor,
        "risk_level": c.risk_level,
        "description": c.description,
    }


@router.get("")
def list_command_categories(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:view")),
):
    categories = db.query(CommandCategory).order_by(CommandCategory.vendor.asc(), CommandCategory.name.asc()).all()
    return [_to_dict(c) for c in categories]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_command_category(
    payload: dict,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Name is required.")
    risk_level = payload.get("risk_level")
    if risk_level not in _VALID_RISK_LEVELS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="risk_level must be LOW, MEDIUM, HIGH, CRITICAL, or omitted.")

    category = CommandCategory(
        name=name,
        vendor=(payload.get("vendor") or "cisco_ios").strip(),
        risk_level=risk_level,
        description=payload.get("description"),
    )
    db.add(category)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Could not create that category.")
    db.refresh(category)
    return _to_dict(category)


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_command_category(
    category_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    try:
        parsed_id = uuid.UUID(category_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Category not found.")
    category = db.query(CommandCategory).filter(CommandCategory.id == parsed_id).first()
    if not category:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Category not found.")
    # CommandRule.category_id is ON DELETE SET NULL -- deleting a
    # category un-categorizes any rules that referenced it rather than
    # deleting or blocking on those rules, since category is purely
    # observational metadata (see app/models/command_category.py).
    db.delete(category)
    db.commit()
