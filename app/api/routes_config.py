"""
app.api.routes_config
=======================
The candidate/validate/diff/apply/rollback workflow (spec sections
13-15). `/candidate` is read-only and side-effect-free -- it's safe to
call as often as the GUI wants, e.g. every time the Configuration page
loads, to show "N pending changes". `/apply` is the only route that
touches the live daemon, and it is CSRF-protected and fully logged.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.config_version import ConfigVersion
from ..services import config_backup, config_compiler
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/config", tags=["config"])


class CandidateOut(BaseModel):
    has_changes: bool
    diff: str
    candidate: str
    active: str


class ApplyRequest(BaseModel):
    note: str | None = None


class VersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    version_number: int
    status: str
    created_by: str | None
    note: str | None
    created_at: str


def _version_out(v: ConfigVersion) -> VersionOut:
    return VersionOut(
        id=str(v.id),
        version_number=v.version_number,
        status=v.status,
        created_by=v.created_by,
        note=v.note,
        created_at=v.created_at.isoformat(),
    )


@router.get("/candidate", response_model=CandidateOut)
def get_candidate(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    active = config_compiler.get_active_config()
    candidate = config_compiler.compile_candidate(db)
    diff = config_compiler.compute_diff(active, candidate)
    return CandidateOut(has_changes=bool(diff), diff=diff, candidate=candidate, active=active)


@router.post("/apply", response_model=VersionOut, dependencies=[Depends(verify_csrf)])
def apply_config(
    payload: ApplyRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    candidate = config_compiler.compile_candidate(db)
    active = config_compiler.get_active_config()
    if candidate == active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No pending changes to apply.")

    try:
        version = config_compiler.apply_candidate(
            db,
            candidate_text=candidate,
            admin_username=admin.username,
            note=payload.note,
        )
    except config_compiler.ApplyFailedError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail={"message": str(exc), "journal": exc.journal},
        )
    return _version_out(version)


@router.get("/versions", response_model=list[VersionOut])
def list_versions(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    versions = db.query(ConfigVersion).order_by(ConfigVersion.version_number.desc()).all()
    return [_version_out(v) for v in versions]


def _get_version_or_404(db: Session, version_number: int) -> ConfigVersion:
    version = db.query(ConfigVersion).filter(ConfigVersion.version_number == version_number).first()
    if not version:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Configuration version not found.")
    return version


@router.get("/versions/{version_number}", response_model=VersionOut)
def get_version(
    version_number: int,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    return _version_out(_get_version_or_404(db, version_number))


@router.get("/versions/{version_number}/content")
def get_version_content(
    version_number: int,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Backs the GUI's plain-text Download action (spec section 15) --
    unchanged, still exactly the raw config text this has always been.
    See app.services.config_backup for the SEPARATE, structured,
    version-aware export/import pair this feature added."""
    version = _get_version_or_404(db, version_number)
    return {"version_number": version.version_number, "content": version.content}


@router.get("/versions/{version_number}/export")
def export_version_backup(
    version_number: int,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """The structured, version-aware counterpart to the plain-text
    Download button -- carries a real format_version an import can
    actually check, unlike a plain .conf file."""
    version = _get_version_or_404(db, version_number)
    return config_backup.build_backup_payload(config_text=version.content, source_version_number=version.version_number)


class ImportPreviewRequest(BaseModel):
    file_text: str


@router.post("/import/preview")
def preview_import(
    payload: ImportPreviewRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Parses an uploaded backup file (either this project's own
    structured JSON export, or the older plain-text Download format --
    see config_backup's docstring for why both are accepted) and, if
    usable, returns a diff against the currently active config for the
    admin to review BEFORE calling /import/apply. Never writes
    anything -- read-only, same as /candidate."""
    result = config_backup.parse_uploaded_backup(payload.file_text)
    response = {
        "compatible": result.compatible,
        "is_legacy_plaintext": result.is_legacy_plaintext,
        "message": result.message,
        "diff": None,
    }
    if result.compatible and result.config_text:
        active = config_compiler.get_active_config()
        response["diff"] = config_compiler.compute_diff(active, result.config_text)
        response["config_text"] = result.config_text
    return response


class ImportApplyRequest(BaseModel):
    config_text: str


@router.post("/import/apply", response_model=VersionOut, dependencies=[Depends(verify_csrf)])
def apply_import(
    payload: ImportApplyRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """
    Applies imported config text directly -- the same
    apply_candidate() path /versions/{n}/restore already uses for
    restoring an INTERNAL version, just with the uploaded file's text
    in place of an existing ConfigVersion's content.

    IMPORTANT, and surfaced plainly in the GUI, not just here: this
    makes the imported text the ACTIVE tac_plus-ng configuration
    immediately, but does NOT update the underlying database (devices,
    users, groups, policies) to match it. This project's own stated
    architecture (docs/ARCHITECTURE.md: "the database is always the
    source of truth") is temporarily set aside by design the moment
    this is used -- the next time anyone compiles a fresh candidate
    from the database (the normal Configuration page flow, or simply
    opening it), that candidate will very likely differ from this
    imported config and can overwrite it again on the next Apply. This
    is meant for emergency recovery or side-by-side comparison, not as
    an ongoing way to manage configuration.
    """
    try:
        version = config_compiler.apply_candidate(
            db,
            candidate_text=payload.config_text,
            admin_username=admin.username,
            note="Restored from an imported backup file.",
            status="restored",
        )
    except config_compiler.ApplyFailedError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail={"message": str(exc), "journal": exc.journal},
        )
    return _version_out(version)


@router.get("/versions/{version_number}/diff")
def diff_version(
    version_number: int,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    version = _get_version_or_404(db, version_number)
    active = config_compiler.get_active_config()
    return {"diff": config_compiler.compute_diff(active, version.content)}


@router.post("/versions/{version_number}/restore", response_model=VersionOut, dependencies=[Depends(verify_csrf)])
def restore_version(
    version_number: int,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """
    Restoring is implemented as applying that old version's content as
    a brand-new version (like a revert, not a history rewrite) -- so
    the version log stays a true, append-only record of what was
    actually deployed and when (spec section 15).
    """
    old_version = _get_version_or_404(db, version_number)
    active = config_compiler.get_active_config()
    if old_version.content == active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That version is already the active configuration.")

    try:
        new_version = config_compiler.apply_candidate(
            db,
            candidate_text=old_version.content,
            admin_username=admin.username,
            note=f"Restored from version {version_number}.",
            status="restored",
        )
    except config_compiler.ApplyFailedError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail={"message": str(exc), "journal": exc.journal},
        )
    return _version_out(new_version)
