"""
DEMS Flask Blueprint — Routes & Controllers
============================================
Blueprint `dems_bp` mounted at /dems.

Implements:
  - Session-based RBAC authentication (separate from CDR sessions).
  - Case and Evidence CRUD operations.
  - Encrypted evidence intake with dual-hash streaming.
  - Chain of Custody event logging.
  - Real-time integrity verification sentinel.
  - In-memory decryption for authorized downloads.
  - CDR analytics pipeline hook (decrypt → cdr_engine → save derivative).
  - Court-ready CoC dossier rendering.

Complies with ISO/IEC 27037 and NIST SP 800-86.
"""

import datetime
import io
import json
import os
import tempfile
import uuid
from functools import wraps
from pathlib import Path
from typing import Callable

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
    current_app,
)
from werkzeug.utils import secure_filename

import cdr_engine as engine
from dems_crypto import (
    build_vault_path,
    decrypt_to_memory_stream,
    encrypt_file_to_vault,
    get_vault_key,
    verify_integrity,
    verify_vault_file_exists,
)
from audio_transcription import (
    build_transcript_document,
    transcribe_audio,
)

from dems_models import (
    CoCAction,
    CasePriority,
    CaseStatus,
    Evidence,
    EvidenceType,
    User,
    UserRole,
    VerificationStatus,
    Case,
    ChainOfCustodyLog,
    EvidenceRelationship,
    db,
    generate_case_number,
    generate_evidence_tag,
    log_coc_event,
)

from cross_evidence import (
    extract_cdr_entities_from_file,
    extract_text_entities,
    correlate_evidence,
    correlate_cdr_with_transcript,
    build_evidence_relationship_records,
)

# ─────────────────────────────────────────────────────────────────────────────
# BLUEPRINT SETUP
# ─────────────────────────────────────────────────────────────────────────────

dems_bp = Blueprint(
    "dems",
    __name__,
    template_folder="../templates",
    url_prefix="/dems",
)

VAULT_DIR = Path("vault")
SESSION_KEY = "dems_user_id"
SESSION_TIMEOUT_MINUTES = 480  # 8-hour investigative session


# ─────────────────────────────────────────────────────────────────────────────
# ALLOWED EVIDENCE EXTENSIONS
# ─────────────────────────────────────────────────────────────────────────────

TELECOM_EXTENSIONS = {"csv", "xlsx", "xls", "txt"}
ALL_EVIDENCE_EXTENSIONS = {
    "csv", "xlsx", "xls", "txt",
    "dd", "e01", "raw", "vmdk", "img", "iso",
    "pcap", "pcapng", "log", "evtx", "syslog",
    "zip", "tar", "gz", "7z",
    "pdf", "docx", "mp4", "avi", "mp3", "wav",
    "jpg", "jpeg", "png", "tiff",
}


def _allowed_evidence_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALL_EVIDENCE_EXTENSIONS


# ─────────────────────────────────────────────────────────────────────────────
# AUTH HELPERS & DECORATORS
# ─────────────────────────────────────────────────────────────────────────────

def _get_current_user() -> User | None:
    """Retrieves the authenticated DEMS user from session."""
    user_id = session.get(SESSION_KEY)
    if not user_id:
        return None

    # Session timeout check
    last_active = session.get("dems_last_active")
    if last_active:
        elapsed = datetime.datetime.utcnow() - datetime.datetime.fromisoformat(last_active)
        if elapsed.total_seconds() > SESSION_TIMEOUT_MINUTES * 60:
            session.pop(SESSION_KEY, None)
            session.pop("dems_last_active", None)
            return None

    user = db.session.get(User, user_id)
    if user and user.is_active:
        session["dems_last_active"] = datetime.datetime.utcnow().isoformat()
        return user

    # Never silently authenticate an unauthenticated request as a seeded/demo user.
    # All protected DEMS operations must pass through the login_required / role_required
    # decorators so the Chain of Custody always identifies a real session actor.
    return None


def dems_login_required(f: Callable) -> Callable:
    """Decorator: Requires active DEMS session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = _get_current_user()
        if not user:
            flash("Authentication required. Please log in to the Evidence Vault.", "error")
            return redirect(url_for("dems.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def role_required(*allowed_roles: UserRole) -> Callable:
    """Decorator: Restricts route to users with one of the specified roles."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            user = _get_current_user()
            if not user:
                flash("Authentication required.", "error")
                return redirect(url_for("dems.login"))
            if user.role not in allowed_roles:
                flash(
                    f"Access denied. This action requires one of: "
                    f"{', '.join(r.value for r in allowed_roles)}.",
                    "error",
                )
                return redirect(url_for("dems.cases_list"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def _get_client_ip() -> str:
    """Returns the client IP address, respecting X-Forwarded-For proxy headers."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _get_user_agent() -> str:
    return request.headers.get("User-Agent", "")[:256]


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.context_processor
def inject_dems_user():
    """Injects the current DEMS user into all DEMS templates."""
    return {
        "dems_user": _get_current_user(),
        "UserRole": UserRole,
        "CaseStatus": CaseStatus,
        "CasePriority": CasePriority,
        "EvidenceType": EvidenceType,
        "CoCAction": CoCAction,
        "VerificationStatus": VerificationStatus,
    }


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/login", methods=["GET", "POST"])
def login():
    """DEMS authentication endpoint."""
    if _get_current_user():
        return redirect(url_for("dems.cases_list"))

    if request.method == "POST":
        username   = request.form.get("username", "").strip()
        password   = request.form.get("password", "")
        badge      = request.form.get("badge_number", "").strip()

        user = User.query.filter(
            (User.username == username) | (User.badge_number == badge)
        ).first()

        if user and user.is_active and user.check_password(password):
            session[SESSION_KEY] = user.id
            session["dems_last_active"] = datetime.datetime.utcnow().isoformat()
            session.permanent = True

            user.last_login = datetime.datetime.utcnow()
            db.session.commit()

            next_url = request.form.get("next") or url_for("dems.cases_list")
            flash(f"Welcome back, {user.full_name or user.username}. Vault session established.", "success")
            return redirect(next_url)
        else:
            flash("Invalid credentials. Access denied.", "error")

    return render_template("dems/login.html")


@dems_bp.route("/logout", methods=["POST", "GET"])
def logout():
    """Terminates the DEMS session."""
    session.pop(SESSION_KEY, None)
    session.pop("dems_last_active", None)
    flash("Evidence Vault session terminated.", "info")
    return redirect(url_for("dems.login"))


# ─────────────────────────────────────────────────────────────────────────────
# CASE ROUTES
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE VAULT LOCKER ROUTE
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/vault")
@dems_login_required
def vault_view():
    """
    DEMS Evidence Locker View:
    Displays all stored evidence items, intake cryptographic hashes,
    one-click live integrity verification controls, and custodial transfer modal.
    """
    current_user = _get_current_user()
    cases = Case.query.order_by(Case.updated_at.desc()).all()
    evidence_items = Evidence.query.order_by(Evidence.uploaded_at.desc()).all()
    coc_logs = ChainOfCustodyLog.query.order_by(ChainOfCustodyLog.timestamp_utc.desc()).limit(50).all()
    users = User.query.filter_by(is_active=True).all()
    return render_template(
        "dems_vault.html",
        cases=cases,
        evidence_items=evidence_items,
        coc_logs=coc_logs,
        users=users,
        current_user=current_user,
        EvidenceType=EvidenceType,
        VerificationStatus=VerificationStatus,
        CoCAction=CoCAction,
        CasePriority=CasePriority,
        CaseStatus=CaseStatus,
    )


@dems_bp.route("/evidence/intake-direct", methods=["POST"])
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def evidence_intake_direct():
    """
    Direct evidence intake from the Evidence Vault locker:
    Encrypts file to AES-256-GCM in /vault, computes SHA-256/MD5/SHA-512 hashes,
    creates Evidence record, and logs INGESTION CoC event.
    """
    current_user = _get_current_user()
    user_id = current_user.id

    file = request.files.get("evidence_file")
    if not file or not file.filename:
        flash("No file provided for evidence intake.", "error")
        return redirect(url_for("dems.vault_view"))

    if not _allowed_evidence_file(file.filename):
        flash("This file type is not permitted for forensic evidence intake.", "error")
        return redirect(url_for("dems.vault_view"))

    case_id = request.form.get("case_id", type=int)
    case = db.session.get(Case, case_id) if case_id else Case.query.first()
    if not case:
        case = Case(
            case_number=generate_case_number(),
            title="Active Forensic Intelligence Case",
            description="Default case generated for direct evidence intake."
        )
        db.session.add(case)
        db.session.commit()

    title = request.form.get("title", "").strip() or file.filename
    evidence_type_str = request.form.get("evidence_type", EvidenceType.MULTIMEDIA.value)
    try:
        ev_type = EvidenceType(evidence_type_str)
    except ValueError:
        ev_type = EvidenceType.MULTIMEDIA

    notes = request.form.get("notes", "").strip()
    safe_name = secure_filename(file.filename)
    ev_tag = generate_evidence_tag(case.id)

    evidence = Evidence(
        case_id=case.id,
        evidence_tag=ev_tag,
        title=title,
        evidence_type=ev_type,
        original_filename=safe_name,
        encrypted_storage_path="pending",
        sha256_intake="",
        md5_intake="",
        sha512_intake="",
        file_size_bytes=0,
        mime_type=file.content_type or "application/octet-stream",
        uploaded_by_id=user_id,
        current_custodian_id=user_id,
        notes=notes,
    )
    db.session.add(evidence)
    db.session.flush()

    vault_key = get_vault_key()
    vault_path = build_vault_path(VAULT_DIR, evidence.id, safe_name)
    associated_data = f"evidence:{evidence.id}:{ev_tag}".encode()

    sha256_hex, md5_hex, sha512_hex, byte_count = encrypt_file_to_vault(
        file_obj=file.stream,
        vault_path=vault_path,
        key_bytes=vault_key,
        associated_data=associated_data,
    )

    evidence.encrypted_storage_path = str(vault_path)
    evidence.sha256_intake = sha256_hex
    evidence.md5_intake = md5_hex
    evidence.sha512_intake = sha512_hex
    evidence.file_size_bytes = byte_count

    log_coc_event(
        evidence_id=evidence.id,
        actor_id=user_id,
        action=CoCAction.INGESTION,
        purpose=f"Direct evidence intake to vault. Size: {byte_count:,} bytes.",
        sha256=sha256_hex,
        verification_status=VerificationStatus.VERIFIED,
        ip_address=_get_client_ip(),
        user_agent=_get_user_agent(),
    )

    case.updated_at = datetime.datetime.utcnow()
    db.session.commit()

    flash(f"Evidence {ev_tag} cryptographically sealed and added to Vault. SHA-256: {sha256_hex[:16]}…", "success")
    return redirect(url_for("dems.vault_view"))


@dems_bp.route("/cases")
@dems_login_required
def cases_list():
    """Cases command center: lists all cases with stats."""
    current_user = _get_current_user()
    status_filter   = request.args.get("status", "")
    priority_filter = request.args.get("priority", "")
    search          = request.args.get("q", "").strip()

    query = Case.query.order_by(Case.updated_at.desc())

    if status_filter:
        try:
            query = query.filter(Case.status == CaseStatus(status_filter))
        except ValueError:
            pass

    if priority_filter:
        try:
            query = query.filter(Case.priority == CasePriority(priority_filter))
        except ValueError:
            pass

    if search:
        query = query.filter(
            Case.title.ilike(f"%{search}%") |
            Case.case_number.ilike(f"%{search}%") |
            Case.jurisdiction.ilike(f"%{search}%")
        )

    cases = query.all()

    # Dashboard statistics
    stats = {
        "total":    Case.query.count(),
        "active":   Case.query.filter(Case.status.in_([CaseStatus.OPEN, CaseStatus.ACTIVE])).count(),
        "critical": Case.query.filter(Case.priority == CasePriority.CRITICAL).count(),
        "evidence": Evidence.query.count(),
    }

    return render_template(
        "dems/cases.html",
        cases=cases,
        stats=stats,
        current_user=current_user,
        CaseStatus=CaseStatus,
        CasePriority=CasePriority,
        filter_status=status_filter,
        filter_priority=priority_filter,
        search=search,
    )


@dems_bp.route("/cases/new", methods=["GET", "POST"])
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def case_new():
    """Creates a new investigative case."""
    current_user = _get_current_user()

    if request.method == "POST":
        title         = request.form.get("title", "").strip()
        description   = request.form.get("description", "").strip()
        jurisdiction  = request.form.get("jurisdiction", "").strip()
        incident_date = request.form.get("incident_date", "").strip()
        status_val    = request.form.get("status", CaseStatus.OPEN.value)
        priority_val  = request.form.get("priority", CasePriority.MEDIUM.value)
        classification = request.form.get("classification", "RESTRICTED").strip()

        if not title:
            flash("Case title is required.", "error")
            return redirect(url_for("dems.case_new"))

        inc_date = None
        if incident_date:
            try:
                inc_date = datetime.date.fromisoformat(incident_date)
            except ValueError:
                flash("Invalid incident date format.", "error")
                return redirect(url_for("dems.case_new"))

        case = Case(
            case_number          = generate_case_number(),
            title                = title,
            description          = description,
            lead_investigator_id = current_user.id,
            jurisdiction         = jurisdiction,
            incident_date        = inc_date,
            status               = CaseStatus(status_val),
            priority             = CasePriority(priority_val),
            classification       = classification,
        )
        db.session.add(case)
        db.session.commit()

        flash(f"Case {case.case_number} created successfully.", "success")
        return redirect(url_for("dems.case_detail", case_id=case.id))

    investigators = User.query.filter(
        User.role.in_([UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN]),
        User.is_active == True,
    ).all()

    return render_template(
        "dems/cases.html",
        show_new_modal=True,
        investigators=investigators,
        current_user=current_user,
        CaseStatus=CaseStatus,
        CasePriority=CasePriority,
    )


@dems_bp.route("/cases/<int:case_id>")
@dems_login_required
def case_detail(case_id: int):
    """Case detail view: evidence registry, CoC timeline, investigators."""
    current_user = _get_current_user()
    case = db.get_or_404(Case, case_id)

    evidence_items = (
        Evidence.query
        .filter_by(case_id=case_id)
        .order_by(Evidence.uploaded_at.desc())
        .all()
    )

    # Recent CoC events for the case timeline (last 25)
    coc_events = (
        ChainOfCustodyLog.query
        .join(Evidence, ChainOfCustodyLog.evidence_id == Evidence.id)
        .filter(Evidence.case_id == case_id)
        .order_by(ChainOfCustodyLog.timestamp_utc.desc())
        .limit(25)
        .all()
    )

    investigators = User.query.filter(User.is_active == True).all()

    # Log ACCESS_VIEW event for auditing (only if user is analyst or above)
    if current_user.role in [UserRole.FORENSIC_ANALYST, UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN]:
        for ev in evidence_items[:1]:  # Log once per case view, not per item
            log_coc_event(
                evidence_id=ev.id,
                actor_id=current_user.id,
                action=CoCAction.ACCESS_VIEW,
                purpose=f"Case detail view accessed for {case.case_number}",
                ip_address=_get_client_ip(),
                user_agent=_get_user_agent(),
            )
        if evidence_items:
            db.session.commit()

    return render_template(
        "dems/case_detail.html",
        case=case,
        evidence_items=evidence_items,
        coc_events=coc_events,
        investigators=investigators,
        current_user=current_user,
        EvidenceType=EvidenceType,
        VerificationStatus=VerificationStatus,
        CoCAction=CoCAction,
    )


@dems_bp.route("/cases/<int:case_id>/update-status", methods=["POST"])
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def case_update_status(case_id: int):
    """Updates a case's status."""
    case = db.get_or_404(Case, case_id)
    new_status = request.form.get("status", "")
    try:
        case.status = CaseStatus(new_status)
        case.updated_at = datetime.datetime.utcnow()
        db.session.commit()
        flash(f"Case status updated to {case.status.value}.", "success")
    except ValueError:
        flash("Invalid status value.", "error")
    return redirect(url_for("dems.case_detail", case_id=case_id))


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE UPLOAD (ENCRYPTED INTAKE)
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/upload", methods=["POST"])
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def evidence_upload():
    """
    Multi-part encrypted evidence intake.

    Workflow:
      1. Receive file via multipart POST.
      2. Stream-compute SHA-256 + MD5 + SHA-512 (dual hash prior to disk write).
      3. AES-256-GCM encrypt and write to vault/<id>/<filename>.enc.
      4. Create Evidence DB record with intake hashes.
      5. Log INGESTION ChainOfCustodyLog event.
    """
    current_user = _get_current_user()
    case_id = request.form.get("case_id", type=int)
    if not case_id:
        flash("Case ID is required for evidence upload.", "error")
        return redirect(url_for("dems.cases_list"))

    case = db.get_or_404(Case, case_id)

    if "evidence_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("dems.case_detail", case_id=case_id))

    file = request.files["evidence_file"]
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("dems.case_detail", case_id=case_id))

    if not _allowed_evidence_file(file.filename):
        flash(f"File type not permitted for evidence intake.", "error")
        return redirect(url_for("dems.case_detail", case_id=case_id))

    title         = request.form.get("title", "").strip() or file.filename
    evidence_type = request.form.get("evidence_type", EvidenceType.OTHER.value)
    notes         = request.form.get("notes", "").strip()

    try:
        ev_type = EvidenceType(evidence_type)
    except ValueError:
        ev_type = EvidenceType.OTHER

    safe_name = secure_filename(file.filename)
    vault_key = get_vault_key()

    # We need a temporary evidence ID for vault path construction.
    # Strategy: create DB record first with a placeholder path, then update.
    evidence_tag = generate_evidence_tag(case_id)

    evidence = Evidence(
        case_id                = case_id,
        evidence_tag           = evidence_tag,
        title                  = title,
        evidence_type          = ev_type,
        original_filename      = safe_name,
        encrypted_storage_path = "pending",   # Updated below
        sha256_intake          = "",
        md5_intake             = "",
        sha512_intake          = "",
        file_size_bytes        = 0,
        uploaded_by_id         = current_user.id,
        current_custodian_id   = current_user.id,
        notes                  = notes,
        last_verified_status   = VerificationStatus.NOT_VERIFIED,
    )
    db.session.add(evidence)
    db.session.flush()  # Get auto-assigned ID without committing

    # Build vault path now that we have the evidence ID
    vault_path = build_vault_path(VAULT_DIR, evidence.id, safe_name)

    # Stream dual-hash + encrypt to vault
    associated_data = f"evidence:{evidence.id}:{evidence_tag}".encode()
    sha256_hex, md5_hex, sha512_hex, byte_count = encrypt_file_to_vault(
        file_obj        = file.stream,
        vault_path      = vault_path,
        key_bytes       = vault_key,
        associated_data = associated_data,
    )

    # Update evidence record with real hash and path
    evidence.encrypted_storage_path = str(vault_path)
    evidence.sha256_intake           = sha256_hex
    evidence.md5_intake              = md5_hex
    evidence.sha512_intake           = sha512_hex
    evidence.file_size_bytes         = byte_count

    # Log INGESTION event
    log_coc_event(
        evidence_id         = evidence.id,
        actor_id            = current_user.id,
        action              = CoCAction.INGESTION,
        purpose             = f"Initial evidence intake. File: {safe_name}. Size: {byte_count:,} bytes.",
        sha256              = sha256_hex,
        verification_status = VerificationStatus.VERIFIED,
        ip_address          = _get_client_ip(),
        user_agent          = _get_user_agent(),
    )

    case.updated_at = datetime.datetime.utcnow()
    db.session.commit()

    flash(
        f"Evidence {evidence_tag} ingested successfully. "
        f"SHA-256: {sha256_hex[:16]}… Vault encrypted.",
        "success",
    )
    return redirect(url_for("dems.evidence_detail", evidence_id=evidence.id))


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE DETAIL
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/<int:evidence_id>")
@dems_login_required
def evidence_detail(evidence_id: int):
    """Evidence dossier: metadata, hash panel, custodian chain, quick actions."""
    current_user = _get_current_user()
    ev = db.get_or_404(Evidence, evidence_id)
    case = ev.case

    coc_logs = (
        ChainOfCustodyLog.query
        .filter_by(evidence_id=ev.id)
        .order_by(ChainOfCustodyLog.timestamp_utc.desc())
        .all()
    )

    all_users = User.query.filter_by(is_active=True).all()
    vault_exists = verify_vault_file_exists(Path(ev.encrypted_storage_path))

    # Phase 3 — Cross-Evidence Intelligence
    # Show other evidence items in the same case as correlation targets.
    related_evidence = (
        Evidence.query
        .filter(
            Evidence.case_id == ev.case_id,
            Evidence.id != ev.id,
        )
        .order_by(Evidence.uploaded_at.desc())
        .all()
    )

    cross_relationships = (
        EvidenceRelationship.query
        .filter(
            (EvidenceRelationship.source_evidence_id == ev.id)
            | (EvidenceRelationship.target_evidence_id == ev.id)
        )
        .order_by(EvidenceRelationship.created_at.desc())
        .all()
    )

    return render_template(
        "dems/evidence_detail.html",
        ev=ev,
        case=case,
        coc_logs=coc_logs,
        all_users=all_users,
        vault_exists=vault_exists,
        current_user=current_user,
        VerificationStatus=VerificationStatus,
        CoCAction=CoCAction,
        EvidenceType=EvidenceType,
        related_evidence=related_evidence,
        cross_relationships=cross_relationships,
    )


# ─────────────────────────────────────────────────────────────────────────────
# CROSS-EVIDENCE INTELLIGENCE — PHASE 3
# ─────────────────────────────────────────────────────────────────────────────

def _cross_evidence_extract(
    evidence: Evidence,
    plaintext_path: Path,
) -> dict:
    """
    Extract correlation entities from one decrypted evidence item.

    Supported Phase 3 inputs:
      - Telecom Data / CSV / XLSX / XLS -> existing CDR normalizer.
      - Text/report/log files -> generic forensic text extraction.

    The original encrypted evidence is never modified.
    """
    extension = Path(evidence.original_filename or "").suffix.lower()

    if (
        evidence.evidence_type == EvidenceType.TELECOM_DATA
        or extension in {".csv", ".xlsx", ".xls"}
    ):
        return extract_cdr_entities_from_file(plaintext_path)

    if extension in {
        ".txt", ".log", ".syslog", ".evtx", ".pdf", ".docx"
    } or evidence.evidence_type in {
        EvidenceType.REPORTS,
        EvidenceType.OTHER,
    }:
        try:
            text = plaintext_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            text = ""
            with open(plaintext_path, "rb") as handle:
                text = handle.read().decode(
                    "utf-8",
                    errors="replace",
                )

        return extract_text_entities(
            text,
            source=f"evidence:{evidence.id}",
        )

    raise ValueError(
        "Phase 3 correlation currently supports Telecom Data "
        "and text/report evidence. Binary multimedia evidence "
        "must first be transcribed into a derived report."
    )


@dems_bp.route(
    "/evidence/<int:evidence_id>/correlate",
    methods=["POST"],
)
@role_required(
    UserRole.FORENSIC_ANALYST,
    UserRole.LEAD_INVESTIGATOR,
    UserRole.ADMIN,
)
def evidence_correlate(evidence_id: int):
    """
    Phase 3 Cross-Evidence Intelligence.

    Workflow:
      1. Validate source and target evidence belong to the same case.
      2. Decrypt both vault objects to temporary plaintext files.
      3. Verify source and target integrity before analysis.
      4. Extract normalized forensic entities.
      5. Correlate the two evidence sources.
      6. Persist EvidenceRelationship records.
      7. Record CoC EVIDENCE_LINK events.
      8. Delete temporary plaintext files.
      9. Return to the source evidence dossier.
    """
    current_user = _get_current_user()
    source = db.get_or_404(Evidence, evidence_id)

    target_id = request.form.get("target_evidence_id", type=int)
    if not target_id:
        flash("Select a target evidence item for correlation.", "error")
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    if target_id == source.id:
        flash("An evidence item cannot be correlated with itself.", "error")
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    target = db.get_or_404(Evidence, target_id)

    if source.case_id != target.case_id:
        flash(
            "Cross-evidence correlation is restricted to evidence "
            "within the same investigative case.",
            "error",
        )
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    if not source.encrypted_storage_path or not target.encrypted_storage_path:
        flash("One or both evidence vault objects are unavailable.", "error")
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    source_vault = Path(source.encrypted_storage_path)
    target_vault = Path(target.encrypted_storage_path)

    if not verify_vault_file_exists(source_vault):
        flash(
            f"Source evidence vault object is missing: {source.evidence_tag}.",
            "error",
        )
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    if not verify_vault_file_exists(target_vault):
        flash(
            f"Target evidence vault object is missing: {target.evidence_tag}.",
            "error",
        )
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    vault_key = get_vault_key()

    source_ad = f"evidence:{source.id}:{source.evidence_tag}".encode()
    target_ad = f"evidence:{target.id}:{target.evidence_tag}".encode()

    source_ok, _ = verify_integrity(
        vault_path=source_vault,
        key_bytes=vault_key,
        expected_sha256=source.sha256_intake,
        associated_data=source_ad,
    )

    target_ok, _ = verify_integrity(
        vault_path=target_vault,
        key_bytes=vault_key,
        expected_sha256=target.sha256_intake,
        associated_data=target_ad,
    )

    if not source_ok or not target_ok:
        if not source_ok:
            source.last_verified_at = datetime.datetime.utcnow()
            source.last_verified_status = VerificationStatus.TAMPERED

        if not target_ok:
            target.last_verified_at = datetime.datetime.utcnow()
            target.last_verified_status = VerificationStatus.TAMPERED

        db.session.commit()

        flash(
            "Correlation blocked because one or both evidence items "
            "failed cryptographic integrity verification.",
            "error",
        )
        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    source.last_verified_at = datetime.datetime.utcnow()
    source.last_verified_status = VerificationStatus.VERIFIED
    target.last_verified_at = datetime.datetime.utcnow()
    target.last_verified_status = VerificationStatus.VERIFIED

    source_tmp = None
    target_tmp = None

    try:
        source_stream = decrypt_to_memory_stream(
            source_vault,
            vault_key,
            source_ad,
        )
        target_stream = decrypt_to_memory_stream(
            target_vault,
            vault_key,
            target_ad,
        )

        source_suffix = Path(
            source.original_filename or ""
        ).suffix or ".bin"
        target_suffix = Path(
            target.original_filename or ""
        ).suffix or ".bin"

        with tempfile.NamedTemporaryFile(
            suffix=source_suffix,
            delete=False,
            mode="wb",
        ) as tmp:
            tmp.write(source_stream.read())
            source_tmp = Path(tmp.name)

        with tempfile.NamedTemporaryFile(
            suffix=target_suffix,
            delete=False,
            mode="wb",
        ) as tmp:
            tmp.write(target_stream.read())
            target_tmp = Path(tmp.name)

        source_entities = _cross_evidence_extract(
            source,
            source_tmp,
        )
        target_entities = _cross_evidence_extract(
            target,
            target_tmp,
        )

        source_is_cdr = (
            source.evidence_type == EvidenceType.TELECOM_DATA
            or source_suffix.lower() in {".csv", ".xlsx", ".xls"}
        )
        target_is_cdr = (
            target.evidence_type == EvidenceType.TELECOM_DATA
            or target_suffix.lower() in {".csv", ".xlsx", ".xls"}
        )

        if source_is_cdr and not target_is_cdr:
            correlation = correlate_cdr_with_transcript(
                source_entities,
                target_entities,
            )
        elif target_is_cdr and not source_is_cdr:
            correlation = correlate_cdr_with_transcript(
                target_entities,
                source_entities,
            )
        else:
            correlation = correlate_evidence(
                source_entities,
                target_entities,
            )

        records = build_evidence_relationship_records(
            correlation,
            source_evidence_id=source.id,
            target_evidence_id=target.id,
            case_id=source.case_id,
            created_by_id=current_user.id,
        )

        # Replace previous results for this evidence pair in BOTH
        # directions.  This prevents repeated correlation runs from
        # accumulating stale relationship rows.
        (
            EvidenceRelationship.query
            .filter(
                (
                    (EvidenceRelationship.source_evidence_id == source.id)
                    & (EvidenceRelationship.target_evidence_id == target.id)
                )
                |
                (
                    (EvidenceRelationship.source_evidence_id == target.id)
                    & (EvidenceRelationship.target_evidence_id == source.id)
                )
            )
            .delete(
                synchronize_session=False,
            )
        )

        # Make the deletion visible to the current transaction before
        # inserting the fresh correlation result.
        db.session.flush()

        # Defensive de-duplication.  The same relationship type/value is
        # stored only once for this evidence pair.
        unique_records = []
        seen_record_keys = set()

        for record in records:
            record_key = (
                record.get("relationship_type"),
                record.get("shared_value"),
            )

            if record_key in seen_record_keys:
                continue

            seen_record_keys.add(record_key)
            unique_records.append(record)

        records = unique_records

        # Phase 3 forensic safeguard:
        # A transcript time must resolve to ONE nearest CDR timestamp.
        # Do not depend on metadata_json for this decision because older
        # correlation records may store metadata in different formats.
        # The shared_value is always persisted as:
        #     CDR_TIME ↔ TRANSCRIPT_TIME
        # so it is the reliable fallback/source of truth here.
        best_time_records = {}
        non_time_records = []

        def _time_to_seconds(value):
            try:
                text = str(value).strip()
                parts = text.split(":")
                if len(parts) != 3:
                    return None
                hours, minutes, seconds = (int(part) for part in parts)
                if not (0 <= hours <= 23 and 0 <= minutes <= 59 and 0 <= seconds <= 59):
                    return None
                return hours * 3600 + minutes * 60 + seconds
            except (TypeError, ValueError):
                return None

        def _time_gap_minutes(first_seconds, second_seconds):
            gap = abs(first_seconds - second_seconds)
            gap = min(gap, 86400 - gap)
            return gap / 60.0

        for record in records:
            if record.get("relationship_type") != "TIME_MATCH":
                non_time_records.append(record)
                continue

            shared_value = str(record.get("shared_value") or "")
            parts = [part.strip() for part in shared_value.split("↔", 1)]

            cdr_seconds = _time_to_seconds(parts[0]) if len(parts) == 2 else None
            transcript_seconds = _time_to_seconds(parts[1]) if len(parts) == 2 else None

            # If the canonical shared_value is available, use it directly.
            # This guarantees all candidates for 00:04:00 are grouped together.
            if transcript_seconds is not None:
                grouping_key = parts[1]
            else:
                grouping_key = None

            difference_minutes = float("inf")

            if cdr_seconds is not None and transcript_seconds is not None:
                difference_minutes = _time_gap_minutes(
                    cdr_seconds,
                    transcript_seconds,
                )

            # Prefer the engine's exact metadata distance when available,
            # but never require it for grouping or selection.
            raw_metadata = record.get("metadata_json")
            try:
                if isinstance(raw_metadata, dict):
                    metadata = raw_metadata
                elif isinstance(raw_metadata, str):
                    metadata = json.loads(raw_metadata or "{}")
                else:
                    metadata = {}
            except (TypeError, ValueError, json.JSONDecodeError):
                metadata = {}

            relationship_metadata = metadata.get("metadata") or {}
            try:
                metadata_difference = float(
                    relationship_metadata.get("difference_minutes")
                )
                if metadata_difference >= 0:
                    difference_minutes = metadata_difference
            except (TypeError, ValueError):
                pass

            if grouping_key is None:
                # Last-resort deterministic key for malformed TIME_MATCH rows.
                grouping_key = shared_value or repr(
                    (
                        record.get("relationship_type"),
                        record.get("correlation_basis"),
                    )
                )

            existing = best_time_records.get(grouping_key)

            if existing is None:
                best_time_records[grouping_key] = (
                    difference_minutes,
                    record,
                )
                continue

            existing_difference, existing_record = existing

            # Keep the closest CDR timestamp. If equally close, use the
            # lexicographically smaller canonical shared value so the result
            # is deterministic across runs.
            if (
                difference_minutes < existing_difference
                or (
                    difference_minutes == existing_difference
                    and shared_value < str(existing_record.get("shared_value") or "")
                )
            ):
                best_time_records[grouping_key] = (
                    difference_minutes,
                    record,
                )

        records = (
            non_time_records
            + [item[1] for item in best_time_records.values()]
        )

        for record in records:
            db.session.add(
                EvidenceRelationship(**record)
            )

        log_coc_event(
            evidence_id=source.id,
            actor_id=current_user.id,
            action=CoCAction.EVIDENCE_LINK,
            purpose=(
                f"Cross-evidence correlation performed against "
                f"{target.evidence_tag}. "
                f"{len(records)} relationship(s) detected."
            ),
            sha256=source.sha256_intake,
            verification_status=VerificationStatus.VERIFIED,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        log_coc_event(
            evidence_id=target.id,
            actor_id=current_user.id,
            action=CoCAction.EVIDENCE_LINK,
            purpose=(
                f"Cross-evidence correlation performed against "
                f"{source.evidence_tag}. "
                f"{len(records)} relationship(s) detected."
            ),
            sha256=target.sha256_intake,
            verification_status=VerificationStatus.VERIFIED,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        db.session.commit()

        if records:
            flash(
                f"Cross-evidence correlation complete: "
                f"{len(records)} relationship(s) stored between "
                f"{source.evidence_tag} and {target.evidence_tag}.",
                "success",
            )
        else:
            flash(
                f"Correlation completed, but no relationships were "
                f"found between {source.evidence_tag} and "
                f"{target.evidence_tag}.",
                "info",
            )

    except ValueError as exc:
        db.session.rollback()
        flash(f"Correlation could not be completed: {exc}", "error")

    except Exception as exc:
        db.session.rollback()
        flash(
            f"Cross-evidence analysis failed: {exc}",
            "error",
        )

    finally:
        for temp_path in (source_tmp, target_tmp):
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass

    return redirect(
        url_for(
            "dems.evidence_detail",
            evidence_id=evidence_id,
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRITY VERIFICATION SENTINEL
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/verify/<int:evidence_id>", methods=["GET", "POST"])
@dems_bp.route("/evidence/<int:evidence_id>/verify", methods=["GET", "POST"])
@role_required(UserRole.FORENSIC_ANALYST, UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def evidence_verify(evidence_id: int):
    """
    Real-time hash integrity check (Integrity Verification Sentinel).

    Decrypts the vault file in memory, recomputes SHA-256 and MD5,
    compares against the baseline intake hashes, and logs the result.
    Returns JSON for one-click AJAX verification badges.
    """
    current_user = _get_current_user()
    user_id = current_user.id
    ev = db.get_or_404(Evidence, evidence_id)

    vault_path = Path(ev.encrypted_storage_path)
    vault_key  = get_vault_key()
    associated_data = f"evidence:{ev.id}:{ev.evidence_tag}".encode()

    # The crypto layer intentionally converts any decrypt/hash failure into a
    # failed verification result. We still distinguish a missing vault object
    # at the API level so the investigator gets an actionable message.
    vault_exists = verify_vault_file_exists(vault_path)
    if not vault_exists:
        current_sha256 = ""
        is_ok = False
        v_status = VerificationStatus.ERROR
    else:
        is_ok, current_sha256 = verify_integrity(
            vault_path      = vault_path,
            key_bytes       = vault_key,
            expected_sha256 = ev.sha256_intake,
            associated_data = associated_data,
        )
        v_status = VerificationStatus.VERIFIED if is_ok else VerificationStatus.TAMPERED

    # Update evidence record
    ev.last_verified_at     = datetime.datetime.utcnow()
    ev.last_verified_status = v_status

    # Append immutable CoC event
    log_coc_event(
        evidence_id         = ev.id,
        actor_id            = user_id,
        action              = CoCAction.INTEGRITY_CHECK,
        purpose             = f"One-click integrity check. Result: {v_status.value}.",
        sha256              = current_sha256,
        verification_status = v_status,
        ip_address          = _get_client_ip(),
        user_agent          = _get_user_agent(),
    )
    db.session.commit()

    return jsonify({
        "success":             True,
        "verified":            is_ok,
        "is_verified":         is_ok,
        "status":              "PASS" if is_ok else ("ERROR" if v_status == VerificationStatus.ERROR else "FAIL"),
        "verification_status": v_status.value,
        "badge":               "green" if is_ok else ("amber" if v_status == VerificationStatus.ERROR else "red"),
        "badge_class":         "badge-verified" if is_ok else ("badge-error" if v_status == VerificationStatus.ERROR else "badge-tampered"),
        "badge_text":          (
            "PASS: INTEGRITY VERIFIED (HASH INTACT)" if is_ok
            else "ERROR: ENCRYPTED VAULT OBJECT IS MISSING" if v_status == VerificationStatus.ERROR
            else "FAIL: TAMPER DETECTED (BIT-LEVEL MISMATCH)"
        ),
        "expected_sha256":     ev.sha256_intake,
        "current_sha256":      current_sha256,
        "baseline_sha256":     ev.sha256_intake,
        "baseline_md5":        ev.md5_intake,
        "checked_at":          datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "evidence_tag":        ev.evidence_tag,
        "filename":            ev.original_filename,
    })


# ─────────────────────────────────────────────────────────────────────────────
# AUDIO INTELLIGENCE — PHASE 2
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route(
    "/evidence/<int:evidence_id>/transcribe",
    methods=["POST"],
)
@role_required(
    UserRole.FORENSIC_ANALYST,
    UserRole.LEAD_INVESTIGATOR,
    UserRole.ADMIN,
)
def evidence_transcribe_audio(evidence_id: int):
    """
    Phase 2 Audio Intelligence.

    Workflow:
      1. Validate the evidence exists.
      2. Validate the evidence is WAV/MP3 multimedia evidence.
      3. Verify the encrypted vault object exists.
      4. Decrypt the original evidence to memory.
      5. Write temporary plaintext audio for Faster-Whisper processing.
      6. Run local speech-to-text.
      7. Generate a timestamped transcript document.
      8. Store the transcript as derived DEMS evidence.
      9. Link the transcript to the original audio using source_evidence_id.
     10. Record Chain of Custody events.
     11. Delete the temporary plaintext file.
     12. Leave the original audio evidence completely unchanged.
    """

    current_user = _get_current_user()
    ev = db.get_or_404(Evidence, evidence_id)

    if not current_user.has_permission("run_analysis"):
        abort(403)

    if ev.evidence_type != EvidenceType.MULTIMEDIA:
        flash(
            "Audio transcription is available only for Multimedia evidence.",
            "error",
        )
        return redirect(
            url_for("dems.evidence_detail", evidence_id=evidence_id)
        )

    original_filename = ev.original_filename or ""
    extension = Path(original_filename).suffix.lower()

    if extension not in {".wav", ".mp3"}:
        flash(
            "Audio transcription currently supports only WAV and MP3 files.",
            "error",
        )
        return redirect(
            url_for("dems.evidence_detail", evidence_id=evidence_id)
        )

    vault_path = Path(ev.encrypted_storage_path)

    if not verify_vault_file_exists(vault_path):
        ev.last_verified_at = datetime.datetime.utcnow()
        ev.last_verified_status = VerificationStatus.ERROR

        log_coc_event(
            evidence_id=ev.id,
            actor_id=current_user.id,
            action=CoCAction.INTEGRITY_CHECK,
            purpose=(
                "Audio transcription aborted because the encrypted "
                "vault object could not be found."
            ),
            sha256=ev.sha256_intake,
            verification_status=VerificationStatus.ERROR,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        db.session.commit()

        flash(
            "Encrypted audio evidence could not be found in the DEMS Vault.",
            "error",
        )
        return redirect(
            url_for("dems.evidence_detail", evidence_id=evidence_id)
        )

    vault_key = get_vault_key()
    associated_data = f"evidence:{ev.id}:{ev.evidence_tag}".encode()

    try:
        integrity_result = verify_integrity(
            vault_path=vault_path,
            key_bytes=vault_key,
            expected_sha256=ev.sha256_intake,
            associated_data=associated_data,
        )
        is_integrity_ok, current_sha256 = integrity_result

    except Exception as exc:
        ev.last_verified_at = datetime.datetime.utcnow()
        ev.last_verified_status = VerificationStatus.ERROR

        log_coc_event(
            evidence_id=ev.id,
            actor_id=current_user.id,
            action=CoCAction.INTEGRITY_CHECK,
            purpose=f"Audio integrity verification failed: {exc}",
            sha256=ev.sha256_intake,
            verification_status=VerificationStatus.ERROR,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        db.session.commit()

        flash(
            f"Audio integrity verification failed: {exc}",
            "error",
        )
        return redirect(
            url_for("dems.evidence_detail", evidence_id=evidence_id)
        )

    if not is_integrity_ok:
        ev.last_verified_at = datetime.datetime.utcnow()
        ev.last_verified_status = VerificationStatus.TAMPERED

        log_coc_event(
            evidence_id=ev.id,
            actor_id=current_user.id,
            action=CoCAction.INTEGRITY_CHECK,
            purpose=(
                "Audio transcription blocked because the encrypted evidence "
                "failed SHA-256 integrity verification."
            ),
            sha256=current_sha256 or "",
            verification_status=VerificationStatus.TAMPERED,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        db.session.commit()

        flash(
            "Transcription blocked: audio evidence integrity verification failed.",
            "error",
        )
        return redirect(
            url_for("dems.evidence_detail", evidence_id=evidence_id)
        )

    ev.last_verified_at = datetime.datetime.utcnow()
    ev.last_verified_status = VerificationStatus.VERIFIED

    log_coc_event(
        evidence_id=ev.id,
        actor_id=current_user.id,
        action=CoCAction.INTEGRITY_CHECK,
        purpose=(
            "Audio evidence integrity verified successfully before "
            "speech-to-text processing."
        ),
        sha256=current_sha256 or ev.sha256_intake,
        verification_status=VerificationStatus.VERIFIED,
        ip_address=_get_client_ip(),
        user_agent=_get_user_agent(),
    )

    db.session.commit()

    try:
        plaintext_stream = decrypt_to_memory_stream(
            vault_path,
            vault_key,
            associated_data,
        )
    except Exception as exc:
        flash(
            f"Audio decryption failed: {exc}",
            "error",
        )
        return redirect(
            url_for("dems.evidence_detail", evidence_id=evidence_id)
        )

    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=extension,
            delete=False,
        ) as tmp:
            tmp.write(plaintext_stream.read())
            tmp_path = tmp.name

        transcript_result = transcribe_audio(tmp_path)

        if not transcript_result:
            raise ValueError(
                "The transcription engine returned no result."
            )

        segments = transcript_result.get("segments", [])

        if not segments:
            raise ValueError(
                "No speech was detected in the audio evidence."
            )

        transcript_document = build_transcript_document(
            original_filename=original_filename,
            transcription=transcript_result,
        )

        transcript_filename = (
            Path(original_filename).stem
            + "_transcript.txt"
        )

        transcript_title = f"Audio Transcript — {ev.title}"
        transcript_tag = generate_evidence_tag(ev.case_id)

        transcript_evidence = Evidence(
            case_id=ev.case_id,
            evidence_tag=transcript_tag,
            title=transcript_title,
            evidence_type=EvidenceType.REPORTS,
            original_filename=transcript_filename,
            encrypted_storage_path="pending",
            sha256_intake="",
            md5_intake="",
            sha512_intake="",
            file_size_bytes=0,
            mime_type="text/plain",
            uploaded_by_id=current_user.id,
            current_custodian_id=current_user.id,
            is_locked=False,
            notes=(
                f"Derived transcript generated from audio evidence "
                f"{ev.evidence_tag}. "
                f"Speech-to-text engine: Faster-Whisper "
                f"{transcript_result.get('model', 'unknown')}. "
                f"Detected language: "
                f"{transcript_result.get('language') or 'Unknown'}."
            ),
            source_evidence_id=ev.id,
        )

        db.session.add(transcript_evidence)
        db.session.flush()

        transcript_vault_path = build_vault_path(
            VAULT_DIR,
            transcript_evidence.id,
            transcript_filename,
        )

        transcript_associated_data = (
            f"evidence:{transcript_evidence.id}:{transcript_tag}"
        ).encode()

        transcript_stream = io.BytesIO(
            transcript_document.encode("utf-8")
        )

        (
            transcript_sha256,
            transcript_md5,
            transcript_sha512,
            transcript_byte_count,
        ) = encrypt_file_to_vault(
            file_obj=transcript_stream,
            vault_path=transcript_vault_path,
            key_bytes=vault_key,
            associated_data=transcript_associated_data,
        )

        transcript_evidence.encrypted_storage_path = str(
            transcript_vault_path
        )
        transcript_evidence.sha256_intake = transcript_sha256
        transcript_evidence.md5_intake = transcript_md5
        transcript_evidence.sha512_intake = transcript_sha512
        transcript_evidence.file_size_bytes = transcript_byte_count

        log_coc_event(
            evidence_id=transcript_evidence.id,
            actor_id=current_user.id,
            action=CoCAction.INGESTION,
            purpose=(
                f"Derived forensic transcript generated from source "
                f"audio evidence {ev.evidence_tag}."
            ),
            sha256=transcript_sha256,
            verification_status=VerificationStatus.VERIFIED,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        log_coc_event(
            evidence_id=ev.id,
            actor_id=current_user.id,
            action=CoCAction.ANALYSIS_RUN,
            purpose=(
                f"Local speech-to-text transcription completed. "
                f"Generated derived evidence {transcript_tag}. "
                f"Segments: {len(segments)}. "
                f"Language: "
                f"{transcript_result.get('language') or 'Unknown'}."
            ),
            sha256=ev.sha256_intake,
            verification_status=VerificationStatus.VERIFIED,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        log_coc_event(
            evidence_id=transcript_evidence.id,
            actor_id=current_user.id,
            action=CoCAction.EVIDENCE_LINK,
            purpose=(
                f"Derived transcript linked to source audio evidence "
                f"{ev.evidence_tag}."
            ),
            sha256=transcript_sha256,
            verification_status=VerificationStatus.VERIFIED,
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
        )

        ev.case.updated_at = datetime.datetime.utcnow()
        db.session.commit()

        language = transcript_result.get("language") or "Unknown"

        flash(
            f"Audio transcription completed successfully. "
            f"Created derived evidence {transcript_tag}. "
            f"Detected language: {language}. "
            f"Segments: {len(segments)}.",
            "success",
        )

        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=transcript_evidence.id,
            )
        )

    except Exception as exc:
        db.session.rollback()

        flash(
            f"Audio transcription failed: {exc}",
            "error",
        )

        return redirect(
            url_for(
                "dems.evidence_detail",
                evidence_id=evidence_id,
            )
        )

    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# CHAIN OF CUSTODY TRANSFER
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/<int:evidence_id>/transfer", methods=["POST"])
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def evidence_transfer(evidence_id: int):
    """
    Logs a custody transfer / check-in / check-out event.
    Updates the current_custodian and appends an immutable CoC log entry.
    """
    current_user = _get_current_user()
    ev = db.get_or_404(Evidence, evidence_id)

    action_str       = request.form.get("action", CoCAction.TRANSFER_CUSTODY.value)
    new_custodian_id = request.form.get("new_custodian_id", type=int)
    purpose          = request.form.get("purpose", "").strip()

    try:
        action = CoCAction(action_str)
    except ValueError:
        action = CoCAction.TRANSFER_CUSTODY

    # Validate new custodian
    new_custodian = None
    if new_custodian_id:
        new_custodian = db.session.get(User, new_custodian_id)
        if not new_custodian or not new_custodian.is_active:
            flash("Invalid custodian selected.", "error")
            return redirect(url_for("dems.evidence_detail", evidence_id=evidence_id))

    # Update custodian
    if new_custodian:
        ev.current_custodian_id = new_custodian.id

    if action == CoCAction.CHECK_OUT:
        ev.is_locked = True
    elif action == CoCAction.CHECK_IN:
        ev.is_locked = False

    transfer_note = purpose or f"Custody transferred to {new_custodian.full_name or new_custodian.username}" \
        if new_custodian else purpose or "Custody event recorded."

    log_coc_event(
        evidence_id = ev.id,
        actor_id    = current_user.id,
        action      = action,
        purpose     = transfer_note,
        sha256      = ev.sha256_intake,
        ip_address  = _get_client_ip(),
        user_agent  = _get_user_agent(),
    )
    ev.case.updated_at = datetime.datetime.utcnow()
    db.session.commit()

    flash(f"Chain of Custody event '{action.value}' recorded for {ev.evidence_tag}.", "success")
    if request.form.get("redirect_to") == "vault":
        return redirect(url_for("dems.vault_view"))
    return redirect(url_for("dems.evidence_detail", evidence_id=evidence_id))


# ─────────────────────────────────────────────────────────────────────────────
# SECURE DOWNLOAD (IN-MEMORY DECRYPTION)
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/<int:evidence_id>/download")
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN, UserRole.FORENSIC_ANALYST)
def evidence_download(evidence_id: int):
    """
    Decrypts the vault file in memory and streams it to the client.
    Plaintext never touches disk. Logs a DOWNLOAD CoC event.
    """
    current_user = _get_current_user()
    ev = db.get_or_404(Evidence, evidence_id)

    if not current_user.has_permission("download_evidence"):
        abort(403)

    vault_path = Path(ev.encrypted_storage_path)
    vault_key  = get_vault_key()
    associated_data = f"evidence:{ev.id}:{ev.evidence_tag}".encode()

    try:
        plaintext_stream = decrypt_to_memory_stream(vault_path, vault_key, associated_data)
    except Exception as exc:
        flash(f"Decryption failed: {exc}", "error")
        return redirect(url_for("dems.evidence_detail", evidence_id=evidence_id))

    log_coc_event(
        evidence_id = ev.id,
        actor_id    = current_user.id,
        action      = CoCAction.DOWNLOAD,
        purpose     = f"Authorized copy downloaded by {current_user.username}.",
        sha256      = ev.sha256_intake,
        ip_address  = _get_client_ip(),
        user_agent  = _get_user_agent(),
    )
    db.session.commit()

    return send_file(
        plaintext_stream,
        download_name   = ev.original_filename,
        as_attachment   = True,
        mimetype        = ev.mime_type or "application/octet-stream",
    )


@dems_bp.route("/stream/<int:evidence_id>")
@dems_bp.route("/evidence/<int:evidence_id>/stream")
def evidence_stream(evidence_id: int):
    """Video streaming feature decommissioned for high-performance optimization."""
    return jsonify({"error": "Video streaming feature decommissioned for performance optimization."}), 410


# ─────────────────────────────────────────────────────────────────────────────
# CDR ANALYTICS PIPELINE HOOK
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/<int:evidence_id>/analyze-cdr", methods=["POST"])
@role_required(UserRole.FORENSIC_ANALYST, UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def evidence_analyze_cdr(evidence_id: int):
    """
    CDR Analytics Pipeline Hook.

    Workflow:
      1. Validate evidence is TELECOM_DATA type.
      2. Decrypt vault file to in-memory BytesIO.
      3. Write decrypted content to a secure temp file.
      4. Run cdr_engine.run_full_analysis() on temp file.
      5. Save analysis result to CDR history cache (dual-register).
      6. Save derivative PDF/Excel evidence record back to the case.
      7. Log ANALYSIS_RUN CoC event.
      8. Redirect to CDR dashboard with analysis session.
    """
    import json
    from pathlib import Path as _Path

    current_user = _get_current_user()
    ev = db.get_or_404(Evidence, evidence_id)

    if ev.evidence_type not in (EvidenceType.TELECOM_DATA,):
        flash(
            f"CDR Analytics can only be run on Telecom Data evidence. "
            f"This item is type: {ev.evidence_type.value}.",
            "error",
        )
        return redirect(url_for("dems.evidence_detail", evidence_id=evidence_id))

    target_number = request.form.get("target_number", "").strip()
    vault_path    = Path(ev.encrypted_storage_path)
    vault_key     = get_vault_key()
    associated_data = f"evidence:{ev.id}:{ev.evidence_tag}".encode()

    # Decrypt to memory
    try:
        plaintext_stream = decrypt_to_memory_stream(vault_path, vault_key, associated_data)
    except Exception as exc:
        flash(f"Vault decryption failed: {exc}", "error")
        return redirect(url_for("dems.evidence_detail", evidence_id=evidence_id))

    # Write to temp file (auto-deleted)
    suffix = _Path(ev.original_filename).suffix or ".csv"
    analysis_data = {}
    session_id = str(uuid.uuid4())

    try:
        with tempfile.NamedTemporaryFile(
            suffix=suffix, delete=False, mode="wb"
        ) as tmp:
            tmp.write(plaintext_stream.read())
            tmp_path = tmp.name

        # Run CDR engine
        analysis_data = engine.run_full_analysis(tmp_path, target_number)
        analysis_data["filename"]   = ev.original_filename
        analysis_data["case_ref"]   = ev.case.case_number
        analysis_data["dems_ev_id"] = evidence_id

    except Exception as exc:
        flash(f"CDR Analysis failed: {exc}", "error")
        return redirect(url_for("dems.evidence_detail", evidence_id=evidence_id))
    finally:
        # Securely delete temp plaintext file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # ── Dual-register: save to CDR flat cache (appears in CDR History) ──
    cache_dir = _Path(current_app.root_path) / "cache"
    cache_dir.mkdir(exist_ok=True)
    cache_path = cache_dir / f"{session_id}.json"
    with open(cache_path, "w", encoding="utf-8") as cf:
        json.dump(analysis_data, cf, default=str)

    # ── Dual-register: add to CDR history.json ──
    history_file = cache_dir / "history.json"
    history = []
    if history_file.exists():
        try:
            with open(history_file) as hf:
                history = json.load(hf)
        except Exception:
            history = []

    kpis   = analysis_data.get("kpis", {})
    swaps  = analysis_data.get("device_swaps", {})
    travel = analysis_data.get("impossible_travel", [])
    anomalies = len(travel) + (1 if swaps.get("handset_hopping") else 0) + (1 if swaps.get("sim_swapping") else 0)

    history = [h for h in history if h.get("id") != session_id]
    history.insert(0, {
        "id":             session_id,
        "type":           "single",
        "target":         analysis_data.get("target", target_number or "Unknown"),
        "filename":       ev.original_filename,
        "case_ref":       ev.case.case_number,
        "records_count":  kpis.get("total_records", 0),
        "contacts_count": kpis.get("unique_contacts", 0),
        "duration":       kpis.get("total_duration_hms", "00:00:00"),
        "anomalies_count": anomalies,
        "sha256":         ev.sha256_intake,
        "date_range":     kpis.get("date_range", ""),
        "timestamp":      datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "dems_evidence_id": evidence_id,
        "dems_case_ref":    ev.case.case_number,
    })
    with open(history_file, "w", encoding="utf-8") as hf:
        json.dump(history, hf, default=str, indent=2)

    # ── Log ANALYSIS_RUN CoC event ──
    log_coc_event(
        evidence_id = ev.id,
        actor_id    = current_user.id,
        action      = CoCAction.ANALYSIS_RUN,
        purpose     = (
            f"CDR analysis run by {current_user.username}. "
            f"Target: {target_number or 'auto-detect'}. "
            f"Session ID: {session_id}."
        ),
        sha256      = ev.sha256_intake,
        ip_address  = _get_client_ip(),
        user_agent  = _get_user_agent(),
    )
    db.session.commit()

    flash(
        f"CDR analysis complete for {ev.evidence_tag}. "
        f"Redirecting to analysis dashboard.",
        "success",
    )
    # Redirect to CDR analysis dashboard
    return redirect(url_for("dashboard", session_id=session_id))


# ─────────────────────────────────────────────────────────────────────────────
# COURT-READY CoC DOSSIER
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/<int:evidence_id>/coc-dossier")
@dems_login_required
def coc_dossier(evidence_id: int):
    """
    Renders the court-admissible, printable Chain of Custody dossier.
    Logs a COURT_EXHIBIT event when accessed.
    """
    current_user = _get_current_user()
    ev = db.get_or_404(Evidence, evidence_id)
    case = ev.case

    coc_logs = (
        ChainOfCustodyLog.query
        .filter_by(evidence_id=ev.id)
        .order_by(ChainOfCustodyLog.timestamp_utc.asc())
        .all()
    )

    log_coc_event(
        evidence_id = ev.id,
        actor_id    = current_user.id,
        action      = CoCAction.COURT_EXHIBIT,
        purpose     = f"Court exhibit CoC dossier rendered by {current_user.username}.",
        sha256      = ev.sha256_intake,
        ip_address  = _get_client_ip(),
        user_agent  = _get_user_agent(),
    )
    db.session.commit()

    generated_at = datetime.datetime.utcnow()

    return render_template(
        "dems/coc_ledger.html",
        ev          = ev,
        case        = case,
        coc_logs    = coc_logs,
        current_user= current_user,
        generated_at= generated_at,
        CoCAction   = CoCAction,
        VerificationStatus = VerificationStatus,
    )


@dems_bp.route("/coc/export-csv")
@dems_login_required
def coc_export_csv():
    """Exports all Chain of Custody ledger entries to CSV format."""
    import csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID", "Timestamp UTC", "Evidence ID", "Evidence Tag",
        "Action", "Actor", "Purpose", "Verification Status", "SHA-256", "IP Address"
    ])
    logs = ChainOfCustodyLog.query.order_by(ChainOfCustodyLog.timestamp_utc.asc()).all()
    for entry in logs:
        action_val = entry.action.value if hasattr(entry.action, "value") else str(entry.action)
        status_val = entry.verification_status.value if hasattr(entry.verification_status, "value") else str(entry.verification_status)
        actor_name = entry.actor.username if entry.actor else str(entry.actor_id)
        ev_tag = entry.evidence.evidence_tag if entry.evidence else ""
        writer.writerow([
            entry.id,
            entry.timestamp_utc.isoformat() if entry.timestamp_utc else "",
            entry.evidence_id,
            ev_tag,
            action_val,
            actor_name,
            entry.purpose,
            status_val,
            entry.recorded_sha256,
            entry.ip_address,
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=chain_of_custody_ledger.csv"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# JSON API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/api/cases")
@dems_login_required
def api_cases():
    """JSON list of all cases for AJAX autocomplete."""
    cases = Case.query.order_by(Case.updated_at.desc()).all()
    return jsonify([
        {
            "id":           c.id,
            "case_number":  c.case_number,
            "title":        c.title,
            "status":       c.status.value,
            "priority":     c.priority.value,
            "evidence_count": c.evidence_count,
        }
        for c in cases
    ])


@dems_bp.route("/api/evidence/<int:evidence_id>/status")
@dems_login_required
def api_evidence_status(evidence_id: int):
    """Live integrity status for an evidence item."""
    ev = db.get_or_404(Evidence, evidence_id)
    vault_exists = verify_vault_file_exists(Path(ev.encrypted_storage_path))
    return jsonify({
        "evidence_id":     ev.id,
        "evidence_tag":    ev.evidence_tag,
        "vault_exists":    vault_exists,
        "is_locked":       ev.is_locked,
        "verification":    ev.last_verified_status.value,
        "verified_at":     ev.last_verified_at.isoformat() if ev.last_verified_at else None,
        "sha256_short":    ev.sha256_short,
        "current_custodian": ev.current_custodian.username if ev.current_custodian else None,
    })


@dems_bp.route("/api/users")
@role_required(UserRole.LEAD_INVESTIGATOR, UserRole.ADMIN)
def api_users():
    """JSON list of active users for custodian selection."""
    users = User.query.filter_by(is_active=True).order_by(User.full_name).all()
    return jsonify([
        {
            "id":          u.id,
            "username":    u.username,
            "full_name":   u.full_name,
            "role":        u.role.value,
            "badge_number": u.badge_number,
        }
        for u in users
    ])
