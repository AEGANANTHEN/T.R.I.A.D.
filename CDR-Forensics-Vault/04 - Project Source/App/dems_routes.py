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
import os
import tempfile
import uuid
from functools import wraps
from pathlib import Path
from typing import Callable

from flask import (
    Blueprint,
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
    db,
    generate_case_number,
    generate_evidence_tag,
    log_coc_event,
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

    user = User.query.get(user_id)
    if user and user.is_active:
        session["dems_last_active"] = datetime.datetime.utcnow().isoformat()
        return user
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
    case = Case.query.get_or_404(case_id)

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
    case = Case.query.get_or_404(case_id)
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

    case = Case.query.get_or_404(case_id)

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
    ev = Evidence.query.get_or_404(evidence_id)
    case = ev.case

    coc_logs = (
        ChainOfCustodyLog.query
        .filter_by(evidence_id=ev.id)
        .order_by(ChainOfCustodyLog.timestamp_utc.desc())
        .all()
    )

    all_users = User.query.filter_by(is_active=True).all()
    vault_exists = verify_vault_file_exists(Path(ev.encrypted_storage_path))

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
    )


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRITY VERIFICATION SENTINEL
# ─────────────────────────────────────────────────────────────────────────────

@dems_bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@dems_login_required
def evidence_verify(evidence_id: int):
    """
    Real-time hash integrity check (Integrity Verification Sentinel).

    Decrypts the vault file in memory, recomputes SHA-256,
    compares against the baseline intake hash, and logs the result.
    Returns JSON for AJAX usage.
    """
    current_user = _get_current_user()
    ev = Evidence.query.get_or_404(evidence_id)

    if not current_user.has_permission("verify_integrity"):
        return jsonify({"error": "Insufficient privileges."}), 403

    vault_path = Path(ev.encrypted_storage_path)
    vault_key  = get_vault_key()
    associated_data = f"evidence:{ev.id}:{ev.evidence_tag}".encode()

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
        actor_id            = current_user.id,
        action              = CoCAction.INTEGRITY_CHECK,
        purpose             = f"Integrity sentinel run. Result: {v_status.value}.",
        sha256              = current_sha256,
        verification_status = v_status,
        ip_address          = _get_client_ip(),
        user_agent          = _get_user_agent(),
    )
    db.session.commit()

    return jsonify({
        "verified":        is_ok,
        "status":          v_status.value,
        "expected_sha256": ev.sha256_intake,
        "current_sha256":  current_sha256,
        "checked_at":      datetime.datetime.utcnow().isoformat() + "Z",
        "evidence_tag":    ev.evidence_tag,
    })


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
    ev = Evidence.query.get_or_404(evidence_id)

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
        new_custodian = User.query.get(new_custodian_id)
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
    ev = Evidence.query.get_or_404(evidence_id)

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
    ev = Evidence.query.get_or_404(evidence_id)

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
    ev = Evidence.query.get_or_404(evidence_id)
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
    ev = Evidence.query.get_or_404(evidence_id)
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
