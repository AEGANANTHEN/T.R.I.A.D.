"""
DEMS Database Models
=====================
SQLAlchemy ORM models for the Digital Evidence Management System.

Schema overview:
  User              — Authenticated system users with RBAC roles.
  Case              — Investigative cases grouping evidence.
  Evidence          — Individual evidence items with cryptographic metadata.
  ChainOfCustodyLog — Immutable append-only event ledger.

Complies with ISO/IEC 27037 (digital evidence handling) and
NIST SP 800-86 (guide to integrating forensic techniques).
"""

import datetime
import enum
import secrets
import string

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
bcrypt = Bcrypt()


# ─────────────────────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class UserRole(enum.Enum):
    """RBAC roles ordered by privilege level (lowest → highest)."""
    AUDITOR             = "Auditor"            # Read-only CoC inspection
    FORENSIC_ANALYST    = "Forensic Analyst"   # Analysis & report generation
    LEAD_INVESTIGATOR   = "Lead Investigator"  # Case creation, check-in/out
    ADMIN               = "Admin"              # Full system access


class CaseStatus(enum.Enum):
    DRAFT       = "Draft"
    OPEN        = "Open"
    ACTIVE      = "Active"
    SUSPENDED   = "Suspended"
    COURT_READY = "Court Ready"
    CLOSED      = "Closed"
    ARCHIVED    = "Archived"


class CasePriority(enum.Enum):
    LOW      = "Low"
    MEDIUM   = "Medium"
    HIGH     = "High"
    CRITICAL = "Critical"


class EvidenceType(enum.Enum):
    TELECOM_DATA     = "Telecom Data"       # CDR, IPDR, Tower Dumps
    MOBILE_EXTRACT   = "Mobile Extraction"  # UFED, Cellebrite, logical/physical dumps
    DISK_MEMORY      = "Disk & Memory Image"# .dd, .E01, .raw, .vmdk
    NETWORK_LOGS     = "Network & System Logs" # .pcap, syslog, event logs
    MULTIMEDIA       = "Multimedia"         # CCTV, audio intercepts
    REPORTS          = "Reports"            # PDF forensic reports, derivatives
    OTHER            = "Other"


class CoCAction(enum.Enum):
    """All possible chain-of-custody lifecycle events."""
    INGESTION          = "INGESTION"
    CHECK_OUT          = "CHECK_OUT"
    CHECK_IN           = "CHECK_IN"
    ANALYSIS_RUN       = "ANALYSIS_RUN"
    TRANSFER_CUSTODY   = "TRANSFER_CUSTODY"
    INTEGRITY_CHECK    = "INTEGRITY_CHECK"
    COURT_EXHIBIT      = "COURT_EXHIBIT_EXPORT"
    DISPOSITION        = "DISPOSITION"
    ACCESS_VIEW        = "ACCESS_VIEW"
    DOWNLOAD           = "DOWNLOAD"


class VerificationStatus(enum.Enum):
    NOT_VERIFIED = "Not Verified"
    VERIFIED     = "Verified"
    TAMPERED     = "Tamper Detected"
    ERROR        = "Error"


# ─────────────────────────────────────────────────────────────────────────────
# ROLE PRIVILEGE MATRIX
# ─────────────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.AUDITOR: {
        "view_cases", "view_evidence", "view_coc", "export_coc"
    },
    UserRole.FORENSIC_ANALYST: {
        "view_cases", "view_evidence", "view_coc", "export_coc",
        "verify_integrity", "run_analysis", "download_evidence"
    },
    UserRole.LEAD_INVESTIGATOR: {
        "view_cases", "view_evidence", "view_coc", "export_coc",
        "verify_integrity", "run_analysis", "download_evidence",
        "create_case", "upload_evidence", "transfer_custody",
        "check_in", "check_out", "edit_case"
    },
    UserRole.ADMIN: {
        "view_cases", "view_evidence", "view_coc", "export_coc",
        "verify_integrity", "run_analysis", "download_evidence",
        "create_case", "upload_evidence", "transfer_custody",
        "check_in", "check_out", "edit_case",
        "manage_users", "system_config", "delete_evidence", "close_case"
    },
}


def has_permission(role: UserRole, permission: str) -> bool:
    """Check whether a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())


# ─────────────────────────────────────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    """
    Authenticated system users with role-based access control.
    Passwords are stored as bcrypt hashes — never plaintext.
    """
    __tablename__ = "dems_users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name     = db.Column(db.String(128), nullable=False, default="")
    role          = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.AUDITOR)
    badge_number  = db.Column(db.String(32), unique=True, nullable=True)
    department    = db.Column(db.String(128), nullable=True)
    email         = db.Column(db.String(128), nullable=True)
    is_active     = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_login    = db.Column(db.DateTime, nullable=True)

    # Relationships
    led_cases       = db.relationship("Case", foreign_keys="Case.lead_investigator_id", back_populates="lead_investigator")
    uploaded_items  = db.relationship("Evidence", foreign_keys="Evidence.uploaded_by_id", back_populates="uploaded_by")
    custodied_items = db.relationship("Evidence", foreign_keys="Evidence.current_custodian_id", back_populates="current_custodian")
    coc_actions     = db.relationship("ChainOfCustodyLog", back_populates="actor")

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

    def has_permission(self, permission: str) -> bool:
        return has_permission(self.role, permission)

    def role_label(self) -> str:
        return self.role.value if self.role else "Unknown"

    def __repr__(self) -> str:
        return f"<User {self.username} [{self.role.value}]>"


class Case(db.Model):
    """
    An investigative case grouping related evidence items.
    Case numbers are auto-generated in CAS-YYYY-NNNN format.
    """
    __tablename__ = "dems_cases"

    id                   = db.Column(db.Integer, primary_key=True)
    case_number          = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title                = db.Column(db.String(256), nullable=False)
    description          = db.Column(db.Text, nullable=True)
    lead_investigator_id = db.Column(db.Integer, db.ForeignKey("dems_users.id"), nullable=True)
    jurisdiction         = db.Column(db.String(128), nullable=True)
    incident_date        = db.Column(db.Date, nullable=True)
    status               = db.Column(db.Enum(CaseStatus), default=CaseStatus.OPEN, nullable=False)
    priority             = db.Column(db.Enum(CasePriority), default=CasePriority.MEDIUM, nullable=False)
    classification       = db.Column(db.String(64), default="RESTRICTED", nullable=False)
    created_at           = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at           = db.Column(db.DateTime, default=datetime.datetime.utcnow,
                                     onupdate=datetime.datetime.utcnow, nullable=False)

    # Relationships
    lead_investigator = db.relationship("User", foreign_keys=[lead_investigator_id], back_populates="led_cases")
    evidence_items    = db.relationship("Evidence", back_populates="case", cascade="all, delete-orphan",
                                        order_by="Evidence.uploaded_at.desc()")

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_items)

    @property
    def open_evidence_count(self) -> int:
        return sum(1 for e in self.evidence_items if not e.is_locked)

    def __repr__(self) -> str:
        return f"<Case {self.case_number}: {self.title}>"


class Evidence(db.Model):
    """
    An individual evidence item with full cryptographic metadata.
    Files are stored AES-256-GCM encrypted in the vault directory.
    The intake SHA-256/MD5/SHA-512 hashes serve as the immutable baseline
    for all future integrity checks.
    """
    __tablename__ = "dems_evidence"

    id                     = db.Column(db.Integer, primary_key=True)
    case_id                = db.Column(db.Integer, db.ForeignKey("dems_cases.id"), nullable=False, index=True)
    evidence_tag           = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title                  = db.Column(db.String(256), nullable=False)
    evidence_type          = db.Column(db.Enum(EvidenceType), nullable=False)
    original_filename      = db.Column(db.String(512), nullable=False)
    encrypted_storage_path = db.Column(db.String(512), nullable=False)
    sha256_intake          = db.Column(db.String(64), nullable=False)
    md5_intake             = db.Column(db.String(32), nullable=False)
    sha512_intake          = db.Column(db.String(128), nullable=False)
    file_size_bytes        = db.Column(db.BigInteger, nullable=False, default=0)
    mime_type              = db.Column(db.String(128), nullable=True)
    uploaded_by_id         = db.Column(db.Integer, db.ForeignKey("dems_users.id"), nullable=False)
    current_custodian_id   = db.Column(db.Integer, db.ForeignKey("dems_users.id"), nullable=True)
    is_locked              = db.Column(db.Boolean, default=False, nullable=False)
    notes                  = db.Column(db.Text, nullable=True)
    source_evidence_id     = db.Column(db.Integer, db.ForeignKey("dems_evidence.id"), nullable=True)
    last_verified_at       = db.Column(db.DateTime, nullable=True)
    last_verified_status   = db.Column(db.Enum(VerificationStatus),
                                       default=VerificationStatus.NOT_VERIFIED, nullable=False)
    uploaded_at            = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    case              = db.relationship("Case", back_populates="evidence_items")
    uploaded_by       = db.relationship("User", foreign_keys=[uploaded_by_id], back_populates="uploaded_items")
    current_custodian = db.relationship("User", foreign_keys=[current_custodian_id], back_populates="custodied_items")
    coc_logs          = db.relationship("ChainOfCustodyLog", back_populates="evidence",
                                        order_by="ChainOfCustodyLog.timestamp_utc.desc()",
                                        cascade="all, delete-orphan")
    derived_artifacts = db.relationship("Evidence", foreign_keys=[source_evidence_id])

    @property
    def file_size_human(self) -> str:
        """Human-readable file size string."""
        size = self.file_size_bytes or 0
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    @property
    def sha256_short(self) -> str:
        return self.sha256_intake[:16] + "…" if self.sha256_intake else "—"

    @property
    def is_telecom(self) -> bool:
        return self.evidence_type == EvidenceType.TELECOM_DATA

    def __repr__(self) -> str:
        return f"<Evidence {self.evidence_tag}: {self.original_filename}>"


class ChainOfCustodyLog(db.Model):
    """
    Immutable append-only Chain of Custody audit ledger.

    Each row records a lifecycle event for an evidence item.
    Rows are NEVER updated or deleted — only appended.
    The recorded_sha256 captures the hash state at the time of the event
    for cryptographic non-repudiation.
    """
    __tablename__ = "dems_coc_log"

    id                  = db.Column(db.Integer, primary_key=True)
    evidence_id         = db.Column(db.Integer, db.ForeignKey("dems_evidence.id"), nullable=False, index=True)
    actor_id            = db.Column(db.Integer, db.ForeignKey("dems_users.id"), nullable=False)
    action              = db.Column(db.Enum(CoCAction), nullable=False)
    purpose             = db.Column(db.Text, nullable=True)
    timestamp_utc       = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    recorded_sha256     = db.Column(db.String(64), nullable=True)
    verification_status = db.Column(db.Enum(VerificationStatus),
                                    default=VerificationStatus.NOT_VERIFIED, nullable=False)
    ip_address          = db.Column(db.String(45), nullable=True)   # IPv4 or IPv6
    user_agent          = db.Column(db.String(256), nullable=True)
    event_uuid          = db.Column(db.String(36), nullable=False,
                                    default=lambda: secrets.token_hex(16))

    # Relationships
    evidence = db.relationship("Evidence", back_populates="coc_logs")
    actor    = db.relationship("User", back_populates="coc_actions")

    def __repr__(self) -> str:
        return f"<CoC {self.action.value} ev={self.evidence_id} by={self.actor_id}>"


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def generate_case_number() -> str:
    """Generates a unique case number in format CAS-YYYY-XXXX."""
    year = datetime.datetime.utcnow().year
    suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return f"CAS-{year}-{suffix}"


def generate_evidence_tag(case_id: int) -> str:
    """Generates an evidence tag in format EVD-<CaseID>-<NNNN>."""
    existing_count = Evidence.query.filter_by(case_id=case_id).count()
    return f"EVD-{case_id:04d}-{existing_count + 1:04d}"


def log_coc_event(
    evidence_id: int,
    actor_id: int,
    action: CoCAction,
    purpose: str = "",
    sha256: str = "",
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED,
    ip_address: str = "",
    user_agent: str = "",
) -> ChainOfCustodyLog:
    """
    Appends an immutable Chain of Custody event to the ledger.

    Args:
        evidence_id:         ID of the evidence item.
        actor_id:            ID of the user performing the action.
        action:              The CoCAction enum value.
        purpose:             Free-text purpose/notes for the event.
        sha256:              SHA-256 hash at the time of the event (if applicable).
        verification_status: Result of any integrity check.
        ip_address:          Client IP address for audit trail.
        user_agent:          Client user agent string.

    Returns:
        The newly created ChainOfCustodyLog instance (not yet committed).
    """
    entry = ChainOfCustodyLog(
        evidence_id         = evidence_id,
        actor_id            = actor_id,
        action              = action,
        purpose             = purpose,
        timestamp_utc       = datetime.datetime.utcnow(),
        recorded_sha256     = sha256,
        verification_status = verification_status,
        ip_address          = ip_address or "",
        user_agent          = (user_agent or "")[:256],
    )
    db.session.add(entry)
    return entry


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE INITIALISATION
# ─────────────────────────────────────────────────────────────────────────────

def init_db(app) -> None:
    """
    Initialises the SQLAlchemy database within the Flask application context.
    Creates all tables and seeds the default admin user if the DB is empty.

    Call this from app.py after configuring db.init_app(app).

    Args:
        app: The Flask application instance.
    """
    db.init_app(app)
    bcrypt.init_app(app)

    with app.app_context():
        db.create_all()

        # Seed default admin if no users exist
        if User.query.count() == 0:
            admin = User(
                username     = "admin",
                full_name    = "System Administrator",
                role         = UserRole.ADMIN,
                badge_number = "ADM-0001",
                department   = "Digital Forensics Unit",
                is_active    = True,
            )
            admin.set_password("Admin@DEMS2024!")
            db.session.add(admin)

            # Seed demo investigator
            investigator = User(
                username     = "investigator",
                full_name    = "Lead Investigator",
                role         = UserRole.LEAD_INVESTIGATOR,
                badge_number = "INV-0001",
                department   = "Digital Forensics Unit",
                is_active    = True,
            )
            investigator.set_password("Invest@DEMS2024!")
            db.session.add(investigator)

            # Seed demo analyst
            analyst = User(
                username     = "analyst",
                full_name    = "Forensic Analyst",
                role         = UserRole.FORENSIC_ANALYST,
                badge_number = "ANL-0001",
                department   = "Digital Forensics Unit",
                is_active    = True,
            )
            analyst.set_password("Analyst@DEMS2024!")
            db.session.add(analyst)

            # Seed demo auditor
            auditor = User(
                username     = "auditor",
                full_name    = "Compliance Auditor",
                role         = UserRole.AUDITOR,
                badge_number = "AUD-0001",
                department   = "Internal Audit",
                is_active    = True,
            )
            auditor.set_password("Audit@DEMS2024!")
            db.session.add(auditor)

            db.session.commit()
