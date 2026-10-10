"""
DEMS Database Models
=====================
SQLAlchemy ORM models for the Digital Evidence Management System.

Schema overview:
  User              — Authenticated system users with RBAC roles.
  Case              — Investigative cases grouping evidence.
  Evidence          — Individual evidence items with cryptographic metadata.
  EvidenceRelationship — Relationships between multiple evidence items.
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
    AUDITOR             = "Auditor"
    FORENSIC_ANALYST    = "Forensic Analyst"
    LEAD_INVESTIGATOR   = "Lead Investigator"
    ADMIN               = "Admin"


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
    TELECOM_DATA     = "Telecom Data"
    MOBILE_EXTRACT   = "Mobile Extraction"
    DISK_MEMORY      = "Disk & Memory Image"
    NETWORK_LOGS     = "Network & System Logs"
    MULTIMEDIA       = "Multimedia"
    REPORTS          = "Reports"
    OTHER            = "Other"


class CoCAction(enum.Enum):
    """All possible chain-of-custody lifecycle events."""
    INGESTION          = "INGESTION"
    CHECK_OUT          = "CHECK_OUT"
    CHECK_IN           = "CHECK_IN"
    ANALYSIS_RUN       = "ANALYSIS_RUN"
    TRANSFER_CUSTODY   = "TRANSFER_CUSTODY"
    INTEGRITY_CHECK    = "INTEGRITY_CHECK"
    EVIDENCE_LINK      = "EVIDENCE_LINK"
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
        "view_cases",
        "view_evidence",
        "view_coc",
        "export_coc",
    },

    UserRole.FORENSIC_ANALYST: {
        "view_cases",
        "view_evidence",
        "view_coc",
        "export_coc",
        "verify_integrity",
        "run_analysis",
        "download_evidence",
    },

    UserRole.LEAD_INVESTIGATOR: {
        "view_cases",
        "view_evidence",
        "view_coc",
        "export_coc",
        "verify_integrity",
        "run_analysis",
        "download_evidence",
        "create_case",
        "upload_evidence",
        "transfer_custody",
        "check_in",
        "check_out",
        "edit_case",
    },

    UserRole.ADMIN: {
        "view_cases",
        "view_evidence",
        "view_coc",
        "export_coc",
        "verify_integrity",
        "run_analysis",
        "download_evidence",
        "create_case",
        "upload_evidence",
        "transfer_custody",
        "check_in",
        "check_out",
        "edit_case",
        "manage_users",
        "system_config",
        "delete_evidence",
        "close_case",
    },
}


def has_permission(role: UserRole, permission: str) -> bool:
    """Check whether a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())


# ─────────────────────────────────────────────────────────────────────────────
# USER MODEL
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    """
    Authenticated system users with role-based access control.
    Passwords are stored as bcrypt hashes — never plaintext.
    """

    __tablename__ = "dems_users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash = db.Column(
        db.String(128),
        nullable=False,
    )
    full_name     = db.Column(
        db.String(128),
        nullable=False,
        default="",
    )
    role          = db.Column(
        db.Enum(UserRole),
        nullable=False,
        default=UserRole.AUDITOR,
    )
    badge_number  = db.Column(
        db.String(32),
        unique=True,
        nullable=True,
    )
    department    = db.Column(
        db.String(128),
        nullable=True,
    )
    email         = db.Column(
        db.String(128),
        nullable=True,
    )
    is_active     = db.Column(
        db.Boolean,
        default=True,
        nullable=False,
    )
    created_at    = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
    )
    last_login    = db.Column(
        db.DateTime,
        nullable=True,
    )

    # Relationships
    led_cases = db.relationship(
        "Case",
        foreign_keys="Case.lead_investigator_id",
        back_populates="lead_investigator",
    )

    uploaded_items = db.relationship(
        "Evidence",
        foreign_keys="Evidence.uploaded_by_id",
        back_populates="uploaded_by",
    )

    custodied_items = db.relationship(
        "Evidence",
        foreign_keys="Evidence.current_custodian_id",
        back_populates="current_custodian",
    )

    coc_actions = db.relationship(
        "ChainOfCustodyLog",
        back_populates="actor",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(
            self.password_hash,
            password,
        )

    def has_permission(self, permission: str) -> bool:
        return has_permission(self.role, permission)

    def role_label(self) -> str:
        return self.role.value if self.role else "Unknown"

    def __repr__(self) -> str:
        return f"<User {self.username} [{self.role.value}]>"


# ─────────────────────────────────────────────────────────────────────────────
# CASE MODEL
# ─────────────────────────────────────────────────────────────────────────────

class Case(db.Model):
    """
    An investigative case grouping related evidence items.
    Case numbers are auto-generated in CAS-YYYY-NNNN format.
    """

    __tablename__ = "dems_cases"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    case_number = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True,
    )

    title = db.Column(
        db.String(256),
        nullable=False,
    )

    description = db.Column(
        db.Text,
        nullable=True,
    )

    lead_investigator_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_users.id"),
        nullable=True,
    )

    jurisdiction = db.Column(
        db.String(128),
        nullable=True,
    )

    incident_date = db.Column(
        db.Date,
        nullable=True,
    )

    status = db.Column(
        db.Enum(CaseStatus),
        default=CaseStatus.OPEN,
        nullable=False,
    )

    priority = db.Column(
        db.Enum(CasePriority),
        default=CasePriority.MEDIUM,
        nullable=False,
    )

    classification = db.Column(
        db.String(64),
        default="RESTRICTED",
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )

    # Relationships
    lead_investigator = db.relationship(
        "User",
        foreign_keys=[lead_investigator_id],
        back_populates="led_cases",
    )

    evidence_items = db.relationship(
        "Evidence",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="Evidence.uploaded_at.desc()",
    )

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_items)

    @property
    def open_evidence_count(self) -> int:
        return sum(
            1
            for evidence in self.evidence_items
            if not evidence.is_locked
        )

    def __repr__(self) -> str:
        return f"<Case {self.case_number}: {self.title}>"


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE MODEL
# ─────────────────────────────────────────────────────────────────────────────

class Evidence(db.Model):
    """
    An individual evidence item with full cryptographic metadata.

    Files are stored AES-256-GCM encrypted in the vault directory.

    The intake SHA-256/MD5/SHA-512 hashes serve as the immutable
    baseline for all future integrity checks.
    """

    __tablename__ = "dems_evidence"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_cases.id"),
        nullable=False,
        index=True,
    )

    evidence_tag = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True,
    )

    title = db.Column(
        db.String(256),
        nullable=False,
    )

    evidence_type = db.Column(
        db.Enum(EvidenceType),
        nullable=False,
    )

    original_filename = db.Column(
        db.String(512),
        nullable=False,
    )

    encrypted_storage_path = db.Column(
        db.String(512),
        nullable=False,
    )

    sha256_intake = db.Column(
        db.String(64),
        nullable=False,
    )

    md5_intake = db.Column(
        db.String(32),
        nullable=False,
    )

    sha512_intake = db.Column(
        db.String(128),
        nullable=False,
    )

    file_size_bytes = db.Column(
        db.BigInteger,
        nullable=False,
        default=0,
    )

    mime_type = db.Column(
        db.String(128),
        nullable=True,
    )

    uploaded_by_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_users.id"),
        nullable=False,
    )

    current_custodian_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_users.id"),
        nullable=True,
    )

    is_locked = db.Column(
        db.Boolean,
        default=False,
        nullable=False,
    )

    notes = db.Column(
        db.Text,
        nullable=True,
    )

    source_evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_evidence.id"),
        nullable=True,
    )

    last_verified_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    last_verified_status = db.Column(
        db.Enum(VerificationStatus),
        default=VerificationStatus.NOT_VERIFIED,
        nullable=False,
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
    )

    # Relationships
    case = db.relationship(
        "Case",
        back_populates="evidence_items",
    )

    uploaded_by = db.relationship(
        "User",
        foreign_keys=[uploaded_by_id],
        back_populates="uploaded_items",
    )

    current_custodian = db.relationship(
        "User",
        foreign_keys=[current_custodian_id],
        back_populates="custodied_items",
    )

    coc_logs = db.relationship(
        "ChainOfCustodyLog",
        back_populates="evidence",
        order_by="ChainOfCustodyLog.timestamp_utc.desc()",
        cascade="all, delete-orphan",
    )

    derived_artifacts = db.relationship(
        "Evidence",
        foreign_keys=[source_evidence_id],
    )

    @property
    def file_size_human(self) -> str:
        """Human-readable file size string."""

        size = self.file_size_bytes or 0

        if size < 1024:
            return f"{size} B"

        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"

        if size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"

        return f"{size / (1024 * 1024 * 1024):.2f} GB"

    def __repr__(self) -> str:
        return (
            f"<Evidence "
            f"{self.evidence_tag}: "
            f"{self.original_filename}>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — CROSS-EVIDENCE RELATIONSHIP MODEL
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceRelationship(db.Model):
    """
    Stores a forensic relationship between two evidence items.

    This is the database foundation for Phase 3
    Cross-Evidence Intelligence.

    Examples of relationships we will support later:

        CDR ↔ Audio
        CDR ↔ Transcript
        CDR ↔ CDR
        Audio ↔ Audio
        Evidence ↔ Derived Evidence

    The relationship stores:
        - the two evidence items
        - the type of relationship
        - the value they have in common
        - why the relationship exists
        - confidence score
        - investigator who created the relationship
    """

    __tablename__ = "dems_evidence_relationships"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_cases.id"),
        nullable=False,
        index=True,
    )

    source_evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_evidence.id"),
        nullable=False,
        index=True,
    )

    target_evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_evidence.id"),
        nullable=False,
        index=True,
    )

    # Example values:
    #
    # PHONE_MATCH
    # TIMESTAMP_MATCH
    # LOCATION_MATCH
    # PERSON_MATCH
    # CDR_AUDIO_CORRELATION
    # DERIVED_FROM
    # SHARED_ENTITY
    # SHARED_EVENT
    # MANUAL_LINK
    relationship_type = db.Column(
        db.String(64),
        nullable=False,
        index=True,
    )

    # The actual value that caused the relationship.
    #
    # Example:
    # +919876543210
    # CELL_001
    # 2026-10-04 14:30:00
    shared_value = db.Column(
        db.String(512),
        nullable=True,
    )

    # Human-readable explanation of the relationship.
    correlation_basis = db.Column(
        db.Text,
        nullable=True,
    )

    # Confidence from 0.0 to 1.0.
    #
    # Example:
    # 0.95 = very strong correlation
    # 0.70 = moderate correlation
    # 0.40 = weak correlation
    confidence_score = db.Column(
        db.Float,
        nullable=False,
        default=1.0,
    )

    # Optional structured information.
    #
    # We store it as text/JSON so we do not need
    # another package or database dependency.
    metadata_json = db.Column(
        db.Text,
        nullable=True,
    )

    created_by_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_users.id"),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Relationships
    # ─────────────────────────────────────────────────────────────────────────

    case = db.relationship(
        "Case",
        foreign_keys=[case_id],
    )

    source_evidence = db.relationship(
        "Evidence",
        foreign_keys=[source_evidence_id],
    )

    target_evidence = db.relationship(
        "Evidence",
        foreign_keys=[target_evidence_id],
    )

    created_by = db.relationship(
        "User",
        foreign_keys=[created_by_id],
    )

    def to_dict(self) -> dict:
        """
        Converts the relationship into a JSON-friendly dictionary.

        This will be used later by the Phase 3 API and UI.
        """

        return {
            "id": self.id,

            "case_id": self.case_id,

            "source_evidence_id": self.source_evidence_id,

            "source_evidence_tag": (
                self.source_evidence.evidence_tag
                if self.source_evidence
                else ""
            ),

            "source_evidence_title": (
                self.source_evidence.title
                if self.source_evidence
                else ""
            ),

            "target_evidence_id": self.target_evidence_id,

            "target_evidence_tag": (
                self.target_evidence.evidence_tag
                if self.target_evidence
                else ""
            ),

            "target_evidence_title": (
                self.target_evidence.title
                if self.target_evidence
                else ""
            ),

            "relationship_type": self.relationship_type,

            "shared_value": (
                self.shared_value
                if self.shared_value
                else ""
            ),

            "correlation_basis": (
                self.correlation_basis
                if self.correlation_basis
                else ""
            ),

            "confidence_score": round(
                float(self.confidence_score or 0.0),
                4,
            ),

            "metadata_json": (
                self.metadata_json
                if self.metadata_json
                else ""
            ),

            "created_by_id": self.created_by_id,

            "created_by": (
                self.created_by.username
                if self.created_by
                else ""
            ),

            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else ""
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<EvidenceRelationship "
            f"{self.source_evidence_id} -> "
            f"{self.target_evidence_id} "
            f"[{self.relationship_type}]>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CHAIN OF CUSTODY MODEL
# ─────────────────────────────────────────────────────────────────────────────

class ChainOfCustodyLog(db.Model):
    """
    Immutable audit ledger for every interaction with evidence.

    Each event records:
      - Who performed the action
      - What evidence was affected
      - What action occurred
      - When it occurred
      - The SHA-256 hash at that point
      - Verification status
      - IP address
      - User agent
    """

    __tablename__ = "dems_chain_of_custody"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_evidence.id"),
        nullable=False,
        index=True,
    )

    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_users.id"),
        nullable=False,
        index=True,
    )

    action = db.Column(
        db.Enum(CoCAction),
        nullable=False,
    )

    purpose = db.Column(
        db.Text,
        nullable=True,
    )

    timestamp_utc = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
        index=True,
    )

    recorded_sha256 = db.Column(
        db.String(64),
        nullable=True,
    )

    verification_status = db.Column(
        db.Enum(VerificationStatus),
        default=VerificationStatus.NOT_VERIFIED,
        nullable=False,
    )

    ip_address = db.Column(
        db.String(64),
        nullable=True,
    )

    user_agent = db.Column(
        db.String(256),
        nullable=True,
    )

    # Relationships
    evidence = db.relationship(
        "Evidence",
        back_populates="coc_logs",
    )

    actor = db.relationship(
        "User",
        back_populates="coc_actions",
    )

    def __repr__(self) -> str:
        return (
            f"<CoC "
            f"{self.action.value} "
            f"ev={self.evidence_id} "
            f"by={self.actor_id}>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE ITEM ALIAS
# ─────────────────────────────────────────────────────────────────────────────

# EvidenceItem alias for Evidence model compatibility.
EvidenceItem = Evidence


# ─────────────────────────────────────────────────────────────────────────────
# TOWER ↔ EVIDENCE LINK MODEL
# ─────────────────────────────────────────────────────────────────────────────

class TowerEvidenceLink(db.Model):
    """
    Direct forensic binding between a physical cell tower ping location
    and authentic seized digital evidence in the DEMS Vault.

    Allows investigators to link seized CCTV footage, bodycam video,
    or photographs to specific tower pings and call timestamps.
    """

    __tablename__ = "dems_tower_evidence_links"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    cell_tower_id = db.Column(
        db.String(64),
        nullable=False,
        index=True,
    )

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_evidence.id"),
        nullable=False,
        index=True,
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_cases.id"),
        nullable=True,
        index=True,
    )

    lat = db.Column(
        db.Float,
        nullable=False,
    )

    lon = db.Column(
        db.Float,
        nullable=False,
    )

    call_timestamp = db.Column(
        db.String(64),
        nullable=True,
    )

    target_number = db.Column(
        db.String(64),
        nullable=True,
    )

    camera_name = db.Column(
        db.String(256),
        default="Cell Site Surveillance Camera",
        nullable=False,
    )

    notes = db.Column(
        db.Text,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
    )

    # Relationships
    evidence = db.relationship(
        "Evidence",
        foreign_keys=[evidence_id],
    )

    case = db.relationship(
        "Case",
        foreign_keys=[case_id],
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cell_tower_id": self.cell_tower_id,
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "lat": self.lat,
            "lon": self.lon,
            "call_timestamp": self.call_timestamp or "",
            "target_number": self.target_number or "",
            "camera_name": self.camera_name,
            "notes": self.notes or "",
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else ""
            ),
            "evidence_tag": (
                self.evidence.evidence_tag
                if self.evidence
                else ""
            ),
            "title": (
                self.evidence.title
                if self.evidence
                else ""
            ),
            "original_filename": (
                self.evidence.original_filename
                if self.evidence
                else ""
            ),
            "sha256": (
                self.evidence.sha256_intake
                if self.evidence
                else ""
            ),
            "file_size": (
                self.evidence.file_size_human
                if self.evidence
                else ""
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<TowerEvidenceLink "
            f"Tower:{self.cell_tower_id} "
            f"Evidence:{self.evidence_id}>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# REGISTERED CAMERA MODEL
# ─────────────────────────────────────────────────────────────────────────────

class RegisteredCamera(db.Model):
    """
    Forensic Camera & Seized Video Registry linked to Cell Towers and Cases.

    Supports:
      - Actual seized .mp4 footage clips stored in the DEMS Evidence Vault
      - Authentic live RTSP streams
      - Local IP webcams
      - Public traffic streams
    """

    __tablename__ = "dems_registered_cameras"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    camera_uid = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    name = db.Column(
        db.String(256),
        nullable=False,
    )

    cell_tower_id = db.Column(
        db.String(64),
        nullable=True,
        index=True,
    )

    lat = db.Column(
        db.Float,
        nullable=False,
    )

    lon = db.Column(
        db.Float,
        nullable=False,
    )

    azimuth = db.Column(
        db.Float,
        default=0.0,
        nullable=False,
    )

    fov_degrees = db.Column(
        db.Float,
        default=60.0,
        nullable=False,
    )

    coverage_range_m = db.Column(
        db.Float,
        default=120.0,
        nullable=False,
    )

    source_type = db.Column(
        db.String(32),
        default="SEIZED_MP4",
        nullable=False,
    )

    stream_url = db.Column(
        db.String(512),
        nullable=True,
    )

    evidence_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_evidence.id"),
        nullable=True,
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("dems_cases.id"),
        nullable=True,
    )

    operator = db.Column(
        db.String(128),
        default="Forensic Vault Attached Footage",
        nullable=True,
    )

    notes = db.Column(
        db.Text,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
    )

    # Relationships
    evidence = db.relationship(
        "Evidence",
        foreign_keys=[evidence_id],
    )

    case = db.relationship(
        "Case",
        foreign_keys=[case_id],
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "uid": self.camera_uid,
            "name": self.name,
            "cell_tower_id": self.cell_tower_id,
            "lat": self.lat,
            "lon": self.lon,
            "azimuth": self.azimuth,
            "fov_degrees": self.fov_degrees,
            "coverage_range_m": self.coverage_range_m,
            "source_type": self.source_type,
            "stream_url": self.stream_url,
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "operator": self.operator,
            "notes": self.notes,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else ""
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<RegisteredCamera "
            f"{self.camera_uid}: "
            f"{self.name} "
            f"(Tower: {self.cell_tower_id})>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def generate_case_number() -> str:
    """Generates a unique case number in format CAS-YYYY-XXXX."""

    year = datetime.datetime.utcnow().year

    suffix = "".join(
        secrets.choice(
            string.ascii_uppercase + string.digits
        )
        for _ in range(6)
    )

    return f"CAS-{year}-{suffix}"


def generate_evidence_tag(case_id: int) -> str:
    """Generates an evidence tag in format EVD-<CaseID>-<NNNN>."""

    existing_count = Evidence.query.filter_by(
        case_id=case_id
    ).count()

    return (
        f"EVD-{case_id:04d}-"
        f"{existing_count + 1:04d}"
    )


def log_coc_event(
    evidence_id: int,
    actor_id: int,
    action: CoCAction,
    purpose: str = "",
    sha256: str = "",
    verification_status: VerificationStatus = (
        VerificationStatus.NOT_VERIFIED
    ),
    ip_address: str = "",
    user_agent: str = "",
) -> ChainOfCustodyLog:
    """
    Appends an immutable Chain of Custody event to the ledger.

    Args:
        evidence_id:
            ID of the evidence item.

        actor_id:
            ID of the user performing the action.

        action:
            The CoCAction enum value.

        purpose:
            Free-text purpose/notes for the event.

        sha256:
            SHA-256 hash at the time of the event.

        verification_status:
            Result of any integrity check.

        ip_address:
            Client IP address for audit trail.

        user_agent:
            Client user agent string.

    Returns:
        The newly created ChainOfCustodyLog instance.
    """

    entry = ChainOfCustodyLog(
        evidence_id=evidence_id,
        actor_id=actor_id,
        action=action,
        purpose=purpose,
        timestamp_utc=datetime.datetime.utcnow(),
        recorded_sha256=sha256,
        verification_status=verification_status,
        ip_address=ip_address or "",
        user_agent=(user_agent or "")[:256],
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
        app:
            The Flask application instance.
    """

    db.init_app(app)

    bcrypt.init_app(app)

    with app.app_context():

        # Creates any tables that do not already exist.
        #
        # This includes the new Phase 3 table:
        #
        #     dems_evidence_relationships
        #
        # Existing tables/data are preserved.
        db.create_all()

        # Seed default admin if no users exist
        if User.query.count() == 0:

            admin = User(
                username="admin",
                full_name="System Administrator",
                role=UserRole.ADMIN,
                badge_number="ADM-0001",
                department="Digital Forensics Unit",
                is_active=True,
            )

            admin.set_password(
                "Admin@DEMS2024!"
            )

            db.session.add(admin)

            # Seed demo investigator
            investigator = User(
                username="investigator",
                full_name="Lead Investigator",
                role=UserRole.LEAD_INVESTIGATOR,
                badge_number="INV-0001",
                department="Digital Forensics Unit",
                is_active=True,
            )

            investigator.set_password(
                "Invest@DEMS2024!"
            )

            db.session.add(investigator)

            # Seed demo analyst
            analyst = User(
                username="analyst",
                full_name="Forensic Analyst",
                role=UserRole.FORENSIC_ANALYST,
                badge_number="ANL-0001",
                department="Digital Forensics Unit",
                is_active=True,
            )

            analyst.set_password(
                "Analyst@DEMS2024!"
            )

            db.session.add(analyst)

            # Seed demo auditor
            auditor = User(
                username="auditor",
                full_name="Compliance Auditor",
                role=UserRole.AUDITOR,
                badge_number="AUD-0001",
                department="Internal Audit",
                is_active=True,
            )

            auditor.set_password(
                "Audit@DEMS2024!"
            )

            db.session.add(auditor)

            db.session.commit()