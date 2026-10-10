"""
TRIAD — Phase 8 Forensic Reporting + Security Validation
==========================================================

Phase 8 adds:

- Evidence-grounded forensic reporting
- PDF / HTML / JSON / CSV / XLSX exports
- Investigation provenance
- Investigation leads
- AI interpretation summary
- Security validation
- Evidence integrity sampling

This module is intentionally isolated from the existing
CDR, DEMS, Cross-Evidence and Phase 7 engines.

It consumes existing investigation results and does not
modify raw evidence.
"""

from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json
import os
from pathlib import Path
from typing import Any, Callable

import pandas as pd

from flask import (
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    send_file,
    url_for,
)

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from werkzeug.utils import secure_filename

from dems_crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    PBKDF2_ITERATIONS,
    compute_sha256_of_bytes,
    get_vault_key,
    verify_integrity,
    verify_vault_file_exists,
)

from dems_models import (
    ChainOfCustodyLog,
    Evidence,
    ROLE_PERMISSIONS,
    User,
    UserRole,
)

from dems_routes import (
    SESSION_TIMEOUT_MINUTES,
    _get_current_user,
    dems_login_required,
    role_required,
)


PHASE8_VERSION = "1.0"

DEFAULT_SECRET_KEY = (
    "cdr-forensic-intel-2024-secret"
)


# ============================================================================
# GENERIC HELPERS
# ============================================================================


def _text(
    value: Any,
    default: str = "",
) -> str:
    if value is None:
        return default

    return str(value).strip()


def _safe_int(
    value: Any,
    default: int = 0,
) -> int:

    if isinstance(value, bool):
        return int(value)

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
            dict,
        ),
    ):
        return len(value)

    try:
        return int(float(value))
    except (
        TypeError,
        ValueError,
    ):
        return default


def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def _json_safe(
    value: Any,
) -> Any:

    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            _json_safe(item)
            for item in value
        ]

    if isinstance(
        value,
        (
            dt.datetime,
            dt.date,
            dt.time,
        ),
    ):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    if hasattr(value, "value"):
        return _json_safe(
            value.value
        )

    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _clip(
    value: Any,
    limit: int = 500,
) -> str:

    text = _text(value)

    if len(text) <= limit:
        return text

    return (
        text[:limit].rstrip()
        + "…"
    )


def _utc_now() -> str:
    return dt.datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _status(
    ok: bool,
    warning: bool = False,
) -> str:

    if ok:
        return "PASS"

    if warning:
        return "WARN"

    return "FAIL"


# ============================================================================
# FORENSIC REPORT PAYLOAD
# ============================================================================


def build_forensic_report_payload(
    data: dict[str, Any],
    analytics: dict[str, Any] | None,
    ai_intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Creates one stable, serialisable forensic dossier
    from existing TRIAD investigation results.
    """

    data = (
        data
        if isinstance(data, dict)
        else {}
    )

    analytics = (
        analytics
        if isinstance(
            analytics,
            dict,
        )
        else {}
    )

    ai_intelligence = (
        ai_intelligence
        if isinstance(
            ai_intelligence,
            dict,
        )
        else {}
    )

    kpis = data.get(
        "kpis",
        {},
    ) or {}

    metadata = data.get(
        "metadata",
        {},
    ) or {}

    summary = analytics.get(
        "summary",
        {},
    ) or {}

    communication = analytics.get(
        "communication",
        {},
    ) or {}

    temporal = analytics.get(
        "temporal",
        {},
    ) or {}

    geographic = analytics.get(
        "geographic",
        {},
    ) or {}

    network = analytics.get(
        "network",
        {},
    ) or {}

    cross_match = analytics.get(
        "cross_match",
        {},
    ) or {}

    leads = analytics.get(
        "leads",
        [],
    ) or []

    source_names = []

    filename = _text(
        data.get("filename")
    )

    if filename:
        source_names.append(
            filename
        )

    for name in (
        data.get(
            "filenames",
            [],
        )
        or []
    ):

        clean_name = _text(name)

        if (
            clean_name
            and clean_name
            not in source_names
        ):
            source_names.append(
                clean_name
            )

    hashes = []

    for key in (
        "sha256",
        "sha256_intake",
    ):

        value = (
            _text(
                metadata.get(key)
            )
            or _text(
                data.get(key)
            )
        )

        if (
            value
            and value not in hashes
        ):
            hashes.append(value)

    normalized_leads = []

    for lead in leads[:100]:

        if not isinstance(
            lead,
            dict,
        ):
            continue

        normalized_leads.append(
            {
                "severity": _text(
                    lead.get(
                        "severity"
                    ),
                    "INFO",
                ),
                "type": _text(
                    lead.get(
                        "type"
                    ),
                    "ANALYTICAL",
                ),
                "title": _clip(
                    lead.get(
                        "title"
                    ),
                    200,
                ),
                "detail": _clip(
                    lead.get(
                        "detail"
                    ),
                    700,
                ),
                "basis": _clip(
                    lead.get(
                        "basis"
                    ),
                    500,
                ),
                "target": _text(
                    lead.get(
                        "target"
                    )
                ),
            }
        )

    session_id = _text(
        data.get(
            "id",
            data.get(
                "session_id"
            ),
        )
    )

    target = _text(
        data.get(
            "target"
        ),
        _text(
            summary.get(
                "target"
            ),
            "TARGET",
        ),
    )

    # Important:
    # Do NOT put multiline expressions inside an f-string.
    # Python 3.11 does not support the Python 3.12 PEP 701 behavior.
    report_id = (
        "TRIAD-"
        + (
            session_id[:13]
            if session_id
            else "SESSION"
        )
    )

    payload = {
        "phase": 8,

        "version":
            PHASE8_VERSION,

        "report_id":
            report_id,

        "generated_at":
            _utc_now(),

        "session_id":
            session_id,

        "classification":
            "RESTRICTED / FORENSIC WORK PRODUCT",

        "report_type":
            (
                "CROSS-MATCH INVESTIGATION"
                if data.get("type")
                == "cross_match"
                else
                "CDR FORENSIC ANALYSIS"
            ),

        "source": {
            "target":
                target,

            "targets":
                data.get(
                    "targets",
                    [],
                ),

            "filenames":
                source_names,

            "sha256":
                hashes,

            "analysis_mode":
                (
                    "Multi-Target Cross-Match"
                    if data.get("type")
                    == "cross_match"
                    else
                    "Single CDR Analysis"
                ),
        },

        "summary": {
            "total_records":
                _safe_int(
                    kpis.get(
                        "total_records",
                        summary.get(
                            "total_records",
                            0,
                        ),
                    )
                ),

            "unique_entities":
                _safe_int(
                    summary.get(
                        "unique_entities",
                        kpis.get(
                            "unique_contacts",
                            0,
                        ),
                    )
                ),

            "active_days":
                _safe_int(
                    summary.get(
                        "active_days",
                        0,
                    )
                ),

            "peak_hour":
                summary.get(
                    "peak_hour",
                    kpis.get(
                        "peak_hour",
                        "—",
                    ),
                ),

            "peak_day":
                summary.get(
                    "peak_day",
                    kpis.get(
                        "peak_day",
                        "—",
                    ),
                ),

            "top_contact":
                summary.get(
                    "top_contact",
                    "—",
                ),

            "total_distance_km":
                _safe_float(
                    summary.get(
                        "total_distance_km",
                        geographic.get(
                            "total_distance_km",
                            0,
                        ),
                    )
                ),

            "signal_score":
                _safe_float(
                    summary.get(
                        "investigation_signal_score",
                        summary.get(
                            "signal_score",
                            0,
                        ),
                    )
                ),

            "date_range":
                kpis.get(
                    "date_range",
                    "—",
                ),

            "incoming":
                _safe_int(
                    kpis.get(
                        "incoming",
                        communication.get(
                            "incoming",
                            0,
                        ),
                    )
                ),

            "outgoing":
                _safe_int(
                    kpis.get(
                        "outgoing",
                        communication.get(
                            "outgoing",
                            0,
                        ),
                    )
                ),

            "sms":
                _safe_int(
                    kpis.get(
                        "sms_count",
                        communication.get(
                            "sms",
                            0,
                        ),
                    )
                ),

            "night_calls":
                _safe_int(
                    kpis.get(
                        "night_calls",
                        0,
                    )
                ),

            "imei_count":
                _safe_int(
                    kpis.get(
                        "imei_count",
                        0,
                    )
                ),

            "imsi_count":
                _safe_int(
                    kpis.get(
                        "imsi_count",
                        0,
                    )
                ),
        },

        "communication":
            communication,

        "temporal":
            temporal,

        "geographic":
            geographic,

        "network":
            network,

        "cross_match":
            cross_match,

        "leads":
            normalized_leads,

        "ai_intelligence":
            ai_intelligence,

        "provenance": {
            "raw_evidence_preserved":
                True,

            "deterministic_analytics":
                bool(analytics),

            "ai_is_interpretive":
                True,

            "unsupported_facts_policy":
                (
                    "AI output must not create "
                    "unsupported evidence."
                ),
        },
    }

    return _json_safe(
        payload
    )


# ============================================================================
# JSON / CSV / XLSX
# ============================================================================


def build_json_bytes(
    payload: dict[str, Any],
) -> bytes:

    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        default=str,
    ).encode(
        "utf-8"
    )


def build_csv_bytes(
    payload: dict[str, Any],
) -> bytes:

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow(
        [
            "TRIAD Phase 8 "
            "Forensic Report"
        ]
    )

    writer.writerow(
        [
            "Report ID",
            payload.get(
                "report_id",
                "",
            ),
        ]
    )

    writer.writerow(
        [
            "Generated",
            payload.get(
                "generated_at",
                "",
            ),
        ]
    )

    writer.writerow(
        [
            "Session ID",
            payload.get(
                "session_id",
                "",
            ),
        ]
    )

    writer.writerow([])

    writer.writerow(
        [
            "Metric",
            "Value",
        ]
    )

    for key, value in (
        payload.get(
            "summary",
            {},
        )
        or {}
    ).items():

        writer.writerow(
            [
                key,
                value,
            ]
        )

    writer.writerow([])

    writer.writerow(
        [
            "Investigation Leads"
        ]
    )

    writer.writerow(
        [
            "Severity",
            "Type",
            "Title",
            "Detail",
            "Basis",
            "Target",
        ]
    )

    for lead in (
        payload.get(
            "leads",
            [],
        )
        or []
    ):

        writer.writerow(
            [
                lead.get(
                    "severity",
                    "",
                ),
                lead.get(
                    "type",
                    "",
                ),
                lead.get(
                    "title",
                    "",
                ),
                lead.get(
                    "detail",
                    "",
                ),
                lead.get(
                    "basis",
                    "",
                ),
                lead.get(
                    "target",
                    "",
                ),
            ]
        )

    return output.getvalue().encode(
        "utf-8-sig"
    )


def build_xlsx_bytes(
    payload: dict[str, Any],
) -> bytes:

    output = io.BytesIO()

    summary_rows = []

    for key, value in (
        payload.get(
            "summary",
            {},
        )
        or {}
    ).items():

        summary_rows.append(
            {
                "Metric": key,
                "Value": value,
            }
        )

    lead_rows = payload.get(
        "leads",
        [],
    ) or []

    with pd.ExcelWriter(
        output,
        engine="openpyxl",
    ) as writer:

        pd.DataFrame(
            summary_rows
        ).to_excel(
            writer,
            sheet_name="Forensic_Summary",
            index=False,
        )

        pd.DataFrame(
            lead_rows
            or [
                {
                    "severity":
                        "",
                    "title":
                        "No leads",
                }
            ]
        ).to_excel(
            writer,
            sheet_name="Investigation_Leads",
            index=False,
        )

        sections = [
            (
                "Communication",
                payload.get(
                    "communication",
                    {},
                ),
            ),
            (
                "Temporal",
                payload.get(
                    "temporal",
                    {},
                ),
            ),
            (
                "Geographic",
                payload.get(
                    "geographic",
                    {},
                ),
            ),
            (
                "Network",
                payload.get(
                    "network",
                    {},
                ),
            ),
            (
                "Cross_Match",
                payload.get(
                    "cross_match",
                    {},
                ),
            ),
        ]

        for sheet_name, section in sections:

            rows = []

            if isinstance(
                section,
                dict,
            ):

                for key, value in section.items():

                    if isinstance(
                        value,
                        (
                            dict,
                            list,
                        ),
                    ):

                        value = json.dumps(
                            value,
                            ensure_ascii=False,
                            default=str,
                        )

                    rows.append(
                        {
                            "Metric":
                                key,
                            "Value":
                                value,
                        }
                    )

            pd.DataFrame(
                rows
                or [
                    {
                        "Metric":
                            "status",
                        "Value":
                            "No data",
                    }
                ]
            ).to_excel(
                writer,
                sheet_name=sheet_name,
                index=False,
            )

        source = payload.get(
            "source",
            {},
        ) or {}

        pd.DataFrame(
            [
                {
                    "Field":
                        "Target",
                    "Value":
                        source.get(
                            "target",
                            "",
                        ),
                },
                {
                    "Field":
                        "Source Files",
                    "Value":
                        ", ".join(
                            source.get(
                                "filenames",
                                [],
                            )
                        ),
                },
                {
                    "Field":
                        "SHA-256",
                    "Value":
                        ", ".join(
                            source.get(
                                "sha256",
                                [],
                            )
                        ),
                },
                {
                    "Field":
                        "Classification",
                    "Value":
                        payload.get(
                            "classification",
                            "",
                        ),
                },
            ]
        ).to_excel(
            writer,
            sheet_name="Provenance",
            index=False,
        )

    return output.getvalue()


# ============================================================================
# PDF
# ============================================================================


def _pdf_styles():

    styles = getSampleStyleSheet()

    return {
        "title":
            ParagraphStyle(
                "TriadTitle",
                parent=styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                alignment=TA_CENTER,
                textColor=colors.HexColor(
                    "#0f172a"
                ),
                spaceAfter=8,
            ),

        "subtitle":
            ParagraphStyle(
                "TriadSubtitle",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=12,
                alignment=TA_CENTER,
                textColor=colors.HexColor(
                    "#475569"
                ),
                spaceAfter=14,
            ),

        "h2":
            ParagraphStyle(
                "TriadH2",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                textColor=colors.HexColor(
                    "#0f172a"
                ),
                spaceBefore=10,
                spaceAfter=6,
            ),

        "body":
            ParagraphStyle(
                "TriadBody",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=12,
                textColor=colors.HexColor(
                    "#1e293b"
                ),
                spaceAfter=4,
            ),

        "small":
            ParagraphStyle(
                "TriadSmall",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor(
                    "#475569"
                ),
            ),
    }


def _pdf_paragraph(
    value: Any,
    style,
) -> Paragraph:

    safe = html.escape(
        _text(
            value,
            "—",
        )
    )

    safe = safe.replace(
        "\n",
        "<br/>",
    )

    return Paragraph(
        safe,
        style,
    )


def _pdf_table(
    rows,
    widths=None,
):

    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#0f172a"
                    ),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7.5,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor(
                        "#cbd5e1"
                    ),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [
                        colors.white,
                        colors.HexColor(
                            "#f8fafc"
                        ),
                    ],
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    return table


def build_pdf_bytes(
    payload: dict[str, Any],
) -> bytes:

    output = io.BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=(
            "TRIAD Forensic "
            "Investigation Dossier"
        ),
        author="T.R.I.A.D.",
    )

    styles = _pdf_styles()

    story = []

    story.append(
        _pdf_paragraph(
            "T.R.I.A.D. — FORENSIC INVESTIGATION DOSSIER",
            styles["title"],
        )
    )

    story.append(
        _pdf_paragraph(
            (
                "Telecom Records & "
                "Intelligence Analysis Dashboard"
            ),
            styles["subtitle"],
        )
    )

    source = payload.get(
        "source",
        {},
    ) or {}

    summary = payload.get(
        "summary",
        {},
    ) or {}

    header_rows = [
        [
            _pdf_paragraph(
                "Report ID",
                styles["small"],
            ),
            _pdf_paragraph(
                payload.get(
                    "report_id"
                ),
                styles["small"],
            ),
            _pdf_paragraph(
                "Generated",
                styles["small"],
            ),
            _pdf_paragraph(
                payload.get(
                    "generated_at"
                ),
                styles["small"],
            ),
        ],
        [
            _pdf_paragraph(
                "Classification",
                styles["small"],
            ),
            _pdf_paragraph(
                payload.get(
                    "classification"
                ),
                styles["small"],
            ),
            _pdf_paragraph(
                "Target",
                styles["small"],
            ),
            _pdf_paragraph(
                source.get(
                    "target"
                ),
                styles["small"],
            ),
        ],
    ]

    story.append(
        _pdf_table(
            header_rows,
            widths=[
                30 * mm,
                60 * mm,
                30 * mm,
                60 * mm,
            ],
        )
    )

    story.append(
        Spacer(
            1,
            7,
        )
    )

    story.append(
        _pdf_paragraph(
            "1. Executive Summary",
            styles["h2"],
        )
    )

    summary_rows = [
        [
            _pdf_paragraph(
                "Metric",
                styles["small"],
            ),
            _pdf_paragraph(
                "Value",
                styles["small"],
            ),
        ]
    ]

    for key, value in summary.items():

        summary_rows.append(
            [
                _pdf_paragraph(
                    key.replace(
                        "_",
                        " ",
                    ).title(),
                    styles["small"],
                ),
                _pdf_paragraph(
                    value,
                    styles["small"],
                ),
            ]
        )

    story.append(
        _pdf_table(
            summary_rows,
            widths=[
                65 * mm,
                115 * mm,
            ],
        )
    )

    story.append(
        _pdf_paragraph(
            "2. Evidence Provenance",
            styles["h2"],
        )
    )

    story.append(
        _pdf_table(
            [
                [
                    _pdf_paragraph(
                        "Field",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        "Value",
                        styles["small"],
                    ),
                ],
                [
                    _pdf_paragraph(
                        "Source Files",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        ", ".join(
                            source.get(
                                "filenames",
                                [],
                            )
                        )
                        or "Not available",
                        styles["small"],
                    ),
                ],
                [
                    _pdf_paragraph(
                        "SHA-256",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        ", ".join(
                            source.get(
                                "sha256",
                                [],
                            )
                        )
                        or "Not available",
                        styles["small"],
                    ),
                ],
                [
                    _pdf_paragraph(
                        "Raw Evidence",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        "Preserved",
                        styles["small"],
                    ),
                ],
                [
                    _pdf_paragraph(
                        "Analytics",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        "Deterministic TRIAD analytics",
                        styles["small"],
                    ),
                ],
                [
                    _pdf_paragraph(
                        "AI Role",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        (
                            "Interpretive only; "
                            "unsupported facts "
                            "must not be created."
                        ),
                        styles["small"],
                    ),
                ],
            ],
            widths=[
                55 * mm,
                125 * mm,
            ],
        )
    )

    sections = [
        (
            "3. Communication Intelligence",
            payload.get(
                "communication",
                {},
            ),
        ),
        (
            "4. Temporal Intelligence",
            payload.get(
                "temporal",
                {},
            ),
        ),
        (
            "5. Geographic Intelligence",
            payload.get(
                "geographic",
                {},
            ),
        ),
        (
            "6. Network Intelligence",
            payload.get(
                "network",
                {},
            ),
        ),
        (
            "7. Cross-Evidence Intelligence",
            payload.get(
                "cross_match",
                {},
            ),
        ),
    ]

    for title, section in sections:

        story.append(
            _pdf_paragraph(
                title,
                styles["h2"],
            )
        )

        rows = [
            [
                _pdf_paragraph(
                    "Indicator",
                    styles["small"],
                ),
                _pdf_paragraph(
                    "Value",
                    styles["small"],
                ),
            ]
        ]

        if isinstance(
            section,
            dict,
        ):

            for key, value in list(
                section.items()
            )[:40]:

                if isinstance(
                    value,
                    (
                        dict,
                        list,
                    ),
                ):

                    value = json.dumps(
                        value,
                        ensure_ascii=False,
                        default=str,
                    )

                rows.append(
                    [
                        _pdf_paragraph(
                            key.replace(
                                "_",
                                " ",
                            ).title(),
                            styles["small"],
                        ),
                        _pdf_paragraph(
                            _clip(
                                value,
                                700,
                            ),
                            styles["small"],
                        ),
                    ]
                )

        if len(rows) == 1:

            rows.append(
                [
                    _pdf_paragraph(
                        "Status",
                        styles["small"],
                    ),
                    _pdf_paragraph(
                        "No derived data available",
                        styles["small"],
                    ),
                ]
            )

        story.append(
            _pdf_table(
                rows,
                widths=[
                    55 * mm,
                    125 * mm,
                ],
            )
        )

    story.append(
        PageBreak()
    )

    story.append(
        _pdf_paragraph(
            "8. Investigation Leads",
            styles["h2"],
        )
    )

    lead_rows = [
        [
            _pdf_paragraph(
                "Severity",
                styles["small"],
            ),
            _pdf_paragraph(
                "Type",
                styles["small"],
            ),
            _pdf_paragraph(
                "Title",
                styles["small"],
            ),
            _pdf_paragraph(
                "Basis",
                styles["small"],
            ),
        ]
    ]

    leads = payload.get(
        "leads",
        [],
    ) or []

    for lead in leads[:50]:

        lead_rows.append(
            [
                _pdf_paragraph(
                    lead.get(
                        "severity"
                    ),
                    styles["small"],
                ),
                _pdf_paragraph(
                    lead.get(
                        "type"
                    ),
                    styles["small"],
                ),
                _pdf_paragraph(
                    lead.get(
                        "title"
                    ),
                    styles["small"],
                ),
                _pdf_paragraph(
                    lead.get(
                        "basis"
                    ),
                    styles["small"],
                ),
            ]
        )

    if len(lead_rows) == 1:

        lead_rows.append(
            [
                _pdf_paragraph(
                    "INFO",
                    styles["small"],
                ),
                _pdf_paragraph(
                    "NONE",
                    styles["small"],
                ),
                _pdf_paragraph(
                    "No leads generated",
                    styles["small"],
                ),
                _pdf_paragraph(
                    "No analytical lead was available.",
                    styles["small"],
                ),
            ]
        )

    story.append(
        _pdf_table(
            lead_rows,
            widths=[
                22 * mm,
                32 * mm,
                62 * mm,
                64 * mm,
            ],
        )
    )

    ai = payload.get(
        "ai_intelligence",
        {},
    ) or {}

    story.append(
        _pdf_paragraph(
            "9. AI Intelligence Summary",
            styles["h2"],
        )
    )

    ai_provider = _text(
        ai.get(
            "provider"
        ),
        "Not available",
    )

    ai_model = _text(
        ai.get(
            "model"
        ),
        "Not available",
    )

    story.append(
        _pdf_paragraph(
            (
                "Provider: "
                + ai_provider
                + " | Model: "
                + ai_model
            ),
            styles["body"],
        )
    )

    ai_text = (
        _text(
            ai.get(
                "assessment"
            )
        )
        or _text(
            ai.get(
                "ai_summary"
            )
        )
        or
        (
            "No additional AI narrative "
            "was generated."
        )
    )

    story.append(
        _pdf_paragraph(
            ai_text,
            styles["body"],
        )
    )

    story.append(
        _pdf_paragraph(
            "10. Forensic Limitations",
            styles["h2"],
        )
    )

    limitations = [
        (
            "Analytical signals are investigative "
            "indicators and are not, by themselves, "
            "proof of criminal conduct."
        ),
        (
            "The report reflects evidence and "
            "analytics available at generation time."
        ),
        (
            "AI interpretation remains subordinate "
            "to verified evidence and analyst review."
        ),
        (
            "Production deployment requires "
            "operational, legal, retention and "
            "security review."
        ),
    ]

    for item in limitations:

        story.append(
            _pdf_paragraph(
                "• " + item,
                styles["body"],
            )
        )

    story.append(
        _pdf_paragraph(
            "11. Chain of Custody / Integrity",
            styles["h2"],
        )
    )

    story.append(
        _pdf_paragraph(
            (
                "DEMS evidence is designed around "
                "encrypted vault storage, SHA-256/"
                "SHA-512/MD5 intake fingerprints, "
                "integrity verification and an "
                "append-only Chain-of-Custody ledger."
            ),
            styles["body"],
        )
    )

    def footer(
        canvas,
        doc,
    ):

        canvas.saveState()

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.setFillColor(
            colors.HexColor(
                "#64748b"
            )
        )

        canvas.drawString(
            15 * mm,
            8 * mm,
            (
                "T.R.I.A.D. — "
                "Restricted Forensic Work Product"
            ),
        )

        canvas.drawRightString(
            195 * mm,
            8 * mm,
            f"Page {doc.page}",
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=footer,
        onLaterPages=footer,
    )

    return output.getvalue()


# ============================================================================
# STANDALONE HTML
# ============================================================================


def _html_value(
    value: Any,
) -> str:
    """
    Safely converts a report value to HTML text.

    Kept separate from f-strings because the project
    runs on Python 3.11.
    """

    if isinstance(
        value,
        (
            dict,
            list,
            tuple,
            set,
        ),
    ):

        value = json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )

    return html.escape(
        _text(
            value,
            "—",
        )
    )


def _build_html_document(
    payload: dict[str, Any],
) -> str:

    summary = payload.get(
        "summary",
        {},
    ) or {}

    source = payload.get(
        "source",
        {},
    ) or {}

    leads = payload.get(
        "leads",
        [],
    ) or {}

    ai = payload.get(
        "ai_intelligence",
        {},
    ) or {}

    summary_rows = ""

    for key, value in summary.items():

        label = (
            key.replace(
                "_",
                " ",
            ).title()
        )

        summary_rows += (
            "<tr>"
            "<th>"
            + html.escape(label)
            + "</th>"
            "<td>"
            + _html_value(value)
            + "</td>"
            "</tr>"
        )

    lead_rows = ""

    for lead in leads:

        lead_rows += (
            "<tr>"
            "<td>"
            + _html_value(
                lead.get(
                    "severity"
                )
            )
            + "</td>"
            "<td>"
            + _html_value(
                lead.get(
                    "type"
                )
            )
            + "</td>"
            "<td>"
            + _html_value(
                lead.get(
                    "title"
                )
            )
            + "</td>"
            "<td>"
            + _html_value(
                lead.get(
                    "basis"
                )
            )
            + "</td>"
            "</tr>"
        )

    if not lead_rows:

        lead_rows = (
            "<tr>"
            "<td colspan='4'>"
            "No investigation leads generated."
            "</td>"
            "</tr>"
        )

    sections_html = ""

    sections = [
        (
            "Communication Intelligence",
            "communication",
        ),
        (
            "Temporal Intelligence",
            "temporal",
        ),
        (
            "Geographic Intelligence",
            "geographic",
        ),
        (
            "Network Intelligence",
            "network",
        ),
        (
            "Cross-Evidence Intelligence",
            "cross_match",
        ),
    ]

    for title, key in sections:

        section = payload.get(
            key,
            {},
        ) or {}

        rows = ""

        if isinstance(
            section,
            dict,
        ):

            for field, value in list(
                section.items()
            )[:60]:

                label = (
                    field.replace(
                        "_",
                        " ",
                    ).title()
                )

                rows += (
                    "<tr>"
                    "<th>"
                    + html.escape(label)
                    + "</th>"
                    "<td>"
                    + _html_value(value)
                    + "</td>"
                    "</tr>"
                )

        if not rows:

            rows = (
                "<tr>"
                "<td colspan='2'>"
                "No derived data available."
                "</td>"
                "</tr>"
            )

        sections_html += (
            "<h2>"
            + html.escape(title)
            + "</h2>"
            "<table>"
            "<tr>"
            "<th>Indicator</th>"
            "<th>Value</th>"
            "</tr>"
            + rows
            + "</table>"
        )

    ai_provider = _html_value(
        ai.get(
            "provider"
        )
    )

    ai_model = _html_value(
        ai.get(
            "model"
        )
    )

    ai_text = _html_value(
        ai.get(
            "assessment"
        )
        or ai.get(
            "ai_summary"
        )
        or
        "No additional AI narrative was generated."
    )

    return (
        "<!doctype html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='utf-8'>"
        "<title>"
        "TRIAD Forensic Dossier"
        "</title>"
        "<style>"
        "body{"
        "font-family:Arial,sans-serif;"
        "background:#f1f5f9;"
        "color:#0f172a;"
        "margin:0;"
        "padding:32px;"
        "}"
        "main{"
        "max-width:1000px;"
        "margin:auto;"
        "background:#fff;"
        "padding:42px;"
        "border:1px solid #cbd5e1;"
        "}"
        "h1{"
        "margin:0 0 6px;"
        "font-size:25px;"
        "}"
        "h2{"
        "margin-top:28px;"
        "border-bottom:2px solid #0f172a;"
        "padding-bottom:7px;"
        "font-size:15px;"
        "}"
        ".meta{"
        "color:#475569;"
        "font-size:12px;"
        "margin-bottom:24px;"
        "}"
        ".notice{"
        "background:#f8fafc;"
        "border:1px solid #cbd5e1;"
        "padding:12px;"
        "font-size:12px;"
        "}"
        "table{"
        "width:100%;"
        "border-collapse:collapse;"
        "margin:10px 0 18px;"
        "font-size:12px;"
        "}"
        "th,td{"
        "border:1px solid #cbd5e1;"
        "padding:7px;"
        "text-align:left;"
        "vertical-align:top;"
        "}"
        "th{"
        "background:#0f172a;"
        "color:#fff;"
        "}"
        "tr:nth-child(even){"
        "background:#f8fafc;"
        "}"
        "@media print{"
        "body{"
        "background:#fff;"
        "padding:0;"
        "}"
        "main{"
        "border:0;"
        "padding:0;"
        "max-width:none;"
        "}"
        "}"
        "</style>"
        "</head>"
        "<body>"
        "<main>"

        "<h1>"
        "T.R.I.A.D. — Forensic Investigation Dossier"
        "</h1>"

        "<div class='meta'>"
        "Report ID: "
        + _html_value(
            payload.get(
                "report_id"
            )
        )
        + " | Generated: "
        + _html_value(
            payload.get(
                "generated_at"
            )
        )
        + " | Session: "
        + _html_value(
            payload.get(
                "session_id"
            )
        )
        + "</div>"

        "<div class='notice'>"
        "<b>Classification:</b> "
        + _html_value(
            payload.get(
                "classification"
            )
        )
        + "<br>"
        "<b>Target:</b> "
        + _html_value(
            source.get(
                "target"
            )
        )
        + "<br>"
        "<b>Source Files:</b> "
        + _html_value(
            ", ".join(
                source.get(
                    "filenames",
                    [],
                )
            )
        )
        + "<br>"
        "<b>SHA-256:</b> "
        + _html_value(
            ", ".join(
                source.get(
                    "sha256",
                    [],
                )
            )
        )
        + "<br>"
        "<b>Provenance:</b> "
        "Deterministic analytics derived from "
        "existing TRIAD evidence; AI is interpretive only."
        "</div>"

        "<h2>Executive Summary</h2>"
        "<table>"
        "<tr>"
        "<th>Metric</th>"
        "<th>Value</th>"
        "</tr>"
        + summary_rows
        + "</table>"

        + sections_html

        + "<h2>Investigation Leads</h2>"
        "<table>"
        "<tr>"
        "<th>Severity</th>"
        "<th>Type</th>"
        "<th>Title</th>"
        "<th>Basis</th>"
        "</tr>"
        + lead_rows
        + "</table>"

        "<h2>AI Intelligence</h2>"
        "<div class='notice'>"
        "<b>Provider:</b> "
        + ai_provider
        + "<br>"
        "<b>Model:</b> "
        + ai_model
        + "<br><br>"
        + ai_text
        + "</div>"

        "<h2>Forensic Limitations</h2>"
        "<ul>"
        "<li>"
        "Analytical signals are investigative indicators, "
        "not proof of criminal conduct."
        "</li>"
        "<li>"
        "The report reflects evidence and analytics "
        "available at generation time."
        "</li>"
        "<li>"
        "AI interpretation remains subordinate to "
        "verified evidence and analyst review."
        "</li>"
        "<li>"
        "Production deployment requires operational, "
        "legal, retention and security review."
        "</li>"
        "</ul>"

        "</main>"
        "</body>"
        "</html>"
    )


# ============================================================================
# SECURITY VALIDATION
# ============================================================================


def run_security_validation(
    max_integrity_samples: int = 10,
) -> dict[str, Any]:

    checks = []

    # ------------------------------------------------------------------
    # AES-256-GCM
    # ------------------------------------------------------------------

    try:

        from cryptography.hazmat.primitives.ciphers.aead import (
            AESGCM,
        )

        import secrets

        key = secrets.token_bytes(
            KEY_SIZE
        )

        nonce = secrets.token_bytes(
            NONCE_SIZE
        )

        plaintext = (
            b"TRIAD-PHASE8-SECURITY-TEST"
        )

        aad = b"triad-phase8"

        encrypted = AESGCM(
            key
        ).encrypt(
            nonce,
            plaintext,
            aad,
        )

        decrypted = AESGCM(
            key
        ).decrypt(
            nonce,
            encrypted,
            aad,
        )

        checks.append(
            {
                "name":
                    "AES-256-GCM encryption",
                "status":
                    _status(
                        decrypted
                        == plaintext
                    ),
                "detail":
                    "Authenticated encryption round-trip passed.",
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "AES-256-GCM encryption",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # SHA-256
    # ------------------------------------------------------------------

    try:

        digest = compute_sha256_of_bytes(
            b"TRIAD-PHASE8-SHA256-TEST"
        )

        checks.append(
            {
                "name":
                    "SHA-256 integrity hashing",
                "status":
                    _status(
                        len(digest)
                        == 64
                    ),
                "detail":
                    (
                        "Digest length: "
                        + str(len(digest))
                        + " hexadecimal characters."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "SHA-256 integrity hashing",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Vault key
    # ------------------------------------------------------------------

    try:

        key = get_vault_key()

        checks.append(
            {
                "name":
                    "Vault key length",
                "status":
                    _status(
                        len(key)
                        == KEY_SIZE
                    ),
                "detail":
                    (
                        "Resolved key length: "
                        + str(len(key))
                        + " bytes."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "Vault key length",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # PBKDF2
    # ------------------------------------------------------------------

    checks.append(
        {
            "name":
                "PBKDF2 hardening",
            "status":
                _status(
                    PBKDF2_ITERATIONS
                    >= 600_000
                ),
            "detail":
                (
                    "Configured iterations: "
                    f"{PBKDF2_ITERATIONS:,}."
                ),
        }
    )

    # ------------------------------------------------------------------
    # RBAC
    # ------------------------------------------------------------------

    try:

        configured_roles = set(
            ROLE_PERMISSIONS.keys()
        )

        expected_roles = set(
            UserRole
        )

        all_present = (
            expected_roles
            .issubset(
                configured_roles
            )
        )

        role_names = ", ".join(
            role.value
            for role in expected_roles
        )

        checks.append(
            {
                "name":
                    "RBAC role matrix",
                "status":
                    _status(
                        all_present
                    ),
                "detail":
                    (
                        "Configured roles: "
                        + role_names
                        + "."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "RBAC role matrix",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Bcrypt
    # ------------------------------------------------------------------

    try:

        probe = User(
            username="phase8_probe",
            full_name="Phase 8 Probe",
            role=UserRole.AUDITOR,
        )

        probe.set_password(
            "TRIAD-Phase8-Probe-Password"
        )

        valid = probe.check_password(
            "TRIAD-Phase8-Probe-Password"
        )

        checks.append(
            {
                "name":
                    "Bcrypt password verification",
                "status":
                    _status(valid),
                "detail":
                    (
                        "Password hash/verify "
                        "round-trip passed."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "Bcrypt password verification",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Secure filenames
    # ------------------------------------------------------------------

    try:

        samples = [
            "../../evidence.csv",
            (
                "C:\\Windows\\system32\\"
                "evil.exe"
            ),
            "normal-file.pdf",
        ]

        sanitised = [
            secure_filename(
                name
            )
            for name in samples
        ]

        safe = all(
            ".." not in name
            and "/" not in name
            and "\\" not in name
            for name in sanitised
        )

        checks.append(
            {
                "name":
                    "Secure filename handling",
                "status":
                    _status(safe),
                "detail":
                    (
                        "Sanitised samples: "
                        + ", ".join(
                            sanitised
                        )
                        + "."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "Secure filename handling",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Chain of Custody schema
    # ------------------------------------------------------------------

    try:

        fields = {
            column.name
            for column
            in ChainOfCustodyLog
            .__table__
            .columns
        }

        required = {
            "evidence_id",
            "actor_id",
            "action",
            "timestamp_utc",
            "recorded_sha256",
            "verification_status",
            "ip_address",
            "user_agent",
        }

        ok = required.issubset(
            fields
        )

        checks.append(
            {
                "name":
                    "Chain-of-Custody audit schema",
                "status":
                    _status(ok),
                "detail":
                    (
                        "Required actor, action, "
                        "timestamp, hash, verification "
                        "and request metadata fields "
                        "were checked."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "Chain-of-Custody audit schema",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Evidence integrity schema
    # ------------------------------------------------------------------

    try:

        fields = {
            column.name
            for column
            in Evidence
            .__table__
            .columns
        }

        required = {
            "encrypted_storage_path",
            "sha256_intake",
            "md5_intake",
            "sha512_intake",
            "last_verified_status",
            "last_verified_at",
        }

        ok = required.issubset(
            fields
        )

        checks.append(
            {
                "name":
                    "Evidence integrity baseline",
                "status":
                    _status(ok),
                "detail":
                    (
                        "Encrypted storage and "
                        "hash/integrity metadata "
                        "fields were checked."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "Evidence integrity baseline",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Session timeout
    # ------------------------------------------------------------------

    checks.append(
        {
            "name":
                "DEMS session timeout",
            "status":
                _status(
                    SESSION_TIMEOUT_MINUTES
                    > 0
                ),
            "detail":
                (
                    "Configured inactivity timeout: "
                    f"{SESSION_TIMEOUT_MINUTES} minutes."
                ),
        }
    )

    # ------------------------------------------------------------------
    # SECRET_KEY
    # ------------------------------------------------------------------

    secret = (
        current_app.secret_key
        or ""
    )

    hardened = (
        bool(
            os.getenv(
                "SECRET_KEY"
            )
        )
        and secret
        != DEFAULT_SECRET_KEY
    )

    checks.append(
        {
            "name":
                "Application secret hardening",
            "status":
                (
                    "PASS"
                    if hardened
                    else "WARN"
                ),
            "detail":
                (
                    "SECRET_KEY is supplied through "
                    "the environment."
                    if hardened
                    else
                    "Development fallback secret is "
                    "active. Set SECRET_KEY before "
                    "production deployment."
                ),
        }
    )

    # ------------------------------------------------------------------
    # Debug
    # ------------------------------------------------------------------

    checks.append(
        {
            "name":
                "Production debug posture",
            "status":
                (
                    "WARN"
                    if current_app.debug
                    else "PASS"
                ),
            "detail":
                (
                    "Flask debug mode is enabled "
                    "for development."
                    if current_app.debug
                    else
                    "Flask debug mode is disabled."
                ),
        }
    )

    # ------------------------------------------------------------------
    # Session cookie
    # ------------------------------------------------------------------

    secure_cookie = bool(
        current_app.config.get(
            "SESSION_COOKIE_SECURE",
            False,
        )
    )

    checks.append(
        {
            "name":
                "Secure session cookie",
            "status":
                (
                    "PASS"
                    if secure_cookie
                    else "WARN"
                ),
            "detail":
                (
                    "SESSION_COOKIE_SECURE is enabled."
                    if secure_cookie
                    else
                    "Enable secure cookies behind HTTPS "
                    "in production."
                ),
        }
    )

    # ------------------------------------------------------------------
    # Database availability
    # ------------------------------------------------------------------

    try:

        user_count = User.query.count()

        evidence_count = (
            Evidence.query.count()
        )

        coc_count = (
            ChainOfCustodyLog.query.count()
        )

        checks.append(
            {
                "name":
                    "DEMS audit database availability",
                "status":
                    "PASS",
                "detail":
                    (
                        f"Users: {user_count} | "
                        f"Evidence: {evidence_count} | "
                        f"Chain-of-Custody events: "
                        f"{coc_count}."
                    ),
            }
        )

    except Exception as exc:

        checks.append(
            {
                "name":
                    "DEMS audit database availability",
                "status":
                    "FAIL",
                "detail":
                    _clip(exc),
            }
        )

    # ------------------------------------------------------------------
    # Live evidence integrity sample
    # ------------------------------------------------------------------

    integrity = {
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "details": [],
    }

    try:

        rows = (
            Evidence.query
            .order_by(
                Evidence.id.asc()
            )
            .limit(
                max_integrity_samples
            )
            .all()
        )

        for evidence in rows:

            integrity["checked"] += 1

            path = Path(
                evidence.encrypted_storage_path
            )

            if not verify_vault_file_exists(
                path
            ):

                integrity["failed"] += 1

                integrity[
                    "details"
                ].append(
                    (
                        f"{evidence.evidence_tag}: "
                        "vault file missing/empty"
                    )
                )

                continue

            aad = (
                f"evidence:"
                f"{evidence.id}:"
                f"{evidence.evidence_tag}"
            ).encode()

            ok, _current_sha = (
                verify_integrity(
                    path,
                    get_vault_key(),
                    evidence.sha256_intake,
                    aad,
                )
            )

            if ok:

                integrity["passed"] += 1

            else:

                integrity["failed"] += 1

                integrity[
                    "details"
                ].append(
                    (
                        f"{evidence.evidence_tag}: "
                        "integrity mismatch"
                    )
                )

        if integrity["checked"] == 0:

            integrity_status = "WARN"

            integrity_detail = (
                "No stored evidence objects are "
                "available for a live integrity sample."
            )

        elif integrity["failed"] == 0:

            integrity_status = "PASS"

            integrity_detail = (
                f"{integrity['passed']}/"
                f"{integrity['checked']} sampled "
                "evidence objects verified successfully."
            )

        else:

            integrity_status = "FAIL"

            integrity_detail = (
                f"{integrity['failed']} sampled "
                "evidence object(s) failed "
                "integrity verification."
            )

    except Exception as exc:

        integrity_status = "FAIL"

        integrity_detail = _clip(
            exc
        )

        integrity["failed"] += 1

    checks.append(
        {
            "name":
                "Live evidence integrity sample",
            "status":
                integrity_status,
            "detail":
                integrity_detail,
        }
    )

    passed = sum(
        1
        for check in checks
        if check["status"] == "PASS"
    )

    warnings = sum(
        1
        for check in checks
        if check["status"] == "WARN"
    )

    failed = sum(
        1
        for check in checks
        if check["status"] == "FAIL"
    )

    total = len(checks)

    score = (
        round(
            (
                passed
                / total
            )
            * 100,
            1,
        )
        if total
        else 0
    )

    overall = (
        "FAIL"
        if failed
        else (
            "WARN"
            if warnings
            else "PASS"
        )
    )

    current_user = (
        _get_current_user()
    )

    return {
        "phase": 8,

        "version":
            PHASE8_VERSION,

        "generated_at":
            _utc_now(),

        "overall":
            overall,

        "score":
            score,

        "passed":
            passed,

        "warnings":
            warnings,

        "failed":
            failed,

        "checks":
            checks,

        "integrity_sample":
            integrity,

        "current_user":
            _text(
                getattr(
                    current_user,
                    "username",
                    "",
                ),
                "Not authenticated",
            ),

        "principle":
            (
                "Validation is non-destructive and "
                "does not modify source evidence."
            ),
    }


# ============================================================================
# ROUTE REGISTRATION
# ============================================================================


def register_phase8_routes(
    bp,
    data_loader: Callable,
    analytics_loader: Callable,
    ai_loader: Callable,
) -> None:
    """
    Registers Phase 8 routes on the existing Phase 7 blueprint.
    """

    @bp.route(
        "/forensic-reports"
    )
    @bp.route(
        "/forensic-reports/<session_id>"
    )
    @dems_login_required
    def forensic_reports_view(
        session_id=None,
    ):

        if not session_id:

            return redirect(
                url_for("index")
            )

        data = data_loader(
            session_id
        )

        if not data:

            flash(
                (
                    "The selected investigation "
                    "session could not be loaded."
                ),
                "error",
            )

            return redirect(
                url_for("index")
            )

        analytics = (
            analytics_loader(
                session_id
            )
            or {}
        )

        ai_intelligence = (
            ai_loader(
                data,
                analytics,
            )
            if analytics
            else {}
        )

        payload = (
            build_forensic_report_payload(
                data,
                analytics,
                ai_intelligence,
            )
        )

        return render_template(
            "forensic_reports.html",
            session_id=session_id,
            payload=payload,
            user=_get_current_user(),
        )

    @bp.route(
        "/forensic-reports/<session_id>/pdf"
    )
    @role_required(
        UserRole.FORENSIC_ANALYST,
        UserRole.LEAD_INVESTIGATOR,
        UserRole.ADMIN,
    )
    def forensic_report_pdf(
        session_id,
    ):

        data = data_loader(
            session_id
        )

        if not data:

            return jsonify(
                {
                    "success": False,
                    "error":
                        "Analysis session not found.",
                }
            ), 404

        analytics = (
            analytics_loader(
                session_id
            )
            or {}
        )

        ai_intelligence = (
            ai_loader(
                data,
                analytics,
            )
            if analytics
            else {}
        )

        payload = (
            build_forensic_report_payload(
                data,
                analytics,
                ai_intelligence,
            )
        )

        pdf = build_pdf_bytes(
            payload
        )

        return send_file(
            io.BytesIO(pdf),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=(
                "TRIAD_Forensic_Dossier_"
                + session_id[:8]
                + ".pdf"
            ),
        )

    @bp.route(
        "/forensic-reports/<session_id>/html"
    )
    @role_required(
        UserRole.FORENSIC_ANALYST,
        UserRole.LEAD_INVESTIGATOR,
        UserRole.ADMIN,
    )
    def forensic_report_html(
        session_id,
    ):

        data = data_loader(
            session_id
        )

        if not data:

            return jsonify(
                {
                    "success": False,
                    "error":
                        "Analysis session not found.",
                }
            ), 404

        analytics = (
            analytics_loader(
                session_id
            )
            or {}
        )

        ai_intelligence = (
            ai_loader(
                data,
                analytics,
            )
            if analytics
            else {}
        )

        payload = (
            build_forensic_report_payload(
                data,
                analytics,
                ai_intelligence,
            )
        )

        return Response(
            _build_html_document(
                payload
            ),
            mimetype=(
                "text/html; charset=utf-8"
            ),
            headers={
                "Content-Disposition":
                    (
                        "attachment; "
                        "filename="
                        "\"TRIAD_Forensic_Dossier_"
                        + session_id[:8]
                        + ".html\""
                    )
            },
        )

    @bp.route(
        "/forensic-reports/<session_id>/json"
    )
    @role_required(
        UserRole.FORENSIC_ANALYST,
        UserRole.LEAD_INVESTIGATOR,
        UserRole.ADMIN,
    )
    def forensic_report_json(
        session_id,
    ):

        data = data_loader(
            session_id
        )

        if not data:

            return jsonify(
                {
                    "success": False,
                    "error":
                        "Analysis session not found.",
                }
            ), 404

        analytics = (
            analytics_loader(
                session_id
            )
            or {}
        )

        ai_intelligence = (
            ai_loader(
                data,
                analytics,
            )
            if analytics
            else {}
        )

        payload = (
            build_forensic_report_payload(
                data,
                analytics,
                ai_intelligence,
            )
        )

        return Response(
            build_json_bytes(
                payload
            ),
            mimetype="application/json",
            headers={
                "Content-Disposition":
                    (
                        "attachment; "
                        "filename="
                        "\"TRIAD_Forensic_Dossier_"
                        + session_id[:8]
                        + ".json\""
                    )
            },
        )

    @bp.route(
        "/forensic-reports/<session_id>/csv"
    )
    @role_required(
        UserRole.FORENSIC_ANALYST,
        UserRole.LEAD_INVESTIGATOR,
        UserRole.ADMIN,
    )
    def forensic_report_csv(
        session_id,
    ):

        data = data_loader(
            session_id
        )

        if not data:

            return jsonify(
                {
                    "success": False,
                    "error":
                        "Analysis session not found.",
                }
            ), 404

        analytics = (
            analytics_loader(
                session_id
            )
            or {}
        )

        ai_intelligence = (
            ai_loader(
                data,
                analytics,
            )
            if analytics
            else {}
        )

        payload = (
            build_forensic_report_payload(
                data,
                analytics,
                ai_intelligence,
            )
        )

        return Response(
            build_csv_bytes(
                payload
            ),
            mimetype=(
                "text/csv; charset=utf-8"
            ),
            headers={
                "Content-Disposition":
                    (
                        "attachment; "
                        "filename="
                        "\"TRIAD_Forensic_Dossier_"
                        + session_id[:8]
                        + ".csv\""
                    )
            },
        )

    @bp.route(
        "/forensic-reports/<session_id>/xlsx"
    )
    @role_required(
        UserRole.FORENSIC_ANALYST,
        UserRole.LEAD_INVESTIGATOR,
        UserRole.ADMIN,
    )
    def forensic_report_xlsx(
        session_id,
    ):

        data = data_loader(
            session_id
        )

        if not data:

            return jsonify(
                {
                    "success": False,
                    "error":
                        "Analysis session not found.",
                }
            ), 404

        analytics = (
            analytics_loader(
                session_id
            )
            or {}
        )

        ai_intelligence = (
            ai_loader(
                data,
                analytics,
            )
            if analytics
            else {}
        )

        payload = (
            build_forensic_report_payload(
                data,
                analytics,
                ai_intelligence,
            )
        )

        return send_file(
            io.BytesIO(
                build_xlsx_bytes(
                    payload
                )
            ),
            mimetype=(
                "application/"
                "vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet"
            ),
            as_attachment=True,
            download_name=(
                "TRIAD_Forensic_Dossier_"
                + session_id[:8]
                + ".xlsx"
            ),
        )

    @bp.route(
        "/security-validation"
    )
    @dems_login_required
    def security_validation_view():

        validation = (
            run_security_validation()
        )

        return render_template(
            "security_validation.html",
            validation=validation,
            user=_get_current_user(),
        )

    @bp.route(
        "/api/security-validation"
    )
    @dems_login_required
    def api_security_validation():

        return jsonify(
            run_security_validation()
        )