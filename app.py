"""
T.R.I.A.D. — Telecom Records & Intelligence Analysis Dashboard
==============================================================
Flask Application — routes for CDR upload, analysis, cross-matching,
investigation history, and all interactive visualization API endpoints.

DEMS Integration: Digital Evidence Management System blueprint registered
at /dems — provides encrypted evidence vault, chain of custody, and RBAC.
"""

import datetime
import gzip
import hashlib
import io
import json
import os
import secrets
import time
import uuid
from collections import OrderedDict
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

import pandas as pd
import requests
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.utils import secure_filename

import cdr_engine as engine
from realtime_engine import build_replay_events, normalize_speed, stream_delay_seconds
from investigation_analytics import build_investigation_analytics

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — AI INTELLIGENCE IMPORT
# ─────────────────────────────────────────────────────────────────────────────
from ai_intelligence import (
    create_ai_intelligence_blueprint,
    generate_ai_intelligence,
)
from forensic_reporting import register_phase8_routes

from dems_models import (
    db,
    bcrypt,
    init_db,
    User,
    Case,
    Evidence,
    EvidenceItem,
    ChainOfCustodyLog,
    RegisteredCamera,
    TowerEvidenceLink,
    CoCAction,
    VerificationStatus,
    EvidenceType,
    log_coc_event,
    generate_evidence_tag,
    generate_case_number,
)

from dems_crypto import (
    encrypt_file_to_vault,
    decrypt_to_memory_stream,
    get_vault_key,
    compute_sha256_of_bytes,
    compute_md5_of_bytes,
    build_vault_path,
)

from dems_routes import dems_bp


# ─────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cdr-forensic-intel-2024-secret",
)


# ── SQLAlchemy / DEMS Database ───────────────────────────────────────────────

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DEMS_DB_URI",
    f"sqlite:///{Path(__file__).parent / 'dems.db'}",
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "connect_args": {"check_same_thread": False},
}


# High-Performance SQLite WAL Mode & PRAGMA Tuning
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = NORMAL")
        cursor.execute("PRAGMA cache_size = -64000")
        cursor.execute("PRAGMA temp_store = MEMORY")
        cursor.close()
    except Exception:
        pass


# ── Register DEMS Blueprint ──────────────────────────────────────────────────
app.register_blueprint(dems_bp)


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ── Initialize DEMS Database ─────────────────────────────────────────────────
init_db(app)


UPLOAD_FOLDER = Path("uploads")
CACHE_FOLDER = Path("cache")

UPLOAD_FOLDER.mkdir(exist_ok=True)
CACHE_FOLDER.mkdir(exist_ok=True)


# ── Vault directory ──────────────────────────────────────────────────────────
VAULT_FOLDER = Path("vault")
VAULT_FOLDER.mkdir(exist_ok=True)

HISTORY_FILE = CACHE_FOLDER / "history.json"

ALLOWED_EXTENSIONS = {"csv", "xlsx", "xls"}


def allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ─────────────────────────────────────────────────────────────────────────────
# IN-MEMORY HIGH-PERFORMANCE LRU CACHE
# ─────────────────────────────────────────────────────────────────────────────

def _cache_path(session_id: str) -> Path:
    return CACHE_FOLDER / f"{session_id}.json"


class SessionMemoryCache:
    """
    High-performance in-memory LRU cache for CDR sessions.

    Automatically checks file mtime to invalidate whenever files change on disk.
    Eliminates redundant multi-megabyte disk I/O reads per page load.
    """

    def __init__(self, max_size: int = 32):
        self.max_size = max_size
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def get(self, session_id: str) -> dict | None:
        path = _cache_path(session_id)

        if not path.exists():
            self._cache.pop(session_id, None)
            return None

        try:
            mtime = path.stat().st_mtime

            if session_id in self._cache:
                cached_mtime, data = self._cache[session_id]

                if cached_mtime == mtime:
                    self._cache.move_to_end(session_id)
                    return data

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._cache[session_id] = (mtime, data)
            self._cache.move_to_end(session_id)

            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

            return data

        except Exception:
            return None

    def set(self, session_id: str, data: dict) -> None:
        path = _cache_path(session_id)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, default=str)

        try:
            mtime = path.stat().st_mtime

            self._cache[session_id] = (mtime, data)
            self._cache.move_to_end(session_id)

            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

        except Exception:
            pass

    def delete(self, session_id: str) -> None:
        self._cache.pop(session_id, None)

        path = _cache_path(session_id)

        if path.exists():
            try:
                path.unlink()
            except Exception:
                pass


_session_memory_cache = SessionMemoryCache(max_size=32)


def _save_cache(session_id: str, data: dict) -> None:
    _session_memory_cache.set(session_id, data)


def _load_cache(session_id: str) -> dict | None:
    return _session_memory_cache.get(session_id)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP OPTIMIZATION MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

@app.after_request
def compress_and_cache_response(response):
    """
    High-performance middleware:

    1. Sets 24h browser cache headers on static assets.
    2. Dynamically compresses text/json/html responses > 1KB with gzip.
    """

    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    accept_encoding = request.headers.get("Accept-Encoding", "")

    if (
        "gzip" in accept_encoding.lower()
        and response.status_code == 200
        and not response.direct_passthrough
        and "gzip" not in response.headers.get("Content-Encoding", "")
    ):
        data = response.get_data()

        if len(data) > 1024:
            content_type = response.headers.get("Content-Type", "")

            if any(
                ct in content_type
                for ct in (
                    "application/json",
                    "text/html",
                    "text/css",
                    "application/javascript",
                )
            ):
                gzip_buffer = io.BytesIO()

                with gzip.GzipFile(
                    mode="wb",
                    fileobj=gzip_buffer,
                    compresslevel=6,
                ) as gzip_file:
                    gzip_file.write(data)

                compressed = gzip_buffer.getvalue()

                if len(compressed) < len(data):
                    response.set_data(compressed)
                    response.headers["Content-Encoding"] = "gzip"
                    response.headers["Content-Length"] = len(compressed)

    return response


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def _get_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_history(history_list: list[dict]) -> None:
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history_list, f, default=str, indent=2)


def _add_history_entry(entry: dict) -> None:
    history = _get_history()

    history = [
        h for h in history
        if h.get("id") != entry.get("id")
    ]

    history.insert(0, entry)

    _save_history(history)


def _delete_history_entry(session_id: str) -> bool:
    history = _get_history()

    new_history = [
        h for h in history
        if h.get("id") != session_id
    ]

    _save_history(new_history)

    _session_memory_cache.delete(session_id)

    return True


def _get_latest_session_id(session_type: str = "single") -> str | None:
    history = _get_history()

    for h in history:
        if session_type == "any" or h.get("type") == session_type:
            if _cache_path(h["id"]).exists():
                return h["id"]

    return None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN NAVIGATION ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    active_tab = request.args.get("tab", "single")

    history = _get_history()[:5]

    return render_template(
        "index.html",
        active_tab=active_tab,
        recent_history=history,
    )


@app.route("/dashboard")
def route_dashboard():
    """Smart dashboard route — opens active/latest analysis or redirects to upload."""

    latest_id = _get_latest_session_id("single")

    if latest_id:
        return redirect(url_for("dashboard", session_id=latest_id))

    flash(
        "No CDR analysis session found. Please upload a file to begin.",
        "info",
    )

    return redirect(url_for("index"))


@app.route("/link-analysis")
@app.route("/link-analysis/<session_id>")
def route_link_analysis(session_id: str | None = None):
    """Direct route for Link Analysis (Vis.js Network Graph)."""

    target_sid = session_id or _get_latest_session_id("single")

    if target_sid:
        return redirect(
            url_for("dashboard", session_id=target_sid)
            + "#section-link-analysis"
        )

    flash(
        "Please upload a CDR file first to view Link Analysis.",
        "info",
    )

    return redirect(url_for("index"))


@app.route("/geo-tracking")
@app.route("/geo-tracking/<session_id>")
def route_geo_tracking(session_id: str | None = None):
    """Direct route for Geo Tracking (Leaflet Map)."""

    target_sid = session_id or _get_latest_session_id("single")

    if target_sid:
        return redirect(
            url_for("dashboard", session_id=target_sid)
            + "#section-geo-tracking"
        )

    flash(
        "Please upload a CDR file first to view Geo Tracking.",
        "info",
    )

    return redirect(url_for("index"))


@app.route("/vault")
def route_vault():
    """Direct route to DEMS Digital Evidence Management Vault."""

    return redirect(url_for("dems.vault_view"))


@app.route("/cctv-surveillance")
@app.route("/cctv-surveillance/<session_id>")
@app.route("/tactical-surveillance")
@app.route("/tactical-surveillance/<session_id>")
def cctv_surveillance_redirect(session_id: str | None = None):
    """Redirect legacy CCTV routes to Tactical GIS Map."""

    target_sid = session_id or _get_latest_session_id("single")

    if target_sid:
        return redirect(
            url_for("dashboard", session_id=target_sid)
            + "#section-geo-tracking"
        )

    return redirect(url_for("index"))


@app.route("/cross-match", methods=["GET", "POST"])
def cross_match_route():
    """Handles both GET and POST cross-match requests."""

    if request.method == "GET":
        latest_cross = _get_latest_session_id("cross_match")

        if latest_cross and request.args.get("view") == "latest":
            return redirect(
                url_for(
                    "cross_match_view",
                    session_id=latest_cross,
                )
            )

        return redirect(url_for("index", tab="multi"))

    return handle_cross_match_upload()


@app.route("/history")
def history_view():
    """Investigation History page showing all past CDR analyses."""

    history = _get_history()

    return render_template(
        "history.html",
        history=history,
    )


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — REAL-TIME INTELLIGENCE REPLAY
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/realtime")
@app.route("/realtime/<session_id>")
def realtime_view(session_id: str | None = None):
    """Phase 4 real-time intelligence dashboard using an existing CDR session."""

    target_sid = session_id or _get_latest_session_id("single")

    if not target_sid:
        flash(
            "No CDR analysis session found. Please upload a file first.",
            "info",
        )
        return redirect(url_for("index"))

    data = _get_data(target_sid)

    if not data:
        flash(
            "The selected CDR analysis session could not be loaded.",
            "error",
        )
        return redirect(url_for("index"))

    records = data.get("records", [])

    events = build_replay_events(records)

    return render_template(
        "realtime.html",
        session_id=target_sid,
        target=data.get("target", "TARGET"),
        filename=data.get("filename", "CDR Dataset"),
        total_records=len(records),
        total_events=len(events),
    )


@app.route("/api/realtime/<session_id>/snapshot")
def realtime_snapshot(session_id: str):
    """Return metadata and deterministic replay event count."""

    data = _get_data(session_id)

    if not data:
        return jsonify({
            "error": "Analysis session not found."
        }), 404

    events = build_replay_events(
        data.get("records", [])
    )

    return jsonify({
        "session_id": session_id,
        "target": data.get("target", "TARGET"),
        "filename": data.get("filename", "CDR Dataset"),
        "total_records": len(data.get("records", [])),
        "total_events": len(events),
        "mode": "SIMULATION / REPLAY",
    })


@app.route("/api/realtime/<session_id>/events")
def realtime_events(session_id: str):
    """
    Reliable Phase 4 event-batch endpoint.

    Uses normal JSON polling instead of Server-Sent Events.
    """

    data = _get_data(session_id)

    if not data:
        return jsonify({
            "error": "Analysis session not found."
        }), 404

    try:
        offset = max(
            0,
            int(request.args.get("offset", 0)),
        )
    except (TypeError, ValueError):
        offset = 0

    try:
        limit = int(
            request.args.get("limit", 10)
        )
    except (TypeError, ValueError):
        limit = 10

    limit = max(1, min(limit, 100))

    events = build_replay_events(
        data.get("records", [])
    )

    total = len(events)

    offset = min(offset, total)

    batch = events[
        offset:offset + limit
    ]

    next_offset = offset + len(batch)

    return jsonify({
        "success": True,
        "session_id": session_id,
        "events": batch,
        "offset": offset,
        "next_offset": next_offset,
        "total_events": total,
        "completed": next_offset >= total,
    })


# Backward-compatible SSE endpoint.
@app.route("/api/realtime/<session_id>/stream")
def realtime_stream(session_id: str):
    """Legacy SSE endpoint retained for compatibility."""

    data = _get_data(session_id)

    if not data:
        return jsonify({
            "error": "Analysis session not found."
        }), 404

    try:
        speed = normalize_speed(
            request.args.get("speed", 1)
        )

        start = max(
            0,
            int(request.args.get("start", 0)),
        )

    except (TypeError, ValueError):
        speed = 1
        start = 0

    events = build_replay_events(
        data.get("records", [])
    )

    start = min(start, len(events))

    delay = stream_delay_seconds(speed)

    def generate():
        import json as _json
        import time as _time

        yield "event: connected\n"

        yield "data: " + _json.dumps({
            "session_id": session_id,
            "mode": "SIMULATION / REPLAY",
            "speed": speed,
            "total_events": len(events),
            "start": start,
        }) + "\n\n"

        for event in events[start:]:
            yield "event: intelligence\n"

            yield "data: " + _json.dumps(
                event,
                ensure_ascii=False,
            ) + "\n\n"

            _time.sleep(delay)

        yield "event: complete\n"

        yield "data: " + _json.dumps({
            "total_events": len(events),
            "completed": True,
        }) + "\n\n"

    response = Response(
        generate(),
        mimetype="text/event-stream",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate"
    )

    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"

    return response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — ADVANCED INVESTIGATION ANALYTICS
# ─────────────────────────────────────────────────────────────────────────────

PHASE6_ANALYTICS_VERSION = "1.3"


def seconds_to_hms(seconds):
    """Convert duration in seconds to HH:MM:SS."""

    try:
        total_seconds = max(
            0,
            int(float(seconds or 0)),
        )
    except (TypeError, ValueError):
        total_seconds = 0

    hours, remainder = divmod(
        total_seconds,
        3600,
    )

    minutes, secs = divmod(
        remainder,
        60,
    )

    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _get_phase6_analytics(session_id: str):
    """
    Build or retrieve deterministic Phase 6 analytics.
    """

    data = _get_data(session_id)

    if not data:
        return None

    if data.get("type") == "cross_match" or (
        "individuals" in data
        and "records" not in data
    ):
        return _get_phase6_cross_match_analytics(
            session_id,
            data,
        )

    cached = data.get("phase6_analytics")

    if (
        isinstance(cached, dict)
        and cached.get("_engine_version")
        == PHASE6_ANALYTICS_VERSION
    ):
        return cached

    records = data.get("records", [])

    target = data.get(
        "target",
        "TARGET",
    )

    analytics = build_investigation_analytics(
        records=records,
        target=target,
        existing_analysis=data,
    )

    analytics["_engine_version"] = (
        PHASE6_ANALYTICS_VERSION
    )

    data["phase6_analytics"] = analytics

    _save_cache(
        session_id,
        data,
    )

    return analytics


def _get_phase6_cross_match_analytics(
    session_id: str,
    data: dict,
):
    """
    Build unified Phase 6 investigation package
    for a multi-target Cross-Match session.
    """

    cached = data.get("phase6_analytics")

    if (
        isinstance(cached, dict)
        and cached.get("_engine_version")
        == PHASE6_ANALYTICS_VERSION
    ):
        return cached

    individuals = data.get(
        "individuals",
        [],
    ) or []

    labels = data.get(
        "labels",
        [],
    ) or []

    targets = data.get(
        "targets",
        [],
    ) or []

    target_profiles = []

    total_records = 0
    total_distance = 0.0
    max_speed = 0.0

    unique_entities = set()

    incoming = 0
    outgoing = 0
    sms = 0
    unknown_direction = 0

    contact_map = {}
    active_map = {}

    hourly = [0] * 24
    daily = {}

    all_movement = []
    top_locations = []
    all_leads = []

    node_map = {}
    edge_map = {}

    def _safe_int(value, default=0):
        if value is None:
            return default

        if isinstance(
            value,
            (list, tuple, set, dict),
        ):
            return len(value)

        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default

    def _safe_float(value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    for i, individual in enumerate(individuals):

        individual = individual or {}

        records = individual.get(
            "records",
            [],
        ) or []

        target = (
            individual.get("target")
            or (
                targets[i]
                if i < len(targets)
                else f"Target {i + 1}"
            )
        )

        label = (
            labels[i]
            if i < len(labels)
            else individual.get(
                "filename",
                f"Target {i + 1}",
            )
        )

        try:
            profile = build_investigation_analytics(
                records=records,
                target=target,
                existing_analysis=individual,
            )

        except Exception as exc:

            profile = {
                "summary": {
                    "target": target,
                    "total_records": len(records),
                    "unique_entities": 0,
                    "active_days": 0,
                },
                "communication": {},
                "temporal": {},
                "geographic": {},
                "network": {},
                "leads": [
                    {
                        "severity": "INFO",
                        "type": "ANALYTICS_ERROR",
                        "title": "Target analytics unavailable",
                        "detail": str(exc),
                        "basis": "Per-target analytics engine error",
                    }
                ],
            }

        summary = profile.get(
            "summary",
            {},
        ) or {}

        comm = profile.get(
            "communication",
            {},
        ) or {}

        temporal = profile.get(
            "temporal",
            {},
        ) or {}

        geo = profile.get(
            "geographic",
            {},
        ) or {}

        network = profile.get(
            "network",
            {},
        ) or {}

        total_records += _safe_int(
            summary.get(
                "total_records",
                len(records),
            ),
            len(records),
        )

        incoming += _safe_int(
            comm.get("incoming")
        )

        outgoing += _safe_int(
            comm.get("outgoing")
        )

        sms += _safe_int(
            comm.get(
                "sms",
                comm.get("sms_count"),
            )
        )

        unknown_direction += _safe_int(
            comm.get("unknown_direction")
        )

        # Communication contacts
        for contact in comm.get(
            "target_contacts",
            [],
        ) or []:

            if isinstance(contact, str):
                contact = {
                    "contact": contact,
                    "interaction_count": 0,
                    "total_duration_sec": 0,
                    "relationship_strength": 0,
                }

            if not isinstance(
                contact,
                dict,
            ):
                continue

            number = str(
                contact.get(
                    "contact",
                    "",
                )
            ).strip()

            if not number:
                continue

            entry = contact_map.setdefault(
                number,
                {
                    "contact": number,
                    "interaction_count": 0,
                    "total_duration_sec": 0,
                    "incoming": 0,
                    "outgoing": 0,
                    "sms": 0,
                    "target_count": 0,
                    "last_seen": "",
                },
            )

            entry["interaction_count"] += _safe_int(
                contact.get(
                    "interaction_count"
                )
            )

            entry["total_duration_sec"] += _safe_int(
                contact.get(
                    "total_duration_sec"
                )
            )

            entry["incoming"] += _safe_int(
                contact.get("incoming")
            )

            entry["outgoing"] += _safe_int(
                contact.get("outgoing")
            )

            entry["sms"] += _safe_int(
                contact.get("sms")
            )

            if contact.get("last_seen"):
                entry["last_seen"] = max(
                    entry["last_seen"],
                    str(
                        contact.get(
                            "last_seen"
                        )
                    ),
                )

            entry["target_count"] += 1

        for active in comm.get(
            "active_numbers",
            [],
        ) or []:

            if isinstance(active, str):
                active = {
                    "number": active,
                    "interaction_count": 0,
                }

            if not isinstance(
                active,
                dict,
            ):
                continue

            number = str(
                active.get(
                    "number",
                    "",
                )
            ).strip()

            if not number:
                continue

            active_map[number] = (
                active_map.get(
                    number,
                    0,
                )
                + _safe_int(
                    active.get(
                        "interaction_count"
                    )
                )
            )

        # Temporal
        for item in temporal.get(
            "hourly",
            [],
        ) or []:

            if not isinstance(
                item,
                dict,
            ):
                continue

            try:
                hour = int(
                    item.get(
                        "hour",
                        item.get(
                            "hour_of_day"
                        ),
                    )
                )
            except (TypeError, ValueError):
                continue

            if 0 <= hour < 24:
                hourly[hour] += _safe_int(
                    item.get(
                        "count",
                        item.get(
                            "events"
                        ),
                    )
                )

        for item in temporal.get(
            "daily",
            [],
        ) or []:

            if not isinstance(
                item,
                dict,
            ):
                continue

            day = str(
                item.get(
                    "date",
                    item.get(
                        "day",
                        "",
                    ),
                )
            ).strip()

            if not day:
                continue

            daily[day] = (
                daily.get(day, 0)
                + _safe_int(
                    item.get(
                        "count",
                        item.get(
                            "events"
                        ),
                    )
                )
            )

        # Geography
        total_distance += _safe_float(
            geo.get(
                "total_distance_km"
            )
        )

        max_speed = max(
            max_speed,
            _safe_float(
                geo.get(
                    "max_leg_speed_kmh"
                )
            ),
        )

        for movement in geo.get(
            "movement",
            [],
        ) or []:

            if not isinstance(
                movement,
                dict,
            ):
                continue

            point = dict(movement)
            point["target"] = target

            all_movement.append(point)

        for location in geo.get(
            "top_locations",
            [],
        ) or []:

            if isinstance(
                location,
                dict,
            ):
                loc = dict(location)
                loc["target"] = target
                top_locations.append(loc)

        # Network merge
        for node in network.get(
            "nodes",
            [],
        ) or []:

            if not isinstance(
                node,
                dict,
            ):
                continue

            number = str(
                node.get(
                    "number",
                    "",
                )
            ).strip()

            if not number:
                continue

            if number not in node_map:
                node_map[number] = {
                    "number": number,
                    "degree": 0,
                    "interaction_strength": 0.0,
                    "betweenness": 0.0,
                    "is_target": False,
                    "targets": set(),
                }

            merged = node_map[number]

            merged["degree"] += _safe_int(
                node.get("degree")
            )

            merged["interaction_strength"] += _safe_float(
                node.get(
                    "interaction_strength"
                )
            )

            merged["betweenness"] = max(
                merged["betweenness"],
                _safe_float(
                    node.get(
                        "betweenness"
                    )
                ),
            )

            merged["is_target"] = (
                merged["is_target"]
                or bool(
                    node.get(
                        "is_target"
                    )
                )
            )

            merged["targets"].add(
                str(target)
            )

        for edge in network.get(
            "edges",
            [],
        ) or []:

            if not isinstance(
                edge,
                dict,
            ):
                continue

            source = str(
                edge.get(
                    "source",
                    "",
                )
            ).strip()

            target_node = str(
                edge.get(
                    "target",
                    "",
                )
            ).strip()

            if (
                not source
                or not target_node
                or source == target_node
            ):
                continue

            left, right = sorted(
                [
                    source,
                    target_node,
                ]
            )

            key = (
                left,
                right,
            )

            if key not in edge_map:
                edge_map[key] = {
                    "source": left,
                    "target": right,
                    "interaction_count": 0,
                    "duration_sec": 0,
                    "sms_count": 0,
                    "relationship_strength": 0.0,
                }

            merged_edge = edge_map[key]

            merged_edge["interaction_count"] += _safe_int(
                edge.get(
                    "interaction_count"
                )
            )

            merged_edge["duration_sec"] += _safe_int(
                edge.get(
                    "duration_sec"
                )
            )

            merged_edge["sms_count"] += _safe_int(
                edge.get(
                    "sms_count"
                )
            )

        target_profiles.append(
            {
                "label": label,
                "target": target,
                "filename": individual.get(
                    "filename",
                    label,
                ),
                "analytics": profile,
            }
        )

        all_leads.extend(
            {
                **dict(lead),
                "target": target,
            }
            for lead in (
                profile.get(
                    "leads",
                    [],
                )
                or []
            )
            if isinstance(
                lead,
                dict,
            )
        )

    # Cross-match findings
    common_contacts = data.get(
        "common_contacts",
        [],
    ) or []

    colocation = data.get(
        "colocation",
        [],
    ) or []

    for contact in common_contacts[:50]:

        if not isinstance(
            contact,
            dict,
        ):
            continue

        number = str(
            contact.get(
                "contact",
                "",
            )
        ).strip()

        if not number:
            continue

        existing = contact_map.setdefault(
            number,
            {
                "contact": number,
                "interaction_count": 0,
                "total_duration_sec": 0,
                "incoming": 0,
                "outgoing": 0,
                "sms": 0,
                "target_count": 0,
                "last_seen": "",
            },
        )

        existing["target_count"] = max(
            existing["target_count"],
            _safe_int(
                contact.get(
                    "target_count"
                )
            ),
        )

        all_leads.append(
            {
                "severity": (
                    "HIGH"
                    if _safe_int(
                        contact.get(
                            "target_count"
                        )
                    ) >= 3
                    else "MEDIUM"
                ),
                "type": "SHARED_CONTACT",
                "title": "Shared intermediary across targets",
                "detail": (
                    f"Contact {number} appears across "
                    f"{contact.get('target_count', 0)} target dataset(s)."
                ),
                "basis": "Cross-match mutual-contact correlation",
                "target": "MULTI-TARGET",
            }
        )

    for event in colocation[:50]:

        if not isinstance(
            event,
            dict,
        ):
            continue

        diff = _safe_float(
            event.get(
                "diff_minutes"
            ),
            99,
        )

        all_leads.append(
            {
                "severity": (
                    "HIGH"
                    if diff <= 5
                    else "MEDIUM"
                ),
                "type": "SPATIAL_TEMPORAL_CONVERGENCE",
                "title": "Spatial-temporal convergence detected",
                "detail": (
                    f"{event.get('target_a', 'Target A')} and "
                    f"{event.get('target_b', 'Target B')} were observed "
                    f"near {event.get('cell_id', 'the same cell')} "
                    f"within {event.get('diff_minutes', '?')} minutes."
                ),
                "basis": "Cross-match co-location engine",
                "target": "MULTI-TARGET",
            }
        )

    # Final communication collections
    target_contacts = []

    for item in contact_map.values():

        duration = item["total_duration_sec"]
        interactions = item["interaction_count"]

        relationship_strength = (
            min(
                50,
                interactions * 2,
            )
            + min(
                30,
                duration / 60,
            )
            + min(
                20,
                (
                    item["incoming"]
                    + item["outgoing"]
                )
                * 1.5,
            )
        )

        item["relationship_strength"] = round(
            min(
                100,
                relationship_strength,
            ),
            2,
        )

        item["duration_hms"] = seconds_to_hms(
            duration
        )

        target_contacts.append(item)

    target_contacts.sort(
        key=lambda item: (
            item["target_count"],
            item["interaction_count"],
            item["total_duration_sec"],
        ),
        reverse=True,
    )

    active_numbers = [
        {
            "number": number,
            "interaction_count": count,
        }
        for number, count in sorted(
            active_map.items(),
            key=lambda pair: pair[1],
            reverse=True,
        )[:20]
    ]

    # Network finalization
    network_nodes = []

    for node in node_map.values():

        finalized = dict(node)

        finalized["targets"] = sorted(
            finalized["targets"]
        )

        network_nodes.append(finalized)

    network_nodes.sort(
        key=lambda item: (
            item["interaction_strength"],
            item["degree"],
        ),
        reverse=True,
    )

    network_nodes = network_nodes[:150]

    allowed_nodes = {
        item["number"]
        for item in network_nodes
    }

    network_edges = []

    for edge in edge_map.values():

        if (
            edge["source"] not in allowed_nodes
            or edge["target"] not in allowed_nodes
        ):
            continue

        strength = (
            min(
                60,
                edge["interaction_count"] * 4,
            )
            + min(
                40,
                edge["duration_sec"] / 60,
            )
        )

        edge["relationship_strength"] = round(
            min(
                100,
                strength,
            ),
            2,
        )

        network_edges.append(edge)

    network_edges.sort(
        key=lambda item: item["relationship_strength"],
        reverse=True,
    )

    network_edges = network_edges[:300]

    central_nodes = sorted(
        network_nodes,
        key=lambda item: (
            item["interaction_strength"],
            item["betweenness"],
        ),
        reverse=True,
    )[:15]

    # Temporal finalization
    peak_hour = (
        max(
            range(24),
            key=lambda hour: hourly[hour],
        )
        if any(hourly)
        else None
    )

    peak_day = (
        max(
            daily,
            key=daily.get,
        )
        if daily
        else None
    )

    # Geographic movement ordering
    all_movement.sort(
        key=lambda item: (
            str(
                item.get(
                    "timestamp",
                    "",
                )
            ),
            str(
                item.get(
                    "target",
                    "",
                )
            ),
        )
    )

    # Deterministic signal score
    signal_score = min(
        100,
        25
        + min(
            30,
            len(common_contacts) * 5,
        )
        + min(
            30,
            len(colocation) * 8,
        )
        + min(
            15,
            len(network_edges) // 10,
        ),
    )

    top_contact = (
        target_contacts[0]
        if target_contacts
        else None
    )

    result = {
        "_engine_version": PHASE6_ANALYTICS_VERSION,
        "mode": "cross_match",

        "summary": {
            "target": "MULTI-TARGET",
            "total_targets": len(individuals),
            "total_records": total_records,
            "investigation_signal_score": signal_score,
            "unique_entities": len(
                {
                    node["number"]
                    for node in network_nodes
                }
            ),
            "active_days": len(daily),
            "peak_hour": peak_hour,
            "peak_day": peak_day,
            "top_contact": top_contact,
            "total_distance_km": round(
                total_distance,
                3,
            ),
            "mutual_contacts": len(
                common_contacts
            ),
            "colocation_events": len(
                colocation
            ),
        },

        "communication": {
            "incoming": incoming,
            "outgoing": outgoing,
            "sms": sms,
            "unknown_direction": unknown_direction,
            "target_contacts": target_contacts[:30],
            "active_numbers": active_numbers,
        },

        "temporal": {
            "hourly": [
                {
                    "hour": hour,
                    "count": hourly[hour],
                }
                for hour in range(24)
            ],

            "daily": [
                {
                    "date": day,
                    "count": count,
                }
                for day, count in sorted(
                    daily.items()
                )
            ],

            "peak_hours": sorted(
                [
                    {
                        "hour": hour,
                        "count": hourly[hour],
                    }
                    for hour in range(24)
                ],
                key=lambda item: item["count"],
                reverse=True,
            )[:5],
        },

        "geographic": {
            "total_distance_km": round(
                total_distance,
                3,
            ),
            "max_leg_speed_kmh": round(
                max_speed,
                2,
            ),
            "movement": all_movement[:1000],
            "top_locations": top_locations[:30],

            "first_location": (
                all_movement[0]
                if all_movement
                else None
            ),

            "last_location": (
                all_movement[-1]
                if all_movement
                else None
            ),
        },

        "network": {
            "total_nodes": len(network_nodes),
            "total_edges": len(network_edges),
            "nodes": network_nodes,
            "edges": network_edges,
            "central_nodes": central_nodes,

            "clusters": [
                {
                    "contact": item.get(
                        "contact"
                    ),
                    "targets": item.get(
                        "present_in",
                        [],
                    ),
                }
                for item in common_contacts
                if isinstance(
                    item,
                    dict,
                )
            ][:20],
        },

        "cross_match": {
            "targets": targets,
            "labels": labels,
            "common_contacts": common_contacts,
            "colocation": colocation,
            "matrix": data.get(
                "matrix",
                {},
            ),
        },

        "target_profiles": target_profiles,
        "leads": all_leads[:100],
    }

    data["phase6_analytics"] = result

    _save_cache(
        session_id,
        data,
    )

    return result


@app.route("/investigation-analytics")
@app.route("/investigation-analytics/<session_id>")
def investigation_analytics_view(
    session_id: str | None = None,
):
    """Phase 6 Advanced Investigation Analytics workspace."""

    target_sid = (
        session_id
        or _get_latest_session_id("single")
    )

    if not target_sid:
        flash(
            "No CDR analysis session found. Please upload a file first.",
            "info",
        )
        return redirect(url_for("index"))

    data = _get_data(target_sid)

    if not data:
        flash(
            "The selected CDR analysis session could not be loaded.",
            "error",
        )
        return redirect(url_for("index"))

    analytics = _get_phase6_analytics(
        target_sid
    )

    return render_template(
        "investigation_analytics.html",
        session_id=target_sid,
        target=data.get(
            "target",
            "TARGET",
        ),
        filename=data.get(
            "filename",
            "CDR Dataset",
        ),
        total_records=len(
            data.get(
                "records",
                [],
            )
        ),
        analytics=analytics,
    )


@app.route("/api/investigation-analytics/<session_id>")
def api_investigation_analytics(
    session_id: str,
):
    """Return deterministic Phase 6 analytics package."""

    data = _get_data(session_id)

    if not data:
        return jsonify({
            "error": "Analysis session not found."
        }), 404

    analytics = _get_phase6_analytics(
        session_id
    )

    if analytics is None:
        return jsonify({
            "error": (
                "Analysis session does not contain "
                "usable analytics data."
            )
        }), 400

    return jsonify(analytics)


# ─────────────────────────────────────────────────────────────────────────────
# FILE UPLOAD & PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload():
    """Single CDR file upload + analysis."""

    if "cdr_file" not in request.files:
        flash(
            "No file selected.",
            "error",
        )
        return redirect(url_for("index"))

    file = request.files["cdr_file"]

    target_number = request.form.get(
        "target_number",
        "",
    ).strip()

    case_ref = request.form.get(
        "case_ref",
        "",
    ).strip()

    if file.filename == "":
        flash(
            "No file selected.",
            "error",
        )
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash(
            "Unsupported file type. Please upload CSV, XLS, or XLSX.",
            "error",
        )
        return redirect(url_for("index"))

    sid = str(uuid.uuid4())

    safe_name = secure_filename(
        file.filename
    )

    filepath = (
        UPLOAD_FOLDER
        / f"{sid}_{safe_name}"
    )

    file.save(str(filepath))

    try:

        data = engine.run_full_analysis(
            str(filepath),
            target_number,
        )

        data["filename"] = safe_name
        data["case_ref"] = case_ref

        _save_cache(
            sid,
            data,
        )

        travel_anomalies = len(
            data.get(
                "impossible_travel",
                [],
            )
        )

        device_swaps = data.get(
            "device_swaps",
            {},
        )

        swap_count = (
            1
            if device_swaps.get(
                "handset_hopping"
            )
            else 0
        ) + (
            1
            if device_swaps.get(
                "sim_swapping"
            )
            else 0
        )

        _add_history_entry({
            "id": sid,
            "type": "single",
            "target": data.get(
                "target",
                "Unknown",
            ),
            "filename": safe_name,
            "case_ref": (
                case_ref
                or "—"
            ),
            "records_count": data.get(
                "kpis",
                {},
            ).get(
                "total_records",
                0,
            ),
            "contacts_count": data.get(
                "kpis",
                {},
            ).get(
                "unique_contacts",
                0,
            ),
            "duration": data.get(
                "kpis",
                {},
            ).get(
                "total_duration_hms",
                "00:00:00",
            ),
            "anomalies_count": (
                travel_anomalies
                + swap_count
            ),
            "sha256": data.get(
                "metadata",
                {},
            ).get(
                "sha256",
                "",
            ),
            "date_range": data.get(
                "kpis",
                {},
            ).get(
                "date_range",
                "",
            ),
            "timestamp": datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        })

    except Exception as exc:

        flash(
            f"Analysis failed: {exc}",
            "error",
        )

        return redirect(
            url_for("index")
        )

    return redirect(
        url_for(
            "dashboard",
            session_id=sid,
        )
    )


@app.route("/demo-sample/<sample_name>")
def demo_sample(sample_name):
    """Load pre-generated forensic sample datasets instantly for 1-click testing."""
    sample_map = {
        "triad_test": ("sample_cdr_triad_test.csv", "9876543210", "CASE-2026-TRIAD-TEST"),
        "sample1": ("sample_cdr.csv", "9876543210", "CASE-2026-DEMO-1"),
        "sample2": ("sample_cdr_2.csv", "9123456789", "CASE-2026-DEMO-2"),
    }
    
    if sample_name == "cross_match":
        f1 = Path(__file__).parent / "sample_cdr.csv"
        f2 = Path(__file__).parent / "sample_cdr_2.csv"
        if not f1.exists() or not f2.exists():
            flash("Sample files not found.", "error")
            return redirect(url_for("index"))
            
        sid = str(uuid.uuid4())
        dest1 = UPLOAD_FOLDER / f"{sid}_sample_cdr.csv"
        dest2 = UPLOAD_FOLDER / f"{sid}_sample_cdr_2.csv"
        dest1.write_bytes(f1.read_bytes())
        dest2.write_bytes(f2.read_bytes())
        
        file_specs = [
            {"path": str(dest1), "filename": "sample_cdr.csv", "target": "9876543210"},
            {"path": str(dest2), "filename": "sample_cdr_2.csv", "target": "9123456789"},
        ]
        res = engine.run_multi_cross_match(file_specs)
        _save_cache(sid, res)
        
        _add_history_entry({
            "id": sid,
            "type": "multi",
            "targets": res.get("targets", []),
            "filenames": ["sample_cdr.csv", "sample_cdr_2.csv"],
            "case_ref": "CASE-2026-CROSS-MATCH-DEMO",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "records_count": res.get("total_records_sum", 0),
            "anomalies_count": len(res.get("co_locations", [])),
        })
        return redirect(url_for("cross_match_view", session_id=sid))

    if sample_name not in sample_map:
        flash("Invalid sample dataset requested.", "error")
        return redirect(url_for("index"))

    fname, target, case_ref = sample_map[sample_name]
    src_file = Path(__file__).parent / fname
    if not src_file.exists():
        flash(f"Sample file {fname} not found.", "error")
        return redirect(url_for("index"))

    sid = str(uuid.uuid4())
    dest_path = UPLOAD_FOLDER / f"{sid}_{fname}"
    dest_path.write_bytes(src_file.read_bytes())

    data = engine.run_full_analysis(str(dest_path), target)
    data["filename"] = fname
    data["case_ref"] = case_ref
    _save_cache(sid, data)

    travel_anomalies = len(data.get("impossible_travel", []))
    device_swaps = data.get("device_swaps", {})
    swap_count = (1 if device_swaps.get("handset_hopping") else 0) + (1 if device_swaps.get("sim_swapping") else 0)

    _add_history_entry({
        "id": sid,
        "type": "single",
        "target": data.get("target", "Unknown"),
        "filename": fname,
        "case_ref": case_ref,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "records_count": len(data.get("df", [])),
        "anomalies_count": travel_anomalies + swap_count,
    })

    return redirect(url_for("dashboard", session_id=sid))


def handle_cross_match_upload():
    """Multi-CDR upload and cross-match analysis implementation."""

    files = request.files.getlist(
        "cdr_files"
    )

    targets_raw = request.form.get(
        "targets",
        "",
    ).strip()

    case_ref = request.form.get(
        "case_ref",
        "",
    ).strip()

    targets = [
        t.strip()
        for t in targets_raw.split(",")
        if t.strip()
    ]

    if len(files) < 2:
        flash(
            "Please upload at least 2 CDR files for cross-matching.",
            "error",
        )
        return redirect(
            url_for(
                "index",
                tab="multi",
            )
        )

    if len(files) > 5:
        flash(
            "Maximum 5 CDR files allowed for cross-matching.",
            "error",
        )
        return redirect(
            url_for(
                "index",
                tab="multi",
            )
        )

    datasets = []

    sid = str(uuid.uuid4())

    total_records = 0

    for i, file in enumerate(files):

        if (
            not file
            or file.filename == ""
            or not allowed_file(file.filename)
        ):
            flash(
                f"File {i + 1} is invalid or unsupported.",
                "error",
            )

            return redirect(
                url_for(
                    "index",
                    tab="multi",
                )
            )

        safe_name = secure_filename(
            file.filename
        )

        filepath = (
            UPLOAD_FOLDER
            / f"{sid}_{i}_{safe_name}"
        )

        file.save(
            str(filepath)
        )

        try:

            normalizer = engine.CDRNormalizer(
                str(filepath)
            )

            df = normalizer.df

            total_records += len(df)

            target = (
                targets[i]
                if i < len(targets)
                and targets[i]
                else (
                    df["caller"].mode()[0]
                    if not df.empty
                    and "caller" in df
                    else f"Target_{i + 1}"
                )
            )

            label = (
                safe_name.rsplit(
                    ".",
                    1,
                )[0]
                or f"Target_{i + 1}"
            )

            ind_sid = str(
                uuid.uuid4()
            )

            individual = engine.run_full_analysis(
                str(filepath),
                target,
            )

            individual["filename"] = safe_name
            individual["session_id"] = ind_sid

            _save_cache(
                ind_sid,
                individual,
            )

            datasets.append({
                "label": label,
                "df": df,
                "target": target,
                "individual": individual,
                "filename": safe_name,
                "session_id": ind_sid,
            })

        except Exception as exc:

            flash(
                f"Error processing file '{file.filename}': {exc}",
                "error",
            )

            return redirect(
                url_for(
                    "index",
                    tab="multi",
                )
            )

    # Cross-match analysis
    try:

        cross_engine = engine.CrossMatchEngine(
            datasets
        )

        common_contacts = (
            cross_engine.common_contacts()
        )

        colocation = (
            cross_engine.colocation_events()
        )

        matrix = (
            cross_engine.contact_matrix()
        )

    except Exception as exc:

        flash(
            f"Cross-match analysis failed: {exc}",
            "error",
        )

        return redirect(
            url_for(
                "index",
                tab="multi",
            )
        )

    cache_data = {
        "type": "cross_match",
        "targets": [
            ds["target"]
            for ds in datasets
        ],
        "labels": [
            ds["label"]
            for ds in datasets
        ],
        "filenames": [
            ds["filename"]
            for ds in datasets
        ],
        "individuals": [
            ds["individual"]
            for ds in datasets
        ],
        "common_contacts": common_contacts,
        "colocation": colocation,
        "matrix": matrix,
        "case_ref": case_ref,
    }

    _save_cache(
        sid,
        cache_data,
    )

    _add_history_entry({
        "id": sid,
        "type": "cross_match",
        "targets": [
            ds["target"]
            for ds in datasets
        ],
        "filenames": [
            ds["filename"]
            for ds in datasets
        ],
        "case_ref": (
            case_ref
            or "—"
        ),
        "records_count": total_records,
        "contacts_count": len(
            common_contacts
        ),
        "duration": "—",
        "anomalies_count": len(
            colocation
        ),
        "sha256": "Multi-File Hash",
        "date_range": (
            f"{len(datasets)} Targets Comparison"
        ),
        "timestamp": datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    })

    return redirect(
        url_for(
            "cross_match_view",
            session_id=sid,
        )
    )


@app.route("/dashboard/<session_id>")
def dashboard(session_id: str):

    data = _load_cache(
        session_id
    )

    if not data:
        flash(
            "Session expired or not found.",
            "error",
        )
        return redirect(
            url_for("index")
        )

    if (
        data.get("type")
        == "cross_match"
        or (
            "individuals" in data
            and "kpis" not in data
        )
    ):
        return redirect(
            url_for(
                "cross_match_view",
                session_id=session_id,
            )
        )

    data.setdefault(
        "kpis",
        {},
    )

    data.setdefault(
        "metadata",
        {},
    )

    data.setdefault(
        "impossible_travel",
        [],
    )

    data.setdefault(
        "device_swaps",
        {},
    )

    data.setdefault(
        "target",
        "Target",
    )

    data.setdefault(
        "filename",
        "CDR File",
    )

    return render_template(
        "dashboard.html",
        session_id=session_id,
        data=data,
    )


@app.route("/cross-match/<session_id>")
def cross_match_view(session_id: str):

    data = _load_cache(
        session_id
    )

    if not data:
        flash(
            "Session expired or not found.",
            "error",
        )
        return redirect(
            url_for("index")
        )

    if (
        data.get("type")
        == "single"
        or (
            "kpis" in data
            and "individuals" not in data
        )
    ):
        return redirect(
            url_for(
                "dashboard",
                session_id=session_id,
            )
        )

    data.setdefault(
        "targets",
        [],
    )

    data.setdefault(
        "labels",
        [],
    )

    data.setdefault(
        "individuals",
        [],
    )

    data.setdefault(
        "common_contacts",
        [],
    )

    data.setdefault(
        "colocation",
        [],
    )

    data.setdefault(
        "matrix",
        {},
    )

    return render_template(
        "cross_match.html",
        session_id=session_id,
        data=data,
    )


# ─────────────────────────────────────────────────────────────────────────────
# REPORT & EXPORT ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/report/<session_id>")
def report_view(session_id: str):
    """Printable & PDF-exportable Forensic Intelligence Report."""

    data = _load_cache(
        session_id
    )

    if not data:
        flash(
            "Session expired or not found.",
            "error",
        )
        return redirect(
            url_for("index")
        )

    generated_at = datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    return render_template(
        "report.html",
        session_id=session_id,
        data=data,
        generated_at=generated_at,
    )


@app.route("/export/excel/<session_id>")
def export_excel(session_id: str):
    """Generates multi-sheet formatted forensic Excel workbook."""

    data = _load_cache(
        session_id
    )

    if not data:
        flash(
            "Session not found.",
            "error",
        )
        return redirect(
            url_for("index")
        )

    output = io.BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl",
    ) as writer:

        is_cross = (
            data.get("type")
            == "cross_match"
        )

        if not is_cross:

            kpis = data.get(
                "kpis",
                {},
            )

            meta = data.get(
                "metadata",
                {},
            )

            swaps = data.get(
                "device_swaps",
                {},
            )

            overview_rows = [
                {
                    "Metric": "Target Number",
                    "Value": data.get(
                        "target",
                        "Target",
                    ),
                },
                {
                    "Metric": "Source File",
                    "Value": data.get(
                        "filename",
                        "",
                    ),
                },
                {
                    "Metric": "SHA-256 Hash",
                    "Value": meta.get(
                        "sha256",
                        "",
                    ),
                },
                {
                    "Metric": "Date Range",
                    "Value": kpis.get(
                        "date_range",
                        "",
                    ),
                },
                {
                    "Metric": "Total Records",
                    "Value": kpis.get(
                        "total_records",
                        0,
                    ),
                },
                {
                    "Metric": "Unique Contacts",
                    "Value": kpis.get(
                        "unique_contacts",
                        0,
                    ),
                },
                {
                    "Metric": "Total Talk Time",
                    "Value": kpis.get(
                        "total_duration_hms",
                        "",
                    ),
                },
                {
                    "Metric": "Incoming Calls",
                    "Value": kpis.get(
                        "incoming",
                        0,
                    ),
                },
                {
                    "Metric": "Outgoing Calls",
                    "Value": kpis.get(
                        "outgoing",
                        0,
                    ),
                },
                {
                    "Metric": "SMS Messages",
                    "Value": kpis.get(
                        "sms_count",
                        0,
                    ),
                },
                {
                    "Metric": "Night Calls (00-05)",
                    "Value": kpis.get(
                        "night_calls",
                        0,
                    ),
                },
                {
                    "Metric": "IMEI Count",
                    "Value": kpis.get(
                        "imei_count",
                        1,
                    ),
                },
                {
                    "Metric": "Handset Hopping Detected",
                    "Value": (
                        "YES"
                        if swaps.get(
                            "handset_hopping"
                        )
                        else "NO"
                    ),
                },
                {
                    "Metric": "SIM Swapping Detected",
                    "Value": (
                        "YES"
                        if swaps.get(
                            "sim_swapping"
                        )
                        else "NO"
                    ),
                },
            ]

            pd.DataFrame(
                overview_rows
            ).to_excel(
                writer,
                sheet_name="Forensic_Overview",
                index=False,
            )

            records = data.get(
                "records",
                [],
            )

            if records:
                pd.DataFrame(
                    records
                ).to_excel(
                    writer,
                    sheet_name="CDR_Records",
                    index=False,
                )

            contacts = data.get(
                "top_contacts",
                [],
            )

            if contacts:
                pd.DataFrame(
                    contacts
                ).to_excel(
                    writer,
                    sheet_name="Top_Contacts",
                    index=False,
                )

            travel = data.get(
                "impossible_travel",
                [],
            )

            if travel:
                pd.DataFrame(
                    travel
                ).to_excel(
                    writer,
                    sheet_name="Impossible_Travel",
                    index=False,
                )
            else:
                pd.DataFrame([
                    {
                        "Notice":
                        "No impossible travel anomalies detected"
                    }
                ]).to_excel(
                    writer,
                    sheet_name="Impossible_Travel",
                    index=False,
                )

        else:

            summary_rows = [
                {
                    "Parameter": "Analysis Type",
                    "Value": (
                        "Multi-Target CDR Cross-Match"
                    ),
                },
                {
                    "Parameter": "Targets Count",
                    "Value": len(
                        data.get(
                            "labels",
                            [],
                        )
                    ),
                },
                {
                    "Parameter": "Targets",
                    "Value": ", ".join(
                        data.get(
                            "targets",
                            [],
                        )
                    ),
                },
                {
                    "Parameter": "Mutual Contacts Count",
                    "Value": len(
                        data.get(
                            "common_contacts",
                            [],
                        )
                    ),
                },
                {
                    "Parameter": "Co-location Events",
                    "Value": len(
                        data.get(
                            "colocation",
                            [],
                        )
                    ),
                },
            ]

            pd.DataFrame(
                summary_rows
            ).to_excel(
                writer,
                sheet_name="Cross_Match_Summary",
                index=False,
            )

            common = data.get(
                "common_contacts",
                [],
            )

            if common:

                common_rows = []

                for c in common:
                    common_rows.append({
                        "Contact Number": c.get(
                            "contact"
                        ),
                        "Target Count": c.get(
                            "target_count"
                        ),
                        "Present In Targets": ", ".join(
                            c.get(
                                "present_in",
                                [],
                            )
                        ),
                    })

                pd.DataFrame(
                    common_rows
                ).to_excel(
                    writer,
                    sheet_name="Mutual_Contacts",
                    index=False,
                )

            coloc = data.get(
                "colocation",
                [],
            )

            if coloc:
                pd.DataFrame(
                    coloc
                ).to_excel(
                    writer,
                    sheet_name="Colocation_Events",
                    index=False,
                )

    output.seek(0)

    filename = (
        f"CDR_Forensic_Report_"
        f"{session_id[:8]}.xlsx"
    )

    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )


@app.route("/export/csv/<session_id>")
def export_csv(session_id: str):
    """Exports raw cleaned CDR records as CSV."""

    data = _load_cache(
        session_id
    )

    if not data:
        flash(
            "Session not found.",
            "error",
        )
        return redirect(
            url_for("index")
        )

    is_cross = (
        data.get("type")
        == "cross_match"
    )

    if not is_cross:

        records = data.get(
            "records",
            [],
        )

        df = pd.DataFrame(records)

    else:

        df = pd.DataFrame(
            data.get(
                "common_contacts",
                [],
            )
        )

    csv_data = df.to_csv(
        index=False
    )

    output = io.BytesIO(
        csv_data.encode(
            "utf-8-sig"
        )
    )

    filename = (
        f"CDR_Records_"
        f"{session_id[:8]}.csv"
    )

    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype="text/csv",
    )


@app.route("/export/json/<session_id>")
def export_json(session_id: str):
    """Exports full structured analysis package as JSON."""

    data = _load_cache(
        session_id
    )

    if not data:
        flash(
            "Session not found.",
            "error",
        )
        return redirect(
            url_for("index")
        )

    json_str = json.dumps(
        data,
        default=str,
        indent=2,
    )

    output = io.BytesIO(
        json_str.encode(
            "utf-8"
        )
    )

    filename = (
        f"CDR_Dossier_"
        f"{session_id[:8]}.json"
    )

    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype="application/json",
    )


# ─────────────────────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

def _get_data(session_id: str):
    return _load_cache(session_id)


@app.route("/api/history")
def api_history():
    return jsonify(
        _get_history()
    )


@app.route(
    "/api/history/delete/<session_id>",
    methods=["POST"],
)
def api_history_delete(session_id: str):

    _delete_history_entry(
        session_id
    )

    return jsonify({
        "success": True,
        "deleted_id": session_id,
    })


@app.route(
    "/api/history/clear",
    methods=["POST"],
)
def api_history_clear():

    _save_history([])

    return jsonify({
        "success": True,
        "message": "All history cleared",
    })


@app.route("/api/latest-session")
def api_latest_session():

    return jsonify({
        "latest_single":
            _get_latest_session_id("single"),

        "latest_cross":
            _get_latest_session_id("cross_match"),
    })


@app.route("/api/kpis/<session_id>")
def api_kpis(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify(
        data.get(
            "kpis",
            {},
        )
    )


@app.route("/api/hourly/<session_id>")
def api_hourly(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify(
        data.get(
            "hourly",
            [],
        )
    )


@app.route("/api/dow/<session_id>")
def api_dow(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify(
        data.get(
            "dow",
            [],
        )
    )


@app.route("/api/calltypes/<session_id>")
def api_calltypes(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify(
        data.get(
            "call_types",
            [],
        )
    )


@app.route("/api/graph/<session_id>")
def api_graph(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    graph = data.get(
        "graph",
        {},
    )

    if (
        (
            not graph.get("nodes")
            or len(
                graph.get(
                    "nodes",
                    [],
                )
            ) == 0
        )
        and data.get("records")
    ):

        try:

            df_rec = pd.DataFrame(
                data["records"]
            )

            target = data.get(
                "target",
                "",
            )

            graph = engine.NetworkGraphBuilder(
                df_rec,
                target,
            ).build()

            data["graph"] = graph

            _save_cache(
                session_id,
                data,
            )

        except Exception:
            pass

    return jsonify(graph)


@app.route("/api/geo/<session_id>")
def api_geo(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    geo = data.get(
        "geo",
        {},
    )

    if (
        (
            not geo.get("trajectory")
            or not geo.get("heat_points")
        )
        and data.get("records")
    ):

        try:

            df_rec = pd.DataFrame(
                data["records"]
            )

            if "timestamp" in df_rec.columns:
                df_rec["timestamp"] = pd.to_datetime(
                    df_rec["timestamp"],
                    errors="coerce",
                )

            geo = engine.GeoTracker(
                df_rec
            ).trajectory()

            data["geo"] = geo

            _save_cache(
                session_id,
                data,
            )

        except Exception:
            pass

    return jsonify(geo)


@app.route("/api/records/<session_id>")
def api_records(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify(
        data.get(
            "records",
            [],
        )
    )


@app.route("/api/anomalies/<session_id>")
def api_anomalies(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify({
        "impossible_travel":
            data.get(
                "impossible_travel",
                [],
            ),

        "device_swaps":
            data.get(
                "device_swaps",
                {},
            ),

        "bursts":
            data.get(
                "bursts",
                [],
            ),

        "dormant":
            data.get(
                "dormant",
                [],
            ),
    })


@app.route("/api/top-contacts/<session_id>")
def api_top_contacts(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify(
        data.get(
            "top_contacts",
            [],
        )
    )


@app.route("/api/cross/<session_id>")
def api_cross(session_id: str):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    return jsonify({
        "common_contacts":
            data.get(
                "common_contacts",
                [],
            ),

        "colocation":
            data.get(
                "colocation",
                [],
            ),

        "matrix":
            data.get(
                "matrix",
                {},
            ),

        "labels":
            data.get(
                "labels",
                [],
            ),
    })


@app.route(
    "/api/cross/individual/<session_id>/<int:index>"
)
def api_cross_individual(
    session_id: str,
    index: int,
):

    data = _get_data(
        session_id
    )

    if not data:
        return jsonify({
            "error": "Session not found"
        }), 404

    individuals = data.get(
        "individuals",
        [],
    )

    if index >= len(individuals):
        return jsonify({
            "error": "Index out of range"
        }), 404

    return jsonify(
        individuals[index]
    )


# ─────────────────────────────────────────────────────────────────────────────
# CELL TOWER METADATA & TELECOM PROXY ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/towers/<path:tower_id>/evidence")
def api_tower_evidence(tower_id: str):
    """Fast stub: Video streaming decommissioned for performance optimization."""

    return jsonify({
        "has_evidence": False,
        "tower_id": tower_id.strip(),
        "message": (
            "Video surveillance decommissioned "
            "for high-performance operation."
        ),
    })


@app.route("/api/towers/linked-evidence")
def api_towers_linked_evidence():
    """Returns empty list: Video pins removed for high-speed map performance."""

    return jsonify([])


@app.route("/api/dems/video-evidence-items")
def api_dems_video_evidence_items():
    """Returns empty list: Video evidence decommissioned."""

    return jsonify([])


# ─────────────────────────────────────────────────────────────────────────────
# OSINT ZERO-KEY PUBLIC TELEMETRY PROXY ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

_OSINT_CACHE: dict[str, dict] = {}


def _get_cached_osint(
    key: str,
    ttl_seconds: int,
    fetch_fn,
):
    now = time.time()

    cached = _OSINT_CACHE.get(key)

    if (
        cached
        and (
            now - cached["timestamp"]
        ) < ttl_seconds
    ):
        return cached["data"]

    try:

        data = fetch_fn()

        if data is not None:

            _OSINT_CACHE[key] = {
                "timestamp": now,
                "data": data,
            }

            return data

    except Exception:

        if cached:
            return cached["data"]

    return None


@app.route("/api/osint/submarine-cables")
def api_osint_submarine_cables():
    """
    TeleGeography Submarine Fiber-Optic Cables telemetry proxy.
    Caches global submarine cable GeoJSON locally.
    """

    def _fetch():

        url = (
            "https://raw.githubusercontent.com/"
            "telegeography/www.submarinecablemap.com/"
            "master/web/public/api/v3/cable/"
            "cable-geo.json"
        )

        try:

            resp = requests.get(
                url,
                timeout=6,
                headers={
                    "User-Agent":
                        "DEMS-Forensic-Intel/2.0"
                },
            )

            if resp.status_code == 200:
                return resp.json()

        except Exception:
            pass

        return None

    try:

        data = _get_cached_osint(
            "submarine_cables",
            86400,
            _fetch,
        )

        if data and data.get(
            "features"
        ):
            return jsonify(data)

    except Exception:
        pass

    fallback_path = os.path.join(
        app.root_path,
        "static",
        "data",
        "submarine_cables.json",
    )

    if os.path.exists(
        fallback_path
    ):

        try:

            with open(
                fallback_path,
                "r",
                encoding="utf-8",
            ) as f:

                return jsonify(
                    json.load(f)
                )

        except Exception:
            pass

    return jsonify({
        "type": "FeatureCollection",
        "features": [],
    })


@app.route("/api/osint/earthquakes")
def api_osint_earthquakes():
    """
    USGS M4.5+ 24-Hour Real-Time Seismic Activity telemetry proxy.
    """

    def _fetch():

        url = (
            "https://earthquake.usgs.gov/"
            "earthquakes/feed/v1.0/summary/"
            "4.5_day.geojson"
        )

        resp = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent":
                    "DEMS-Forensic-Intel/2.0"
            },
        )

        if resp.status_code == 200:
            return resp.json()

        return None

    try:

        data = _get_cached_osint(
            "earthquakes",
            300,
            _fetch,
        )

        if data:
            return jsonify(data)

    except Exception:
        pass

    return jsonify({
        "type": "FeatureCollection",
        "features": [],
    })


@app.route("/api/osint/rainviewer")
def api_osint_rainviewer():
    """
    RainViewer Live Dynamic Precipitation Radar tiles API proxy.
    """

    def _fetch():

        url = (
            "https://api.rainviewer.com/"
            "public/weather-maps.json"
        )

        resp = requests.get(
            url,
            timeout=8,
            headers={
                "User-Agent":
                    "DEMS-Forensic-Intel/2.0"
            },
        )

        if resp.status_code == 200:
            return resp.json()

        return None

    try:

        data = _get_cached_osint(
            "rainviewer",
            300,
            _fetch,
        )

        if data:
            return jsonify(data)

    except Exception:
        pass

    return jsonify({
        "radar": {
            "past": [],
            "nowcast": [],
        }
    })


@app.route("/api/osint/opensky")
def api_osint_opensky():
    """
    OpenSky Network Live Commercial Aircraft ADS-B telemetry proxy.
    Accepts optional bounding box coordinates.
    """

    lamin = request.args.get(
        "lamin",
        type=float,
    )

    lomin = request.args.get(
        "lomin",
        type=float,
    )

    lamax = request.args.get(
        "lamax",
        type=float,
    )

    lomax = request.args.get(
        "lomax",
        type=float,
    )

    cache_key = (
        f"opensky_"
        f"{lamin}_"
        f"{lomin}_"
        f"{lamax}_"
        f"{lomax}"
    )

    def _fetch():

        url = (
            "https://opensky-network.org/"
            "api/states/all"
        )

        params = {}

        if all(
            v is not None
            for v in (
                lamin,
                lomin,
                lamax,
                lomax,
            )
        ):
            params = {
                "lamin": lamin,
                "lomin": lomin,
                "lamax": lamax,
                "lomax": lomax,
            }

        resp = requests.get(
            url,
            params=params,
            timeout=6,
            headers={
                "User-Agent":
                    "DEMS-Forensic-Intel/2.0"
            },
        )

        if resp.status_code == 200:

            res_json = resp.json()

            if (
                res_json
                and res_json.get("states")
            ):
                return res_json

        return None

    try:

        data = _get_cached_osint(
            cache_key,
            15,
            _fetch,
        )

        if (
            data
            and data.get("states")
        ):
            return jsonify(data)

    except Exception:
        pass

    # Resilient synthetic fallback
    center_lat = (
        ((lamin + lamax) / 2.0)
        if (
            lamin is not None
            and lamax is not None
        )
        else 19.076
    )

    center_lon = (
        ((lomin + lomax) / 2.0)
        if (
            lomin is not None
            and lomax is not None
        )
        else 72.877
    )

    now_ts = int(
        time.time()
    )

    synthetic_states = [
        [
            "800abc",
            "AIC651  ",
            "India",
            now_ts,
            now_ts,
            center_lon + 0.12,
            center_lat + 0.08,
            9750,
            False,
            220.5,
            78.0,
            0,
            None,
            10050,
            None,
            False,
            0,
        ],
        [
            "800def",
            "IGO814  ",
            "India",
            now_ts,
            now_ts,
            center_lon - 0.18,
            center_lat + 0.15,
            8500,
            False,
            215.0,
            195.0,
            0,
            None,
            8800,
            None,
            False,
            0,
        ],
        [
            "800111",
            "SEJ204  ",
            "India",
            now_ts,
            now_ts,
            center_lon + 0.25,
            center_lat - 0.22,
            10200,
            False,
            235.2,
            285.0,
            0,
            None,
            10500,
            None,
            False,
            0,
        ],
        [
            "76ce12",
            "UAE506  ",
            "United Arab Emirates",
            now_ts,
            now_ts,
            center_lon - 0.45,
            center_lat - 0.35,
            11580,
            False,
            248.0,
            310.0,
            0,
            None,
            11800,
            None,
            False,
            0,
        ],
    ]

    return jsonify({
        "time": now_ts,
        "states": synthetic_states,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — AI INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
#
# This is the ONLY Phase 7 integration block added to app.py.
#
# It is registered here, after _get_data() and _get_phase6_analytics()
# already exist, so the blueprint receives the existing TRIAD data loaders
# without modifying any Phase 1–6 processing logic.
#
# ─────────────────────────────────────────────────────────────────────────────

app.register_blueprint(
    create_ai_intelligence_blueprint(
        _get_data,
        _get_phase6_analytics,
    )
)


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 — FORENSIC REPORTING & SECURITY VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
#
# Phase 8 is layered on top of the existing TRIAD application.
# It does not replace or modify the CDR engine, realtime engine,
# Phase 6 analytics, Phase 7 AI blueprint, DEMS, or existing exports.
#
# The reporting module receives read-only loader callbacks so that
# Phase 8 can consume the existing investigation state without
# changing the underlying processing pipeline.
# ─────────────────────────────────────────────────────────────────────────────

def _get_ai_intelligence_for_report(
    data,
    analytics,
):
    """Build Phase 7 AI intelligence for Phase 8 reporting.

    Phase 8 passes the already-loaded investigation data and
    Phase 6 analytics directly to this adapter.

    This keeps Phase 8 reporting read-only and does not modify
    the existing CDR, analytics, AI, or evidence pipelines.
    """
    try:
        if not data:
            return None

        if not analytics:
            return None

        return generate_ai_intelligence(
            data,
            analytics,
        )

    except Exception:
        return None

register_phase8_routes(
    app,
    _get_data,
    _get_phase6_analytics,
    _get_ai_intelligence_for_report,
)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5001,
    )