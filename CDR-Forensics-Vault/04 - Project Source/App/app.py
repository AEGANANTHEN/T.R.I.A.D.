"""
T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard — Flask Application
=======================================================
Routes for CDR upload, analysis, cross-matching, investigation history,
and all interactive visualization API endpoints.
"""

import datetime
import io
import json
import os
import uuid
from pathlib import Path

import pandas as pd
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
from werkzeug.utils import secure_filename

import cdr_engine as engine

# ─────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cdr-forensic-intel-2024-secret")

UPLOAD_FOLDER = Path("uploads")
CACHE_FOLDER = Path("cache")
UPLOAD_FOLDER.mkdir(exist_ok=True)
CACHE_FOLDER.mkdir(exist_ok=True)

HISTORY_FILE = CACHE_FOLDER / "history.json"
ALLOWED_EXTENSIONS = {"csv", "xlsx", "xls"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _cache_path(session_id: str) -> Path:
    return CACHE_FOLDER / f"{session_id}.json"


def _save_cache(session_id: str, data: dict) -> None:
    with open(_cache_path(session_id), "w", encoding="utf-8") as f:
        json.dump(data, f, default=str)


def _load_cache(session_id: str) -> dict | None:
    path = _cache_path(session_id)
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
    # Remove existing if any with same id
    history = [h for h in history if h.get("id") != entry.get("id")]
    # Insert newest at top
    history.insert(0, entry)
    _save_history(history)


def _delete_history_entry(session_id: str) -> bool:
    history = _get_history()
    new_history = [h for h in history if h.get("id") != session_id]
    _save_history(new_history)
    # Also delete cached JSON file if exists
    c_path = _cache_path(session_id)
    if c_path.exists():
        try:
            c_path.unlink()
        except Exception:
            pass
    return True


def _get_latest_session_id(session_type: str = "single") -> str | None:
    history = _get_history()
    for h in history:
        if session_type == "any" or h.get("type") == session_type:
            # Check cache file exists
            if _cache_path(h["id"]).exists():
                return h["id"]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN NAVIGATION ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    active_tab = request.args.get("tab", "single")
    history = _get_history()[:5]  # Top 5 recent for quick access
    return render_template("index.html", active_tab=active_tab, recent_history=history)


@app.route("/dashboard")
def route_dashboard():
    """Smart dashboard route — opens active/latest analysis or redirects to upload."""
    latest_id = _get_latest_session_id("single")
    if latest_id:
        return redirect(url_for("dashboard", session_id=latest_id))
    flash("No CDR analysis session found. Please upload a file to begin.", "info")
    return redirect(url_for("index"))


@app.route("/link-analysis")
@app.route("/link-analysis/<session_id>")
def route_link_analysis(session_id: str | None = None):
    """Direct route for Link Analysis (Vis.js Network Graph)."""
    target_sid = session_id or _get_latest_session_id("single")
    if target_sid:
        return redirect(url_for("dashboard", session_id=target_sid) + "#section-link-analysis")
    flash("Please upload a CDR file first to view Link Analysis.", "info")
    return redirect(url_for("index"))


@app.route("/geo-tracking")
@app.route("/geo-tracking/<session_id>")
def route_geo_tracking(session_id: str | None = None):
    """Direct route for Geo Tracking (Leaflet Map)."""
    target_sid = session_id or _get_latest_session_id("single")
    if target_sid:
        return redirect(url_for("dashboard", session_id=target_sid) + "#section-geo-tracking")
    flash("Please upload a CDR file first to view Geo Tracking.", "info")
    return redirect(url_for("index"))


@app.route("/cross-match", methods=["GET", "POST"])
def cross_match_route():
    """Handles both GET (redirect to upload tab) and POST (cross-match upload)."""
    if request.method == "GET":
        latest_cross = _get_latest_session_id("cross_match")
        if latest_cross and request.args.get("view") == "latest":
            return redirect(url_for("cross_match_view", session_id=latest_cross))
        return redirect(url_for("index", tab="multi"))

    # POST method: Process multi-CDR upload
    return handle_cross_match_upload()


@app.route("/history")
def history_view():
    """Investigation History page showing all past CDR analyses."""
    history = _get_history()
    return render_template("history.html", history=history)


# ─────────────────────────────────────────────────────────────────────────────
# FILE UPLOAD & PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/upload", methods=["POST"])
def upload():
    """Single CDR file upload + analysis."""
    if "cdr_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    file = request.files["cdr_file"]
    target_number = request.form.get("target_number", "").strip()
    case_ref = request.form.get("case_ref", "").strip()

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Unsupported file type. Please upload CSV, XLS, or XLSX.", "error")
        return redirect(url_for("index"))

    # Save uploaded file
    sid = str(uuid.uuid4())
    safe_name = secure_filename(file.filename)
    filepath = UPLOAD_FOLDER / f"{sid}_{safe_name}"
    file.save(str(filepath))

    try:
        data = engine.run_full_analysis(str(filepath), target_number)
        data["filename"] = safe_name
        data["case_ref"] = case_ref
        _save_cache(sid, data)

        # Register in persistent history
        travel_anomalies = len(data.get("impossible_travel", []))
        device_swaps = data.get("device_swaps", {})
        swap_count = (1 if device_swaps.get("handset_hopping") else 0) + (1 if device_swaps.get("sim_swapping") else 0)

        _add_history_entry({
            "id": sid,
            "type": "single",
            "target": data.get("target", "Unknown"),
            "filename": safe_name,
            "case_ref": case_ref or "—",
            "records_count": data.get("kpis", {}).get("total_records", 0),
            "contacts_count": data.get("kpis", {}).get("unique_contacts", 0),
            "duration": data.get("kpis", {}).get("total_duration_hms", "00:00:00"),
            "anomalies_count": travel_anomalies + swap_count,
            "sha256": data.get("metadata", {}).get("sha256", ""),
            "date_range": data.get("kpis", {}).get("date_range", ""),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    except Exception as exc:
        flash(f"Analysis failed: {exc}", "error")
        return redirect(url_for("index"))

    return redirect(url_for("dashboard", session_id=sid))


def handle_cross_match_upload():
    """Multi-CDR upload and cross-match analysis implementation."""
    files = request.files.getlist("cdr_files")
    targets_raw = request.form.get("targets", "").strip()
    case_ref = request.form.get("case_ref", "").strip()

    targets = [t.strip() for t in targets_raw.split(",") if t.strip()]

    if len(files) < 2:
        flash("Please upload at least 2 CDR files for cross-matching.", "error")
        return redirect(url_for("index", tab="multi"))
    if len(files) > 5:
        flash("Maximum 5 CDR files allowed for cross-matching.", "error")
        return redirect(url_for("index", tab="multi"))

    datasets = []
    sid = str(uuid.uuid4())
    total_records = 0

    for i, file in enumerate(files):
        if not file or file.filename == "" or not allowed_file(file.filename):
            flash(f"File {i+1} is invalid or unsupported.", "error")
            return redirect(url_for("index", tab="multi"))

        safe_name = secure_filename(file.filename)
        filepath = UPLOAD_FOLDER / f"{sid}_{i}_{safe_name}"
        file.save(str(filepath))

        try:
            normalizer = engine.CDRNormalizer(str(filepath))
            df = normalizer.df
            total_records += len(df)
            target = targets[i] if i < len(targets) and targets[i] else (
                df["caller"].mode()[0] if not df.empty and "caller" in df else f"Target_{i+1}"
            )
            label = safe_name.rsplit(".", 1)[0] or f"Target_{i+1}"

            ind_sid = str(uuid.uuid4())
            individual = engine.run_full_analysis(str(filepath), target)
            individual["filename"] = safe_name
            individual["session_id"] = ind_sid
            _save_cache(ind_sid, individual)

            datasets.append({
                "label": label,
                "df": df,
                "target": target,
                "individual": individual,
                "filename": safe_name,
                "session_id": ind_sid,
            })
        except Exception as exc:
            flash(f"Error processing file '{file.filename}': {exc}", "error")
            return redirect(url_for("index", tab="multi"))

    # Cross-match analysis
    try:
        cross_engine = engine.CrossMatchEngine(datasets)
        common_contacts = cross_engine.common_contacts()
        colocation = cross_engine.colocation_events()
        matrix = cross_engine.contact_matrix()
    except Exception as exc:
        flash(f"Cross-match analysis failed: {exc}", "error")
        return redirect(url_for("index", tab="multi"))

    cache_data = {
        "type": "cross_match",
        "targets": [ds["target"] for ds in datasets],
        "labels": [ds["label"] for ds in datasets],
        "filenames": [ds["filename"] for ds in datasets],
        "individuals": [ds["individual"] for ds in datasets],
        "common_contacts": common_contacts,
        "colocation": colocation,
        "matrix": matrix,
        "case_ref": case_ref,
    }
    _save_cache(sid, cache_data)

    # Register in history
    _add_history_entry({
        "id": sid,
        "type": "cross_match",
        "targets": [ds["target"] for ds in datasets],
        "filenames": [ds["filename"] for ds in datasets],
        "case_ref": case_ref or "—",
        "records_count": total_records,
        "contacts_count": len(common_contacts),
        "duration": "—",
        "anomalies_count": len(colocation),
        "sha256": "Multi-File Hash",
        "date_range": f"{len(datasets)} Targets Comparison",
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    return redirect(url_for("cross_match_view", session_id=sid))


@app.route("/dashboard/<session_id>")
def dashboard(session_id: str):
    data = _load_cache(session_id)
    if not data:
        flash("Session expired or not found.", "error")
        return redirect(url_for("index"))

    # Auto-redirect if this is a cross-match session
    if data.get("type") == "cross_match" or ("individuals" in data and "kpis" not in data):
        return redirect(url_for("cross_match_view", session_id=session_id))

    # Ensure safe defaults for template
    data.setdefault("kpis", {})
    data.setdefault("metadata", {})
    data.setdefault("impossible_travel", [])
    data.setdefault("device_swaps", {})
    data.setdefault("target", "Target")
    data.setdefault("filename", "CDR File")

    return render_template("dashboard.html", session_id=session_id, data=data)


@app.route("/cross-match/<session_id>")
def cross_match_view(session_id: str):
    data = _load_cache(session_id)
    if not data:
        flash("Session expired or not found.", "error")
        return redirect(url_for("index"))

    # Auto-redirect if this is a single CDR session
    if data.get("type") == "single" or ("kpis" in data and "individuals" not in data):
        return redirect(url_for("dashboard", session_id=session_id))

    data.setdefault("targets", [])
    data.setdefault("labels", [])
    data.setdefault("individuals", [])
    data.setdefault("common_contacts", [])
    data.setdefault("colocation", [])
    data.setdefault("matrix", {})

    return render_template("cross_match.html", session_id=session_id, data=data)


# ─────────────────────────────────────────────────────────────────────────────
# REPORT & EXPORT ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/report/<session_id>")
def report_view(session_id: str):
    """Printable & PDF-exportable Forensic Intelligence Report."""
    data = _load_cache(session_id)
    if not data:
        flash("Session expired or not found.", "error")
        return redirect(url_for("index"))

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    return render_template(
        "report.html",
        session_id=session_id,
        data=data,
        generated_at=generated_at,
    )


@app.route("/export/excel/<session_id>")
def export_excel(session_id: str):
    """Generates and downloads a multi-sheet formatted forensic Excel workbook."""
    data = _load_cache(session_id)
    if not data:
        flash("Session not found.", "error")
        return redirect(url_for("index"))

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        is_cross = data.get("type") == "cross_match"

        if not is_cross:
            # Sheet 1: Overview & KPIs
            kpis = data.get("kpis", {})
            meta = data.get("metadata", {})
            swaps = data.get("device_swaps", {})
            overview_rows = [
                {"Metric": "Target Number", "Value": data.get("target", "Target")},
                {"Metric": "Source File", "Value": data.get("filename", "")},
                {"Metric": "SHA-256 Hash", "Value": meta.get("sha256", "")},
                {"Metric": "Date Range", "Value": kpis.get("date_range", "")},
                {"Metric": "Total Records", "Value": kpis.get("total_records", 0)},
                {"Metric": "Unique Contacts", "Value": kpis.get("unique_contacts", 0)},
                {"Metric": "Total Talk Time", "Value": kpis.get("total_duration_hms", "")},
                {"Metric": "Incoming Calls", "Value": kpis.get("incoming", 0)},
                {"Metric": "Outgoing Calls", "Value": kpis.get("outgoing", 0)},
                {"Metric": "SMS Messages", "Value": kpis.get("sms_count", 0)},
                {"Metric": "Night Calls (00-05)", "Value": kpis.get("night_calls", 0)},
                {"Metric": "IMEI Count", "Value": kpis.get("imei_count", 1)},
                {"Metric": "Handset Hopping Detected", "Value": "YES" if swaps.get("handset_hopping") else "NO"},
                {"Metric": "SIM Swapping Detected", "Value": "YES" if swaps.get("sim_swapping") else "NO"},
            ]
            pd.DataFrame(overview_rows).to_excel(writer, sheet_name="Forensic_Overview", index=False)

            # Sheet 2: CDR Records
            records = data.get("records", [])
            if records:
                df_rec = pd.DataFrame(records)
                df_rec.to_excel(writer, sheet_name="CDR_Records", index=False)

            # Sheet 3: Top Contacts
            contacts = data.get("top_contacts", [])
            if contacts:
                pd.DataFrame(contacts).to_excel(writer, sheet_name="Top_Contacts", index=False)

            # Sheet 4: Impossible Travel Anomalies
            travel = data.get("impossible_travel", [])
            if travel:
                pd.DataFrame(travel).to_excel(writer, sheet_name="Impossible_Travel", index=False)
            else:
                pd.DataFrame([{"Notice": "No impossible travel anomalies detected"}]).to_excel(writer, sheet_name="Impossible_Travel", index=False)

        else:
            # Multi-CDR Cross Match Export
            summary_rows = [
                {"Parameter": "Analysis Type", "Value": "Multi-Target CDR Cross-Match"},
                {"Parameter": "Targets Count", "Value": len(data.get("labels", []))},
                {"Parameter": "Targets", "Value": ", ".join(data.get("targets", []))},
                {"Parameter": "Mutual Contacts Count", "Value": len(data.get("common_contacts", []))},
                {"Parameter": "Co-location Events", "Value": len(data.get("colocation", []))},
            ]
            pd.DataFrame(summary_rows).to_excel(writer, sheet_name="Cross_Match_Summary", index=False)

            # Sheet 2: Mutual Contacts
            common = data.get("common_contacts", [])
            if common:
                common_rows = []
                for c in common:
                    common_rows.append({
                        "Contact Number": c.get("contact"),
                        "Target Count": c.get("target_count"),
                        "Present In Targets": ", ".join(c.get("present_in", []))
                    })
                pd.DataFrame(common_rows).to_excel(writer, sheet_name="Mutual_Contacts", index=False)

            # Sheet 3: Co-location Events
            coloc = data.get("colocation", [])
            if coloc:
                pd.DataFrame(coloc).to_excel(writer, sheet_name="Colocation_Events", index=False)

    output.seek(0)
    filename = f"CDR_Forensic_Report_{session_id[:8]}.xlsx"
    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/export/csv/<session_id>")
def export_csv(session_id: str):
    """Exports raw cleaned CDR records as CSV."""
    data = _load_cache(session_id)
    if not data:
        flash("Session not found.", "error")
        return redirect(url_for("index"))

    is_cross = data.get("type") == "cross_match"
    if not is_cross:
        records = data.get("records", [])
        df = pd.DataFrame(records)
    else:
        df = pd.DataFrame(data.get("common_contacts", []))

    csv_data = df.to_csv(index=False)
    output = io.BytesIO(csv_data.encode("utf-8-sig"))
    filename = f"CDR_Records_{session_id[:8]}.csv"
    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype="text/csv",
    )


@app.route("/export/json/<session_id>")
def export_json(session_id: str):
    """Exports full structured analysis package as JSON."""
    data = _load_cache(session_id)
    if not data:
        flash("Session not found.", "error")
        return redirect(url_for("index"))

    json_str = json.dumps(data, default=str, indent=2)
    output = io.BytesIO(json_str.encode("utf-8"))
    filename = f"CDR_Dossier_{session_id[:8]}.json"
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
    return jsonify(_get_history())


@app.route("/api/history/delete/<session_id>", methods=["POST"])
def api_history_delete(session_id: str):
    _delete_history_entry(session_id)
    return jsonify({"success": True, "deleted_id": session_id})


@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    _save_history([])
    return jsonify({"success": True, "message": "All history cleared"})


@app.route("/api/latest-session")
def api_latest_session():
    return jsonify({
        "latest_single": _get_latest_session_id("single"),
        "latest_cross": _get_latest_session_id("cross_match"),
    })


@app.route("/api/kpis/<session_id>")
def api_kpis(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("kpis", {}))


@app.route("/api/hourly/<session_id>")
def api_hourly(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("hourly", []))


@app.route("/api/dow/<session_id>")
def api_dow(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("dow", []))


@app.route("/api/calltypes/<session_id>")
def api_calltypes(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("call_types", []))


@app.route("/api/graph/<session_id>")
def api_graph(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("graph", {}))


@app.route("/api/geo/<session_id>")
def api_geo(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("geo", {}))


@app.route("/api/records/<session_id>")
def api_records(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("records", []))


@app.route("/api/anomalies/<session_id>")
def api_anomalies(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "impossible_travel": data.get("impossible_travel", []),
        "device_swaps": data.get("device_swaps", {}),
        "bursts": data.get("bursts", []),
        "dormant": data.get("dormant", []),
    })


@app.route("/api/top-contacts/<session_id>")
def api_top_contacts(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(data.get("top_contacts", []))


@app.route("/api/cross/<session_id>")
def api_cross(session_id: str):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "common_contacts": data.get("common_contacts", []),
        "colocation": data.get("colocation", []),
        "matrix": data.get("matrix", {}),
        "labels": data.get("labels", []),
    })


@app.route("/api/cross/individual/<session_id>/<int:index>")
def api_cross_individual(session_id: str, index: int):
    data = _get_data(session_id)
    if not data:
        return jsonify({"error": "Session not found"}), 404
    individuals = data.get("individuals", [])
    if index >= len(individuals):
        return jsonify({"error": "Index out of range"}), 404
    return jsonify(individuals[index])


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
