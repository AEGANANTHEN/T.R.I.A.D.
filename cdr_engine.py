"""
T.R.I.A.D. — Telecom Records & Intelligence Analysis Dashboard
=================================================================
Core analytics engine: normalization, anomaly detection, KPI extraction,
and link-graph generation for the T.R.I.A.D. Intelligence Platform.
"""

import hashlib
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd
from geopy.distance import geodesic


# ─────────────────────────────────────────────────────────────────────────────
# COLUMN SCHEMA MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# COLUMN SCHEMA MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────

COLUMN_MAP = {
    "caller": [
        "cdrno", "cdr no", "cdr_no", "cdr number", "cdr_number",
        "target_number", "target number", "target", "subscriber", "subscriber_no",
        "subscriber_number", "sub_no", "calling_number", "calling number",
        "calling_no", "calling no", "calling party", "calling_party", "calling",
        "caller_number", "caller number", "caller_no", "caller no", "caller",
        "a_party", "a party", "aparty", "a_num", "a_number", "anumber", "a-number",
        "party_a", "party a", "msisdn_a", "msisdn", "source", "from", "originating",
        "own_no", "own number", "own_number", "phone_number", "mobile_number",
        "mobile_no", "mobile", "number_a"
    ],
    "receiver": [
        "b_party", "b party", "bparty", "b_party_no", "b_party_number", "b party no",
        "b party number", "called_number", "called number", "called_no", "called no",
        "called_party", "called party", "calledparty", "called",
        "receiver_number", "receiver number", "receiver_no", "receiver no", "receiver",
        "b_num", "b_number", "bnumber", "b-number", "party_b", "party b",
        "msisdn_b", "destination", "dest_number", "dest_msisdn", "to", "terminating",
        "other_party", "other party", "dialed_number", "dialed number", "dialled_number",
        "number_b"
    ],
    "timestamp": [
        "timestamp", "call date", "call_date", "date_time", "datetime", "date",
        "start_time", "starttime", "start time", "event_time", "record_date",
        "call_datetime", "call_time"
    ],
    "duration": [
        "duration", "duration_sec", "duration seconds", "duration_seconds",
        "call duration", "call_duration", "talk_time", "talk time", "seconds",
        "call_length", "length", "dur", "billable_seconds"
    ],
    "call_type": [
        "call_type", "call type", "type", "service type", "service_type",
        "call_direction", "direction", "event_type", "record_type", "traffic_type",
        "service", "traffic"
    ],
    "cell_id": [
        "first cell id", "first_cell_id", "first cell id address", "cell_id", "cell id",
        "cellid", "tower_id", "tower id", "bts_id", "site_id", "cell_tower", "cell",
        "first_cgid", "cgid", "cgi", "serving_cell"
    ],
    "lat": [
        "latitude", "lat", "tower latitude", "tower_latitude", "cell_lat", "tower_lat",
        "site_lat", "y_coord", "geo_lat", "latitude_deg"
    ],
    "lon": [
        "longitude", "lon", "lng", "tower longitude", "tower_longitude", "cell_lon",
        "tower_lon", "site_lon", "x_coord", "geo_lon", "longitude_deg"
    ],
    "imei": [
        "imei", "imei_number", "imei number", "handset id", "handset_id",
        "device_id", "equipment_id", "tac"
    ],
    "imsi": [
        "imsi", "imsi_number", "imsi number", "sim_id", "subscriber_id"
    ],
}


def _normalize_col(name: str) -> str:
    """Lower + strip special chars for fuzzy matching."""
    return re.sub(r"[^a-z0-9 ]", " ", str(name).strip().lower()).strip()


def map_columns(df: pd.DataFrame) -> dict[str, str | None]:
    """
    Return a canonical→actual column name mapping for any CDR DataFrame.
    Uses strict priority for exact match before falling back to substring match.
    """
    cols_norm = {_normalize_col(c): c for c in df.columns}
    mapping: dict[str, str | None] = {}

    for canonical, variants in COLUMN_MAP.items():
        found = None
        # 1. Exact normalized match
        for variant in variants:
            v_norm = _normalize_col(variant)
            if v_norm in cols_norm:
                found = cols_norm[v_norm]
                break
        # 2. Exact word / substring match as fallback
        if not found:
            for variant in variants:
                v_norm = _normalize_col(variant)
                if len(v_norm) < 3:
                    continue
                for norm_col, orig_col in cols_norm.items():
                    # Check as complete token or clean substring
                    if v_norm == norm_col or f" {v_norm} " in f" {norm_col} ":
                        found = orig_col
                        break
                    elif v_norm in norm_col and not any(ex in norm_col for ex in ("address", "provider", "manufacturer")):
                        found = orig_col
                        break
                if found:
                    break
        mapping[canonical] = found

    return mapping


# ─────────────────────────────────────────────────────────────────────────────
# CDR NORMALIZER
# ─────────────────────────────────────────────────────────────────────────────

class CDRNormalizer:
    """Parse, normalize, and compute SHA-256 hash for CDR files."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.sha256 = self._compute_hash()
        self.raw_df = self._load()
        self.col_map = map_columns(self.raw_df)
        self.df = self._normalize()

    def _compute_hash(self) -> str:
        h = hashlib.sha256()
        with open(self.filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _load(self) -> pd.DataFrame:
        fp = self.filepath.lower()
        if fp.endswith(".csv"):
            # Try common encodings
            for enc in ("utf-8", "latin-1", "cp1252"):
                try:
                    return pd.read_csv(self.filepath, encoding=enc, dtype=str, keep_default_na=False)
                except Exception:
                    continue
            raise ValueError("Cannot read CSV file")
        elif fp.endswith((".xlsx", ".xls")):
            engine = "openpyxl" if fp.endswith(".xlsx") else "xlrd"
            return pd.read_excel(self.filepath, dtype=str, engine=engine, keep_default_na=False)
        else:
            raise ValueError(f"Unsupported file type: {self.filepath}")

    def _normalize(self) -> pd.DataFrame:
        df = self.raw_df.copy()
        cm = self.col_map

        normalized = pd.DataFrame()

        # ── Caller / Receiver ──────────────────────────────────────────────
        for field in ("caller", "receiver"):
            col = cm.get(field)
            if col and col in df.columns:
                normalized[field] = df[col].astype(str).str.strip()
            else:
                normalized[field] = pd.Series(["UNKNOWN"] * len(df))

        # ── Timestamp (handling split Date + Time columns) ─────────────────
        time_col = None
        for c in df.columns:
            cnorm = _normalize_col(c)
            if cnorm in ("time", "call time", "call_time", "start time", "event time"):
                time_col = c
                break

        ts_col = cm.get("timestamp")
        if ts_col and time_col and ts_col != time_col and ts_col in df.columns and time_col in df.columns:
            combined_ts = df[ts_col].astype(str).str.strip() + " " + df[time_col].astype(str).str.strip()
            normalized["timestamp"] = pd.to_datetime(combined_ts, errors="coerce")
            # If combined failed for some rows, fallback to ts_col
            mask_na = normalized["timestamp"].isna()
            if mask_na.any():
                normalized.loc[mask_na, "timestamp"] = pd.to_datetime(df.loc[mask_na, ts_col], errors="coerce")
        elif ts_col and ts_col in df.columns:
            normalized["timestamp"] = pd.to_datetime(df[ts_col], errors="coerce")
        else:
            normalized["timestamp"] = pd.NaT

        # ── Duration ──────────────────────────────────────────────────────
        dur_col = cm.get("duration")
        if dur_col and dur_col in df.columns:
            normalized["duration"] = pd.to_numeric(df[dur_col], errors="coerce").fillna(0)
        else:
            normalized["duration"] = 0

        # ── Call Type ─────────────────────────────────────────────────────
        ct_col = cm.get("call_type")
        if ct_col and ct_col in df.columns:
            normalized["call_type"] = df[ct_col].astype(str).str.strip().str.upper()
        else:
            normalized["call_type"] = "UNKNOWN"

        # Normalize call_type values
        def _map_call_type(val: str) -> str:
            val = str(val).upper()
            if any(k in val for k in ("OUT", "MOC", "ORIGINATING")):
                return "OUTGOING"
            elif any(k in val for k in ("IN", "MTC", "TERMINATING")):
                return "INCOMING"
            elif "SMS" in val:
                return "SMS"
            elif "ROAM" in val:
                return "ROAMING"
            return val if val and val != "NAN" else "OUTGOING"

        normalized["call_type"] = normalized["call_type"].apply(_map_call_type)

        # ── Cell ID ───────────────────────────────────────────────────────
        cell_col = cm.get("cell_id")
        normalized["cell_id"] = df[cell_col].astype(str).str.strip() if (cell_col and cell_col in df.columns) else ""

        # ── Coordinates ───────────────────────────────────────────────────
        lat_col = cm.get("lat")
        lon_col = cm.get("lon")
        if lat_col and lon_col and lat_col in df.columns and lon_col in df.columns:
            normalized["lat"] = pd.to_numeric(df[lat_col], errors="coerce")
            normalized["lon"] = pd.to_numeric(df[lon_col], errors="coerce")
        else:
            normalized["lat"] = np.nan
            normalized["lon"] = np.nan

        # Check for composite coordinate column (e.g., "Lat-Long-Azimuth", "Location") if lat/lon is missing
        if normalized["lat"].isna().all():
            coord_col = None
            for c in df.columns:
                cnorm = _normalize_col(c)
                if any(k in cnorm for k in ("lat long", "lat_long", "lat lon", "lat_lon", "azimuth", "coordinate")):
                    coord_col = c
                    break

            if coord_col and coord_col in df.columns:
                def _extract_coords(val):
                    if not val or pd.isna(val):
                        return (np.nan, np.nan)
                    matches = re.findall(r"[-+]?\d+\.?\d*", str(val))
                    if len(matches) >= 2:
                        try:
                            v1, v2 = float(matches[0]), float(matches[1])
                            if -90 <= v1 <= 90 and -180 <= v2 <= 180:
                                return (v1, v2)
                            elif -90 <= v2 <= 90 and -180 <= v1 <= 180:
                                return (v2, v1)
                        except Exception:
                            pass
                    return (np.nan, np.nan)

                coords = df[coord_col].apply(_extract_coords)
                normalized["lat"] = [c[0] for c in coords]
                normalized["lon"] = [c[1] for c in coords]

        # ── Device IDs ────────────────────────────────────────────────────
        imei_col = cm.get("imei")
        imsi_col = cm.get("imsi")
        normalized["imei"] = df[imei_col].astype(str).str.strip() if (imei_col and imei_col in df.columns) else ""
        normalized["imsi"] = df[imsi_col].astype(str).str.strip() if (imsi_col and imsi_col in df.columns) else ""

        # ── Clean placeholders ────────────────────────────────────────────
        for c in ("imei", "imsi", "cell_id"):
            normalized[c] = normalized[c].replace({"nan": "", "None": "", "UNKNOWN": ""})

        # ── Drop rows with no caller AND no receiver ──────────────────────
        normalized = normalized[
            ~((normalized["caller"].isin(["", "UNKNOWN", "nan"])) & (normalized["receiver"].isin(["", "UNKNOWN", "nan"])))
        ].reset_index(drop=True)

        # Sort chronologically if timestamps exist
        if not normalized["timestamp"].isna().all():
            normalized = normalized.sort_values("timestamp").reset_index(drop=True)

        return normalized

    @property
    def metadata(self) -> dict:
        return {
            "sha256": self.sha256,
            "total_records": len(self.df),
            "column_mapping": {k: v for k, v in self.col_map.items() if v},
        }


# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class ForensicAnalyzer:
    """
    Computes all KPIs, temporal distributions, burst detection,
    and dormant period tracking for a normalized CDR DataFrame.
    """

    def __init__(self, df: pd.DataFrame, target_number: str = ""):
        self.df = df
        self.target = target_number
        # Identify the target if not explicitly provided
        if not self.target or self.target == "UNKNOWN":
            valid_callers = df[~df["caller"].isin(["", "UNKNOWN", "nan", "None"])]["caller"]
            if not valid_callers.empty:
                self.target = valid_callers.mode()[0]
            else:
                valid_receivers = df[~df["receiver"].isin(["", "UNKNOWN", "nan", "None"])]["receiver"]
                self.target = valid_receivers.mode()[0] if not valid_receivers.empty else "TARGET"

    # ── KPIs ──────────────────────────────────────────────────────────────

    def kpis(self) -> dict:
        df = self.df
        total = len(df)

        # Contacts: all numbers the target communicated with
        target = self.target
        if target and target not in ("UNKNOWN", "TARGET"):
            target_calls = df[(df["caller"] == target) | (df["receiver"] == target)]
            if target_calls.empty:
                target_calls = df
        else:
            target_calls = df

        contacts = set(target_calls["caller"].astype(str)) | set(target_calls["receiver"].astype(str))
        for drop_val in (target, "UNKNOWN", "TARGET", "", "nan", "None"):
            contacts.discard(drop_val)

        total_duration = int(df["duration"].sum()) if not df.empty else 0
        incoming = int((df["call_type"] == "INCOMING").sum())
        outgoing = int((df["call_type"] == "OUTGOING").sum())
        sms_count = int((df["call_type"] == "SMS").sum())

        # Night calls: 00:00–05:00
        night_calls = 0
        if "timestamp" in df.columns and not df["timestamp"].isna().all():
            night_mask = df["timestamp"].dt.hour.between(0, 4)
            night_calls = int(night_mask.sum())

        imei_count = int(df["imei"].replace({"": np.nan, "UNKNOWN": np.nan, "nan": np.nan}).dropna().nunique()) if "imei" in df.columns else 0
        imsi_count = int(df["imsi"].replace({"": np.nan, "UNKNOWN": np.nan, "nan": np.nan}).dropna().nunique()) if "imsi" in df.columns else 0

        # Date range
        valid_ts = df["timestamp"].dropna() if "timestamp" in df.columns else pd.Series([], dtype="datetime64[ns]")
        date_range = ""
        if not valid_ts.empty:
            date_range = f"{valid_ts.min().strftime('%Y-%m-%d')} → {valid_ts.max().strftime('%Y-%m-%d')}"

        return {
            "total_records": total,
            "unique_contacts": len(contacts),
            "total_duration_sec": total_duration,
            "total_duration_hms": _sec_to_hms(total_duration),
            "incoming": incoming,
            "outgoing": outgoing,
            "sms_count": sms_count,
            "night_calls": night_calls,
            "imei_count": imei_count,
            "imsi_count": imsi_count,
            "date_range": date_range,
            "target": self.target,
        }

    # ── Temporal Distributions ────────────────────────────────────────────

    def hourly_distribution(self) -> list[dict]:
        """Returns list of {hour, count, duration} for all 24 hours."""
        if self.df.empty or "timestamp" not in self.df.columns or self.df["timestamp"].isna().all():
            return [{"hour": h, "count": 0, "duration": 0} for h in range(24)]
        df = self.df.dropna(subset=["timestamp"]).copy()
        df["hour"] = df["timestamp"].dt.hour
        grouped = df.groupby("hour").agg(
            count=("caller", "size"),
            duration=("duration", "sum")
        ).reindex(range(24), fill_value=0).reset_index()
        return grouped.rename(columns={"hour": "hour"}).to_dict("records")

    def dow_distribution(self) -> list[dict]:
        """Returns list of {day, count, duration} for Mon–Sun."""
        DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        if self.df.empty or "timestamp" not in self.df.columns or self.df["timestamp"].isna().all():
            return [{"day": d, "count": 0, "duration": 0} for d in DAYS]
        df = self.df.dropna(subset=["timestamp"]).copy()
        df["dow"] = df["timestamp"].dt.dayofweek
        grouped = df.groupby("dow").agg(
            count=("caller", "size"),
            duration=("duration", "sum")
        ).reindex(range(7), fill_value=0).reset_index()
        grouped["day"] = grouped["dow"].apply(lambda x: DAYS[x])
        return grouped[["day", "count", "duration"]].to_dict("records")

    def call_type_distribution(self) -> list[dict]:
        counts = self.df["call_type"].value_counts().to_dict()
        return [{"type": k, "count": int(v)} for k, v in counts.items()]

    # ── Burst Detection ───────────────────────────────────────────────────

    def detect_bursts(self, window_minutes: int = 60, threshold: int = 5) -> list[dict]:
        """
        Find time windows where ≥ threshold calls occur within window_minutes.
        Returns list of burst event dicts.
        """
        if self.df.empty or "timestamp" not in self.df.columns:
            return []
        df = self.df.dropna(subset=["timestamp"]).sort_values("timestamp")
        if df.empty:
            return []

        bursts = []
        times = df["timestamp"].tolist()
        n = len(times)

        for i in range(n):
            window_end = times[i] + timedelta(minutes=window_minutes)
            j = i
            while j < n and times[j] <= window_end:
                j += 1
            count = j - i
            if count >= threshold:
                bursts.append({
                    "start": times[i].isoformat(),
                    "end": times[j - 1].isoformat(),
                    "count": count,
                    "window_minutes": window_minutes,
                })

        # Deduplicate overlapping bursts greedily
        deduplicated = []
        last_end = None
        for b in bursts:
            b_start = datetime.fromisoformat(b["start"])
            if last_end is None or b_start > last_end:
                deduplicated.append(b)
                last_end = datetime.fromisoformat(b["end"])

        return deduplicated[:20]  # cap at 20

    def dormant_periods(self, gap_hours: int = 24) -> list[dict]:
        """
        Find silent/dormant periods where no calls occurred for ≥ gap_hours.
        """
        if self.df.empty or "timestamp" not in self.df.columns:
            return []
        df = self.df.dropna(subset=["timestamp"]).sort_values("timestamp")
        if len(df) < 2:
            return []

        times = df["timestamp"].tolist()
        dormant = []
        for i in range(1, len(times)):
            gap = times[i] - times[i - 1]
            if gap >= timedelta(hours=gap_hours):
                dormant.append({
                    "from": times[i - 1].isoformat(),
                    "to": times[i].isoformat(),
                    "gap_hours": round(gap.total_seconds() / 3600, 1),
                })
        return dormant[:20]

    # ── Top Contacts ─────────────────────────────────────────────────────

    def top_contacts(self, n: int = 20) -> list[dict]:
        df = self.df
        if df.empty:
            return []
        target = self.target

        # Calls involving the target or all calls if target not distinctly separated
        if target and target not in ("UNKNOWN", "TARGET"):
            mask = (df["caller"] == target) | (df["receiver"] == target)
            target_calls = df[mask].copy()
            if target_calls.empty:
                target_calls = df.copy()
        else:
            target_calls = df.copy()

        def _get_contact(r):
            c = str(r.get("caller", "")).strip()
            rc = str(r.get("receiver", "")).strip()
            if target and target not in ("UNKNOWN", "TARGET"):
                if c == target:
                    return rc
                if rc == target:
                    return c
            return rc if rc not in ("", "UNKNOWN", "nan", "None") else c

        target_calls["contact"] = target_calls.apply(_get_contact, axis=1)
        target_calls = target_calls[
            ~target_calls["contact"].isin([target, "UNKNOWN", "TARGET", "", "nan", "None"])
        ]
        if target_calls.empty:
            return []

        grouped = target_calls.groupby("contact").agg(
            call_count=("caller", "size"),
            total_duration=("duration", "sum"),
            last_seen=("timestamp", "max"),
        ).sort_values("call_count", ascending=False).head(n).reset_index()
        grouped["last_seen"] = grouped["last_seen"].apply(
            lambda x: x.isoformat() if pd.notna(x) else ""
        )
        return grouped.to_dict("records")


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE SWAP DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class DeviceSwapDetector:
    """Detects IMEI handset hopping and IMSI/SIM swaps."""

    def __init__(self, df: pd.DataFrame, target: str = ""):
        self.df = df
        self.target = target

    def detect(self) -> dict:
        df = self.df.copy()

        imei_series = df["imei"].replace("", np.nan).dropna()
        imsi_series = df["imsi"].replace("", np.nan).dropna()

        unique_imeis = imei_series.unique().tolist()
        unique_imsis = imsi_series.unique().tolist()

        imei_timeline = []
        if len(unique_imeis) > 1:
            grp = df[df["imei"].replace("", np.nan).notna()].groupby("imei")
            for imei, g in grp:
                g_sorted = g.sort_values("timestamp")
                imei_timeline.append({
                    "imei": imei,
                    "first_seen": g_sorted["timestamp"].min().isoformat() if pd.notna(g_sorted["timestamp"].min()) else "",
                    "last_seen": g_sorted["timestamp"].max().isoformat() if pd.notna(g_sorted["timestamp"].max()) else "",
                    "call_count": len(g),
                })

        imsi_timeline = []
        if len(unique_imsis) > 1:
            grp = df[df["imsi"].replace("", np.nan).notna()].groupby("imsi")
            for imsi, g in grp:
                g_sorted = g.sort_values("timestamp")
                imsi_timeline.append({
                    "imsi": imsi,
                    "first_seen": g_sorted["timestamp"].min().isoformat() if pd.notna(g_sorted["timestamp"].min()) else "",
                    "last_seen": g_sorted["timestamp"].max().isoformat() if pd.notna(g_sorted["timestamp"].max()) else "",
                    "call_count": len(g),
                })

        return {
            "imei_count": len(unique_imeis),
            "imsi_count": len(unique_imsis),
            "handset_hopping": len(unique_imeis) > 1,
            "sim_swapping": len(unique_imsis) > 1,
            "imei_timeline": imei_timeline,
            "imsi_timeline": imsi_timeline,
        }


# ─────────────────────────────────────────────────────────────────────────────
# IMPOSSIBLE TRAVEL DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

MAX_SPEED_KMH = 900  # Supersonic threshold for flagging


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance in km between two (lat, lon) points."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class ImpossibleTravelDetector:
    """
    Detects physically impossible travel between consecutive cell tower pings
    using vectorized Haversine formula. Flags records where v > MAX_SPEED_KMH.
    Accelerated with NumPy vectorization for instant multi-thousand row scans.
    """

    def __init__(self, df: pd.DataFrame, speed_threshold_kmh: float = MAX_SPEED_KMH):
        self.df = df
        self.speed_threshold_kmh = speed_threshold_kmh

    def detect(self) -> list[dict]:
        df = self.df.dropna(subset=["lat", "lon", "timestamp"]).copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")
        df = df[(df["lat"].between(-90, 90)) & (df["lon"].between(-180, 180))]

        if len(df) < 2:
            return []

        lats = df["lat"].to_numpy(dtype=np.float64)
        lons = df["lon"].to_numpy(dtype=np.float64)
        ts_values = df["timestamp"].to_numpy()
        cell_ids = df["cell_id"].fillna("").astype(str).to_numpy() if "cell_id" in df.columns else np.array([""] * len(df))

        # Vectorized great-circle distance
        R = 6371.0
        phi1 = np.radians(lats[:-1])
        phi2 = np.radians(lats[1:])
        dphi = np.radians(lats[1:] - lats[:-1])
        dlambda = np.radians(lons[1:] - lons[:-1])

        a = np.sin(dphi / 2.0) ** 2 + np.cos(phi1) * np.cos(phi2) * np.sin(dlambda / 2.0) ** 2
        a = np.clip(a, 0.0, 1.0)
        dist_km_arr = R * 2.0 * np.arctan2(np.sqrt(a), np.sqrt(1.0 - a))

        # Time difference in hours
        time_diff_ns = (ts_values[1:] - ts_values[:-1]).astype("timedelta64[ns]").astype(np.float64)
        time_diff_h_arr = time_diff_ns / (3600.0 * 1e9)

        valid_time_mask = time_diff_h_arr > 0
        speed_kmh_arr = np.zeros_like(dist_km_arr)
        speed_kmh_arr[valid_time_mask] = dist_km_arr[valid_time_mask] / time_diff_h_arr[valid_time_mask]

        anomaly_indices = np.where(speed_kmh_arr > self.speed_threshold_kmh)[0]
        anomalies = []
        for idx in anomaly_indices:
            prev_ts = pd.Timestamp(ts_values[idx]).isoformat()
            curr_ts = pd.Timestamp(ts_values[idx + 1]).isoformat()
            time_h = time_diff_h_arr[idx]
            anomalies.append({
                "from_ts": prev_ts,
                "to_ts": curr_ts,
                "from_cell": cell_ids[idx],
                "to_cell": cell_ids[idx + 1],
                "from_lat": float(lats[idx]),
                "from_lon": float(lons[idx]),
                "to_lat": float(lats[idx + 1]),
                "to_lon": float(lons[idx + 1]),
                "distance_km": round(float(dist_km_arr[idx]), 2),
                "speed_kmh": round(float(speed_kmh_arr[idx]), 1),
                "time_diff_min": round(float(time_h * 60.0), 1),
            })

        return anomalies


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK GRAPH BUILDER
# ─────────────────────────────────────────────────────────────────────────────

class NetworkGraphBuilder:
    """
    Builds a NetworkX communication graph and serializes it to
    Vis.js-compatible node/edge JSON for frontend rendering.
    """

    def __init__(self, df: pd.DataFrame, target: str = "", max_nodes: int = 150):
        self.df = df
        self.target = target
        self.max_nodes = max_nodes

    def build(self) -> dict:
        if self.df.empty:
            return {"nodes": [], "edges": [], "total_nodes": 0, "total_edges": 0}

        G = nx.DiGraph()
        target_node = self.target if (self.target and self.target not in ("UNKNOWN", "TARGET")) else "TARGET"

        # Fast edge aggregation using itertuples
        edge_data: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "duration": 0.0})
        cols = self.df.columns.tolist()
        caller_idx = cols.index("caller") if "caller" in cols else -1
        receiver_idx = cols.index("receiver") if "receiver" in cols else -1
        call_type_idx = cols.index("call_type") if "call_type" in cols else -1
        dur_idx = cols.index("duration") if "duration" in cols else -1

        for row in self.df.itertuples(index=False, name=None):
            caller = str(row[caller_idx] if caller_idx >= 0 else "").strip()
            receiver = str(row[receiver_idx] if receiver_idx >= 0 else "").strip()
            call_type = str(row[call_type_idx] if call_type_idx >= 0 else "").upper()
            raw_dur = row[dur_idx] if dur_idx >= 0 else 0
            try:
                dur = float(raw_dur or 0)
            except (ValueError, TypeError):
                dur = 0.0

            # Resolve UNKNOWN/missing parties
            if caller in ("", "UNKNOWN", "nan", "None") and receiver not in ("", "UNKNOWN", "nan", "None"):
                if "IN" in call_type:
                    caller = receiver
                    receiver = target_node
                else:
                    caller = target_node
            elif receiver in ("", "UNKNOWN", "nan", "None") and caller not in ("", "UNKNOWN", "nan", "None"):
                if "OUT" in call_type:
                    receiver = caller
                    caller = target_node
                else:
                    receiver = target_node
            elif caller in ("", "UNKNOWN", "nan", "None") and receiver in ("", "UNKNOWN", "nan", "None"):
                continue

            if caller == receiver and caller == target_node:
                continue

            key = (caller, receiver)
            edge_data[key]["count"] += 1
            edge_data[key]["duration"] += dur

        if not edge_data:
            return {"nodes": [], "edges": [], "total_nodes": 0, "total_edges": 0}

        # Limit to top nodes by degree
        all_numbers: dict[str, int] = defaultdict(int)
        for (caller, receiver), data in edge_data.items():
            all_numbers[caller] += data["count"]
            all_numbers[receiver] += data["count"]

        top_numbers = set(
            sorted(all_numbers, key=lambda x: all_numbers[x], reverse=True)[: self.max_nodes]
        )
        # Always include target
        if target_node:
            top_numbers.add(target_node)
        if self.target:
            top_numbers.add(self.target)

        # Build graph
        for (caller, receiver), data in edge_data.items():
            if caller in top_numbers and receiver in top_numbers:
                G.add_edge(caller, receiver, count=data["count"], duration=data["duration"])

        # Also add any top node that might be isolated
        for n in top_numbers:
            if n in all_numbers and not G.has_node(n):
                G.add_node(n)

        # Centrality
        try:
            centrality = nx.degree_centrality(G) if len(G) > 1 else {n: 1.0 for n in G.nodes()}
        except Exception:
            centrality = {n: 0.0 for n in G.nodes()}

        # Serialize nodes
        nodes = []
        for node in G.nodes():
            degree = G.degree(node)
            is_target = (node == self.target) or (node == target_node) or (node == "TARGET")
            size = max(18, min(65, 14 + degree * 3))
            bg_color = "#38bdf8" if is_target else _degree_color(degree)
            border_color = "#0284c7" if is_target else "#334155"

            nodes.append({
                "id": node,
                "label": node,
                "value": degree,
                "size": size,
                "color": {
                    "background": bg_color,
                    "border": border_color,
                    "highlight": {"background": "#f59e0b", "border": "#f59e0b"},
                },
                "font": {"color": "#f1f5f9", "size": 11, "face": "Inter, sans-serif"},
                "title": f"📞 {node}<br>Role: {'Target Number' if is_target else 'Contact'}<br>Degree: {degree}<br>Centrality: {centrality.get(node, 0):.3f}",
                "is_target": is_target,
                "degree": degree,
                "centrality": round(centrality.get(node, 0), 4),
            })

        # Serialize edges
        edges = []
        for (caller, receiver), data in edge_data.items():
            if caller not in top_numbers or receiver not in top_numbers:
                continue
            weight = data["count"]
            edges.append({
                "from": caller,
                "to": receiver,
                "value": weight,
                "width": max(1, min(8, weight)),
                "title": f"Calls: {weight}<br>Duration: {_sec_to_hms(int(data['duration']))}",
                "color": {"color": "#334155", "highlight": "#38bdf8", "opacity": 0.8},
                "arrows": "to",
                "smooth": {"type": "curvedCW", "roundness": 0.1},
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        }


def _degree_color(degree: int) -> str:
    if degree >= 20:
        return "#f43f5e"
    elif degree >= 10:
        return "#f59e0b"
    elif degree >= 5:
        return "#10b981"
    return "#64748b"


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-LAYER TACTICAL GIS GEO TRACKER
# ─────────────────────────────────────────────────────────────────────────────

class GeoTracker:
    """
    Builds enterprise-grade multi-layer GIS trajectory data for Leaflet.js.
    Calculates:
      - Chronological vector trajectory with leg velocities (v = Δd / Δt)
      - Weighted dwell-time heatmap points (intensity based on call count + talk time)
      - Night-owl (00:00–05:00) vs Daytime call classification layers
      - Tower dwell aggregates and bounding centroid
    """

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def trajectory(self) -> dict:
        geo_df = self.df.dropna(subset=["lat", "lon"]).copy()
        geo_df = geo_df[
            geo_df["lat"].between(-90, 90) & geo_df["lon"].between(-180, 180)
        ].sort_values("timestamp")

        if geo_df.empty:
            return {
                "markers": [],
                "trajectory": [],
                "path": [],
                "legs": [],
                "heatmap": [],
                "heat_points": [],
                "night_markers": [],
                "day_markers": [],
                "towers": [],
                "has_geo": False,
                "center": [20.5937, 78.9629],
            }

        n = len(geo_df)
        lats = geo_df["lat"].to_numpy(dtype=np.float64)
        lons = geo_df["lon"].to_numpy(dtype=np.float64)
        ts_values = geo_df["timestamp"].to_numpy()

        dist_km_arr = np.zeros(n, dtype=np.float64)
        speed_kmh_arr = np.zeros(n, dtype=np.float64)
        time_diff_min_arr = np.zeros(n, dtype=np.float64)
        is_impossible_arr = np.zeros(n, dtype=bool)

        if n > 1:
            R = 6371.0
            phi1 = np.radians(lats[:-1])
            phi2 = np.radians(lats[1:])
            dphi = np.radians(lats[1:] - lats[:-1])
            dlambda = np.radians(lons[1:] - lons[:-1])
            a = np.sin(dphi / 2.0) ** 2 + np.cos(phi1) * np.cos(phi2) * np.sin(dlambda / 2.0) ** 2
            a = np.clip(a, 0.0, 1.0)
            dists = R * 2.0 * np.arctan2(np.sqrt(a), np.sqrt(1.0 - a))
            dist_km_arr[1:] = dists

            time_diff_ns = (ts_values[1:] - ts_values[:-1]).astype("timedelta64[ns]").astype(np.float64)
            time_diff_h = time_diff_ns / (3600.0 * 1e9)
            time_diff_min_arr[1:] = time_diff_h * 60.0

            valid_mask = time_diff_h > 0
            speeds = np.zeros_like(dists)
            speeds[valid_mask] = dists[valid_mask] / time_diff_h[valid_mask]
            speed_kmh_arr[1:] = speeds
            is_impossible_arr[1:] = speeds > 900.0

        markers = []
        trajectory_records = []
        legs = []
        records_list = geo_df.to_dict("records")

        for seq_idx, row in enumerate(records_list):
            ts = row.get("timestamp")
            hour = ts.hour if pd.notna(ts) and hasattr(ts, "hour") else 12
            is_night = (hour < 5)  # 00:00–05:00 night-owl calls
            call_type = str(row.get("call_type", ""))
            lat = float(lats[seq_idx])
            lon = float(lons[seq_idx])
            cid = str(row.get("cell_id", ""))
            dur = float(row.get("duration", 0) or 0)
            caller = str(row.get("caller", ""))
            receiver = str(row.get("receiver", ""))
            imei = str(row.get("imei", ""))
            imsi = str(row.get("imsi", ""))

            speed_kmh = float(speed_kmh_arr[seq_idx])
            dist_km = float(dist_km_arr[seq_idx])
            time_diff_min = float(time_diff_min_arr[seq_idx])
            is_impossible = bool(is_impossible_arr[seq_idx])

            if seq_idx > 0:
                prev_row = records_list[seq_idx - 1]
                prev_ts = prev_row.get("timestamp")
                legs.append({
                    "from_idx": seq_idx,
                    "to_idx": seq_idx + 1,
                    "from_lat": float(lats[seq_idx - 1]),
                    "from_lon": float(lons[seq_idx - 1]),
                    "to_lat": lat,
                    "to_lon": lon,
                    "distance_km": round(dist_km, 2),
                    "time_diff_min": round(time_diff_min, 1),
                    "speed_kmh": round(speed_kmh, 1),
                    "is_impossible": is_impossible,
                    "from_tower": str(prev_row.get("cell_id", "")),
                    "to_tower": cid,
                    "from_ts": prev_ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(prev_ts) and hasattr(prev_ts, "strftime") else str(prev_ts or ""),
                    "to_ts": ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) and hasattr(ts, "strftime") else str(ts or ""),
                })

            iso_ts = ts.isoformat() if pd.notna(ts) and hasattr(ts, "isoformat") else str(ts or "")
            str_ts = ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) and hasattr(ts, "strftime") else str(ts or "")

            m_obj = {
                "seq_index": seq_idx + 1,
                "lat": lat,
                "lon": lon,
                "cell_id": cid,
                "timestamp": iso_ts,
                "time_str": str_ts,
                "caller": caller,
                "receiver": receiver,
                "call_type": call_type,
                "duration": dur,
                "imei": imei,
                "imsi": imsi,
                "is_night": is_night,
                "speed_kmh": round(speed_kmh, 1),
                "distance_km": round(dist_km, 2),
                "time_diff_min": round(time_diff_min, 1),
                "is_impossible": is_impossible,
                "color": "#f43f5e" if is_night else _marker_color(call_type, is_night),
            }
            markers.append(m_obj)

            trajectory_records.append({
                "lat": lat,
                "lon": lon,
                "timestamp": iso_ts,
                "time_str": str_ts,
                "call_type": call_type,
                "duration": dur,
                "speed_kmh": round(speed_kmh, 1),
                "tower_id": cid,
                "seq_index": seq_idx + 1,
                "is_night": is_night,
                "is_impossible": is_impossible,
                "distance_km": round(dist_km, 2),
                "time_diff_min": round(time_diff_min, 1),
                "imei": imei,
                "imsi": imsi,
                "caller": caller,
                "receiver": receiver,
            })

        # Polyline path coordinates
        path = [[m["lat"], m["lon"]] for m in markers]

        # Day & Night Marker splits
        night_markers = [m for m in markers if m["is_night"]]
        day_markers = [m for m in markers if not m["is_night"]]

        # Dwell-time weighted heatmap data: [lat, lon, intensity]
        # Weighted by total call frequency and talk time duration at that location
        tower_dwell: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "duration": 0.0, "lat": 0.0, "lon": 0.0, "cell_ids": set()})
        for m in markers:
            key = (round(m["lat"], 4), round(m["lon"], 4))
            tower_dwell[key]["lat"] = m["lat"]
            tower_dwell[key]["lon"] = m["lon"]
            tower_dwell[key]["count"] += 1
            tower_dwell[key]["duration"] += m["duration"]
            if m["cell_id"]:
                tower_dwell[key]["cell_ids"].add(m["cell_id"])

        max_weight = max([d["count"] * 1.0 + (d["duration"] / 60.0) * 0.5 for d in tower_dwell.values()]) if tower_dwell else 1.0
        if max_weight <= 0:
            max_weight = 1.0

        heat_points = []
        for (lat_k, lon_k), d in tower_dwell.items():
            raw_weight = d["count"] * 1.0 + (d["duration"] / 60.0) * 0.5
            norm_intensity = min(1.0, max(0.2, raw_weight / max_weight))
            heat_points.append([d["lat"], d["lon"], round(norm_intensity, 3)])

        # Tower clusters
        tower_list = []
        for (lat_k, lon_k), d in tower_dwell.items():
            tower_list.append({
                "cell_id": ", ".join(sorted(d["cell_ids"])) or f"{d['lat']:.3f},{d['lon']:.3f}",
                "lat": d["lat"],
                "lon": d["lon"],
                "count": d["count"],
                "duration": int(d["duration"]),
            })

        return {
            "markers": markers,
            "trajectory": trajectory_records,
            "path": path,
            "legs": legs,
            "heatmap": heat_points,
            "heat_points": heat_points,
            "night_markers": night_markers,
            "day_markers": day_markers,
            "towers": tower_list,
            "has_geo": len(markers) > 0,
            "center": [
                float(geo_df["lat"].mean()),
                float(geo_df["lon"].mean()),
            ],
        }


def _marker_color(call_type: str, is_night: bool) -> str:
    if is_night:
        return "#f43f5e"  # rose/red for night-owl
    if "OUTGOING" in call_type:
        return "#38bdf8"  # cyan for outgoing
    elif "INCOMING" in call_type:
        return "#10b981"  # emerald for incoming
    elif "SMS" in call_type:
        return "#f59e0b"  # amber for SMS
    return "#38bdf8"



# ─────────────────────────────────────────────────────────────────────────────
# CROSS-MATCH ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CrossMatchEngine:
    """
    Analyzes multiple CDR datasets to find common contacts,
    co-location events, and shared communication patterns.
    """

    def __init__(self, datasets: list[dict[str, Any]]):
        """
        datasets: list of {"label": str, "df": pd.DataFrame, "target": str}
        """
        self.datasets = datasets

    def common_contacts(self) -> list[dict]:
        """Find contacts that appear in 2+ CDR datasets."""
        contact_sets: dict[str, set] = {}
        for ds in self.datasets:
            df = ds["df"]
            target = ds["target"]
            contacts: set[str] = set()
            for _, row in df.iterrows():
                for field in ("caller", "receiver"):
                    val = str(row.get(field, ""))
                    if val and val != "UNKNOWN" and val != target:
                        contacts.add(val)
            contact_sets[ds["label"]] = contacts

        labels = list(contact_sets.keys())
        all_contacts = set().union(*contact_sets.values())

        results = []
        for contact in all_contacts:
            present_in = [lbl for lbl, s in contact_sets.items() if contact in s]
            if len(present_in) >= 2:
                results.append({
                    "contact": contact,
                    "present_in": present_in,
                    "target_count": len(present_in),
                })

        results.sort(key=lambda x: x["target_count"], reverse=True)
        return results[:100]

    def colocation_events(self, window_minutes: int = 15) -> list[dict]:
        """
        Find instances where 2+ targets pinged the same cell tower
        within a ±window_minutes time window.
        """
        # Collect all tower pings per dataset
        all_pings: list[dict] = []
        for ds in self.datasets:
            df = ds["df"]
            for _, row in df.iterrows():
                cell = str(row.get("cell_id", "")).strip()
                ts = row.get("timestamp")
                if cell and pd.notna(ts):
                    all_pings.append({
                        "label": ds["label"],
                        "target": ds["target"],
                        "cell_id": cell,
                        "timestamp": ts,
                        "lat": row.get("lat", np.nan),
                        "lon": row.get("lon", np.nan),
                    })

        if not all_pings:
            return []

        ping_df = pd.DataFrame(all_pings).dropna(subset=["timestamp"])
        ping_df = ping_df.sort_values("timestamp")

        events = []
        # Group by cell_id
        for cell_id, group in ping_df.groupby("cell_id"):
            group = group.sort_values("timestamp")
            rows_list = group.to_dict("records")
            n = len(rows_list)
            for i in range(n):
                for j in range(i + 1, n):
                    a, b = rows_list[i], rows_list[j]
                    if a["label"] == b["label"]:
                        continue
                    diff_min = abs((b["timestamp"] - a["timestamp"]).total_seconds() / 60)
                    if diff_min <= window_minutes:
                        events.append({
                            "cell_id": cell_id,
                            "target_a": a["label"],
                            "target_b": b["label"],
                            "time_a": a["timestamp"].isoformat(),
                            "time_b": b["timestamp"].isoformat(),
                            "diff_minutes": round(diff_min, 1),
                            "lat": float(a["lat"]) if pd.notna(a["lat"]) else None,
                            "lon": float(a["lon"]) if pd.notna(a["lon"]) else None,
                        })

        events.sort(key=lambda x: x["diff_minutes"])
        return events[:200]

    def contact_matrix(self) -> dict:
        """Build a matrix showing call counts between each pair of targets."""
        labels = [ds["label"] for ds in self.datasets]
        # Collect all contacts per label
        label_contacts: dict[str, dict[str, int]] = {}
        for ds in self.datasets:
            df = ds["df"]
            target = ds["target"]
            contacts: dict[str, int] = defaultdict(int)
            for _, row in df.iterrows():
                for field in ("caller", "receiver"):
                    val = str(row.get(field, ""))
                    if val and val != "UNKNOWN" and val != target:
                        contacts[val] += 1
            label_contacts[ds["label"]] = dict(contacts)

        # Build matrix
        matrix = []
        for lbl_a in labels:
            row_data = []
            for lbl_b in labels:
                if lbl_a == lbl_b:
                    row_data.append(0)
                else:
                    # Common contacts
                    set_a = set(label_contacts.get(lbl_a, {}).keys())
                    set_b = set(label_contacts.get(lbl_b, {}).keys())
                    row_data.append(len(set_a & set_b))
            matrix.append({"label": lbl_a, "values": row_data})

        return {"labels": labels, "matrix": matrix}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _sec_to_hms(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def run_full_analysis(filepath: str, target_number: str = "") -> dict:
    """
    Convenience function: run all forensic analysis on a single CDR file.
    Returns a complete analysis dict ready for JSON serialization.
    """
    normalizer = CDRNormalizer(filepath)
    df = normalizer.df

    target = target_number.strip() if target_number else ""
    if not target or target == "UNKNOWN":
        valid_callers = df[~df["caller"].isin(["", "UNKNOWN", "nan", "None"])]["caller"]
        if not valid_callers.empty:
            target = valid_callers.mode()[0]
        else:
            valid_receivers = df[~df["receiver"].isin(["", "UNKNOWN", "nan", "None"])]["receiver"]
            if not valid_receivers.empty:
                target = valid_receivers.mode()[0]
            else:
                target = "TARGET"

    analyzer = ForensicAnalyzer(df, target)
    device_detector = DeviceSwapDetector(df, target)
    travel_detector = ImpossibleTravelDetector(df)
    graph_builder = NetworkGraphBuilder(df, target)
    geo_tracker = GeoTracker(df)

    records_list = []
    if not df.empty:
        for _, r in df.head(5000).iterrows():
            ts = r.get("timestamp")
            ts_str = ts.isoformat() if pd.notna(ts) and hasattr(ts, "isoformat") else (str(ts) if pd.notna(ts) else "")
            
            dur = r.get("duration")
            try:
                dur_int = int(float(dur)) if pd.notna(dur) and dur != "" else 0
            except (ValueError, TypeError):
                dur_int = 0

            lat_val = r.get("lat")
            try:
                lat_float = float(lat_val) if pd.notna(lat_val) and lat_val != "" else None
            except (ValueError, TypeError):
                lat_float = None

            lon_val = r.get("lon")
            try:
                lon_float = float(lon_val) if pd.notna(lon_val) and lon_val != "" else None
            except (ValueError, TypeError):
                lon_float = None

            records_list.append({
                "caller": str(r.get("caller", "")),
                "receiver": str(r.get("receiver", "")),
                "timestamp": ts_str,
                "duration": dur_int,
                "call_type": str(r.get("call_type", "")),
                "cell_id": str(r.get("cell_id", "")),
                "lat": lat_float,
                "lon": lon_float,
                "imei": str(r.get("imei", "")),
            })

    return {
        "metadata": normalizer.metadata,
        "target": target,
        "kpis": analyzer.kpis(),
        "hourly": analyzer.hourly_distribution(),
        "dow": analyzer.dow_distribution(),
        "call_types": analyzer.call_type_distribution(),
        "top_contacts": analyzer.top_contacts(),
        "bursts": analyzer.detect_bursts(),
        "dormant": analyzer.dormant_periods(),
        "device_swaps": device_detector.detect(),
        "impossible_travel": travel_detector.detect(),
        "graph": graph_builder.build(),
        "geo": geo_tracker.trajectory(),
        "records": records_list,
    }
