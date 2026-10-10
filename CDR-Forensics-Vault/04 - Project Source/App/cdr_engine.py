"""
T.R.I.A.D.ligence Engine
=================================
Core analytics, normalization, anomaly detection, and graph generation
for the T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard.
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

COLUMN_MAP = {
    "caller": [
        "a_party", "a party", "calling number", "caller", "a_num",
        "source", "from", "originating", "msisdn_a", "party_a",
        "calling_party", "a-number", "anumber", "number_a"
    ],
    "receiver": [
        "b_party", "b party", "called number", "receiver", "b_num",
        "destination", "to", "terminating", "msisdn_b", "party_b",
        "called_party", "b-number", "bnumber", "number_b"
    ],
    "timestamp": [
        "timestamp", "date", "call date", "start_time", "time",
        "datetime", "call_datetime", "call_time", "start time",
        "date_time", "starttime", "event_time", "record_date"
    ],
    "duration": [
        "duration", "duration_sec", "call duration", "call_duration",
        "talk_time", "seconds", "duration_seconds", "call_length",
        "length", "billable_seconds", "dur"
    ],
    "call_type": [
        "call_type", "type", "service type", "service_type",
        "call_direction", "direction", "event_type", "record_type",
        "call type", "traffic_type"
    ],
    "cell_id": [
        "cell_id", "cell id", "first cell id", "last cell id",
        "cellid", "tower_id", "tower id", "bts_id", "site_id",
        "cell_tower", "cell", "serving_cell"
    ],
    "lat": [
        "lat", "latitude", "cell_lat", "tower_lat", "site_lat",
        "y_coord", "geo_lat", "latitude_deg"
    ],
    "lon": [
        "lon", "longitude", "lng", "cell_lon", "tower_lon", "site_lon",
        "x_coord", "geo_lon", "longitude_deg"
    ],
    "imei": [
        "imei", "handset id", "handset_id", "device_id",
        "equipment_id", "tac", "imei_number"
    ],
    "imsi": [
        "imsi", "sim_id", "subscriber_id", "imsi_number"
    ],
}


def _normalize_col(name: str) -> str:
    """Lower + strip special chars for fuzzy matching."""
    return re.sub(r"[^a-z0-9 ]", " ", name.strip().lower()).strip()


def map_columns(df: pd.DataFrame) -> dict[str, str | None]:
    """
    Return a canonical→actual column name mapping for any CDR DataFrame.
    Uses fuzzy prefix/substring matching as fallback.
    """
    cols_norm = {_normalize_col(c): c for c in df.columns}
    mapping: dict[str, str | None] = {}

    for canonical, variants in COLUMN_MAP.items():
        found = None
        for variant in variants:
            v_norm = _normalize_col(variant)
            # Exact match
            if v_norm in cols_norm:
                found = cols_norm[v_norm]
                break
        if not found:
            # Substring match
            for norm_col, orig_col in cols_norm.items():
                for variant in variants:
                    if _normalize_col(variant) in norm_col:
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
            normalized[field] = df[col].str.strip() if col else pd.Series(["UNKNOWN"] * len(df))

        # ── Timestamp ─────────────────────────────────────────────────────
        ts_col = cm.get("timestamp")
        if ts_col:
            normalized["timestamp"] = pd.to_datetime(df[ts_col], errors="coerce")
        else:
            normalized["timestamp"] = pd.NaT

        # ── Duration ──────────────────────────────────────────────────────
        dur_col = cm.get("duration")
        if dur_col:
            normalized["duration"] = pd.to_numeric(df[dur_col], errors="coerce").fillna(0)
        else:
            normalized["duration"] = 0

        # ── Call Type ─────────────────────────────────────────────────────
        ct_col = cm.get("call_type")
        if ct_col:
            normalized["call_type"] = df[ct_col].str.strip().str.upper()
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
            return val

        normalized["call_type"] = normalized["call_type"].apply(_map_call_type)

        # ── Cell ID ───────────────────────────────────────────────────────
        cell_col = cm.get("cell_id")
        normalized["cell_id"] = df[cell_col].str.strip() if cell_col else ""

        # ── Coordinates ───────────────────────────────────────────────────
        lat_col = cm.get("lat")
        lon_col = cm.get("lon")
        normalized["lat"] = pd.to_numeric(df[lat_col], errors="coerce") if lat_col else np.nan
        normalized["lon"] = pd.to_numeric(df[lon_col], errors="coerce") if lon_col else np.nan

        # ── Device IDs ────────────────────────────────────────────────────
        imei_col = cm.get("imei")
        imsi_col = cm.get("imsi")
        normalized["imei"] = df[imei_col].str.strip() if imei_col else ""
        normalized["imsi"] = df[imsi_col].str.strip() if imsi_col else ""

        # ── Drop rows with no caller AND no receiver ──────────────────────
        normalized = normalized[
            ~((normalized["caller"] == "UNKNOWN") & (normalized["receiver"] == "UNKNOWN"))
        ].reset_index(drop=True)

        # Sort chronologically
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
        # Identify the target as the most frequent caller if not provided
        if not self.target:
            all_callers = df["caller"].value_counts()
            self.target = all_callers.index[0] if len(all_callers) else "UNKNOWN"

    # ── KPIs ──────────────────────────────────────────────────────────────

    def kpis(self) -> dict:
        df = self.df
        total = len(df)

        # Contacts: all numbers the target communicated with
        target_calls = df[(df["caller"] == self.target) | (df["receiver"] == self.target)]
        contacts = set(target_calls["caller"]) | set(target_calls["receiver"])
        contacts.discard(self.target)

        total_duration = int(df["duration"].sum())
        incoming = int((df["call_type"] == "INCOMING").sum())
        outgoing = int((df["call_type"] == "OUTGOING").sum())
        sms_count = int((df["call_type"] == "SMS").sum())

        # Night calls: 00:00–05:00
        night_mask = df["timestamp"].dt.hour.between(0, 4)
        night_calls = int(night_mask.sum())

        imei_count = int(df["imei"].replace("", np.nan).dropna().nunique())
        imsi_count = int(df["imsi"].replace("", np.nan).dropna().nunique())

        # Date range
        valid_ts = df["timestamp"].dropna()
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
        df = self.df.copy()
        df["hour"] = df["timestamp"].dt.hour
        grouped = df.groupby("hour").agg(
            count=("caller", "size"),
            duration=("duration", "sum")
        ).reindex(range(24), fill_value=0).reset_index()
        return grouped.rename(columns={"hour": "hour"}).to_dict("records")

    def dow_distribution(self) -> list[dict]:
        """Returns list of {day, count, duration} for Mon–Sun."""
        DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        df = self.df.copy()
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
            # Skip to avoid overlapping windows from same burst
            if count >= threshold:
                pass  # report all overlapping windows

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
        target = self.target
        # Calls involving the target
        mask = (df["caller"] == target) | (df["receiver"] == target)
        target_calls = df[mask].copy()
        target_calls["contact"] = target_calls.apply(
            lambda r: r["receiver"] if r["caller"] == target else r["caller"], axis=1
        )
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
    using the Haversine formula. Flags records where v > MAX_SPEED_KMH.
    """

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def detect(self) -> list[dict]:
        df = self.df.dropna(subset=["lat", "lon", "timestamp"]).sort_values("timestamp").copy()
        df = df[(df["lat"].between(-90, 90)) & (df["lon"].between(-180, 180))]

        if len(df) < 2:
            return []

        anomalies = []
        rows = df.reset_index(drop=True)

        for i in range(1, len(rows)):
            prev = rows.iloc[i - 1]
            curr = rows.iloc[i]

            time_diff_h = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 3600
            if time_diff_h <= 0:
                continue

            dist_km = haversine_km(
                float(prev["lat"]), float(prev["lon"]),
                float(curr["lat"]), float(curr["lon"])
            )
            speed_kmh = dist_km / time_diff_h

            if speed_kmh > MAX_SPEED_KMH:
                anomalies.append({
                    "from_ts": prev["timestamp"].isoformat(),
                    "to_ts": curr["timestamp"].isoformat(),
                    "from_cell": str(prev.get("cell_id", "")),
                    "to_cell": str(curr.get("cell_id", "")),
                    "from_lat": float(prev["lat"]),
                    "from_lon": float(prev["lon"]),
                    "to_lat": float(curr["lat"]),
                    "to_lon": float(curr["lon"]),
                    "distance_km": round(dist_km, 2),
                    "speed_kmh": round(speed_kmh, 1),
                    "time_diff_min": round(time_diff_h * 60, 1),
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
        G = nx.DiGraph()

        # Aggregate edges
        edge_data: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "duration": 0})
        for _, row in self.df.iterrows():
            caller = str(row["caller"])
            receiver = str(row["receiver"])
            if caller in ("", "UNKNOWN") or receiver in ("", "UNKNOWN"):
                continue
            key = (caller, receiver)
            edge_data[key]["count"] += 1
            edge_data[key]["duration"] += float(row["duration"])

        # Limit to top nodes by degree
        all_numbers: dict[str, int] = defaultdict(int)
        for (caller, receiver), data in edge_data.items():
            all_numbers[caller] += data["count"]
            all_numbers[receiver] += data["count"]

        top_numbers = set(
            sorted(all_numbers, key=lambda x: all_numbers[x], reverse=True)[: self.max_nodes]
        )
        # Always include target
        if self.target:
            top_numbers.add(self.target)

        # Build graph
        for (caller, receiver), data in edge_data.items():
            if caller in top_numbers and receiver in top_numbers:
                G.add_edge(caller, receiver, count=data["count"], duration=data["duration"])

        # Centrality
        try:
            centrality = nx.degree_centrality(G)
        except Exception:
            centrality = {n: 0 for n in G.nodes()}

        # Serialize nodes
        nodes = []
        for node in G.nodes():
            degree = G.degree(node)
            is_target = node == self.target
            size = max(15, min(60, 10 + degree * 3))
            nodes.append({
                "id": node,
                "label": node,
                "value": degree,
                "size": size,
                "color": {
                    "background": "#38bdf8" if is_target else _degree_color(degree),
                    "border": "#f43f5e" if is_target else "#334155",
                    "highlight": {"background": "#f59e0b", "border": "#f59e0b"},
                },
                "font": {"color": "#f1f5f9", "size": 11},
                "title": f"📞 {node}<br>Calls: {degree}<br>Centrality: {centrality.get(node, 0):.3f}",
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
# GEO TRACKER
# ─────────────────────────────────────────────────────────────────────────────

class GeoTracker:
    """
    Builds geo-spatial trajectory data for Leaflet.js visualization.
    Groups towers, computes dwell times, and prepares heatmap data.
    """

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def trajectory(self) -> dict:
        geo_df = self.df.dropna(subset=["lat", "lon"]).copy()
        geo_df = geo_df[
            geo_df["lat"].between(-90, 90) & geo_df["lon"].between(-180, 180)
        ].sort_values("timestamp")

        markers = []
        for _, row in geo_df.iterrows():
            hour = row["timestamp"].hour if pd.notna(row["timestamp"]) else 12
            is_night = hour < 5 or hour >= 22
            call_type = str(row.get("call_type", ""))

            markers.append({
                "lat": float(row["lat"]),
                "lon": float(row["lon"]),
                "cell_id": str(row.get("cell_id", "")),
                "timestamp": row["timestamp"].isoformat() if pd.notna(row["timestamp"]) else "",
                "caller": str(row.get("caller", "")),
                "receiver": str(row.get("receiver", "")),
                "call_type": call_type,
                "duration": float(row.get("duration", 0)),
                "is_night": is_night,
                "color": _marker_color(call_type, is_night),
            })

        # Polyline path
        path = [[m["lat"], m["lon"]] for m in markers]

        # Heatmap data [lat, lon, intensity]
        tower_counts: dict[tuple, int] = defaultdict(int)
        for m in markers:
            key = (round(m["lat"], 4), round(m["lon"], 4))
            tower_counts[key] += 1
        heatmap = [[lat, lon, min(count / 10, 1.0)] for (lat, lon), count in tower_counts.items()]

        # Tower clusters
        tower_dwell: dict[str, dict] = {}
        for _, row in geo_df.iterrows():
            cid = str(row.get("cell_id", "")) or f"{round(float(row['lat']), 3)},{round(float(row['lon']), 3)}"
            if cid not in tower_dwell:
                tower_dwell[cid] = {
                    "cell_id": cid,
                    "lat": float(row["lat"]),
                    "lon": float(row["lon"]),
                    "count": 0,
                    "duration": 0,
                }
            tower_dwell[cid]["count"] += 1
            tower_dwell[cid]["duration"] += float(row.get("duration", 0))

        return {
            "markers": markers,
            "path": path,
            "heatmap": heatmap,
            "towers": list(tower_dwell.values()),
            "has_geo": len(markers) > 0,
            "center": [
                float(geo_df["lat"].mean()) if not geo_df.empty else 20.5937,
                float(geo_df["lon"].mean()) if not geo_df.empty else 78.9629,
            ],
        }


def _marker_color(call_type: str, is_night: bool) -> str:
    if is_night:
        return "#818cf8"  # purple for night
    if "OUTGOING" in call_type:
        return "#38bdf8"  # cyan for outgoing
    elif "INCOMING" in call_type:
        return "#10b981"  # emerald for incoming
    elif "SMS" in call_type:
        return "#f59e0b"  # amber for SMS
    return "#64748b"


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

    target = target_number or (df["caller"].mode()[0] if not df.empty else "")

    analyzer = ForensicAnalyzer(df, target)
    device_detector = DeviceSwapDetector(df, target)
    travel_detector = ImpossibleTravelDetector(df)
    graph_builder = NetworkGraphBuilder(df, target)
    geo_tracker = GeoTracker(df)

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
        "records": df.fillna("").apply(
            lambda r: {
                "caller": r["caller"],
                "receiver": r["receiver"],
                "timestamp": r["timestamp"].isoformat() if pd.notna(r["timestamp"]) else "",
                "duration": int(r["duration"]),
                "call_type": r["call_type"],
                "cell_id": r["cell_id"],
                "imei": r["imei"],
            },
            axis=1,
        ).tolist()[:5000],  # cap records for browser performance
    }
