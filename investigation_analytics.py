"""
T.R.I.A.D. — Advanced Investigation Analytics Engine
=====================================================

PHASE 6 — ENHANCED DATA ANALYSIS

This module builds a deterministic investigation profile from the
existing CDR analysis session.

It does NOT modify:
- Original CDR evidence
- DEMS evidence
- Existing CDR analysis
- Phase 4 replay
- Phase 5 visualization

It combines existing forensic results with additional investigator-
oriented communication, temporal, geographic and network analytics.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from math import asin, cos, radians, sin, sqrt
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd


INVALID_VALUES = {
    "",
    "UNKNOWN",
    "TARGET",
    "nan",
    "None",
    "N/A",
    "NA",
}


# ================================================================
# BASIC HELPERS
# ================================================================

def clean(value: Any) -> str:
    """Convert a value to a safe normalized string."""
    if value is None:
        return ""

    text = str(value).strip()

    if text in {"nan", "NaT"}:
        return ""

    return text


def valid_entity(value: Any) -> bool:
    """Return True when a value represents a usable entity."""
    return clean(value).upper() not in INVALID_VALUES


def safe_number(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    try:
        number = float(value)

        if np.isfinite(number):
            return number

    except (TypeError, ValueError):
        pass

    return default


def iso_value(value: Any) -> str:
    """Convert timestamps to JSON-safe ISO strings."""
    if value is None:
        return ""

    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass

    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime().isoformat()

    return str(value)


def seconds_to_hms(seconds: Any) -> str:
    """Convert seconds to HH:MM:SS."""
    seconds = max(0, int(safe_number(seconds)))

    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def haversine_km(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    """Calculate great-circle distance in kilometres."""

    earth_radius = 6371.0088

    p1 = radians(lat1)
    p2 = radians(lat2)

    delta_lat = radians(lat2 - lat1)
    delta_lon = radians(lon2 - lon1)

    value = (
        sin(delta_lat / 2) ** 2
        + cos(p1)
        * cos(p2)
        * sin(delta_lon / 2) ** 2
    )

    value = min(1.0, max(0.0, value))

    return (
        2
        * earth_radius
        * asin(sqrt(value))
    )


# ================================================================
# PHASE 6 ANALYTICS ENGINE
# ================================================================

class InvestigationAnalytics:
    """
    Deterministic investigation analytics engine.

    Input:
        Existing normalized CDR records.

    Output:
        Investigator-oriented analytics covering:

        - Communication
        - Temporal activity
        - Geography
        - Network structure
        - Investigation leads
    """

    def __init__(
        self,
        records: list[dict] | pd.DataFrame,
        target: str = "",
        existing_analysis: dict | None = None,
    ):

        if isinstance(records, pd.DataFrame):
            self.df = records.copy()

        else:
            self.df = pd.DataFrame(
                records or []
            ).copy()

        self._normalize_dataframe()

        requested_target = clean(target)

        if (
            requested_target
            and valid_entity(requested_target)
        ):
            self.target = requested_target

        else:
            self.target = self._detect_target()

        self.existing_analysis = (
            existing_analysis or {}
        )

    # ============================================================
    # NORMALIZATION
    # ============================================================

    def _normalize_dataframe(self) -> None:
        """Normalize the cached CDR records."""

        defaults = {
            "caller": "",
            "receiver": "",
            "timestamp": pd.NaT,
            "duration": 0,
            "call_type": "",
            "cell_id": "",
            "lat": np.nan,
            "lon": np.nan,
            "imei": "",
            "imsi": "",
        }

        for column, default in defaults.items():

            if column not in self.df.columns:
                self.df[column] = default

        self.df["caller"] = (
            self.df["caller"]
            .map(clean)
        )

        self.df["receiver"] = (
            self.df["receiver"]
            .map(clean)
        )

        self.df["call_type"] = (
            self.df["call_type"]
            .map(
                lambda value:
                clean(value).upper()
            )
        )

        self.df["cell_id"] = (
            self.df["cell_id"]
            .map(clean)
        )

        self.df["imei"] = (
            self.df["imei"]
            .map(clean)
        )

        self.df["imsi"] = (
            self.df["imsi"]
            .map(clean)
        )

        self.df["timestamp"] = pd.to_datetime(
            self.df["timestamp"],
            errors="coerce",
        )

        self.df["duration"] = pd.to_numeric(
            self.df["duration"],
            errors="coerce",
        ).fillna(0)

        self.df["lat"] = pd.to_numeric(
            self.df["lat"],
            errors="coerce",
        )

        self.df["lon"] = pd.to_numeric(
            self.df["lon"],
            errors="coerce",
        )

        self.df = (
            self.df
            .sort_values(
                "timestamp",
                na_position="last",
            )
            .reset_index(drop=True)
        )

    # ============================================================
    # TARGET DETECTION
    # ============================================================

    def _detect_target(self) -> str:

        if self.df.empty:
            return "TARGET"

        valid_callers = self.df[
            self.df["caller"]
            .map(valid_entity)
        ]["caller"]

        if not valid_callers.empty:
            return str(
                valid_callers.mode().iloc[0]
            )

        valid_receivers = self.df[
            self.df["receiver"]
            .map(valid_entity)
        ]["receiver"]

        if not valid_receivers.empty:
            return str(
                valid_receivers.mode().iloc[0]
            )

        return "TARGET"

    def _target_records(self) -> pd.DataFrame:

        if (
            self.target
            and valid_entity(self.target)
        ):

            target_rows = self.df[
                (
                    self.df["caller"]
                    == self.target
                )
                |
                (
                    self.df["receiver"]
                    == self.target
                )
            ]

            if not target_rows.empty:
                return target_rows.copy()

        return self.df.copy()

    # ============================================================
    # COMMUNICATION ANALYSIS
    # ============================================================

    def communication_analysis(self) -> dict:

        df = self._target_records()

        if df.empty:

            return {
                "incoming": 0,
                "outgoing": 0,
                "sms": 0,
                "unknown_direction": 0,
                "active_numbers": [],
                "target_contacts": [],
            }

        incoming = int(
            df["call_type"]
            .str.contains(
                "INCOMING",
                na=False,
            )
            .sum()
        )

        outgoing = int(
            df["call_type"]
            .str.contains(
                "OUTGOING",
                na=False,
            )
            .sum()
        )

        sms = int(
            df["call_type"]
            .str.contains(
                "SMS",
                na=False,
            )
            .sum()
        )

        known_direction = (
            incoming
            + outgoing
            + sms
        )

        unknown_direction = max(
            0,
            len(df) - known_direction,
        )

        # --------------------------------------------------------
        # MOST ACTIVE NUMBERS
        # --------------------------------------------------------

        active_counter = Counter()

        for row in self.df.itertuples(
            index=False
        ):

            caller = clean(row.caller)
            receiver = clean(row.receiver)

            if valid_entity(caller):
                active_counter[caller] += 1

            if valid_entity(receiver):
                active_counter[receiver] += 1

        active_numbers = []

        for number, count in (
            active_counter
            .most_common(20)
        ):

            active_numbers.append(
                {
                    "number": number,
                    "interaction_count": count,
                }
            )

        # --------------------------------------------------------
        # TARGET CONTACTS
        # --------------------------------------------------------

        contacts = defaultdict(
            lambda: {
                "interaction_count": 0,
                "total_duration_sec": 0,
                "incoming": 0,
                "outgoing": 0,
                "sms": 0,
                "last_seen": "",
            }
        )

        for row in df.itertuples(
            index=False
        ):

            caller = clean(row.caller)
            receiver = clean(row.receiver)

            if caller == self.target:
                contact = receiver

            elif receiver == self.target:
                contact = caller

            else:
                contact = (
                    receiver
                    if valid_entity(receiver)
                    else caller
                )

            if (
                not valid_entity(contact)
                or contact == self.target
            ):
                continue

            stat = contacts[contact]

            stat["interaction_count"] += 1

            stat["total_duration_sec"] += int(
                safe_number(row.duration)
            )

            call_type = clean(
                row.call_type
            )

            if "INCOMING" in call_type:
                stat["incoming"] += 1

            elif "OUTGOING" in call_type:
                stat["outgoing"] += 1

            elif "SMS" in call_type:
                stat["sms"] += 1

            if pd.notna(row.timestamp):
                stat["last_seen"] = iso_value(
                    row.timestamp
                )

        target_contacts = []

        for contact, stat in contacts.items():

            interaction_count = (
                stat["interaction_count"]
            )

            duration_minutes = (
                stat["total_duration_sec"]
                / 60
            )

            relationship_strength = (
                min(
                    50,
                    interaction_count * 2,
                )
                + min(
                    30,
                    duration_minutes,
                )
                + min(
                    20,
                    (
                        stat["incoming"]
                        + stat["outgoing"]
                    ) * 1.5,
                )
            )

            target_contacts.append(
                {
                    "contact": contact,
                    **stat,
                    "relationship_strength": round(
                        min(
                            100,
                            relationship_strength,
                        ),
                        2,
                    ),
                    "duration_hms":
                        seconds_to_hms(
                            stat[
                                "total_duration_sec"
                            ]
                        ),
                }
            )

        target_contacts.sort(
            key=lambda item: (
                item["interaction_count"],
                item["total_duration_sec"],
            ),
            reverse=True,
        )

        return {
            "incoming": incoming,
            "outgoing": outgoing,
            "sms": sms,
            "unknown_direction":
                unknown_direction,
            "active_numbers":
                active_numbers,
            "target_contacts":
                target_contacts[:20],
        }

    # ============================================================
    # TEMPORAL ANALYSIS
    # ============================================================

    def temporal_analysis(self) -> dict:

        df = self.df.dropna(
            subset=["timestamp"]
        ).copy()

        hourly = [
            {
                "hour": hour,
                "count": 0,
                "duration": 0,
            }
            for hour in range(24)
        ]

        if df.empty:

            return {
                "hourly": hourly,
                "daily": [],
                "peak_hours": [],
                "repeated_hours": [],
            }

        df["hour"] = (
            df["timestamp"]
            .dt.hour
        )

        df["date"] = (
            df["timestamp"]
            .dt.date
        )

        hourly_group = (
            df.groupby("hour")
            .agg(
                count=("caller", "size"),
                duration=("duration", "sum"),
            )
        )

        for hour in range(24):

            if hour in hourly_group.index:

                hourly[hour] = {
                    "hour": hour,
                    "count": int(
                        hourly_group
                        .loc[hour, "count"]
                    ),
                    "duration": int(
                        hourly_group
                        .loc[hour, "duration"]
                    ),
                }

        daily_group = (
            df.groupby("date")
            .agg(
                count=("caller", "size"),
                duration=("duration", "sum"),
            )
            .sort_values(
                "count",
                ascending=False,
            )
        )

        daily = []

        for date, row in (
            daily_group
            .head(31)
            .iterrows()
        ):

            daily.append(
                {
                    "date": str(date),
                    "count": int(
                        row["count"]
                    ),
                    "duration": int(
                        row["duration"]
                    ),
                }
            )

        ranked_hours = sorted(
            hourly,
            key=lambda item: (
                item["count"],
                item["duration"],
            ),
            reverse=True,
        )

        return {
            "hourly": hourly,
            "daily": daily,
            "peak_hours":
                ranked_hours[:5],
            "repeated_hours":
                [
                    item
                    for item in hourly
                    if item["count"] >= 2
                ],
        }

    # ============================================================
    # GEOGRAPHIC ANALYSIS
    # ============================================================

    def geographic_analysis(self) -> dict:

        geo = self.df.dropna(
            subset=[
                "lat",
                "lon",
                "timestamp",
            ]
        ).copy()

        geo = geo[
            geo["lat"].between(-90, 90)
            &
            geo["lon"].between(
                -180,
                180,
            )
        ]

        geo = geo.sort_values(
            "timestamp"
        )

        if geo.empty:

            return {
                "top_locations": [],
                "movement": [],
                "first_location": None,
                "last_location": None,
                "total_distance_km": 0,
                "max_leg_speed_kmh": 0,
                "location_clusters": [],
            }

        # --------------------------------------------------------
        # FREQUENT LOCATIONS
        # --------------------------------------------------------

        locations = defaultdict(
            lambda: {
                "event_count": 0,
                "total_duration_sec": 0,
                "entities": set(),
                "lat_sum": 0.0,
                "lon_sum": 0.0,
            }
        )

        for row in geo.itertuples(
            index=False
        ):

            cell = clean(row.cell_id)

            if valid_entity(cell):
                key = cell
            else:
                key = (
                    f"{safe_number(row.lat):.4f},"
                    f"{safe_number(row.lon):.4f}"
                )

            item = locations[key]

            item["event_count"] += 1

            item["total_duration_sec"] += int(
                safe_number(row.duration)
            )

            item["lat_sum"] += safe_number(
                row.lat
            )

            item["lon_sum"] += safe_number(
                row.lon
            )

            for entity in (
                row.caller,
                row.receiver,
            ):

                if valid_entity(entity):
                    item["entities"].add(
                        clean(entity)
                    )

        top_locations = []

        for key, item in locations.items():

            count = item["event_count"]

            top_locations.append(
                {
                    "location": key,
                    "event_count": count,
                    "total_duration_sec":
                        item[
                            "total_duration_sec"
                        ],
                    "unique_entities":
                        len(
                            item["entities"]
                        ),
                    "latitude": round(
                        item["lat_sum"]
                        / max(count, 1),
                        6,
                    ),
                    "longitude": round(
                        item["lon_sum"]
                        / max(count, 1),
                        6,
                    ),
                }
            )

        top_locations.sort(
            key=lambda item: (
                item["event_count"],
                item["total_duration_sec"],
            ),
            reverse=True,
        )

        # --------------------------------------------------------
        # MOVEMENT ANALYSIS
        # --------------------------------------------------------

        rows = list(
            geo.itertuples(
                index=False
            )
        )

        movement = []

        total_distance = 0.0
        max_speed = 0.0

        for index, row in enumerate(rows):

            distance = 0.0
            speed = 0.0
            elapsed_minutes = 0.0

            if index > 0:

                previous = rows[index - 1]

                distance = haversine_km(
                    safe_number(
                        previous.lat
                    ),
                    safe_number(
                        previous.lon
                    ),
                    safe_number(
                        row.lat
                    ),
                    safe_number(
                        row.lon
                    ),
                )

                elapsed_seconds = (
                    row.timestamp
                    - previous.timestamp
                ).total_seconds()

                elapsed_minutes = max(
                    0.0,
                    elapsed_seconds / 60,
                )

                if elapsed_seconds > 0:

                    speed = (
                        distance
                        /
                        (
                            elapsed_seconds
                            / 3600
                        )
                    )

            total_distance += distance

            max_speed = max(
                max_speed,
                speed,
            )

            movement.append(
                {
                    "timestamp":
                        iso_value(
                            row.timestamp
                        ),
                    "latitude": round(
                        safe_number(
                            row.lat
                        ),
                        6,
                    ),
                    "longitude": round(
                        safe_number(
                            row.lon
                        ),
                        6,
                    ),
                    "cell":
                        clean(row.cell_id),
                    "distance_from_previous_km":
                        round(
                            distance,
                            3,
                        ),
                    "speed_kmh":
                        round(
                            speed,
                            2,
                        ),
                    "elapsed_minutes":
                        round(
                            elapsed_minutes,
                            2,
                        ),
                    "caller":
                        clean(row.caller),
                    "receiver":
                        clean(row.receiver),
                }
            )

        # --------------------------------------------------------
        # SIMPLE LOCATION CLUSTERS
        # --------------------------------------------------------

        clusters = defaultdict(list)

        for item in movement:

            key = (
                round(
                    item["latitude"],
                    2,
                ),
                round(
                    item["longitude"],
                    2,
                ),
            )

            clusters[key].append(
                item
            )

        location_clusters = []

        for (
            latitude,
            longitude,
        ), items in clusters.items():

            location_clusters.append(
                {
                    "cluster":
                        f"{latitude:.2f}, "
                        f"{longitude:.2f}",
                    "event_count":
                        len(items),
                    "latitude":
                        latitude,
                    "longitude":
                        longitude,
                    "first_seen":
                        items[0]["timestamp"],
                    "last_seen":
                        items[-1]["timestamp"],
                }
            )

        location_clusters.sort(
            key=lambda item:
                item["event_count"],
            reverse=True,
        )

        return {
            "top_locations":
                top_locations[:20],
            "movement":
                movement[:1000],
            "first_location":
                movement[0],
            "last_location":
                movement[-1],
            "total_distance_km":
                round(
                    total_distance,
                    3,
                ),
            "max_leg_speed_kmh":
                round(
                    max_speed,
                    2,
                ),
            "location_clusters":
                location_clusters[:20],
        }

    # ============================================================
    # NETWORK ANALYSIS
    # ============================================================

    def network_analysis(self) -> dict:

        graph = nx.Graph()

        edge_stats = defaultdict(
            lambda: {
                "count": 0,
                "duration": 0,
                "sms": 0,
            }
        )

        for row in self.df.itertuples(
            index=False
        ):

            caller = clean(row.caller)
            receiver = clean(row.receiver)

            if (
                not valid_entity(caller)
                or not valid_entity(receiver)
                or caller == receiver
            ):
                continue

            left, right = sorted(
                [caller, receiver]
            )

            key = (
                left,
                right,
            )

            edge_stats[key]["count"] += 1

            edge_stats[key]["duration"] += int(
                safe_number(row.duration)
            )

            if "SMS" in clean(
                row.call_type
            ):

                edge_stats[key]["sms"] += 1

        for (
            left,
            right,
        ), stats in edge_stats.items():

            graph.add_edge(
                left,
                right,
                **stats,
            )

        if graph.number_of_nodes() == 0:

            return {
                "nodes": [],
                "edges": [],
                "central_nodes": [],
                "clusters": [],
                "total_nodes": 0,
                "total_edges": 0,
            }

        # --------------------------------------------------------
        # LIMIT TO MOST ACTIVE ENTITIES
        # --------------------------------------------------------

        weighted_degree = dict(
            graph.degree(
                weight="count"
            )
        )

        ranked_nodes = [
            node
            for node, _ in sorted(
                weighted_degree.items(),
                key=lambda item:
                    item[1],
                reverse=True,
            )[:150]
        ]

        if self.target in graph:
            ranked_nodes.append(
                self.target
            )

        ranked_nodes = list(
            dict.fromkeys(
                ranked_nodes
            )
        )

        subgraph = graph.subgraph(
            ranked_nodes
        ).copy()

        # --------------------------------------------------------
        # CENTRALITY
        # --------------------------------------------------------

        degree = dict(
            subgraph.degree()
        )

        weighted = dict(
            subgraph.degree(
                weight="count"
            )
        )

        try:

            betweenness = (
                nx.betweenness_centrality(
                    subgraph,
                    normalized=True,
                )
            )

        except Exception:

            betweenness = {
                node: 0.0
                for node in subgraph.nodes()
            }

        nodes = []

        for node in subgraph.nodes():

            nodes.append(
                {
                    "number": node,
                    "degree": int(
                        degree.get(
                            node,
                            0,
                        )
                    ),
                    "interaction_strength":
                        round(
                            safe_number(
                                weighted.get(
                                    node,
                                    0,
                                )
                            ),
                            2,
                        ),
                    "betweenness":
                        round(
                            safe_number(
                                betweenness.get(
                                    node,
                                    0,
                                )
                            ),
                            4,
                        ),
                    "is_target":
                        node == self.target,
                }
            )

        nodes.sort(
            key=lambda item: (
                item[
                    "interaction_strength"
                ],
                item["betweenness"],
            ),
            reverse=True,
        )

        # --------------------------------------------------------
        # RELATIONSHIPS
        # --------------------------------------------------------

        edges = []

        for (
            left,
            right,
        ), stats in edge_stats.items():

            if (
                left not in subgraph
                or right not in subgraph
            ):
                continue

            relationship_strength = (
                min(
                    60,
                    stats["count"] * 4,
                )
                +
                min(
                    40,
                    stats["duration"] / 60,
                )
            )

            edges.append(
                {
                    "source": left,
                    "target": right,
                    "interaction_count":
                        stats["count"],
                    "duration_sec":
                        stats["duration"],
                    "sms_count":
                        stats["sms"],
                    "relationship_strength":
                        round(
                            min(
                                100,
                                relationship_strength,
                            ),
                            2,
                        ),
                }
            )

        edges.sort(
            key=lambda item:
                item[
                    "relationship_strength"
                ],
            reverse=True,
        )

        # --------------------------------------------------------
        # COMMUNICATION CLUSTERS
        # --------------------------------------------------------

        clusters = []

        try:

            communities = (
                nx.community
                .greedy_modularity_communities(
                    subgraph
                )
            )

            for index, community in enumerate(
                communities[:10],
                start=1,
            ):

                members = sorted(
                    community
                )

                clusters.append(
                    {
                        "cluster_id":
                            index,
                        "size":
                            len(members),
                        "members":
                            members[:15],
                    }
                )

        except Exception:
            clusters = []

        return {
            "nodes": nodes[:150],
            "edges": edges[:300],
            "central_nodes":
                nodes[:15],
            "clusters":
                clusters,
            "total_nodes":
                subgraph.number_of_nodes(),
            "total_edges":
                subgraph.number_of_edges(),
        }

    # ============================================================
    # INVESTIGATION LEADS
    # ============================================================

    def investigation_leads(
        self,
        communication: dict,
        temporal: dict,
        geographic: dict,
        network: dict,
    ) -> list[dict]:

        leads = []

        travel = self.existing_analysis.get(
            "impossible_travel",
            [],
        )

        swaps = self.existing_analysis.get(
            "device_swaps",
            {},
        )

        bursts = self.existing_analysis.get(
            "bursts",
            [],
        )

        dormant = self.existing_analysis.get(
            "dormant",
            [],
        )

        # --------------------------------------------------------
        # IMPOSSIBLE TRAVEL
        # --------------------------------------------------------

        if travel:

            leads.append(
                {
                    "severity": "HIGH",
                    "type": "GEOGRAPHIC",
                    "title":
                        "Impossible-travel events detected",
                    "detail":
                        f"{len(travel)} movement event(s) "
                        "exceed the configured travel-speed "
                        "threshold.",
                    "basis":
                        "Existing deterministic CDR "
                        "geographic analysis.",
                }
            )

        # --------------------------------------------------------
        # IMEI
        # --------------------------------------------------------

        if swaps.get(
            "handset_hopping"
        ):

            leads.append(
                {
                    "severity": "HIGH",
                    "type": "DEVICE",
                    "title":
                        "Multiple IMEI identities observed",
                    "detail":
                        f"{swaps.get('imei_count', 0)} "
                        "distinct IMEI values were observed.",
                    "basis":
                        "IMEI timeline analysis.",
                }
            )

        # --------------------------------------------------------
        # IMSI
        # --------------------------------------------------------

        if swaps.get(
            "sim_swapping"
        ):

            leads.append(
                {
                    "severity": "HIGH",
                    "type": "SUBSCRIBER",
                    "title":
                        "Multiple IMSI identities observed",
                    "detail":
                        f"{swaps.get('imsi_count', 0)} "
                        "distinct IMSI values were observed.",
                    "basis":
                        "IMSI timeline analysis.",
                }
            )

        # --------------------------------------------------------
        # BURSTS
        # --------------------------------------------------------

        if bursts:

            leads.append(
                {
                    "severity": "MEDIUM",
                    "type": "TEMPORAL",
                    "title":
                        "Communication bursts detected",
                    "detail":
                        f"{len(bursts)} high-density "
                        "communication window(s) were detected.",
                    "basis":
                        "Existing burst detector.",
                }
            )

        # --------------------------------------------------------
        # DORMANT PERIODS
        # --------------------------------------------------------

        if dormant:

            leads.append(
                {
                    "severity": "INFO",
                    "type": "TEMPORAL",
                    "title":
                        "Extended communication gaps detected",
                    "detail":
                        f"{len(dormant)} dormant period(s) "
                        "meet the configured silence threshold.",
                    "basis":
                        "Existing dormant-period detector.",
                }
            )

        # --------------------------------------------------------
        # OVERNIGHT ACTIVITY
        # --------------------------------------------------------

        timestamped = self.df.dropna(
            subset=["timestamp"]
        )

        if not timestamped.empty:

            night_count = int(
                timestamped[
                    "timestamp"
                ]
                .dt.hour
                .between(0, 4)
                .sum()
            )

            night_ratio = (
                night_count
                / len(timestamped)
            )

            if night_ratio >= 0.20:

                leads.append(
                    {
                        "severity": "MEDIUM",
                        "type": "TEMPORAL",
                        "title":
                            "Concentrated overnight activity",
                        "detail":
                            f"{night_count} event(s) occurred "
                            "between 00:00 and 04:59.",
                        "basis":
                            "Deterministic timestamp distribution.",
                    }
                )

        # --------------------------------------------------------
        # CENTRAL ENTITY
        # --------------------------------------------------------

        if network["central_nodes"]:

            central = (
                network["central_nodes"][0]
            )

            if (
                central["number"]
                != self.target
            ):

                leads.append(
                    {
                        "severity": "MEDIUM",
                        "type": "NETWORK",
                        "title":
                            "High-connectivity entity identified",
                        "detail":
                            f"{central['number']} has the highest "
                            "interaction strength in the analyzed network.",
                        "basis":
                            "Weighted communication network analysis.",
                    }
                )

        # --------------------------------------------------------
        # PRIMARY RELATIONSHIP
        # --------------------------------------------------------

        if communication[
            "target_contacts"
        ]:

            strongest = (
                communication[
                    "target_contacts"
                ][0]
            )

            leads.append(
                {
                    "severity": "INFO",
                    "type": "COMMUNICATION",
                    "title":
                        "Primary communication relationship identified",
                    "detail":
                        f"{strongest['contact']} is the most frequently "
                        f"observed target relationship with "
                        f"{strongest['interaction_count']} interaction(s).",
                    "basis":
                        "Target-centered communication analysis.",
                }
            )

        return leads[:20]

    # ============================================================
    # FINAL PROFILE
    # ============================================================

    def build(self) -> dict:

        if self.df.empty:

            return {
                "summary": {
                    "target": self.target,
                    "total_records": 0,
                    "total_communications": 0,
                    "unique_entities": 0,
                    "active_days": 0,
                    "total_duration_sec": 0,
                    "average_duration_sec": 0,
                    "median_duration_sec": 0,
                    "peak_hour": None,
                    "peak_hour_count": 0,
                    "peak_day": None,
                    "peak_day_count": 0,
                    "top_contact": None,
                    "top_location": None,
                    "total_distance_km": 0,
                    "investigation_signal_score": 0,
                    "lead_count": 0,
                },
                "communication": {},
                "temporal": {},
                "geographic": {},
                "network": {},
                "leads": [],
            }

        communication = (
            self.communication_analysis()
        )

        temporal = (
            self.temporal_analysis()
        )

        geographic = (
            self.geographic_analysis()
        )

        network = (
            self.network_analysis()
        )

        leads = self.investigation_leads(
            communication,
            temporal,
            geographic,
            network,
        )

        timestamped = self.df.dropna(
            subset=["timestamp"]
        )

        entities = set()

        for column in (
            "caller",
            "receiver",
        ):

            entities.update(
                value
                for value
                in self.df[column]
                if valid_entity(value)
            )

        peak_hour = max(
            temporal["hourly"],
            key=lambda item: (
                item["count"],
                item["duration"],
            ),
        )

        peak_day = (
            temporal["daily"][0]
            if temporal["daily"]
            else None
        )

        top_contact = (
            communication[
                "target_contacts"
            ][0]
            if communication[
                "target_contacts"
            ]
            else None
        )

        top_location = (
            geographic[
                "top_locations"
            ][0]
            if geographic[
                "top_locations"
            ]
            else None
        )

        # --------------------------------------------------------
        # TRANSPARENT SIGNAL SCORE
        #
        # This is NOT a criminality probability.
        # It simply counts deterministic investigation signals.
        # --------------------------------------------------------

        signal_score = 0

        if self.existing_analysis.get(
            "impossible_travel"
        ):
            signal_score += 25

        if self.existing_analysis.get(
            "device_swaps",
        ).get(
            "handset_hopping"
        ):
            signal_score += 20

        if self.existing_analysis.get(
            "device_swaps",
        ).get(
            "sim_swapping"
        ):
            signal_score += 20

        if self.existing_analysis.get(
            "bursts"
        ):
            signal_score += 10

        signal_score += min(
            10,
            len(
                network["clusters"]
            ) * 2,
        )

        if not timestamped.empty:

            night_count = int(
                timestamped[
                    "timestamp"
                ]
                .dt.hour
                .between(0, 4)
                .sum()
            )

            if (
                night_count
                / len(timestamped)
            ) >= 0.20:

                signal_score += 10

        if (
            top_contact
            and
            top_contact[
                "interaction_count"
            ] >= 20
        ):

            signal_score += 5

        signal_score = min(
            100,
            signal_score,
        )

        total_duration = int(
            self.df[
                "duration"
            ].sum()
        )

        return {
            "summary": {
                "target": self.target,
                "total_records":
                    len(self.df),
                "total_communications":
                    len(self.df),
                "unique_entities":
                    len(entities),
                "active_days":
                    (
                        timestamped[
                            "timestamp"
                        ]
                        .dt.date
                        .nunique()
                        if not timestamped.empty
                        else 0
                    ),
                "total_duration_sec":
                    total_duration,
                "average_duration_sec":
                    round(
                        safe_number(
                            self.df[
                                "duration"
                            ].mean()
                        ),
                        2,
                    ),
                "median_duration_sec":
                    round(
                        safe_number(
                            self.df[
                                "duration"
                            ].median()
                        ),
                        2,
                    ),
                "peak_hour":
                    peak_hour["hour"],
                "peak_hour_count":
                    peak_hour["count"],
                "peak_day":
                    (
                        peak_day["date"]
                        if peak_day
                        else None
                    ),
                "peak_day_count":
                    (
                        peak_day["count"]
                        if peak_day
                        else 0
                    ),
                "top_contact":
                    top_contact,
                "top_location":
                    top_location,
                "total_distance_km":
                    geographic[
                        "total_distance_km"
                    ],
                "investigation_signal_score":
                    signal_score,
                "lead_count":
                    len(leads),
            },
            "communication":
                communication,
            "temporal":
                temporal,
            "geographic":
                geographic,
            "network":
                network,
            "leads":
                leads,
        }


# ================================================================
# PUBLIC CONVENIENCE FUNCTION
# ================================================================

def build_investigation_analytics(
    records: list[dict] | pd.DataFrame,
    target: str = "",
    existing_analysis: dict | None = None,
) -> dict:
    """
    Public Phase 6 entry point.
    """

    analyzer = InvestigationAnalytics(
        records=records,
        target=target,
        existing_analysis=existing_analysis,
    )

    return analyzer.build()