"""
T.R.I.A.D. — Phase 4/5 Real-Time Intelligence Engine
======================================================

Deterministic replay engine for existing normalized CDR analysis records.

Phase 4:
    Converts normalized CDR records into a controlled intelligence
    replay/event stream.

Phase 5:
    Provides a stable event structure for live visualization including:

    - CALL
    - SMS
    - LOCATION
    - caller / receiver
    - geographic coordinates
    - cell tower
    - IMEI / IMSI
    - timestamps
    - deterministic sequence numbers

IMPORTANT:
    This module NEVER modifies the original forensic/static CDR analysis.

    Phase 4/5 represents a SIMULATION / REPLAY of recorded intelligence.
    It is NOT a live telecom carrier feed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable


# ============================================================================
# CONSTANTS
# ============================================================================

VALID_SPEEDS = (1, 2, 5)


# ============================================================================
# SAFE VALUE HELPERS
# ============================================================================

def _safe_text(value: Any, default: str = "") -> str:
    """
    Convert a value to clean text.

    Empty, None and whitespace-only values are replaced with default.
    """

    if value is None:
        return default

    text = str(value).strip()

    return text if text else default


def _safe_float(value: Any) -> float | None:
    """
    Safely convert a value to float.

    Returns None when conversion is not possible.
    """

    try:

        if value in (
            None,
            "",
            "nan",
            "NaN",
            "None",
        ):
            return None

        return float(value)

    except (TypeError, ValueError):

        return None


# ============================================================================
# TIMESTAMP SORTING
# ============================================================================

def _timestamp_key(value: Any) -> tuple[int, str]:
    """
    Stable chronological sort key.

    Valid timestamps are sorted chronologically.
    Invalid or empty timestamps are placed last.
    """

    text = _safe_text(value)

    if not text:
        return (1, "")

    try:

        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )

        return (
            0,
            parsed.isoformat(),
        )

    except ValueError:

        return (
            0,
            text,
        )


# ============================================================================
# EVENT TYPE
# ============================================================================

def _primary_event_type(
    record: dict[str, Any]
) -> str:
    """
    Map the normalized CDR call_type into a replay event type.
    """

    call_type = _safe_text(
        record.get("call_type"),
        "UNKNOWN",
    ).upper()

    if "SMS" in call_type:

        return "SMS"

    if call_type in {
        "INCOMING",
        "OUTGOING",
        "ROAMING",
    }:

        return "CALL"

    if "CALL" in call_type:

        return "CALL"

    # Existing TRIAD records are primarily CDR call records.
    return "CALL"


# ============================================================================
# LOCATION SIGNATURE
# ============================================================================

def _location_signature(
    record: dict[str, Any]
) -> tuple[Any, ...] | None:

    lat = _safe_float(
        record.get("lat")
    )

    lon = _safe_float(
        record.get("lon")
    )

    cell_id = _safe_text(
        record.get("cell_id")
    )

    if (
        lat is None
        and lon is None
        and not cell_id
    ):

        return None

    return (
        round(lat, 6)
        if lat is not None
        else None,

        round(lon, 6)
        if lon is not None
        else None,

        cell_id,
    )


# ============================================================================
# EVENT BUILDER
# ============================================================================

def _build_event(
    *,
    sequence: int,
    event_type: str,
    record: dict[str, Any],
    record_index: int,
    direction: str | None = None,
) -> dict[str, Any]:
    """
    Build one standardized TRIAD intelligence event.

    Both canonical Phase-4 names and convenient visualization aliases
    are deliberately included.

    This prevents frontend components from becoming tightly coupled
    to one naming convention.
    """

    timestamp = _safe_text(
        record.get("timestamp"),
        "Unknown time",
    )

    caller = _safe_text(
        record.get("caller"),
        "UNKNOWN",
    )

    receiver = _safe_text(
        record.get("receiver"),
        "UNKNOWN",
    )

    cell_id = _safe_text(
        record.get("cell_id")
    )

    latitude = _safe_float(
        record.get("lat")
    )

    longitude = _safe_float(
        record.get("lon")
    )

    imei = _safe_text(
        record.get("imei")
    )

    imsi = _safe_text(
        record.get("imsi")
    )

    call_type = _safe_text(
        record.get("call_type"),
        "UNKNOWN",
    )

    duration = record.get(
        "duration"
    )

    try:

        duration_seconds = int(
            float(duration or 0)
        )

    except (
        TypeError,
        ValueError,
    ):

        duration_seconds = 0


    # ------------------------------------------------------------------------
    # Standardized event structure
    # ------------------------------------------------------------------------

    event = {

        "sequence":
            sequence,

        "event_id":
            f"RT-{sequence:06d}",

        "event_type":
            event_type,

        "timestamp":
            timestamp,

        "source":
            "CDR REPLAY",

        # ----------------------------------------------------------------
        # Telecom participants
        # ----------------------------------------------------------------

        "from_number":
            caller,

        "to_number":
            receiver,

        # Visualization-friendly aliases.
        #
        # These are especially useful for network/link-analysis
        # components.

        "caller":
            caller,

        "receiver":
            receiver,

        # ----------------------------------------------------------------
        # Communication metadata
        # ----------------------------------------------------------------

        "direction":
            direction or call_type,

        "call_type":
            call_type,

        "duration_seconds":
            duration_seconds,

        # ----------------------------------------------------------------
        # Cell / geographic intelligence
        # ----------------------------------------------------------------

        "cell_id":
            cell_id,

        "latitude":
            latitude,

        "longitude":
            longitude,

        # Visualization-friendly aliases.

        "lat":
            latitude,

        "lon":
            longitude,

        # ----------------------------------------------------------------
        # Device intelligence
        # ----------------------------------------------------------------

        "imei":
            imei,

        "imsi":
            imsi,

        # ----------------------------------------------------------------
        # Provenance
        # ----------------------------------------------------------------

        "record_index":
            record_index,

    }

    return event


# ============================================================================
# REPLAY EVENT GENERATION
# ============================================================================

def build_replay_events(
    records: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Convert normalized CDR records into deterministic replay events.

    Each CDR record generates one primary:

        CALL
        or
        SMS

    event.

    When the geographic/cell location changes, a LOCATION event is
    generated immediately after the corresponding communication event.

    The source dataset is never modified.

    Example:

        CALL
        LOCATION
        CALL
        CALL
        LOCATION
        SMS
        LOCATION

    This produces a realistic investigative stream while remaining
    completely deterministic and forensic-safe.
    """

    # ------------------------------------------------------------------------
    # Normalize input
    # ------------------------------------------------------------------------

    normalized_records = [
        dict(record)
        for record in (records or [])
    ]


    # ------------------------------------------------------------------------
    # Chronological ordering
    # ------------------------------------------------------------------------

    normalized_records.sort(
        key=lambda record:
            _timestamp_key(
                record.get("timestamp")
            )
    )


    events: list[dict[str, Any]] = []

    previous_location = None

    sequence = 0


    # ------------------------------------------------------------------------
    # Build event stream
    # ------------------------------------------------------------------------

    for record_index, record in enumerate(
        normalized_records
    ):

        primary_type = _primary_event_type(
            record
        )


        # ================================================================
        # PRIMARY COMMUNICATION EVENT
        # ================================================================

        sequence += 1

        events.append(

            _build_event(

                sequence=sequence,

                event_type=primary_type,

                record=record,

                record_index=record_index,

                direction=_safe_text(
                    record.get(
                        "call_type"
                    ),
                    "UNKNOWN",
                ),

            )

        )


        # ================================================================
        # LOCATION EVENT
        # ================================================================

        location = _location_signature(
            record
        )


        if (
            location is not None
            and location != previous_location
        ):

            sequence += 1

            events.append(

                _build_event(

                    sequence=sequence,

                    event_type="LOCATION",

                    record=record,

                    record_index=record_index,

                    direction="LOCATION UPDATE",

                )

            )

            previous_location = location


    return events


# ============================================================================
# SPEED HANDLING
# ============================================================================

def normalize_speed(
    value: Any
) -> int:
    """
    Normalize replay speed.

    Supported:

        1x
        2x
        5x
    """

    try:

        speed = int(value)

    except (
        TypeError,
        ValueError,
    ):

        return 1


    if speed in VALID_SPEEDS:

        return speed


    return 1


# ============================================================================
# STREAM DELAY
# ============================================================================

def stream_delay_seconds(
    speed: int
) -> float:
    """
    Base delay per replay event.

    The browser-side polling implementation can use this information
    when required.
    """

    speed = normalize_speed(
        speed
    )

    return {
        1: 1.0,
        2: 0.5,
        5: 0.2,
    }.get(
        speed,
        1.0,
    )