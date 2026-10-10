---
title: Code Map
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Code Map

## `app.py`

### Responsibilities

- Flask initialization
- upload validation
- session/cache handling
- history management
- page routes
- analysis API routes
- report route
- export routes

### Important functions

```text
allowed_file
_cache_path
_save_cache
_load_cache
_get_history
_save_history
_add_history_entry
_delete_history_entry
_get_latest_session_id
index
route_dashboard
route_link_analysis
route_geo_tracking
cross_match_route
history_view
upload
handle_cross_match_upload
dashboard
cross_match_view
report_view
export_excel
export_csv
export_json
_get_data
api_history
api_history_delete
api_history_clear
api_latest_session
api_kpis
api_hourly
api_dow
api_calltypes
api_graph
api_geo
api_records
api_anomalies
api_top_contacts
api_cross
api_cross_individual
```

## `cdr_engine.py`

See [[02 - Forensics & Analytics/01 - CDR Normalization]] and [[02 - Forensics & Analytics/05 - Anomaly Detection]].

### Classes

```text
CDRNormalizer
ForensicAnalyzer
DeviceSwapDetector
ImpossibleTravelDetector
NetworkGraphBuilder
GeoTracker
CrossMatchEngine
```

### Main orchestration

```text
run_full_analysis()
```

This function coordinates the major single-target analysis components.## 🧠 Recommended code-reading order

If you want to understand the implementation rather than just run it:

### 1. Read `cdr_engine.py` from the top

Start with `COLUMN_MAP`. It explains what input schemas the project expects.

### 2. Read `CDRNormalizer`

Understand how raw data becomes the canonical dataframe.

### 3. Read `ForensicAnalyzer`

This is where the basic metrics and time-based rules live.

### 4. Read specialist detectors

Then inspect:

- `DeviceSwapDetector`
- `ImpossibleTravelDetector`

### 5. Read graph/geographic classes

Inspect:

- `NetworkGraphBuilder`
- `GeoTracker`

### 6. Read `CrossMatchEngine`

This shows how multiple target datasets are compared.

### 7. Read `app.py`

Only after understanding the engine should you inspect how Flask connects user actions to analytics.

This order prevents the web UI from hiding the underlying forensic logic.
