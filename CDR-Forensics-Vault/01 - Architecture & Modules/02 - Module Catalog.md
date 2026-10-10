---
title: Module Catalog
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Module Catalog

## `CDRNormalizer`

**Role:** Parse and normalize input files.

Key operations:

- SHA-256 hashing
- CSV encoding fallback
- Excel loading
- fuzzy column mapping
- type conversion
- call-type normalization
- chronological sorting
- metadata generation

## `ForensicAnalyzer`

**Role:** General behavioral analytics.

Key methods:

- `kpis()`
- `hourly_distribution()`
- `dow_distribution()`
- `call_type_distribution()`
- `detect_bursts()`
- `dormant_periods()`
- `top_contacts()`

## `DeviceSwapDetector`

**Role:** Identify multiple IMEIs associated with a target.

## `ImpossibleTravelDetector`

**Role:** Compare consecutive geospatial observations and estimate implied velocity.

## `NetworkGraphBuilder`

**Role:** Convert communications into graph nodes and edges suitable for Vis.js.

## `GeoTracker`

**Role:** Prepare tower events, trajectory paths, heatmap data and tower summaries.

## `CrossMatchEngine`

**Role:** Compare multiple datasets.

Key methods:

- `common_contacts()`
- `colocation_events()`
- `contact_matrix()`

## `app.py`

**Role:** Web application orchestration.

It handles uploads, sessions, history, dashboards, APIs and exports.

## 🔬 Module-by-module explanation

### `CDRNormalizer`

**Question it answers:** "Can this source file be converted into a standard structure?"

It loads the source, maps columns, converts types, removes unusable identity rows and sorts events by timestamp.

### `ForensicAnalyzer`

**Question it answers:** "What does the dataset look like?"

It produces KPIs, time distributions, call-type distributions, bursts, dormant periods and top contacts.

### `DeviceSwapDetector`

**Question it answers:** "Are multiple device/subscriber identifiers present?"

It builds timelines for IMEI and IMSI values when more than one unique value exists.

### `ImpossibleTravelDetector`

**Question it answers:** "Do consecutive valid coordinates imply an extremely high speed?"

It calculates geographic distance and divides it by elapsed time.

### `NetworkGraphBuilder`

**Question it answers:** "What is the communication network?"

It aggregates caller/receiver pairs into directed graph edges and calculates degree centrality.

### `GeoTracker`

**Question it answers:** "How can geographic CDR events be presented chronologically?"

It prepares markers, paths and tower summaries for map visualization.

### `CrossMatchEngine`

**Question it answers:** "What do multiple targets have in common?"

It compares contacts and cell/timestamp overlap.

## Dependency direction

```text
app.py
  ↓
cdr_engine.py
  ↓
Pandas / NetworkX / Geopy / NumPy
```

The forensic classes should remain as independent as possible from Flask so they can be unit-tested separately.
