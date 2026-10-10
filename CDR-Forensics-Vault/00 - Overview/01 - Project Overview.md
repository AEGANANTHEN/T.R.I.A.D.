---
title: Project Overview
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Project Overview

## Project identity

**Name:** T.R.I.A.D.ligence & Link Analysis Platform  
**Version described by the supplied README:** v2.0  
**Primary implementation:** Python + Flask  
**Purpose:** Analyze telecom Call Detail Records for investigative intelligence.

## Problem statement

CDR datasets contain large volumes of communication, identity, temporal and cell-location information. A raw spreadsheet makes it difficult to recognize relationships and behavioral patterns.

This platform converts those records into:

- normalized records
- investigator-focused KPIs
- temporal profiles
- anomaly indicators
- communication graphs
- geographic trajectories
- cross-target correlations
- exportable investigation artifacts

## Core capabilities

1. Intelligent ingestion and schema mapping
2. SHA-256 source-file hashing
3. KPI and temporal profiling
4. Burst detection
5. Dormancy detection
6. Device/IMEI change analysis
7. Impossible-travel analysis
8. Interactive link analysis
9. Tower-based geospatial tracking
10. Multi-target cross matching
11. Investigation history
12. CSV/XLSX/JSON/report outputs

## Technology

- Python 3.10+
- Flask 3.0
- Pandas
- NumPy
- NetworkX
- OpenPyXL / xlrd
- Geopy
- Jinja2
- Chart.js
- Vis.js
- Leaflet
- DataTables
- Custom CSS

## Design philosophy

The project follows an **investigator-first** pattern:

```text
Raw evidence
    ↓
Normalization
    ↓
Profiling
    ↓
Detection
    ↓
Correlation
    ↓
Visualization
    ↓
Validation
    ↓
Reporting
```

## Evidence mindset

Every automated result should be considered a hypothesis or lead until it is:

1. traced to source records,
2. checked for data-quality issues,
3. interpreted with telecom context,
4. corroborated where appropriate, and
5. documented in the case record.

## 🧑‍💻 Plain-English explanation

Imagine receiving a spreadsheet containing thousands of phone events. The spreadsheet tells you what happened one row at a time, but it does not naturally tell you the story.

This application tries to turn the spreadsheet into a story that can be investigated:

```text
Spreadsheet
   ↓
"What data is here?"
   ↓
"Who talks to whom?"
   ↓
"When does activity happen?"
   ↓
"Where are the associated towers?"
   ↓
"What looks unusual?"
   ↓
"Do two targets share patterns?"
```

## Example investigation question

Suppose Target A has 500 records.

A raw spreadsheet may make it difficult to notice that:

- a small group of contacts accounts for most communication,
- activity suddenly increases during a particular period,
- two IMEIs appear at different times,
- two tower locations appear repeatedly,
- Target B shares several contacts.

The platform brings these dimensions together so the analyst can investigate the pattern.

## What the project does NOT do

It does not magically determine who is guilty, where a person physically stood, or why a communication occurred.

The software is an **analysis assistant**.

## Suggested project presentation

For a college/project demonstration, explain it in five parts:

1. **Problem:** raw CDRs are difficult to investigate.
2. **Solution:** normalize and analyze them.
3. **Intelligence:** detect temporal, device, network and geographic patterns.
4. **Visualization:** present the patterns through dashboards, graphs and maps.
5. **Validation:** keep the analyst responsible for interpreting the evidence.
