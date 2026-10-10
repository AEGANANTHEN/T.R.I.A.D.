---
title: Investigator Workflow
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Investigator Workflow

## Phase 1 — Prepare

- Create case identifier
- Record evidence identifier
- Preserve original input
- Calculate/record source hash
- Confirm authorized handling

## Phase 2 — Ingest

1. Open the platform.
2. Upload the CDR.
3. Confirm file type.
4. Review normalization metadata.
5. Confirm target number.

## Phase 3 — Profile

Review:

- date range
- total records
- contacts
- call direction
- SMS
- duration
- IMEI/IMSI counts
- night activity

## Phase 4 — Investigate

### Temporal

Review hourly and weekly patterns.

### Anomalies

Review bursts, dormancy, device changes and impossible travel.

### Network

Inspect top contacts and structural intermediaries.

### Geography

Inspect tower sequence and repeated locations.

## Phase 5 — Correlate

For multiple targets:

- compare shared contacts
- review contact matrix
- review ±15-minute tower convergence
- compare activity curves

## Phase 6 — Validate

For every important lead:

```text
Dashboard flag
    ↓
Raw records
    ↓
Data-quality review
    ↓
Contextual explanation
    ↓
Corroboration
    ↓
Case finding
```

## Phase 7 — Report

Export:

- normalized data
- analysis workbook
- JSON
- report

Record the analyst's interpretation separately from the automated detection.

## 🔎 Detailed walkthrough

### Step 1 — Identify the source

Record:

- filename
- source
- date received
- case reference
- hash

### Step 2 — Upload

Use the single-target upload when investigating one dataset.

Use cross-match when comparing multiple datasets.

### Step 3 — Check normalization

Confirm the application recognized:

- caller
- receiver
- timestamp
- duration
- call type
- cell
- coordinates
- IMEI
- IMSI

### Step 4 — Establish baseline

Before hunting anomalies, understand normal activity:

- total volume
- daily pattern
- hourly pattern
- common contacts
- normal towers

### Step 5 — Investigate anomalies

Review the anomaly list and trace each flag back to source events.

### Step 6 — Investigate relationships

Open the graph and identify meaningful contacts.

### Step 7 — Investigate geography

Review the tower timeline in chronological order.

### Step 8 — Compare targets

Look for repeated relationships or temporal/spatial convergence.

### Step 9 — Document

Write findings separately from raw automated alerts.

### Step 10 — Export

Generate the required outputs and preserve their provenance.
