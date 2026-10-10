---
title: Project Source Index
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Project Source Index

The complete original project is preserved in this folder.

## Core

- `app.py`
- `cdr_engine.py`
- `requirements.txt`

## Data generators

- `generate_sample_cdr.py`
- `generate_sample_cdr_2.py`

## Utilities

- `index_history.py`

## Synthetic data

- `sample_cdr.csv`
- `sample_cdr_2.csv`

## Web UI

- `templates/layout.html`
- `templates/index.html`
- `templates/dashboard.html`
- `templates/cross_match.html`
- `templates/history.html`
- `templates/report.html`
- `static/css/custom.css`

## Runtime directories

- `uploads/`
- `cache/`

> The source files are copied unchanged from the supplied project into `04 - Project Source/App`.## 📁 How to navigate the source

Start with:

1. `App/README.md` — original project documentation.
2. `App/app.py` — web application and routes.
3. `App/cdr_engine.py` — forensic engine.
4. `App/templates/` — HTML interface.
5. `App/static/css/custom.css` — visual styling.
6. synthetic CDR generators — repeatable test data.

## 🔗 Documentation-to-code mapping

| Documentation | Source to inspect |
|---|---|
| Normalization | `App/cdr_engine.py` → `COLUMN_MAP`, `map_columns`, `CDRNormalizer` |
| KPIs | `App/cdr_engine.py` → `ForensicAnalyzer.kpis()` |
| Temporal analysis | `ForensicAnalyzer.hourly_distribution()` / `dow_distribution()` |
| Bursts | `ForensicAnalyzer.detect_bursts()` |
| Dormancy | `ForensicAnalyzer.dormant_periods()` |
| Device changes | `DeviceSwapDetector` |
| Impossible travel | `haversine_km`, `ImpossibleTravelDetector` |
| Link analysis | `NetworkGraphBuilder` |
| Geography | `GeoTracker` |
| Cross-match | `CrossMatchEngine` |
| Web routes | `App/app.py` |
