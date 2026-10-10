---
title: Architecture
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Architecture

## Layered architecture

```mermaid
flowchart TB
    subgraph UI["Presentation"]
        T["Jinja2 Templates"]
        JS["Vanilla JavaScript"]
        CH["Chart.js"]
        VN["Vis.js"]
        LF["Leaflet"]
    end

    subgraph APP["Application"]
        FL["Flask app.py"]
        HS["History / Cache"]
        EX["Export Layer"]
    end

    subgraph CORE["Forensic Core"]
        NO["CDRNormalizer"]
        FA["ForensicAnalyzer"]
        DS["DeviceSwapDetector"]
        IT["ImpossibleTravelDetector"]
        NG["NetworkGraphBuilder"]
        GT["GeoTracker"]
        CM["CrossMatchEngine"]
    end

    subgraph DATA["Data Layer"]
        CSV["CSV"]
        XLSX["XLSX"]
        XLS["XLS"]
        CACHE["cache/"]
        UP["uploads/"]
    end

    UI --> FL
    FL --> NO
    FL --> FA
    FL --> DS
    FL --> IT
    FL --> NG
    FL --> GT
    FL --> CM
    NO --> CSV
    NO --> XLSX
    NO --> XLS
    FL --> HS
    FL --> EX
    HS --> CACHE
    FL --> UP

    FL --> T
    T --> JS
    JS --> CH
    JS --> VN
    JS --> LF

## 🏗️ Why this architecture is useful

The architecture separates **presentation**, **application control**, **forensic logic**, and **data**.

### Presentation layer

The browser displays results. It should not be responsible for deciding what a burst or impossible-travel event means.

### Application layer

`app.py` connects browser requests to the forensic engine and manages sessions, exports and history.

### Forensic layer

`cdr_engine.py` contains the reusable domain logic.

This is the most important separation in the project because the analytics can potentially be reused outside Flask.

## Example

A dashboard request can be understood as:

```text
Browser asks for KPI
      ↓
Flask receives /api/kpis/<session_id>
      ↓
Flask loads cached investigation
      ↓
JSON response
      ↓
JavaScript updates dashboard
```

The browser therefore does not need to know how the original CDR was parsed.

## Architecture strengths

- easier maintenance
- reusable analysis classes
- simpler frontend
- clearer debugging
- easier future API development

## Architecture weaknesses to improve

The prototype uses filesystem JSON as storage. A larger deployment would benefit from:

- a relational database
- object storage for evidence
- explicit case/evidence tables
- audit events
- access control
- background processing for large files
