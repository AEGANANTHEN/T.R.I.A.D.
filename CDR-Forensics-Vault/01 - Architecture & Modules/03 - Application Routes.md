---
title: Application Routes
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Application Routes

Source: `Project Files/app.py`

## User-facing routes

| Route | Purpose |
|---|---|
| `/` | Upload/home |
| `/dashboard` | Latest/single investigation dashboard |
| `/dashboard/<session_id>` | Specific dashboard |
| `/link-analysis` | Latest link analysis |
| `/link-analysis/<session_id>` | Specific link graph |
| `/geo-tracking` | Latest geographic analysis |
| `/geo-tracking/<session_id>` | Specific geographic analysis |
| `/cross-match` | Multi-target upload/cross-match |
| `/cross-match/<session_id>` | Cross-match results |
| `/history` | Investigation history |
| `/report/<session_id>` | Report view |

## Export routes

- `/export/excel/<session_id>`
- `/export/csv/<session_id>`
- `/export/json/<session_id>`

## API routes

```text
/api/history
/api/history/delete/<session_id>
/api/history/clear
/api/latest-session
/api/kpis/<session_id>
/api/hourly/<session_id>
/api/dow/<session_id>
/api/calltypes/<session_id>
/api/graph/<session_id>
/api/geo/<session_id>
/api/records/<session_id>
/api/anomalies/<session_id>
/api/top-contacts/<session_id>
/api/cross/<session_id>
/api/cross/individual/<session_id>/<index>
```

## Route design

The API endpoints allow the frontend to request focused analytical datasets instead of embedding every result into one page.

## 🌐 How routes work

A route is an HTTP entry point.

For example:

```text
GET /dashboard
```

asks Flask to open the dashboard route.

An API route such as:

```text
GET /api/kpis/<session_id>
```

returns structured data instead of a complete HTML page.

## Page routes vs API routes

### Page route

Returns a template:

```text
Browser → Flask → HTML template → Browser
```

### API route

Returns data:

```text
Browser JavaScript → Flask → JSON → JavaScript
```

This separation is useful because one dashboard can request several focused datasets.

## Upload route

The upload process is roughly:

```text
POST /upload
    ↓
Check file exists
    ↓
Check extension
    ↓
Generate UUID
    ↓
Sanitize filename
    ↓
Save file
    ↓
run_full_analysis()
    ↓
Save cache
    ↓
Save history entry
    ↓
Redirect to dashboard
```

## Cross-match route

The project accepts at least two and at most five CDR files for a cross-match operation.

Each file is normalized and analyzed before the comparison results are saved.

## Security note

A production version should add authentication and authorization around these routes. A URL containing a session ID should not be assumed to be sufficient authorization to view sensitive evidence.
