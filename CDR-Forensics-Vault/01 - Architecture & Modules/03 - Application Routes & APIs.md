---
title: Application Routes & APIs
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Application Routes & APIs

## Original CDR routes

| Route | Purpose |
|---|---|
| `/` | Upload/home |
| `/dashboard` | Latest single analysis |
| `/link-analysis` | Link-analysis section |
| `/geo-tracking` | Geographic analysis |
| `/cross-match` | Multi-target analysis |
| `/history` | CDR history |
| `/upload` | Single CDR upload |
| `/dashboard/<session_id>` | Specific analysis |
| `/cross-match/<session_id>` | Specific cross-match |
| `/report/<session_id>` | Report |
| `/export/excel/<session_id>` | XLSX |
| `/export/csv/<session_id>` | CSV |
| `/export/json/<session_id>` | JSON |

## CDR APIs

```text
/api/history
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
```

## DEMS routes

| Route | Purpose |
|---|---|
| `/dems/login` | User authentication |
| `/dems/logout` | End session |
| `/dems/cases` | Case list |
| `/dems/cases/new` | Create case |
| `/dems/cases/<id>` | Case detail |
| `/dems/cases/<id>/update-status` | Change case status |
| `/dems/evidence/upload` | Evidence intake |
| `/dems/evidence/<id>` | Evidence dossier |
| `/dems/evidence/<id>/verify` | Integrity verification |
| `/dems/evidence/<id>/transfer` | Custody transfer/check-in/out |
| `/dems/evidence/<id>/download` | Authorized plaintext download |
| `/dems/evidence/<id>/analyze-cdr` | Run CDR analysis |
| `/dems/evidence/<id>/coc-dossier` | CoC dossier |

The exact blueprint prefix should be confirmed from `dems_routes.py` when modifying the application.
