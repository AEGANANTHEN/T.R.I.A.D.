---
title: Code Map
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Code Map

## `app.py`

Start here to understand Flask orchestration.

Important areas:

- app configuration
- DEMS blueprint registration
- database initialization
- upload/cache directories
- single CDR routes
- cross-match routes
- CDR exports
- API endpoints

## `cdr_engine.py`

Start here to understand analytics.

Important classes:

```text
CDRNormalizer
ForensicAnalyzer
DeviceSwapDetector
ImpossibleTravelDetector
NetworkGraphBuilder
GeoTracker
CrossMatchEngine
```

## `dems_models.py`

Start here to understand the database.

Important classes:

```text
User
Case
Evidence
ChainOfCustodyLog
```

Important enums:

```text
UserRole
CaseStatus
CasePriority
EvidenceType
CoCAction
VerificationStatus
```

## `dems_crypto.py`

Start here for evidence protection:

```text
derive_vault_key()
derive_vault_key_hkdf()
get_vault_key()
stream_dual_hash()
encrypt_file_to_vault()
decrypt_to_memory_stream()
verify_integrity()
build_vault_path()
```

## `dems_routes.py`

Start here for the DEMS user workflow:

```text
login()
cases_list()
case_new()
case_detail()
evidence_upload()
evidence_detail()
evidence_verify()
evidence_transfer()
evidence_download()
evidence_analyze_cdr()
coc_dossier()
```

## Recommended code-reading order

```text
README
 ↓
app.py
 ↓
cdr_engine.py
 ↓
dems_models.py
 ↓
dems_crypto.py
 ↓
dems_routes.py
 ↓
templates
 ↓
tests
```
