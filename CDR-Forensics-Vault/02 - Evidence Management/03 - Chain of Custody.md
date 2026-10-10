---
title: Chain of Custody
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Chain of Custody

## What is Chain of Custody?

Chain of Custody (CoC) is the record of how evidence moved through its lifecycle.

A simplified example:

```text
INGESTION
   ↓
CHECK_OUT
   ↓
ANALYSIS_RUN
   ↓
INTEGRITY_CHECK
   ↓
DOWNLOAD
```

## CoC actions in the project

- `INGESTION`
- `CHECK_OUT`
- `CHECK_IN`
- `ANALYSIS_RUN`
- `TRANSFER_CUSTODY`
- `INTEGRITY_CHECK`
- `COURT_EXHIBIT`
- `DISPOSITION`
- `ACCESS_VIEW`
- `DOWNLOAD`

## Ledger fields

Each event records information including:

- evidence ID
- actor ID
- action
- purpose
- UTC timestamp
- recorded SHA-256
- verification status
- IP address
- user agent
- event UUID

## Append-only design

The model documentation describes the ledger as immutable/append-only: events are added rather than edited as the normal workflow.

The application should still be protected at the database and administrative layers because application-level intent alone cannot make a database physically immutable.

## Why hash the event context?

Recording the evidence SHA-256 at the time of an event lets an auditor see which evidence fingerprint was associated with that action.
