---
title: DEMS Overview
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# DEMS Overview

## What is DEMS?

**DEMS = Digital Evidence Management System.**

It is the evidence-control layer added around the CDR analytics engine.

## Main responsibilities

```text
Users
 ↓
Cases
 ↓
Evidence
 ↓
Encrypted Vault
 ↓
Chain of Custody
 ↓
Integrity Verification
 ↓
Authorized Analysis
```

## Why DEMS is important

A forensic analysis system should answer not only:

> "What did the analytics find?"

but also:

> "Which evidence produced that result, who handled it, and can the evidence still be verified?"

## Main DEMS files

| File | Responsibility |
|---|---|
| `dems_models.py` | Database models, enums, permissions, CoC logging |
| `dems_crypto.py` | Hashing, key derivation, encryption, verification |
| `dems_routes.py` | Authentication, case/evidence routes, analysis hook |
| `app.py` | Registers the DEMS blueprint and initializes the application |

## Core entities

- User
- Case
- Evidence
- ChainOfCustodyLog
