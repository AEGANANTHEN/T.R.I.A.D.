---
title: Project Roadmap
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: [cdr-forensics, roadmap, development]
---

# Project Roadmap

## Current prototype

The supplied project already provides:

- CDR upload
- normalization
- KPI profiling
- anomaly detection
- link analysis
- geospatial analysis
- cross-target comparison
- investigation history
- exports
- synthetic datasets

## Phase 1 — Stabilize

- [ ] Add automated unit tests
- [ ] Add integration tests
- [ ] Validate all API responses
- [ ] Improve error messages
- [ ] Resolve documentation/implementation threshold differences

## Phase 2 — Forensic maturity

- [ ] Evidence manifest
- [ ] Acquisition metadata
- [ ] Processing audit trail
- [ ] Per-result provenance
- [ ] Configurable analytical thresholds
- [ ] Reproducible analysis profiles

## Phase 3 — Security

- [ ] Authentication
- [ ] Role-based access control
- [ ] Case-level permissions
- [ ] Secure secret management
- [ ] Encrypted storage
- [ ] Audit logging

## Phase 4 — Analytics

- [ ] Statistical behavioral baselines
- [ ] Better duplicate detection
- [ ] Contact ranking
- [ ] Time-window filtering
- [ ] Network community detection
- [ ] Improved geospatial validation

## Phase 5 — Deployment

- [ ] Database-backed persistence
- [ ] Background analysis jobs
- [ ] Production WSGI deployment
- [ ] Centralized logging
- [ ] Backup/restore procedure
- [ ] Retention policy

## Definition of done

A mature release should be:

1. reproducible,
2. testable,
3. secure,
4. auditable,
5. explainable,
6. conservative in its forensic claims.
