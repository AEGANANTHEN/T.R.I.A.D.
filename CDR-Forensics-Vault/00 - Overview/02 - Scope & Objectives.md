---
title: Scope & Objectives
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Scope & Objectives

## Objectives

### O1 — Make CDR ingestion resilient

Support common CSV, XLSX and XLS exports and tolerate provider-specific column names.

### O2 — Establish a canonical schema

Convert heterogeneous inputs into predictable fields so analytics can operate consistently.

### O3 — Surface investigative signals

Detect patterns that would be difficult to identify manually.

### O4 — Provide relationship intelligence

Represent communication as a graph rather than only a table.

### O5 — Add spatial context

Show where and when CDR events were associated with cell towers.

### O6 — Compare targets

Find shared contacts and temporal/spatial convergence across datasets.

### O7 — Preserve investigation outputs

Provide history, hashes and exportable artifacts.

## In scope

- CDR file processing
- telecom identity fields
- temporal profiling
- tower-based location analysis
- graph construction
- cross-target correlation
- local investigation history
- analyst-facing visualization

## Out of scope

- direct carrier-network access
- real-time lawful interception
- subscriber identity verification from external databases
- guaranteed physical positioning
- automated attribution of criminal intent
- evidentiary certification by software alone

## Success criteria

A successful analysis should allow an analyst to answer:

- What data was analyzed?
- Which target was analyzed?
- What period does it cover?
- Who were the principal contacts?
- When did activity occur?
- Are there unusual bursts or gaps?
- Are device identifiers changing?
- What locations/towers appear in the timeline?
- What relationships are shared across targets?
- What source records support each finding?

## 📌 Why scope matters

A forensic platform can quickly become too broad. Defining scope prevents the project from making claims that its data and algorithms cannot support.

For example:

> "The system identifies the exact physical location of a subscriber."

is outside the safe scope of a tower-based CDR system.

A better statement is:

> "The system visualizes the cell/tower locations associated with available CDR events."

## Functional requirements

### FR-01 — Input

The system shall accept supported CDR file formats.

### FR-02 — Normalization

The system shall convert provider-specific column names into canonical fields.

### FR-03 — Analysis

The system shall calculate behavioral and temporal statistics.

### FR-04 — Detection

The system shall identify configured anomaly patterns.

### FR-05 — Visualization

The system shall expose analytical results through charts, graphs and maps.

### FR-06 — Correlation

The system shall compare multiple datasets.

### FR-07 — Export

The system shall provide machine-readable and human-readable outputs.

## Non-functional requirements

- understandable UI
- reproducible analysis
- traceable source file hash
- modular Python implementation
- predictable API responses
- local development support
- secure handling guidance

## Future scope

Potential future improvements include:

- configurable rule profiles
- role-based access control
- database-backed cases
- audit trails
- evidence packages
- richer tower metadata
- statistical baselines
- automated data-quality scoring
- unit tests for every analytic rule
