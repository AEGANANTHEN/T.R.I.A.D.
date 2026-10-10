---
title: Exports, Reports & Artifacts
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Exports, Reports & Artifacts

## Report

The application exposes a printable report view intended for forensic dossier presentation.

## Excel

The export layer produces an XLSX workbook for structured review.

Potential investigation tabs described by the project include:

- cleaned records
- top contacts
- anomalies
- mutual intermediaries

## CSV

A normalized CSV is useful for:

- external analysis
- reproducibility
- BI tools
- data review

## JSON

A JSON dossier is useful for:

- machine-readable pipelines
- downstream integrations
- archival metadata
- application-to-application exchange

## Artifact naming

Recommended production naming:

```text
CASEID_EVIDENCEID_original.ext
CASEID_EVIDENCEID_normalized.csv
CASEID_EVIDENCEID_analysis.json
CASEID_EVIDENCEID_report.pdf
CASEID_EVIDENCEID_results.xlsx
```

## Export validation

Before release:

- verify target
- verify date range
- verify record count
- verify hash metadata
- inspect output for accidental sensitive fields
- confirm report version
- retain a copy according to case policy

## 📦 Why multiple export formats exist

Different users need different representations.

### CSV

Best for:

- spreadsheet analysis
- Python/R processing
- simple data exchange

### XLSX

Best for:

- analyst review
- multiple worksheets
- filters and formulas
- handoff to non-programmers

### JSON

Best for:

- APIs
- automation
- structured archival
- downstream applications

### Report

Best for:

- human-readable presentation
- case documentation
- printing/PDF workflows

## Artifact chain

A useful case folder can look like:

```text
Case-001/
├── Original/
├── Working/
├── Analysis/
├── Reports/
└── Hashes/
```

## Reproducibility

Every final report should ideally identify:

- source file
- source hash
- analysis timestamp
- software version
- relevant thresholds
- analyst
- limitations

This makes the analysis easier to reproduce and review later.
