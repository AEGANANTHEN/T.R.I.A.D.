---
title: Test & Demo Data Guide
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Test & Demo Data Guide

## Synthetic datasets

### Target A

`sample_cdr.csv`

Used to demonstrate a single-target investigation.

### Target B

`sample_cdr_2.csv`

Used with Target A for multi-target comparison.

## Generators

```text
generate_sample_cdr.py
generate_sample_cdr_2.py
```

These scripts make it possible to regenerate demonstration data instead of relying only on manually edited spreadsheets.

## Suggested demo sequence

1. Start Flask.
2. Open the home page.
3. Upload Target A.
4. Review KPIs.
5. Open link analysis.
6. Open geo tracking.
7. Review anomalies.
8. Open history.
9. Run a cross-match with Target A + Target B.
10. Review common contacts and co-location.
11. Export the report/CSV/XLSX/JSON.

## Test scripts

Run after the application is available:

```bash
python test_reports.py
python test_cross_upload.py
python test_all_exports.py
```
