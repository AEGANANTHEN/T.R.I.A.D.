---
title: Troubleshooting
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Troubleshooting

## `ModuleNotFoundError`

Activate the virtual environment and reinstall:

```bash
pip install -r requirements.txt
```

## Excel import failure

Check:

- `.xlsx` uses OpenPyXL
- `.xls` uses xlrd
- file is not corrupted
- file extension matches content

## Empty dashboard

Check:

1. target identifier
2. source columns
3. timestamp parsing
4. caller/receiver fields
5. cache/session ID

## Missing map

Check:

- latitude and longitude columns
- numeric conversion
- coordinate ranges
- whether the dataset contains geographic data

## Unexpected anomaly

Inspect the raw events first.

Typical causes:

- duplicate records
- missing events
- timezone mismatch
- incorrect tower coordinates
- data provider semantics
- synthetic test artifacts

## Port already in use

Find the process using port 5001 or configure the application to use another development port.

## History not appearing

Check:

```text
cache/
cache/history.json
```

and confirm the application process has write permissions.

## Production troubleshooting

Capture:

- timestamp
- case/session ID
- request route
- application log
- stack trace
- dependency versions

Avoid logging full CDR records or unnecessary subscriber identifiers.

## 🧭 Troubleshooting method

When something fails, separate the problem into four layers:

```text
1. Input
2. Processing
3. Storage
4. Presentation
```

### Input problem

Example:

> "The timestamp chart is empty."

First check whether the source timestamp column was mapped correctly.

### Processing problem

If timestamps exist but all values become `NaT`, inspect date parsing.

### Storage problem

If analysis works but history disappears, inspect the cache directory and write permissions.

### Presentation problem

If API data exists but the chart is blank, inspect browser JavaScript and the API response.

## Debug checklist

```text
What file?
What session ID?
What route?
What input fields?
What normalized fields?
What exception?
What cache file?
What API response?
What browser error?
```

## Avoid dangerous debugging

Do not print complete CDR datasets into production logs.

Log:

- session ID
- case reference
- operation
- error type
- timestamp

Only log sensitive fields when there is a justified operational requirement and appropriate protection.
