---
title: Testing & QA
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Testing & QA

## Smoke test

- [ ] Environment activates
- [ ] Dependencies install
- [ ] `python app.py` starts
- [ ] Home page loads on port 5001
- [ ] Synthetic CDR uploads
- [ ] Dashboard renders
- [ ] Link graph renders
- [ ] Geo view renders when coordinates exist
- [ ] Cross-match accepts two datasets
- [ ] History records the session
- [ ] CSV export works
- [ ] JSON export works
- [ ] XLSX export works
- [ ] Report view works

## Data validation tests

### Required identity behavior

Test records where:

- caller exists
- receiver exists
- both exist
- neither exists

Rows with both caller and receiver `UNKNOWN` should be removed by normalization.

### Timestamp tests

Test:

- valid timestamp
- invalid timestamp
- missing timestamp
- mixed formats

### Duration tests

Test:

- integer seconds
- blank duration
- malformed duration
- zero duration

### Geography tests

Test:

- valid coordinates
- missing coordinates
- out-of-range coordinates

## Regression dataset

Keep a small synthetic dataset with known expected outputs.

Example assertions:

```text
record count = expected
target = expected
unique contacts = expected
IMEI count = expected
IMSI count = expected
```

## Forensic QA principle

A test passing means the software behaved as designed. It does not prove that the analytical rule is scientifically valid for every carrier or investigative context.

## 🧪 Test strategy

Testing should happen at three levels.

### Level 1 — Unit tests

Test individual functions:

- column normalization
- Haversine calculation
- call-type mapping
- burst detection
- dormancy detection

### Level 2 — Integration tests

Test:

```text
Upload
 ↓
Normalization
 ↓
Analysis
 ↓
Cache
 ↓
Dashboard/API
```

### Level 3 — User acceptance

Perform an investigator-style workflow using known synthetic data.

## Known-answer testing

A strong regression test uses synthetic records where the expected result is already known.

Example:

```text
Dataset contains exactly 10 records.
Expected KPI total_records = 10.
```

If a later code change returns 9, the regression test catches it.

## Edge cases

Test:

- empty file
- missing required fields
- duplicate rows
- malformed timestamps
- missing coordinates
- only one record
- no valid locations
- multiple IMEIs
- multiple IMSIs
- all events at same timestamp
- very large duration
- unsupported extension

## QA principle

A system should fail safely and explain the problem rather than silently producing plausible-looking but incorrect forensic results.
