---
title: CDR Normalization
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# CDR Normalization

## Canonical schema

The engine normalizes to:

```text
caller
receiver
timestamp
duration
call_type
cell_id
lat
lon
imei
imsi
```

## Source-to-canonical mapping

The implementation uses a `COLUMN_MAP` and normalized column names.

The mapper first attempts exact normalized matches and then substring matching.

## Supported input formats

- `.csv`
- `.xlsx`
- `.xls`

## CSV handling

The loader attempts:

1. UTF-8
2. Latin-1
3. CP1252

This helps with provider exports containing different encodings.

## Type conversion

- timestamps → pandas datetime
- duration → numeric, missing values become zero
- latitude/longitude → numeric
- identifiers → trimmed strings

## Call-type normalization

Common values are mapped into:

- `OUTGOING`
- `INCOMING`
- `SMS`
- `ROAMING`

Unrecognized values remain available rather than being silently discarded.

## Data-quality risks

Normalization can fail or produce misleading results when:

- a column is absent
- provider semantics differ
- dates use ambiguous formats
- duration units differ
- phone numbers are formatted inconsistently
- cell IDs are not stable identifiers
- coordinates are missing

Always inspect the generated `column_mapping` metadata.

## 🧹 Why normalization is the first forensic step

Analytics are only as reliable as the fields they receive.

Imagine two files:

```text
File A: Calling Number | Called Number | Call Date
File B: A Party        | B Party        | Start Time
```

A human understands they are similar. A program needs an explicit mapping.

The project solves this using `COLUMN_MAP`.

## Mapping strategy

The engine:

1. normalizes column names,
2. checks exact known variants,
3. falls back to substring matching,
4. stores the resulting canonical-to-source mapping.

## Example

```text
"Calling Number"
        ↓
_normalize_col()
        ↓
"calling number"
        ↓
COLUMN_MAP["caller"]
        ↓
caller
```

## Missing fields

The normalizer uses safe defaults for several absent fields:

- missing caller/receiver → `UNKNOWN`
- missing timestamp → `NaT`
- missing duration → `0`
- missing call type → `UNKNOWN`
- missing cell ID → empty string
- missing coordinates → `NaN`
- missing IMEI/IMSI → empty string

This makes the pipeline robust, but it also means analysts must check metadata before assuming the source contained a field.

## Important QA question

Always ask:

> "Was this field truly present in the original data, or was it filled by the normalizer?"

That distinction is critical.
