---
title: Evidence Integrity & Hashing
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Evidence Integrity & Hashing

## SHA-256

`CDRNormalizer` calculates a SHA-256 hash of the original uploaded file before analysis.

Conceptually:

```text
file bytes
   ↓
SHA-256
   ↓
64-character hexadecimal digest
```

## What the hash provides

A hash can demonstrate that a particular byte sequence corresponds to the recorded digest.

It does **not** by itself prove:

- who acquired the file
- where it came from
- whether the source system was trustworthy
- who handled it
- whether the data is complete

## Recommended evidence record

```text
Case ID
Evidence ID
Source
Original filename
Acquisition timestamp
SHA-256
Examiner
Tool version
Processing timestamp
Transformation notes
Export hashes
```

## Preservation rule

Keep the original file immutable. Perform analysis on a working copy whenever the surrounding evidence-management process allows it.

## 🔐 Hashing in simple terms

A SHA-256 hash is like a fingerprint for a file.

If the file changes, even slightly, the resulting hash will normally change.

```text
Original CDR
    ↓
SHA-256
    ↓
abc123...64 hex characters
```

## Example evidence log

```text
Evidence ID: E-001
Filename: target_a.csv
SHA-256: <recorded digest>
Acquired: <timestamp>
Examiner: <analyst>
```

## What to compare

If an exported or transferred copy later produces the same SHA-256 digest, that supports the claim that the bytes are identical.

## What hashing cannot tell you

Hashing does not tell you whether the original source was truthful or complete.

A perfectly hashed file can still contain:

- incorrect timestamps
- missing rows
- duplicated rows
- wrong coordinates
- incorrect identifiers

So:

```text
Integrity ≠ correctness
```

## Good forensic practice

Preserve the original and document every transformation. Do not overwrite the original source merely because a normalized copy is more convenient to analyze.
