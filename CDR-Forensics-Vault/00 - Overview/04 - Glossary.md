---
title: Glossary
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Glossary

| Term | Meaning |
|---|---|
| CDR | Call Detail Record |
| MSISDN | Telephone number/subscriber-facing number |
| IMEI | International Mobile Equipment Identity; handset/device identifier |
| IMSI | International Mobile Subscriber Identity |
| Cell ID | Identifier for a serving cellular cell/tower |
| KPI | Key Performance Indicator |
| Ego network | A graph centered on one target |
| Centrality | Graph measure indicating structural importance |
| Burst | Dense activity inside a configured time window |
| Dormancy | Extended interval without observed events |
| Haversine | Great-circle distance calculation between geographic coordinates |
| Co-location | Two targets observed at the same cell/tower context within a time window |
| Normalization | Conversion of source-specific fields into a canonical schema |
| Chain of custody | Documented handling history of evidence |
| SHA-256 | Cryptographic hash used as an integrity fingerprint |
| Synthetic data | Artificially generated data used for testing/demo purposes |
| False positive | Alert that appears suspicious but has an innocent/data-quality explanation |
| False negative | Suspicious behavior not detected by a rule |

## Telecom-specific caution

A tower observation is generally a **network association**, not a GPS-quality physical coordinate.

A shared cell does not automatically establish that two individuals were physically together.

## 🧠 Terms explained for beginners

### CDR

A **Call Detail Record** is a telecom event record. Depending on the source, it can contain participants, time, duration, service type, cell information and device/subscriber identifiers.

### IMEI vs IMSI

A simple way to remember them:

```text
IMEI → "Which handset/device?"
IMSI → "Which subscriber/SIM identity?"
```

They are different identifiers and should not be treated as interchangeable.

### Cell ID

A network identifier for a cellular serving cell. It provides network/location context but is not the same as a precise GPS coordinate.

### Normalization

Different providers might call the same field:

```text
Calling Number
A Party
Originating Number
MSISDN A
Caller
```

Normalization converts these into one internal field such as `caller`.

### Link analysis

Instead of asking "what is in row 10?", link analysis asks:

> "What relationships exist across all rows?"

### Anomaly

An event that differs from a configured rule or baseline. It is a flag for review, not automatically evidence of wrongdoing.

### Correlation

Two datasets show related patterns. Correlation becomes meaningful only after checking whether the relationship could have a normal explanation.
