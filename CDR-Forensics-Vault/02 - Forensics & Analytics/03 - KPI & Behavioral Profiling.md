---
title: KPI & Behavioral Profiling
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# KPI & Behavioral Profiling

## KPIs produced

The engine calculates:

- total records
- unique contacts
- total duration
- incoming events
- outgoing events
- SMS count
- night events
- unique IMEI count
- unique IMSI count
- analyzed date range
- target identifier

## Contact definition

Contacts are derived from caller/receiver values associated with the target. The target itself is removed from the contact set.

## Night activity

The implementation treats hours `00` through `04` as night activity.

This is a configurable investigative heuristic, not a universal definition of suspicious behavior.

## Top contacts

The analyzer exposes top contacts for graph and dashboard use.

A high communication count may indicate importance, but importance is contextual:

- service numbers can be high-volume
- family members can be frequent
- business contacts can dominate normal activity
- automated systems can generate repeated events

## 📊 KPIs explained

### Total records

How many normalized events remain after processing.

### Unique contacts

How many distinct counterparties appear in events involving the target.

### Total duration

The sum of the `duration` field across the normalized dataset.

### Incoming / outgoing

Counts based on normalized `call_type`.

### SMS

Count of records normalized as `SMS`.

### Night calls

Count of events occurring from hour 00 through 04.

### IMEI count

Number of distinct non-empty IMEI values.

### IMSI count

Number of distinct non-empty IMSI values.

## Example interpretation

Suppose:

```text
Records: 500
Contacts: 37
IMEIs: 2
IMSIs: 1
Night events: 42
```

A reasonable conclusion is:

> "The dataset contains 500 normalized records involving 37 unique contacts, with two observed IMEIs and one IMSI."

An unsafe conclusion would be:

> "The target changed phones because they were hiding something."

The first is an observation. The second is an unsupported interpretation.

## KPI checklist

Before writing a finding:

- confirm target
- confirm date range
- confirm source file
- confirm normalization
- confirm whether missing fields affect the metric
