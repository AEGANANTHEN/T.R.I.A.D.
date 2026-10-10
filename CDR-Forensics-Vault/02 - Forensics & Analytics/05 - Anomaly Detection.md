---
title: Anomaly Detection
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Anomaly Detection

## 1. Call bursts

`detect_bursts(window_minutes=60, threshold=5)` identifies windows containing at least the configured number of events.

The supplied README describes a burst concept of more than five calls in ten minutes; the actual engine defaults to a **60-minute window** with threshold **5**. Therefore, the implementation and README should be treated separately and the rule should be configured explicitly for a production deployment.

### Interpretation

A burst can represent:

- urgent legitimate communication
- operational activity
- automated calling
- coordination
- unusual behavior

It is not inherently malicious.

## 2. Dormancy

`dormant_periods(gap_hours=24)` looks for large gaps between observed events.

Possible explanations include:

- normal inactivity
- device off
- travel
- missing records
- source-system filtering

## 3. Device changes

`DeviceSwapDetector` counts distinct IMEIs.

Multiple IMEIs can mean:

- handset replacement
- dual-device use
- SIM/device movement
- shared equipment
- data inconsistencies

## 4. Impossible travel

The engine compares sequential tower coordinates and timestamps.

The README references a >900 km/h threshold.

This is best treated as an **impossible-travel indicator**, not proof that the subscriber physically traveled at that speed.

## Alert lifecycle

```text
Detection
  ↓
Review raw events
  ↓
Check data quality
  ↓
Add telecom/contextual explanation
  ↓
Corroborate
  ↓
Record finding
```

## 🚨 How to think about alerts

The platform uses rule-based detection.

That means:

```text
IF condition is true
THEN create an alert
```

It does not mean:

```text
IF alert exists
THEN wrongdoing occurred
```

## Alert types

| Alert | Trigger concept | First validation step |
|---|---|---|
| Burst | Many events in a short window | Inspect raw timestamps |
| Dormancy | Long gap between events | Check coverage/completeness |
| Device swap | Multiple IMEIs/IMSIs | Review identifier timeline |
| Impossible travel | Very high implied speed | Verify coordinates/timestamps |

## Why false positives happen

Rule-based systems cannot automatically know every legitimate explanation.

For example, a burst could be a family emergency.

A device change could be a normal handset replacement.

A high-speed location jump could be caused by missing intermediate records.

## Alert triage

Use three levels:

### Level 1 — Detect

Software identifies a condition.

### Level 2 — Validate

Analyst checks the raw evidence and data quality.

### Level 3 — Interpret

Analyst documents a supported explanation or finding.

This workflow should be followed for every important alert.
