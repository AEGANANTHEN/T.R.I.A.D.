---
title: Methodology & Limitations
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Methodology & Limitations

## Strengths

- schema-flexible ingestion
- deterministic source hashing
- reusable analytics classes
- graph representation
- geographic representation
- multi-target comparison
- exportable results

## Key limitations

### 1. CDR semantics vary

Different carriers and vendors may define fields differently.

### 2. Missing data changes conclusions

The platform only sees records provided to it.

### 3. Tower location is approximate

Cell-based location should not be interpreted as exact GPS.

### 4. Rules are heuristic

Thresholds are useful for triage but should be configurable and validated.

### 5. Correlation is not causation

Shared contacts and temporal overlap require contextual interpretation.

### 6. Identity fields can be complicated

IMEI/IMSI relationships may reflect legitimate operational behavior.

### 7. Local cache is not a forensic evidence-management system

A production deployment needs formal access control, audit logging, encryption and retention policies.

## Recommended confidence language

Use:

- "observed"
- "associated with"
- "consistent with"
- "requires validation"
- "investigative lead"

Avoid unsupported statements such as:

- "proves"
- "definitively identifies"
- "confirms criminal activity"

## 🧪 Scientific thinking in forensic analytics

A good forensic workflow distinguishes three things:

### Observation

Something directly present in the data.

> "Two IMEI values occur in the dataset."

### Inference

A reasonable interpretation based on the observation.

> "The target appears to have used more than one handset during the period."

### Conclusion

A stronger statement supported by independent evidence.

The software should generally stop at observations and investigative leads. The analyst decides whether the evidence supports a stronger conclusion.

## Repeatability

A result is more useful when another analyst can reproduce it from:

- the same source
- the same normalization
- the same threshold
- the same software version

## Bias controls

Avoid:

- changing thresholds only to create an alert
- selecting only records that support a hypothesis
- ignoring missing data
- treating visual patterns as proof
- confusing correlation with causation

## Recommended finding template

```text
Finding:
Observed evidence:
Source records:
Analytical method:
Relevant threshold:
Alternative explanations:
Corroborating evidence:
Limitations:
Analyst assessment:
```
