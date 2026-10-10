---
title: DEMS Data Model
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# DEMS Data Model

## Entity relationship

```mermaid
erDiagram
    USER ||--o{ CASE : leads
    USER ||--o{ EVIDENCE : uploads
    USER ||--o{ EVIDENCE : custodies
    USER ||--o{ COC_LOG : performs
    CASE ||--o{ EVIDENCE : contains
    EVIDENCE ||--o{ COC_LOG : has
    EVIDENCE ||--o{ EVIDENCE : derives

    USER {
      int id
      string username
      string role
      bool is_active
    }

    CASE {
      int id
      string case_number
      string title
      string status
      string priority
      string classification
    }

    EVIDENCE {
      int id
      string evidence_tag
      string original_filename
      string evidence_type
      string sha256_intake
      string sha512_intake
      string md5_intake
      bool is_locked
      string verification_status
    }

    COC_LOG {
      int id
      int evidence_id
      int actor_id
      string action
      datetime timestamp_utc
      string recorded_sha256
    }
```

## Case numbering

The model generates case numbers in a `CAS-YYYY-XXXXXX`-style pattern using a random alphanumeric suffix.

## Evidence tags

Evidence tags are generated from the case ID and an incrementing evidence count, such as:

```text
EVD-0001-0001
```

## Derived evidence

`source_evidence_id` allows outputs to reference the evidence from which they originated.
