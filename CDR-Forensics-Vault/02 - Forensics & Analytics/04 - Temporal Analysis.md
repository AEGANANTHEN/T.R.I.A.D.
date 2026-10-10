---
title: Temporal Analysis
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Temporal Analysis

## Hourly distribution

The engine returns all 24 hours, even when a bucket contains zero events.

Useful questions:

- Is activity concentrated in a narrow period?
- Does activity shift between day and night?
- Are there repeated peaks?

## Day-of-week distribution

Events are grouped Monday–Sunday.

Useful questions:

- Is activity highly routine?
- Are weekends different?
- Does the pattern change over the investigation period?

## Temporal baselines

A better production analysis should compare:

```text
observed activity
        vs.
target's historical baseline
        vs.
peer / contextual baseline
```

A single unusual timestamp is weaker evidence than a sustained deviation from a known baseline.

## Time-zone considerations

Timestamp interpretation must be documented.

Potential issues:

- UTC vs local time
- carrier export timezone
- daylight-saving changes
- device clock vs network clock
- mixed-source datasets

## ⏰ Why time analysis matters

Communication behavior often has a rhythm.

A raw table might contain timestamps such as:

```text
09:02
09:04
09:05
21:41
21:43
```

A temporal chart immediately shows clusters.

## Hourly distribution

The engine produces all 24 hours, including zero-count hours.

This is useful because the frontend can always expect the same 24 buckets.

## Day-of-week distribution

The engine produces Monday through Sunday.

This lets an analyst compare routine weekday behavior with weekend behavior.

## Example

If activity is concentrated between 08:00 and 18:00, that may be consistent with a normal work schedule.

If a new cluster appears at 02:00 after months of daytime activity, it may deserve review.

But context matters:

- work schedule
- emergency events
- travel
- timezone
- automated services

## Time-analysis best practice

Do not use "unusual time" as a synonym for "suspicious."

Use it as:

> "A temporal deviation requiring contextual review."
