---
title: Impossible Travel & Haversine
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Impossible Travel & Haversine

## Haversine distance

For two coordinates:

```text
φ = latitude in radians
λ = longitude in radians

a = sin²(Δφ / 2)
    + cos(φ1) × cos(φ2) × sin²(Δλ / 2)

c = 2 × atan2(√a, √(1-a))

distance = R × c
```

The engine uses a great-circle distance helper to estimate kilometers.

## Velocity

```text
velocity = distance / elapsed time
```

The implementation converts the elapsed time into a speed estimate and compares it against a threshold.

## Why this can be misleading

Cell observations are not continuous GPS tracks.

A high implied speed can arise because:

- intermediate observations are missing
- a device switched cells unexpectedly
- timestamps are delayed
- records are out of sequence
- coordinates are wrong
- the same identifier appears in multiple contexts

## Recommended interpretation

Use the result as:

> "These two observations imply a velocity requiring validation."

Do not write:

> "The person traveled at 900+ km/h."

unless independent evidence supports that conclusion.

## 🌍 Haversine in simple terms

The Earth is curved, so straight-line distance on a flat map is not ideal for large geographic separations.

The Haversine formula estimates the shortest surface distance between two latitude/longitude points.

## Example

```text
Point A
lat = 19.07
lon = 72.87

Point B
lat = 18.52
lon = 73.85
```

The engine estimates the distance between them.

If the timestamps are extremely close together, the implied speed can become very large.

## Why the threshold exists

The project uses:

```text
MAX_SPEED_KMH = 900
```

as a flagging threshold.

The threshold is a triage mechanism. It should not be interpreted as a scientific boundary between possible and impossible behavior in every scenario.

## Analyst validation

For each alert:

1. inspect the two timestamps,
2. inspect both coordinates,
3. inspect cell IDs,
4. calculate the time difference,
5. calculate distance,
6. check for missing observations,
7. check source quality,
8. look for corroborating records.

## Key lesson

The algorithm calculates **implied movement between observations**.

It does not observe continuous movement between them.
