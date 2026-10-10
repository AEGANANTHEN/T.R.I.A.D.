---
title: Geospatial Tracking
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Geospatial Tracking

## GeoTracker output

The engine prepares:

- event markers
- chronological path
- heatmap-ready points
- tower summaries
- map center
- geographic availability flag

## Marker information

A marker can contain:

```text
latitude
longitude
cell_id
timestamp
caller
receiver
call_type
duration
is_night
```

## Tower summary

For each tower/cell context, the tracker aggregates:

- count
- total duration
- coordinates

## Interpretation

A cell tower indicates a network service area rather than exact handset coordinates.

Therefore:

```text
tower observation ≠ exact GPS location
```

## Useful investigation views

1. Chronological tower sequence
2. Repeated tower usage
3. Dwell/activity concentration
4. Night vs daytime geography
5. Target-to-target tower overlap

## Quality checks

Before interpreting a path:

- check missing coordinates
- check coordinate ranges
- verify timestamps
- inspect repeated cell IDs
- look for abrupt impossible jumps
- confirm whether the source is sector/cell level

## 🗺️ Geospatial analysis for beginners

A CDR may contain a cell/tower identifier and geographic coordinates associated with that cell.

The platform turns those records into a chronological geographic view.

## Three useful map concepts

### Marker

One observed event at a geographic coordinate.

### Path

A sequence of observations connected chronologically.

### Heatmap

A density-oriented representation showing where events concentrate.

## Example

```text
08:00 → Tower A
10:30 → Tower A
13:10 → Tower B
17:45 → Tower C
```

The map can make the sequence visually understandable.

## Important limitation

A tower coordinate is not necessarily the exact position of the handset.

The actual coverage area depends on:

- tower placement
- sector orientation
- terrain
- network conditions
- propagation
- load
- radio conditions

## Best practice

Use geographic information to identify:

- repeated areas
- changes in tower association
- temporal/spatial correlation

Do not overstate it as exact GPS tracking.
