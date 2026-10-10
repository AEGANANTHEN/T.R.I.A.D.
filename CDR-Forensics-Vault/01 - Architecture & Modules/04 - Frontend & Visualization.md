---
title: Frontend & Visualization
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Frontend & Visualization

## UI stack

- Jinja2 templates
- Vanilla JavaScript
- Tailwind-style dark interface
- Custom CSS
- Lucide-style iconography
- DataTables

## Chart.js

Best suited to:

- hourly activity
- weekday activity
- call-type distribution
- comparative target profiles

## Vis.js Network

Used for:

- target ego network
- contact nodes
- intermediary relationships
- degree-based node sizing
- physics controls
- node inspection

## Leaflet

Used for:

- tower markers
- trajectory lines
- heatmap-ready points
- spatial event inspection

## Investigator UX principle

Visualization should answer a question.

Examples:

| Question | Visualization |
|---|---|
| When is activity concentrated? | Hourly chart |
| Is behavior routine? | Day-of-week profile |
| Who matters most? | Link graph / top contacts |
| Where did events occur? | Map |
| Did two targets overlap? | Cross-match table/map |
| What requires attention? | Anomaly panel |

## 🎨 Why multiple visualization types are used

No single chart answers every forensic question.

### Dashboard cards

Best for quick facts:

```text
Records | Contacts | Duration | IMEIs | IMSIs
```

### Line/bar charts

Best for time distributions.

### Network graph

Best for relationships.

### Map

Best for spatial context.

### Tables

Best for exact records and evidence review.

## Visualization principle

A good visualization should reduce cognitive load.

Instead of asking the investigator to manually calculate:

```text
Which hour has the most events?
```

a chart can make the peak immediately visible.

Instead of scanning hundreds of phone numbers, a graph can show the target's most connected nodes.

## But visualization can mislead

Large nodes can look important even when their degree is high because of a service number.

Thick edges can look suspicious even when the high call count is completely normal.

Therefore, every visualization should allow the analyst to inspect the underlying values.
