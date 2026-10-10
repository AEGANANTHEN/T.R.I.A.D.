# 🛡️ T.R.I.A.D.ligence & Link Analysis Platform (v2.0)

> **Enterprise-Grade Telecom Forensics & Multi-Target Link Analysis Engine**
> Inspired by Palantir Gotham & IBM i2 Analyst's Notebook. Built with Python (Flask), Tailwind CSS, Chart.js, Vis.js, and Leaflet.js.

---

## 🌟 Overview

The **T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard** is a modern, law enforcement-grade investigation dashboard designed to ingest, normalize, and forensically analyze Call Detail Records (`.csv`, `.xlsx`, `.xls`). It automatically extracts actionable intelligence, identifies anomalous subscriber behavioral patterns, tracks spatio-temporal cell tower movements, and exposes criminal syndicates through multi-target link analysis.

---

## ⚡ Key Capabilities & Forensic Modules

### 1. 📥 Intelligent Ingestion & Normalization
* Auto-maps heterogeneous telecom schemas (Caller, Receiver, Timestamp, Duration, Call Type, Cell Tower ID, IMEI, IMSI).
* Computes digital evidence chain-of-custody hashes (**SHA-256**) upon ingestion.

### 2. 📊 Forensic KPI & Temporal Profiling
* Real-time metrics: Unique contacts, total talk-time, incoming/outgoing ratios, and SMS volume.
* **24-Hour Call Frequency Distribution:** Highlights suspicious night-time calling patterns (00:00–05:00).
* **Day-of-Week Behavioral Radar:** Uncovers weekly communication routines.

### 3. 🚨 Anomaly & Velocity Detection
* **Impossible Travel Speed Detection:** Identifies cell tower hops requiring supersonic velocities (>900 km/h) calculated via the Haversine formula.
* **Handset Hopping & SIM Swapping:** Flags multiple IMEIs associated with a single target subscriber.
* **Call Burst & Dormancy Detection:** Detects high-frequency bursts (>5 calls in 10 minutes) and sudden dormant windows.

### 4. 🕸️ Interactive Link Analysis (Vis.js)
* Force-directed interactive network graph with target ego-networks and intermediate brokers.
* Physics engine toggle, cluster controls, degree centrality sizing, and node inspection.

### 5. 🗺️ Spatio-Temporal Geospatial Tracking (Leaflet.js)
* Tower-by-tower breadcrumb path with sequence numbering and timestamps.
* Density heatmap overlay and animated travel trajectory playback with speed controls.

### 6. 🔗 Multi-Target Cross-Match Matrix
* Cross-analyzes multiple CDR files simultaneously to discover mutual intermediary contacts.
* **Spatial Convergence:** Detects co-location events where separate targets were within the same cell tower footprint within a ±15-minute window.
* **Comparative Analytics:** Overlaid 24-hour activity curves, weekly routine radars, and threat profile radars.

### 7. 📑 Forensic Export & Report Generation
* **Printable / PDF Dossier:** Official ISO/IEC 27037-compliant report with embedded high-resolution analytics charts and investigator sign-off blocks.
* **Multi-Tab Excel Workbook (.XLSX):** Comprehensive forensic workbook including Cleaned Records, Top Contacts, Anomalies, and Mutual Intermediaries.
* **Raw Normalized CSV & JSON Dossiers:** Direct export for external BI/Palantir integration.

### 8. 🗂️ Investigation History & Audit Log
* Searchable archive of all past single and cross-match investigations with 1-click reopen, report export, and deletion.

---

## 🛠️ Technology Stack

* **Backend:** Python 3.10+, Flask 3.0, Pandas, NetworkX, OpenPyXL, Geopy
* **Frontend:** Vanilla JS, Tailwind CSS (Slate Dark Mode), Lucide Icons
* **Visualizations:** Chart.js 4.4, Vis.js Network, Leaflet.js 1.9, DataTables

---

## 🚀 Quick Start & Installation

### Prerequisites
* Python 3.10 or higher installed.

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/cdr-forensic-intel.git
cd cdr-forensic-intel
```

### 2. Create and Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch the Platform
```bash
python app.py
```
Open your browser and navigate to **`http://localhost:5001`**.

---

## 📁 Repository Structure

```
├── app.py                      # Flask Application & Routing Engine
├── cdr_engine.py               # Core Telecom Forensics & Analytics Engine
├── requirements.txt            # Python Dependencies
├── .gitignore                  # Git Ignore Rules
├── README.md                   # Platform Documentation
├── sample_cdr.csv              # Synthetic Sample CDR Dataset (Target A)
├── sample_cdr_2.csv            # Synthetic Sample CDR Dataset (Target B)
├── generate_sample_cdr.py      # Generator Script for Sample Dataset 1
├── generate_sample_cdr_2.py    # Generator Script for Sample Dataset 2
├── templates/                  # Jinja2 HTML Templates
│   ├── layout.html             # Base Layout with Cyber-Dark Sidebar
│   ├── index.html              # Upload & Ingestion Center
│   ├── dashboard.html          # Single Target Forensic Dashboard
│   ├── cross_match.html        # Multi-Target Link & Cross-Match Dashboard
│   ├── history.html            # Case Archive & Investigation History
│   └── report.html             # Printable PDF Forensic Dossier
├── static/
│   └── css/
│       └── custom.css          # Custom Glassmorphism & Cyber Theme CSS
├── uploads/                    # Temporary Ingestion Directory (.gitkeep)
└── cache/                      # Session Cache Directory (.gitkeep)
```

---

## 🔒 Security & Privacy Notice
This platform is designed for law enforcement, digital forensics, and telecom fraud investigation. Ensure all real-world CDR datasets are handled in accordance with regional data privacy laws and chain-of-custody protocols.
