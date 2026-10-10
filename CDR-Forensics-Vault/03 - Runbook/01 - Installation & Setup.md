---
title: Installation & Setup
type: project-documentation
project: T.R.I.A.D. - Telecom Records and Intelligence Analysis Dashboard
tags: ["cdr-forensics", "cybersecurity", "obsidian"]
---

# Installation & Setup

## Prerequisites

- Python 3.10+
- pip
- modern web browser

## Windows

```powershell
cd "Project Files"
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

```text
http://localhost:5001
```

## Linux/macOS

```bash
cd "Project Files"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Dependencies

The supplied project pins:

```text
flask==3.0.3
pandas==2.2.2
openpyxl==3.1.4
xlrd==2.0.1
networkx==3.3
geopy==2.4.1
python-dateutil==2.9.0
werkzeug==3.0.3
numpy==1.26.4
```

## Synthetic data

```bash
python generate_sample_cdr.py
python generate_sample_cdr_2.py
```

## History indexing

```bash
python index_history.py
```

## Development vs production

The built-in Flask development server is suitable for local testing.

For production, use:

- a production WSGI server
- TLS termination
- authentication
- protected storage
- centralized logging
- controlled configuration

## 🛠️ What each command does

### Create virtual environment

```bash
python -m venv venv
```

Creates an isolated Python environment for this project.

### Activate

Windows:

```powershell
.\venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

Installs the versions expected by the project.

### Start application

```bash
python app.py
```

Starts the Flask development server.

## First-run checklist

After installation:

- confirm Python version
- confirm dependencies
- run the application
- open port 5001
- upload synthetic Target A data
- inspect the dashboard
- run Target A + B cross-match
- inspect history
- test exports

## Recommended development habit

Do not modify the environment globally.

Keep the project's virtual environment isolated so dependency changes do not unexpectedly affect other projects.
