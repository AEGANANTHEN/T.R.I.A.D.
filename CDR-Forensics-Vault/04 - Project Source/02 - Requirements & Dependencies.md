---
title: Requirements & Dependencies
type: project-documentation
project: T.R.I.A.D.
tags: [cdr-forensics, dems, cybersecurity]
---

# Requirements & Dependencies

## Runtime

The supplied `requirements.txt` pins:

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
flask-sqlalchemy==3.1.1
flask-bcrypt==1.0.1
cryptography==42.0.8
sqlalchemy==2.0.30
```

## Dependency roles

| Package | Role |
|---|---|
| Flask | Web framework |
| Pandas | Tabular CDR processing |
| NumPy | Numerical operations |
| OpenPyXL | XLSX reading/writing |
| xlrd | XLS support |
| NetworkX | Graph analytics |
| Geopy | Geographic utilities |
| Flask-SQLAlchemy | ORM integration |
| SQLAlchemy | Database toolkit/ORM |
| Flask-Bcrypt | Password hashing |
| Cryptography | AES-GCM and KDF primitives |
| Werkzeug | Flask ecosystem utilities |
| python-dateutil | Date/time parsing support |

## Maintenance

Do not update all packages blindly. Validate analytics, crypto behavior and route tests after dependency changes.
