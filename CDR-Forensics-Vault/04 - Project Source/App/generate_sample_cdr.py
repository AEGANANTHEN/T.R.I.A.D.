"""
Generate a realistic sample CDR CSV file for testing the forensic platform.
Run: python generate_sample_cdr.py
"""
import csv
import random
import math
from datetime import datetime, timedelta

TARGET = "+919876543210"
CONTACTS = [
    "+919812345678", "+919823456789", "+919834567890",
    "+919845678901", "+919856789012", "+919867890123",
    "+919878901234", "+919889012345", "+919890123456",
    "+919801234567",
]
CALL_TYPES = ["OUTGOING", "OUTGOING", "INCOMING", "INCOMING", "SMS", "OUTGOING", "INCOMING"]
IMEI_POOL = ["358765043210987", "861234567890123"]
IMSI_POOL = ["404730123456789"]

# Realistic tower locations (approximate Indian cities)
TOWERS = [
    {"id": "MUM001", "lat": 19.0760, "lon": 72.8777},
    {"id": "MUM002", "lat": 19.0800, "lon": 72.8800},
    {"id": "MUM003", "lat": 19.0660, "lon": 72.8340},
    {"id": "PUNE01", "lat": 18.5204, "lon": 73.8567},
    {"id": "PUNE02", "lat": 18.5300, "lon": 73.8700},
    {"id": "NASH01", "lat": 19.9975, "lon": 73.7898},
    {"id": "MUM004", "lat": 19.1136, "lon": 72.8697},
]

start_date = datetime(2024, 1, 1, 8, 0, 0)
rows = []

for i in range(500):
    ts = start_date + timedelta(minutes=random.randint(0, 60 * 24 * 90))
    contact = random.choice(CONTACTS)
    call_type = random.choice(CALL_TYPES)
    duration = random.randint(5, 600) if "SMS" not in call_type else 0
    tower = random.choice(TOWERS)

    # Inject a few night calls
    if random.random() < 0.08:
        ts = ts.replace(hour=random.randint(0, 4))

    # Add small GPS jitter
    lat = tower["lat"] + random.gauss(0, 0.005)
    lon = tower["lon"] + random.gauss(0, 0.005)

    imei = random.choices(IMEI_POOL, weights=[0.85, 0.15])[0]

    rows.append({
        "Call Date": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "Calling Number": TARGET if "OUTGOING" in call_type else contact,
        "Called Number":  contact if "OUTGOING" in call_type else TARGET,
        "Call Duration":  duration,
        "Service Type":   call_type,
        "First Cell ID":  tower["id"],
        "latitude":       round(lat, 6),
        "longitude":      round(lon, 6),
        "IMEI":           imei,
        "IMSI":           IMSI_POOL[0],
    })

# Sort by date
rows.sort(key=lambda r: r["Call Date"])

with open("sample_cdr.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated sample_cdr.csv with {len(rows)} records")
print(f"Target: {TARGET}")
print(f"Date range: {rows[0]['Call Date']} -> {rows[-1]['Call Date']}")
