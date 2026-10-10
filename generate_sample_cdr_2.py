"""
Generate a second CDR CSV file for Target B with shared contacts & co-location events.
"""
import csv
import random
from datetime import datetime, timedelta

TARGET_B = "+919899887766"

# Shared contacts with Target A (+919876543210)
SHARED_CONTACTS = ["+919812345678", "+919823456789", "+919834567890"]
OTHER_CONTACTS = ["+919111222333", "+919444555666", "+919777888999"]
ALL_CONTACTS = SHARED_CONTACTS + OTHER_CONTACTS

TOWERS = [
    {"id": "MUM001", "lat": 19.0760, "lon": 72.8777},
    {"id": "MUM002", "lat": 19.0800, "lon": 72.8800},
    {"id": "PUNE01", "lat": 18.5204, "lon": 73.8567},
    {"id": "DEL001", "lat": 28.6139, "lon": 77.2090},
]

start_date = datetime(2024, 1, 1, 8, 0, 0)
rows = []

for i in range(400):
    ts = start_date + timedelta(minutes=random.randint(0, 60 * 24 * 90))
    # Give higher weight to shared contacts to demonstrate comparative overlap
    contact = random.choices(ALL_CONTACTS, weights=[3, 3, 3, 1, 1, 1])[0]
    call_type = random.choice(["OUTGOING", "INCOMING", "SMS", "INCOMING", "OUTGOING"])
    duration = random.randint(10, 500) if call_type != "SMS" else 0
    tower = random.choice(TOWERS)

    # Night calls
    if random.random() < 0.12:
        ts = ts.replace(hour=random.randint(0, 4))

    lat = tower["lat"] + random.gauss(0, 0.005)
    lon = tower["lon"] + random.gauss(0, 0.005)

    rows.append({
        "Call Date": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "Calling Number": TARGET_B if "OUTGOING" in call_type else contact,
        "Called Number": contact if "OUTGOING" in call_type else TARGET_B,
        "Call Duration": duration,
        "Service Type": call_type,
        "First Cell ID": tower["id"],
        "latitude": round(lat, 6),
        "longitude": round(lon, 6),
        "IMEI": "862345678901234",
        "IMSI": "404730999888777",
    })

rows.sort(key=lambda r: r["Call Date"])

with open("sample_cdr_2.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated sample_cdr_2.csv with {len(rows)} records for Target: {TARGET_B}")
