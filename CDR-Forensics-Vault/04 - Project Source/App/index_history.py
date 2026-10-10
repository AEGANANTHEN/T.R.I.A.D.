import json
import os
import glob
from pathlib import Path
import datetime

cache_files = glob.glob('cache/*.json')
history = []
for f in cache_files:
    if 'history.json' in f:
        continue
    sid = Path(f).stem
    try:
        with open(f, 'r', encoding='utf-8') as fp:
            d = json.load(fp)
        is_cross = d.get('type') == 'cross_match'
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S')
        if is_cross:
            targets = d.get('targets', [])
            history.append({
                'id': sid,
                'type': 'cross_match',
                'targets': targets,
                'filenames': d.get('filenames', d.get('labels', [])),
                'case_ref': 'CASE-2024-AUTO',
                'records_count': sum(len(ind.get('records', [])) for ind in d.get('individuals', [])),
                'contacts_count': len(d.get('common_contacts', [])),
                'duration': '—',
                'anomalies_count': len(d.get('colocation', [])),
                'sha256': 'Multi-File Hash',
                'date_range': f"{len(targets)} Targets Comparison",
                'timestamp': mtime
            })
        else:
            kpis = d.get('kpis', {})
            anom = len(d.get('impossible_travel', [])) + (1 if d.get('device_swaps', {}).get('handset_hopping') else 0)
            history.append({
                'id': sid,
                'type': 'single',
                'target': d.get('target', 'Target'),
                'filename': d.get('filename', 'sample_cdr.csv'),
                'case_ref': 'CASE-2024-001',
                'records_count': kpis.get('total_records', len(d.get('records', []))),
                'contacts_count': kpis.get('unique_contacts', 0),
                'duration': kpis.get('total_duration_hms', '17:50:01'),
                'anomalies_count': anom,
                'sha256': d.get('metadata', {}).get('sha256', '6ecec67225698e27'),
                'date_range': kpis.get('date_range', '2024-01-01 -> 2024-04-01'),
                'timestamp': mtime
            })
    except Exception as e:
        print(f"Error parsing {f}: {e}")

history.sort(key=lambda x: x['timestamp'], reverse=True)
with open('cache/history.json', 'w', encoding='utf-8') as fp:
    json.dump(history, fp, indent=2)
print(f"Populated history.json with {len(history)} cases")
