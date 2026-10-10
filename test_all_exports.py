import urllib.request
import json

with open('cache/history.json') as f:
    history = json.load(f)

for h in history:
    sid = h['id']
    htype = h.get('type')
    print(f"=== Testing Session {sid} ({htype}) ===")
    for action in ['report', 'export/excel', 'export/csv', 'export/json']:
        url = f'http://localhost:5001/{action}/{sid}'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as resp:
                data = resp.read()
                ctype = resp.headers.get('Content-Type')
                cdisp = resp.headers.get('Content-Disposition')
                print(f"  [OK] {action}: {len(data)} bytes | Content-Type: {ctype} | Disp: {cdisp}")
        except Exception as e:
            print(f"  [ERROR] {action}: {e}")
