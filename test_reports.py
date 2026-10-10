import urllib.request

session_id = '285fbc99-7ded-45a4-ace9-c252b84783bf'
endpoints = [
    f'http://localhost:5001/report/{session_id}',
    f'http://localhost:5001/export/excel/{session_id}',
    f'http://localhost:5001/export/csv/{session_id}',
    f'http://localhost:5001/export/json/{session_id}',
    f'http://localhost:5001/report/dfb882ef-3ff9-4852-aaad-affeba2331a3',
    f'http://localhost:5001/export/excel/dfb882ef-3ff9-4852-aaad-affeba2331a3',
]

for ep in endpoints:
    try:
        with urllib.request.urlopen(ep) as resp:
            content = resp.read()
            ctype = resp.headers.get('Content-Type')
            print(f"OK {resp.getcode()}: {ep} -> {len(content)} bytes [{ctype}]")
    except Exception as e:
        print(f"FAIL: {ep} -> {e}")
