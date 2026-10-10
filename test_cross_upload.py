import urllib.request
import uuid

def create_multipart(files, fields):
    boundary = uuid.uuid4().hex.encode('utf-8')
    lines = []
    for k, v in fields.items():
        lines.append(b'--' + boundary)
        lines.append(f'Content-Disposition: form-data; name="{k}"'.encode('utf-8'))
        lines.append(b'')
        lines.append(v.encode('utf-8'))
    for field_name, file_path in files:
        with open(file_path, 'rb') as fp:
            data = fp.read()
        lines.append(b'--' + boundary)
        lines.append(f'Content-Disposition: form-data; name="{field_name}"; filename="{file_path}"'.encode('utf-8'))
        lines.append(b'Content-Type: text/csv')
        lines.append(b'')
        lines.append(data)
    lines.append(b'--' + boundary + b'--')
    lines.append(b'')
    body = b'\r\n'.join(lines)
    headers = {'Content-Type': f'multipart/form-data; boundary={boundary.decode("utf-8")}'}
    return body, headers

body, headers = create_multipart(
    [('cdr_files', 'sample_cdr.csv'), ('cdr_files', 'sample_cdr_2.csv')],
    {'targets': '+919876543210, +919899887766', 'case_ref': 'OPERATION-NEXUS-2024'}
)

req = urllib.request.Request('http://localhost:5001/cross-match', data=body, headers=headers, method='POST')
try:
    with urllib.request.urlopen(req) as resp:
        print('Final URL:', resp.geturl())
        print('Status:', resp.getcode())
except urllib.error.HTTPError as e:
    print('HTTPError:', e.code, e.headers.get('Location'))
