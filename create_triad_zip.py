import os, zipfile, shutil

zip_name = 'TRIAD.zip'
target_path = os.path.abspath(zip_name)
parent_path = os.path.abspath(os.path.join('..', zip_name))

EXCLUDE_DIRS  = {'.venv', 'venv', '__pycache__', '.vscode', '.git', 'vault'}
EXCLUDE_EXTS  = ('.pyc', '.pyo', '.zip', '.rar', '.db-shm', '.db-wal')
EXCLUDE_FILES = {'dems.db', zip_name, 'CDR.zip'}

included = []
with zipfile.ZipFile(target_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith('.')]
        norm_root = os.path.normpath(root)
        if norm_root in {'cache', 'uploads'}:
            files = [f for f in files if f == '.gitkeep']
        for f in files:
            if f.endswith(EXCLUDE_EXTS) or f in EXCLUDE_FILES:
                continue
            fp = os.path.join(root, f)
            arc = os.path.relpath(fp, '.')
            zf.write(fp, arc)
            included.append((arc, os.path.getsize(fp)))

shutil.copy2(target_path, parent_path)

with zipfile.ZipFile(target_path, 'r') as zf:
    bad = zf.testzip()

size_mb = os.path.getsize(target_path) / (1024 * 1024)
integrity = 'PASS' if not bad else ('FAIL - ' + bad)

print('Archive   :', zip_name)
print('Files     :', len(included))
print('Size      :', round(size_mb, 2), 'MB')
print('Integrity :', integrity)
print('Saved to  :', target_path)
print('Also at   :', parent_path)
