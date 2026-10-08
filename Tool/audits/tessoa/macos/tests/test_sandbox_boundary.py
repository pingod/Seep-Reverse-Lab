#!/usr/bin/env python3
"""Exercise sandbox write boundaries with disposable fixtures, not user data."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

base = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='boundary-', dir=str(base)) as temp:
    root = Path(temp)
    allowed = root / 'allowed'
    protected = root / 'protected'
    allowed.mkdir()
    protected.mkdir()
    marker = protected / 'marker.txt'
    marker.write_text('UNCHANGED', encoding='utf-8')
    profile = '(version 1)(allow default)(deny file-write*)(allow file-write* (subpath %s))' % json.dumps(str(allowed))
    child = '''import json, pathlib, sys
allowed, marker = map(pathlib.Path, sys.argv[1:])
(allowed / 'created.txt').write_text('OK')
checks = {}
for name, target in [('overwrite', marker), ('create', marker.parent / 'new.txt')]:
    try:
        target.write_text('BAD')
        checks[name] = False
    except PermissionError:
        checks[name] = True
try:
    marker.unlink()
    checks['delete'] = False
except PermissionError:
    checks['delete'] = True
print(json.dumps(checks))
sys.exit(0 if all(checks.values()) else 1)
'''
    result = subprocess.run(['/usr/bin/sandbox-exec', '-p', profile, sys.executable,
                             '-B', '-c', child, str(allowed), str(marker)],
                            capture_output=True, text=True)
    unchanged = marker.exists() and marker.read_text() == 'UNCHANGED'
    allowed_ok = (allowed / 'created.txt').exists() and (allowed / 'created.txt').read_text() == 'OK'
    denied_create = not (protected / 'new.txt').exists()
    passed = result.returncode == 0 and unchanged and allowed_ok and denied_create
    print(json.dumps({'passed': passed, 'exit': result.returncode,
                      'child_checks': result.stdout.strip(), 'stderr': result.stderr.strip(),
                      'protected_marker_unchanged': unchanged, 'allowed_write_succeeded': allowed_ok,
                      'protected_create_absent': denied_create,
                      'scope': 'synthetic file-write isolation only; no app launched; IPC, reads and network not isolated'}, indent=2))
    raise SystemExit(0 if passed else 1)
