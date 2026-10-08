#!/usr/bin/env python3
"""Read-only isolation preflight; no application launch and no license contents."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

home = Path.home()
roots = [home / 'Library/Application Support', home / 'Library/Preferences',
         home / 'Library/Caches', home / '.config', home / '.local/share']
found = []
errors = []
for root in roots:
    if not root.exists():
        continue
    try:
        for entry in root.iterdir():
            if 'tessoa' in entry.name.lower():
                found.append({'path': str(entry), 'directory': entry.is_dir()})
    except OSError as exc:
        errors.append({'root': str(root), 'error': str(exc)})
proc = subprocess.run(['/usr/bin/pgrep', '-x', 'tessoa'], capture_output=True, text=True)
if proc.returncode not in (0, 1):
    errors.append({'process_probe': proc.stderr.strip(), 'exit': proc.returncode})
# Exercise only /usr/bin/true, not the target. A write-denying sandbox can
# establish tool availability, but cannot prove target configuration isolation.
sandbox = subprocess.run(['/usr/bin/sandbox-exec', '-p',
                          '(version 1)(allow default)(deny file-write*)',
                          '/usr/bin/true'], capture_output=True, text=True)
print(json.dumps({'uid': os.getuid(), 'matching_data_locations': found,
                  'running_pids': proc.stdout.split(), 'errors': errors,
                  'sandbox_probe_exit': sandbox.returncode,
                  'sandbox_probe_diagnostic': sandbox.stderr.strip(),
                  'application_launched': False,
                  'isolation_proven': False,
                  'warning': 'HOME override alone does not isolate macOS preferences, keychain, IPC or singleton locks.'},
                 indent=2, ensure_ascii=False))
raise SystemExit(1 if errors or sandbox.returncode else 0)
