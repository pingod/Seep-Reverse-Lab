#!/usr/bin/env python3
"""Read-only macOS sample baseline. Does not inspect license data or patch files."""
import argparse
import hashlib
import json
import pathlib
import plistlib
import struct
import subprocess


def inspect(app):
    app = pathlib.Path(app).resolve(strict=True)
    with (app / 'Contents' / 'Info.plist').open('rb') as stream:
        info = plistlib.load(stream)
    name = info['CFBundleExecutable']
    if pathlib.Path(name).name != name:
        raise ValueError('Unexpected executable path')
    binary = app / 'Contents' / 'MacOS' / name
    data = binary.read_bytes()
    if len(data) < 32 or data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('Expected thin little-endian Mach-O 64 sample')
    header = struct.unpack_from('<8I', data)
    _, cpu, subtype, filetype, ncmds, sizeofcmds, flags, _ = header
    if cpu != 0x0100000c or filetype != 2:
        raise ValueError('Expected arm64 Mach-O executable')
    end = 32 + sizeofcmds
    if end > len(data):
        raise ValueError('Load command region exceeds file')
    position = 32
    signatures = []
    for _ in range(ncmds):
        if position + 8 > end:
            raise ValueError('Truncated load command')
        cmd, size = struct.unpack_from('<II', data, position)
        if size < 8 or position + size > end:
            raise ValueError('Invalid load command size')
        if cmd == 0x1d:
            if size != 16:
                raise ValueError('Invalid code signature command')
            offset, length = struct.unpack_from('<II', data, position + 8)
            if offset + length > len(data):
                raise ValueError('Signature exceeds file')
            signatures.append({'offset': offset, 'size': length})
        position += size
    if position != end:
        raise ValueError('Load command size mismatch')
    result = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)],
                            capture_output=True, text=True)
    return {'app': str(app), 'bundle_id': info.get('CFBundleIdentifier'),
            'version': info.get('CFBundleShortVersionString'),
            'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'cpu_type': cpu, 'cpu_subtype': subtype, 'file_type': filetype,
            'flags': flags, 'load_commands': ncmds, 'code_signatures': signatures,
            'codesign_exit': result.returncode,
            'codesign_diagnostic': result.stderr.strip(),
            'scope': 'read-only baseline; authorization behavior not tested'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app')
    args = parser.parse_args()
    report = inspect(args.app)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    raise SystemExit(0 if report['codesign_exit'] == 0 else 1)
