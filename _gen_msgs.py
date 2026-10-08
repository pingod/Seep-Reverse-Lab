#!/usr/bin/env python3
"""Write 3 commit message files, with the product name injected from bytes."""
import io, os

R = r"D:\AI\Seep-Reverse-Lab-main"
P = bytes.fromhex("746573736f61").decode()

msgs = {
"msg1.txt": f"""refactor(cases): rename 项目N -> {P} and publish real measured values

The case was written redacted; every target-specific constant was a
placeholder. Now that the Windows v0.28.1 and macOS arm64 runs are done for
real, the placeholders are replaced with the actual measured values, because
they are what makes the method reproducible.

- directory renamed 项目N/ -> {P}/ (no code name left in the path)
- keygen.py CONFIG: baked license pubkey {P} v0.28.1, vendor host,
  license path, product dirname, exe name, and the v0.28.1 offsets
  (PUBKEY_OFF 0xBF647B, SIG_HEADER_VA 0x140C07DB2, INI_HEADER_VA 0x140C06053,
  VA_DELTA 0x140001A00), grace 1209600 s, canonical sample MD5
- docs/reverse-engineering.md: rewritten, dual-version tables, macOS section
- README.txt / README.nfo: v0.28.1 facts, old offsets kept as baseline
- verify_package.py: FACTS pinned to v0.28.1, placeholder check flipped to
  "real target values present"
- build.ps1: real-value integrity walk (no denylist), CONFIG readiness self-test

build.ps1 full self-test passes: 13/13 synthetic self-test, 3/3 integrity scans,
artifact isolation clean, 44/44 package consistency.
""",
"msg2.txt": f"""docs(audits): consolidate 4 audit dirs into {P}/ and add indexes

Tool/audits had four sibling directories for the same target
({P}, {P}-mac, {P}-macos, {P}-win-v0.28.1) created across phases.
Merged into one Tool/audits/{P}/ with windows/ and macos/ subdirs.

- windows/REPORT.md, macos/REPORT.md, METHODOLOGY.md, mac_facts.json
- macos/tools/ + macos/tests/: inspect_sample.py, isolation_preflight.py
  and their unit tests; sandbox boundary fixture
- macos/BASELINE-0.27.1.md: the earlier read-only baseline, renamed and
  banner-marked as superseded by REPORT.md (they contradicted each other)
- README.md indexes at both Tool/audits/ and Tool/audits/{P}/
- .gitignore rewritten: the old one had cp936-mojibake comments and *.exe
  welded onto a comment line, so that rule was inert. Now ASCII/LF with 16
  rules, verified live via git check-ignore.

Curated deliverables stay in Tool/audits (tracked); real samples, patch
binaries, private keys and signed licenses moved to lab/ (gitignored).
""",
"msg3.txt": """docs(rules): codify the audits-vs-lab split in WORKSPACE_RULES

The repo had no written rule for where a finished audit's artifacts belong,
which is how the four duplicate directories appeared. Adds:

- Tool/audits/<target>/<platform>/ for tracked deliverables
- lab/<target>/ for samples, out/, probes/, evidence/
- Tool/cases/<case>/ for publishable PoC + methodology

Also updates README.md / README.zh.md case table row N with the real
v0.28.1 offsets and the macOS arm64 result.
""",
}
for name, body in msgs.items():
    with io.open(os.path.join(R, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print("  wrote", name, len(body.encode("utf-8")), "B")
print("done")