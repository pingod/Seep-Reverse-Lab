#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""项目L package verifier - no target binary needed.

Checks the shipped package against itself: the file manifest, the
checksums, and the exact facts the three documentation layers quote.

Usage: python verify_package.py [<case-dir>]
"""
import hashlib
import os
import re
import sys

CASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(CASE, "src")
sys.path.insert(0, SRC)

REQUIRED = [
    "README.txt", "README.nfo", "build.ps1", "SHA256SUMS.txt",
    "docs/reverse-engineering.md",
    "src/keygen.py", "src/selftest.py", "src/restore.ps1",
    "src/verify_package.py",
]

# (source, offset-in-hex, literal) facts quoted across the docs
FACTS = [
    ("PUBKEY_OFF", "0xB98733"),
    ("SIG_HEADER_VA", "0x140BA72DF"),
    ("INI_HEADER_VA", "0x140BA5418"),
    ("GRACE_SECONDS", "1209600"),
]
ADDRS = [
    "0x140B99733", "0x1404A2296", "0x1404A4A3E", "0x1406A451A", "0x1406D0845",
    "0x1406F02C0", "0x1406F030B", "0x127500", "0x140008885", "0x1404A06F8",
    "0x1404A21C8", "0x140D43DBB", "0x140B998DD",
]


class R:
    def __init__(self):
        self.items = []

    def chk(self, name, ok, detail=""):
        self.items.append((name, bool(ok), detail))
        return bool(ok)

    def eq(self, name, got, want):
        return self.chk(name, got == want, "got %r want %r" % (got, want))


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


SHIPPED_EXT = {".cs", ".ps1", ".py", ".md", ".txt", ".nfo", ".json",
               ".yaml", ".yml", ".cmd", ".bat"}


def denylist_from_argv():
    """--denylist <path>: 'name<TAB>regex' lines, same format as build.ps1.

    Kept out of the archive deliberately -- the patterns identify the target.
    """
    args = sys.argv[1:]
    p = args[args.index("--denylist") + 1] if "--denylist" in args else None
    if not p or not os.path.isfile(p):
        return []
    out = []
    for line in read(p).splitlines():
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        parts = t.split("\t", 1) if "\t" in t else re.split(r"\s{2,}", t, 1)
        if len(parts) == 2:
            out.append((parts[0].strip(), parts[1].strip()))
    return out


def main():
    r = R()
    txt = read(os.path.join(CASE, "README.txt"))
    nfo = read(os.path.join(CASE, "README.nfo"))
    doc = read(os.path.join(CASE, "docs", "reverse-engineering.md"))

    # 1 - manifest
    for rel in REQUIRED:
        r.chk("present: %s" % rel, os.path.isfile(os.path.join(CASE, *rel.split("/"))))

    # 2 - checksums: every shipped file listed, and hashes correct
    sums_path = os.path.join(CASE, "SHA256SUMS.txt")
    lines = read(sums_path).splitlines()
    listed = {}
    for ln in lines:
        m = re.match(r"^([0-9a-f]{64})  (.+)$", ln)
        if m:
            listed[m.group(2).replace("\\", "/")] = m.group(1)
    on_disk = []
    stray = []
    for root, dirs, files in os.walk(CASE):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), CASE).replace("\\", "/")
            if rel == "SHA256SUMS.txt":
                continue
            if os.path.splitext(fn)[1].lower() in SHIPPED_EXT:
                on_disk.append(rel)
            else:
                stray.append(rel)
    r.chk("no non-text artifact shipped (binaries/evidence/keys)", not stray,
          ", ".join(stray))
    r.eq("SHA256SUMS covers every shipped file", sorted(on_disk), sorted(listed))
    bad = [rel for rel, want in listed.items()
           if sha256(os.path.join(CASE, *rel.split("/"))) != want]
    r.chk("SHA256SUMS hashes all match (no stale entry)", not bad, ", ".join(bad))

    # 3 - build.ps1 and restore.ps1 must be parseable
    import subprocess
    import tempfile
    for ps in ("build.ps1", os.path.join("src", "restore.ps1")):
        ap = os.path.abspath(os.path.join(CASE, ps))
        # pass the path via a UTF-8 script file: -Command with a non-ASCII
        # literal gets mangled by the console codepage
        fd, tmp = tempfile.mkstemp(suffix=".ps1")
        # utf-8-sig: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, which
        # mangles the non-ASCII case directory and the path stops resolving
        with os.fdopen(fd, "wb") as f:
            f.write(("$e = $null\n"
                     "[void][System.Management.Automation.Language.Parser]"
                     "::ParseFile('%s', [ref]$null, [ref]$e)\n"
                     "if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }\n"
                     % ap.replace("'", "''")).encode("utf-8-sig"))
        p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy",
                            "Bypass", "-File", tmp], capture_output=True, text=True)
        os.unlink(tmp)
        r.chk("%s parses" % ps, p.returncode == 0,
              (p.stdout or p.stderr).strip()[:200])

    # 4 - quoted facts agree across README.txt / README.nfo / docs / keygen.py
    kg = read(os.path.join(SRC, "keygen.py"))
    for name, lit in FACTS:
        m = re.search(r"^%s\s*=\s*(\S+)" % name, kg, re.M)
        r.chk("keygen.py defines %s" % name, m is not None)
        if m:
            r.eq("%s value" % name, m.group(1).lower(), lit.lower())
    for addr in ADDRS:
        # docs quote these as IDA names (sub_/byte_), so match the digits only
        key = addr.lower().lstrip("0x")
        where = [n for n, s in (("README.txt", txt), ("README.nfo", nfo),
                                ("docs", doc), ("keygen.py", kg))
                 if key in s.lower()]
        r.chk("%s quoted (%s)" % (addr, "+".join(where) or "MISSING"),
              "docs" in where)

    # 5 - the package's own numeric claims
    r.chk("14-day grace stated in every layer",
          all(s in txt and s in nfo and s in doc for s in ("1209600",)))
    r.chk("64-byte / 60-differ anchor size stated", "60" in txt and "60" in nfo)
    st = read(os.path.join(SRC, "selftest.py"))
    n_chk = len(re.findall(r"^\s+chk\(", st, re.M))
    r.eq("selftest.py check count", n_chk, 13)
    r.chk("README quotes the real self-test count",
          ("%d assertions" % n_chk) in txt and ("%d checks" % n_chk) in txt)
    r.chk("redaction placeholders used, no literal secrets",
          "<REDACTED_" in kg and not re.search(r"seed=0x[0-9a-f]{16}", kg))
    # Target identity is checked against the caller-supplied denylist only:
    # the patterns themselves must never appear inside a shipped file.
    dl = denylist_from_argv()
    if dl:
        corpus = [("README.txt", txt), ("README.nfo", nfo), ("docs", doc),
                  ("keygen.py", kg), ("selftest.py", st),
                  ("restore.ps1", read(os.path.join(SRC, "restore.ps1"))),
                  ("build.ps1", read(os.path.join(CASE, "build.ps1")))]
        hits = ["%s@%s" % (label, src) for label, pat in dl
                for src, s in corpus if re.search(pat, s, re.I)]
        r.chk("target denylist: %d pattern(s), zero hits in shipped text" % len(dl),
              not hits, ", ".join(hits[:4]))
    else:
        print("  [SKIP] no --denylist given: target-identity check not run")

    # 6 - keygen is importable and the PoC math is real (independent of the fixture)
    import importlib.util
    spec = importlib.util.spec_from_file_location("kg", os.path.join(SRC, "keygen.py"))
    k = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(k)
    r.eq("grace constant", k.GRACE_SECONDS, 14 * 86400)
    r.eq("anchor offset", hex(k.PUBKEY_OFF), "0xb98733")
    r.eq("anchor slot length", k.PUBKEY_LEN, 64)
    r.eq("VA->file delta", k.VA_DELTA, 0x140000000 + 0x1000)
    try:
        from nacl.signing import VerifyKey
        r.chk("nacl importable (needed by selftest)", True)
    except ImportError:
        r.chk("nacl importable (needed by selftest)", False, "pip install pynacl")

    fails = [i for i in r.items if not i[1]]
    for name, ok, detail in r.items:
        print("  [%s] %s%s" % ("OK  " if ok else "FAIL", name,
                               "" if ok or not detail else "  <- " + detail))
    print("\n  %d/%d package checks passed" % (len(r.items) - len(fails), len(r.items)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
