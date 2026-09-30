#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest.py — 项目L 随包自检：用合成样本验证 keygen.py 的逻辑正确性。

不需要真实目标即可运行，用于回答"脱敏后的脚本还跑得通吗"：

  python src/selftest.py

它构造一个具有相同形状的假 PE 载荷（内置公钥槽 + 两份文件头模板 + 同样的
VA→文件偏移映射），把 keygen.py 的配置指过去，然后执行一次完整签发，核对：

  1. 补丁产物与原样**等长**（等长替换：不动节表/重定位/PE 结构）
  2. 差异字节**只落在**公钥槽内（本案例的整个补丁就是这 64 字节）
  3. 新公钥在产物中出现且仅出现一次；原公钥已消失
  4. 两份文件头模板逐字节保留（签发文件仍以模板头开头）
  5. device_fp 原样写入且不含 "0x" 前缀（带前缀会被逐字节比较判 code=6）
  6. 签名与 digest 自校验通过；宽限死线 = 签名 date 头 + 1209600
"""
import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("kg", os.path.join(HERE, "keygen.py"))
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)

FAKE_PUB = "ab" * 32
PUB_OFF, SIG_OFF, INI_OFF, DELTA = 0x2000, 0x4000, 0x5000, 0x100000
SIG_HDR = b"# fake license proof v1 " + b"x" * 78 + b"\n"
INI_HDR = b"# fake license store v1 " + b"y" * 30 + b"\n"
FP = "0123456789abcdef"

checks = []


def chk(name, ok):
    checks.append((name, bool(ok)))
    print("  [%s] %s" % ("OK  " if ok else "FAIL", name))


def main():
    assert len(SIG_HDR) == 103 and len(INI_HDR) == 55, "fixture header sizes"
    work = tempfile.mkdtemp(prefix="projectL-selftest-")
    samples = os.path.join(work, "samples")
    out = os.path.join(work, "out")
    os.makedirs(samples)
    os.makedirs(out)

    buf = bytearray(0x10000)
    buf[PUB_OFF:PUB_OFF + 64] = FAKE_PUB.encode()
    buf[SIG_OFF:SIG_OFF + 103] = SIG_HDR
    buf[INI_OFF:INI_OFF + 55] = INI_HDR
    exe = os.path.join(samples, "fake.orig.exe")
    open(exe, "wb").write(bytes(buf))

    k.ORIG_EXE = exe
    k.OUT = out
    k.PATCHED_EXE = os.path.join(out, "fake.patched.exe")
    k.KEYS_FILE = os.path.join(out, "mint_keys.json")
    k.SIG_FILE = os.path.join(out, "license.sig")
    k.INI_FILE = os.path.join(out, "license.ini")
    k.BAKED_PUBKEY_HEX = FAKE_PUB
    k.PUBKEY_OFF = PUB_OFF
    k.SIG_HEADER_VA = SIG_OFF + DELTA
    k.INI_HEADER_VA = INI_OFF + DELTA
    k.VA_DELTA = DELTA
    k.VENDOR_HOST = "api.example.test"
    k.LICENSE_PATH = "/v1/accounts/acme/licenses/actions/validate-key"
    k.PRODUCT_DIRNAME = "fakeapp"
    k.EXE_NAME = "fakeapp.exe"
    k.CANON_MD5 = hashlib.md5(bytes(buf)).hexdigest()

    print("  placeholder guard: unfilled() -> %s (expected empty)" % k.unfilled())
    chk("all redacted placeholders accepted once filled", not k.unfilled())

    pub = k.mint(FP, "lifetime", 335, 0, None, 3650)

    orig = bytes(buf)
    data = open(k.PATCHED_EXE, "rb").read()
    diff = [i for i in range(len(orig)) if orig[i] != data[i]]
    chk("patched exe is byte-length identical to the sample", len(data) == len(orig))
    chk("diff confined to the 64-byte pubkey slot",
        bool(diff)
        and min(diff) >= PUB_OFF
        and max(diff) <= PUB_OFF + 63
        and data[PUB_OFF:PUB_OFF + 64] == pub.hex().encode())
    chk("new pubkey present exactly once", data.count(pub.hex().encode()) == 1)
    chk("baked pubkey removed", data.find(FAKE_PUB.encode()) == -1)
    chk("both .rdata header templates untouched by the patch",
        data[SIG_OFF:SIG_OFF + 103] == SIG_HDR and data[INI_OFF:INI_OFF + 55] == INI_HDR)

    blob = open(k.SIG_FILE, "rb").read()
    ini = open(k.INI_FILE, "rb").read()
    chk("minted proof starts with the template header", blob[:103] == SIG_HDR)
    chk("minted store starts with the template header", ini[:55] == INI_HDR)
    chk("device_fp written bare, no 0x prefix",
        ("device_fp = %s\n" % FP).encode() in ini and b"0x" not in ini)
    chk("license key generated at runtime, not a shipped literal",
        b"license_key = FAKEAP-LAB-" in ini)

    print("  independent re-verification of the minted proof:")
    chk("signature + digest re-verify offline", k.verify() == 0)

    import base64
    import json as _json
    from email.utils import parsedate_to_datetime
    fields = {}
    for line in blob.decode().split("\n"):
        if "=" in line and not line.startswith("#"):
            a, b = line.split("=", 1)
            fields[a.strip()] = b.strip()
    body = _json.loads(base64.b64decode(fields["body_b64"]))
    chk("updates=lifetime carried into the signed body",
        body["data"]["attributes"]["metadata"]["updates"] == "lifetime")
    date_ts = int(parsedate_to_datetime(fields["date"]).timestamp())
    ahead = date_ts - int(time.time())
    chk("signed date header forward-dated ~3650d (client has no skew check)",
        3640 * 86400 < ahead < 3660 * 86400)
    print("  signed date header -> %d; grace deadline -> %d (+%dd)"
          % (date_ts, date_ts + k.GRACE_SECONDS, (date_ts + k.GRACE_SECONDS - int(time.time())) // 86400))

    bad = [n for n, ok in checks if not ok]
    print("")
    print("  %d/%d checks passed" % (len(checks) - len(bad), len(checks)))
    if bad:
        for n in bad:
            print("    FAIL: %s" % n)
        return 1
    print("  项目L 随包自检通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
