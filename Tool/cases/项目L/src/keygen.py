#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keygen.py — 项目L 客户端授权旁路 PoC（信任锚替换 + 离线证明自签）.

本脚本是**脱敏版**研究样本。要直接运行，需自备目标样本并填写下方 CONFIG 中
以尖括号标注的占位值（脱敏规范见 README.txt 的"脱敏说明"）。

流程（全部规格来自静态分析 + 运行期插桩，见 docs/reverse-engineering.md）：
  1. 生成/复用 Ed25519 密钥对（out/mint_keys.json，除非 --newkey）
  2. 就地等长替换内置许可公钥（64 位十六进制 ASCII，位于文件偏移 PUBKEY_OFF）
  3. 自签离线许可证明 license.sig：
       header(103B) + schema/host/path/date/digest/signature/body_b64
       签名基串 = "host: H\\n" + "date: D\\n" + "digest: G"   （按 headers 顺序）
       digest = "sha-256=" + b64(sha256(body))；算法串固定 "ed25519"
  4. 生成 license.ini（10 键明文存储：设备指纹 + 有效期 + 显示缓存）
       关键：14 天离线宽限死线锚定在 license.sig 的已签名 `date` 头，
       而非 ini 字段 —— 因此 --sig-date-offset-days 决定离线存活时长。

用法：
  python keygen.py --check-config          # 检查占位值是否已填写
  python keygen.py --mint                  # 生成 out/<product>.patched.exe + 两份产物
  python keygen.py --mint --no-fp          # 不写设备指纹（门控安全路径）
  python keygen.py --deploy                # 下发产物到 %APPDATA%\\<product>（自动备份）
  python keygen.py --install-exe           # 备份已安装 exe 并原位打补丁
  python keygen.py --verify                # 本地自校验已签发的证明

依赖：cryptography（Ed25519）。仅在本机自有副本上做实验。
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import time
import uuid as uuidlib
from email.utils import formatdate

# ============================================================================
# CONFIG —— 尖括号值需自行替换（脱敏项）
# ============================================================================
BAKED_PUBKEY_HEX = "<REDACTED_BAKED_PUBKEY>"   # 目标内置许可公钥：64 位小写十六进制 ASCII
VENDOR_HOST = "<vendor-host>"                  # 证明中的 host 头（参与签名基串）
LICENSE_PATH = "/v1/accounts/<vendor-account>/licenses/actions/validate-key"
PRODUCT_DIRNAME = "<product>"                  # %APPDATA%\<product> / %LOCALAPPDATA%\<product>
EXE_NAME = "<product>.exe"                     # 已安装可执行文件名
LICENSEE = "Seep Reverse Lab"
EDITION = "standard"
QUOTA = 5

# ---- 地址级事实（与目标版本绑定，来自静态分析，无需替换） ------------------
PUBKEY_OFF = 0xB98733            # 文件偏移（VA 0x140B99733 - imagebase - 0x1000）
PUBKEY_LEN = 64
SIG_HEADER_VA = 0x140BA72DF      # 证明文件头模板，103 字节
INI_HEADER_VA = 0x140BA5418      # ini 文件头模板，55 字节
VA_DELTA = 0x140000000 + 0x1000
GRACE_SECONDS = 1209600          # 14 天；全二进制仅出现一次（0x1406F030B）

# ---- 判定语义（实测确认） --------------------------------------------------
# 设备指纹 = FNV-1a-64(MachineGuid 字符串) 的小写十六进制，16 字符，**无 "0x" 前缀**。
#   推导 sub_1404A2108；比较 sub_140008885（逐字节严格相等）。
#   带前缀或不匹配都会在验签**之前**落 code=6（device mismatch）。
# updates 映射 sub_1404A60EB：strict->0 / rollback->1 / lifetime->2 / 其它->3。
#   过期检查只在 updates==3 分支执行，故 lifetime 下 expiration 不参与判定。
UPDATES_DEFAULT = "lifetime"
EXPIRY_DAYS = 335                # 建议落在 (now, now+400d)
SIG_DATE_OFFSET_DEFAULT = 3650   # 日期头前推天数：宽限死线 = date + 14d，无 skew 校验
CANON_MD5 = "<sample-md5>"       # 样本指纹校验，防对错版本下手

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
SAMPLES = os.path.join(CASE, "samples")
OUT = os.path.join(CASE, "out")
ORIG_EXE = os.path.join(SAMPLES, EXE_NAME.replace(".exe", ".orig.exe"))
PATCHED_EXE = os.path.join(OUT, EXE_NAME.replace(".exe", ".patched.exe"))
KEYS_FILE = os.path.join(OUT, "mint_keys.json")
SIG_FILE = os.path.join(OUT, "license.sig")
INI_FILE = os.path.join(OUT, "license.ini")

APPDATA_DIR = os.path.join(os.environ.get("APPDATA", ""), PRODUCT_DIRNAME)
INSTALL_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), PRODUCT_DIRNAME)

PLACEHOLDER_RE = re.compile(r"<[A-Za-z0-9_-]+>")


def log(*a):
    print(*a)


def unfilled():
    """返回仍为占位状态的配置项。"""
    bad = []
    if PLACEHOLDER_RE.search(BAKED_PUBKEY_HEX) or len(BAKED_PUBKEY_HEX) != PUBKEY_LEN:
        bad.append("BAKED_PUBKEY_HEX")
    if PLACEHOLDER_RE.search(VENDOR_HOST):
        bad.append("VENDOR_HOST")
    if PLACEHOLDER_RE.search(LICENSE_PATH):
        bad.append("LICENSE_PATH")
    if PLACEHOLDER_RE.search(PRODUCT_DIRNAME):
        bad.append("PRODUCT_DIRNAME / EXE_NAME")
    if PLACEHOLDER_RE.search(CANON_MD5):
        bad.append("CANON_MD5")
    return bad


def require_config(strict=True):
    bad = unfilled()
    if bad and strict:
        log("FATAL: 以下脱敏占位值尚未填写：%s" % ", ".join(bad))
        log("       参见 README.txt 的『脱敏说明』与 docs/reverse-engineering.md 的地址级事实。")
        sys.exit(3)
    return bad


def fnv1a64(s: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in s:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def machine_guid():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
            return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        return None


def device_fp():
    mg = machine_guid()
    if not mg:
        return None
    return "%016x" % fnv1a64(mg.encode())


def get_keys(new=False):
    os.makedirs(OUT, exist_ok=True)
    if os.path.isfile(KEYS_FILE) and not new:
        d = json.load(open(KEYS_FILE))
        return bytes.fromhex(d["priv"]), bytes.fromhex(d["pub"])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    raw_pub = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    json.dump({"priv": raw_priv.hex(), "pub": raw_pub.hex()}, open(KEYS_FILE, "w"), indent=1)
    log("[keys] 生成新密钥对 -> %s" % KEYS_FILE)
    return raw_priv, raw_pub


def sign_ed25519(raw_priv, msg: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(raw_priv).sign(msg)


def verify_ed25519(raw_pub, msg: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def read_exe():
    if not os.path.isfile(ORIG_EXE):
        log("FATAL: 缺少样本 %s" % ORIG_EXE)
        sys.exit(2)
    data = open(ORIG_EXE, "rb").read()
    md5 = hashlib.md5(data).hexdigest()
    if not PLACEHOLDER_RE.search(CANON_MD5) and md5 != CANON_MD5:
        log("FATAL: 样本 MD5 不符：%s（期望 %s）—— 版本不同则地址级常量全部失效" % (md5, CANON_MD5))
        sys.exit(2)
    return data


def build_patched_exe(raw_pub):
    old = BAKED_PUBKEY_HEX.encode()
    data = bytearray(read_exe())
    if data.find(old) != PUBKEY_OFF or data.find(old, PUBKEY_OFF + 1) != -1:
        log("FATAL: 内置公钥锚点不在预期偏移或不唯一（样本版本不符？）")
        sys.exit(2)
    hexstr = raw_pub.hex().encode()
    assert len(hexstr) == PUBKEY_LEN
    data[PUBKEY_OFF:PUBKEY_OFF + PUBKEY_LEN] = hexstr
    os.makedirs(OUT, exist_ok=True)
    open(PATCHED_EXE, "wb").write(bytes(data))
    log("[patch] %s" % PATCHED_EXE)
    log("[patch] 信任锚 %d 字节等长替换 -> %s" % (PUBKEY_LEN, hexstr.decode()))
    return bytes(data)


def header_bytes(va, size, tag):
    d = read_exe()
    off = va - VA_DELTA
    h = d[off:off + size]
    if not (h.startswith(b"# ") and h.endswith(b"\n")) or h[:-1].find(b"\x00") != -1:
        log("FATAL: %s 文件头模板取数异常（偏移 0x%X）" % (tag, off))
        sys.exit(2)
    return h


def make_license_key():
    part = lambda: int.from_bytes(os.urandom(2), "big")
    return "%s-LAB-%04X-%04X-%04X" % (PRODUCT_DIRNAME[:6].upper(), part(), part(), part())


def mint(fingerprint, updates, expiry_days, lv_offset_days=0, act_offset_days=None,
         sig_date_offset_days=SIG_DATE_OFFSET_DEFAULT, license_key=None):
    require_config()
    raw_priv, raw_pub = get_keys()
    build_patched_exe(raw_pub)

    now = int(time.time())
    lv = now + lv_offset_days * 86400
    exp_date = time.gmtime(now + expiry_days * 86400)
    expiry = time.strftime("%Y-%m-%dT00:00:00.000Z", exp_date)
    expiry_ts = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d", exp_date), "%Y-%m-%d"))
                    - time.timezone)
    # 宽限死线 = 证明的 date 头 + GRACE_SECONDS（fill_result sub_1406F02C0 内
    # `*(a2+104) + 1209600`）。该日期只被**我们自己的签名**覆盖，且客户端不做
    # 时效/偏差校验 => 前推日期即 1:1 外推死线；反向回拨则立即 code=2。
    act = expiry_ts if act_offset_days is None else now + act_offset_days * 86400
    date_ts = now + sig_date_offset_days * 86400
    date_hdr = formatdate(timeval=date_ts, localtime=False, usegmt=True)
    license_id = str(uuidlib.uuid4())
    license_key = license_key or make_license_key()

    meta_scope = {}
    if fingerprint:
        meta_scope["fingerprint"] = fingerprint
    body_obj = {
        "meta": {"code": "VALID", "scope": meta_scope},
        "data": {
            "id": license_id,
            "attributes": {
                "expiry": expiry,
                "key": license_key,
                "metadata": {"licensee": LICENSEE, "edition": EDITION, "updates": updates},
            },
        },
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()
    digest = "sha-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
    headers_list = "host date digest"
    signing_base = ("host: %s\n" % VENDOR_HOST) + ("date: %s\n" % date_hdr) + ("digest: %s" % digest)
    sig = sign_ed25519(raw_priv, signing_base.encode())
    sig_b64 = base64.b64encode(sig).decode()
    signature_value = 'algorithm="ed25519",signature="%s",headers="%s"' % (sig_b64, headers_list)

    sig_lines = [
        "schema = 1",
        "host = %s" % VENDOR_HOST,
        "path = %s" % LICENSE_PATH,
        "date = %s" % date_hdr,
        "digest = %s" % digest,
        "signature = %s" % signature_value,
        "body_b64 = %s" % base64.b64encode(body).decode(),
    ]
    sig_blob = header_bytes(SIG_HEADER_VA, 103, "proof") + ("\n".join(sig_lines) + "\n").encode()
    open(SIG_FILE, "wb").write(sig_blob)

    keys = [
        "schema = 1",
        "uuid = %s" % license_id,
        "install_id = %s" % uuidlib.uuid4().hex,
        "license_key = %s" % license_key,
        "updates = %s" % updates,
        "expiration = %d" % expiry_ts,
        "last_validated = %d" % lv,
        "quota = %d" % QUOTA,
        "activated = %d" % act,
    ]
    if fingerprint:
        keys.append("device_fp = %s" % fingerprint)
    ini_blob = header_bytes(INI_HEADER_VA, 55, "store") + ("\n".join(keys) + "\n").encode()
    open(INI_FILE, "wb").write(ini_blob)

    log("[mint] license.sig %d B + license.ini %d B" % (len(sig_blob), len(ini_blob)))
    log("[mint] 新公钥        = %s" % raw_pub.hex())
    log("[mint] date 头       = %s（%+dd；宽限死线 = date + %ds -> %d）"
        % (date_hdr, sig_date_offset_days, GRACE_SECONDS, date_ts + GRACE_SECONDS))
    log("[mint] expiration    = %s (ts=%d, %+dd)" % (expiry, expiry_ts, expiry_days))
    log("[mint] last_validated= %d（仅显示，%+dd）" % (lv, lv_offset_days))
    log("[mint] activated     = %d（ini 缓存，非宽限锚点）" % act)
    log("[mint] 自校验        = %s"
        % ("OK" if verify_ed25519(raw_pub, signing_base.encode(), sig) else "FAIL"))
    if fingerprint:
        log("[mint] device_fp     = %s（本机实时派生）" % fingerprint)
    return raw_pub


def deploy():
    if not (os.path.isfile(SIG_FILE) and os.path.isfile(INI_FILE)):
        log("FATAL: 先 --mint（license.sig / license.ini 不存在）")
        sys.exit(2)
    os.makedirs(APPDATA_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    for name in ("license.ini", "license.sig"):
        live = os.path.join(APPDATA_DIR, name)
        if os.path.isfile(live):
            bak = live + ".bak-" + ts
            shutil.copy2(live, bak)
            log("[deploy] 备份 %s -> %s" % (name, os.path.basename(bak)))
        shutil.copy2(os.path.join(OUT, name), live)
        log("[deploy] %s -> %s" % (name, live))
    log("[deploy] 提示：目标为单实例应用，注入/插桩前先结束既有进程。")


def install_exe():
    require_config()
    live = os.path.join(INSTALL_DIR, EXE_NAME)
    if not os.path.isfile(live):
        log("FATAL: 未找到已安装 exe：%s" % live)
        sys.exit(2)
    md5 = hashlib.md5(open(live, "rb").read()).hexdigest()
    bak = live + ".orig-backup"
    if not os.path.isfile(bak):
        shutil.copy2(live, bak)
        log("[install] 备份 -> %s" % bak)
    if not PLACEHOLDER_RE.search(CANON_MD5) and md5 == CANON_MD5:
        open(live, "wb").write(open(PATCHED_EXE, "rb").read())
        log("[install] 原位打补丁：%s" % live)
    else:
        log("[install] 已安装 exe md5=%s 与样本不符，保持原样（可能已打过补丁）" % md5)
    got = open(live, "rb").read()
    hexstr = json.load(open(KEYS_FILE))["pub"].encode()
    pos = got.find(hexstr)
    old = got.find(BAKED_PUBKEY_HEX.encode())
    log("[install] 校验：新公钥 @0x%X；原公钥 %s"
        % (pos, "已移除" if old == -1 else "仍在 @0x%X" % old))


def verify():
    raw_priv, raw_pub = get_keys()
    fields = {}
    for line in open(SIG_FILE, "rb").read().decode("utf-8", "replace").split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    base = ("host: %s\n" % fields["host"]) + ("date: %s\n" % fields["date"]) + ("digest: %s" % fields["digest"])
    sig = base64.b64decode(re.search(r'signature="([^"]+)"', fields["signature"]).group(1))
    ok = verify_ed25519(raw_pub, base.encode(), sig)
    body = base64.b64decode(fields["body_b64"])
    digest_ok = hashlib.sha256(body).digest() == base64.b64decode(fields["digest"].split("=", 1)[1])
    log("[verify] signature = %s" % ("OK" if ok else "FAIL"))
    log("[verify] digest    = %s" % ("OK" if digest_ok else "FAIL"))
    log("[verify] date 头   = %s（宽限死线 = date + %ds）" % (fields["date"], GRACE_SECONDS))
    log("[verify] body      = %s" % body.decode())
    return 0 if (ok and digest_ok) else 1


def main():
    ap = argparse.ArgumentParser(description="项目L 授权旁路 PoC（脱敏版）")
    ap.add_argument("--mint", action="store_true")
    ap.add_argument("--newkey", action="store_true", help="轮换自签密钥对")
    ap.add_argument("--no-fp", action="store_true", help="不写设备指纹/指纹声明")
    ap.add_argument("--fp", default=None, help="显式指定设备指纹（16 位十六进制，无 0x 前缀）")
    ap.add_argument("--key", default=None, dest="license_key", help="显式指定授权码字串")
    ap.add_argument("--updates", default=UPDATES_DEFAULT,
                    help="strict|rollback|lifetime（lifetime 下不校验 expiration）")
    ap.add_argument("--expiry-days", type=int, default=EXPIRY_DAYS)
    ap.add_argument("--lv-offset-days", type=int, default=0, dest="lv_offset_days",
                    help="平移 ini 的 last_validated（仅影响显示）")
    ap.add_argument("--act-offset-days", type=int, default=None, dest="act_offset_days",
                    help="平移 ini 的 activated（显示缓存，非宽限锚点）")
    ap.add_argument("--sig-date-offset-days", type=int, default=SIG_DATE_OFFSET_DEFAULT,
                    dest="sig_date_offset_days",
                    help="平移已签证明的 date 头：宽限死线 = date + 14d（负值可复现 code=2）")
    ap.add_argument("--deploy", action="store_true")
    ap.add_argument("--install-exe", action="store_true", dest="install_exe")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--check-config", action="store_true", dest="check_config")
    a = ap.parse_args()

    if a.check_config:
        bad = unfilled()
        if bad:
            log("[config] 待填写的脱敏占位项：%s" % ", ".join(bad))
        else:
            log("[config] 全部就绪")
        return 0 if not bad else 1

    if a.newkey:
        get_keys(new=True)
        log("[keys] 已轮换 -> %s" % KEYS_FILE)
    if a.mint:
        if a.no_fp:
            fp = None
        elif a.fp:
            fp = a.fp
        else:
            fp = device_fp()
            if not fp:
                log("FATAL: 读不到 MachineGuid；请用 --fp 显式给出或改用 --no-fp")
                sys.exit(2)
        mint(fp, a.updates, a.expiry_days, a.lv_offset_days, a.act_offset_days,
             a.sig_date_offset_days, a.license_key)
    if a.deploy:
        deploy()
    if a.install_exe:
        install_exe()
    if a.verify:
        return verify()
    return 0


if __name__ == "__main__":
    sys.exit(main())
