#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tessoa 授权补丁工具 — macOS 版（双击 tessoa-patch.command 运行）
适用于 tessoa v0.28.1（arm64 Mach-O64）

与 Windows 版的区别：
  - macOS 强制代码签名：改字节后必须 ad-hoc 重签（codesign --force --sign -）
    才能启动；Windows 只需等长替换公钥，无需重签。
  - 设备指纹 = FNV-1a-64(IOPlatformUUID as-is)，而非 Windows 的 MachineGuid。
  - 许可证部署到 ~/Library/Application Support/<name>/。

功能（按钮）:
  [状态]    查看 app/binary/许可证当前状态
  [完整补丁] 结束进程 -> 备份 -> 等长替换公钥 -> ad-hoc 重签 -> 自签许可证 -> 部署
  [验证]    校验本工具签发的 license.sig
  [还原]    从工具目录备份恢复 binary -> 重签 -> 删除已部署许可证

密钥与中间产物存于本工具目录（与 .command 同级，所有项目文件集中于此）。

命令行模式（SSH 下可用）:
  python3 tessoa_mac_patcher.py status|patch|verify|restore|gui
"""

import os
import re
import sys
import json
import base64
import calendar
import hashlib
import shutil
import time
import uuid as uuidlib
import threading
import traceback
import subprocess
from email.utils import formatdate
from collections import Counter

# ============================================================================
# CONFIG — 产品名恒从 hex 派生（终端渲染会错乱该 6 字母名）
# ============================================================================
NAME = bytes.fromhex("746573736f61").decode()
ORIG_PUB = "52dde2592618463044d4b602535494c2771dd08a5c3a2c0ca6804bb34e6f7167"
LEGACY_PUB = "98338fe31e49116752409f0a573e581a38f616b6752f69a9e0139bc230664bc8"
PUBKEY_LEN = 64
GRACE_SECONDS = 1209600
SIG_DATE_OFFSET_DAYS = 3650
VENDOR_HOST = "api.keygen.sh"
LICENSE_PATH = "/v1/accounts/" + NAME + "/licenses/actions/validate-key"
QUOTA = 5
EXPIRY = "2036-10-05"

# 密钥对不内嵌（与 Windows 版一致）：首次运行自动生成本机 Ed25519 密钥对，
# 存于工具目录 mint_keys.json（gitignore）。历史公钥仅用于识别已补丁状态。
KNOWN_PUBS = (ORIG_PUB, LEGACY_PUB)

# v0.28.1 已知锚点（内容扫描失败时的回退）
FALLBACK_PUB_OFF = 0x821F76
FALLBACK_PROOF_OFF = 0x82E2F7   # 行首（含尾换行共 103B）
FALLBACK_STORE_OFF = 0x82D649   # 行首（含尾换行共 55B）

HOME = os.path.expanduser("~")
APP = "/Applications/" + NAME + ".app"
BIN = os.path.join(APP, "Contents", "MacOS", NAME)
LIVE_LICENSE_DIR = os.path.join(HOME, "Library", "Application Support", NAME)
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_BIN = os.path.join(TOOL_DIR, NAME + ".orig-backup")
KEYS_FILE = os.path.join(TOOL_DIR, "mint_keys.json")
SIG_FILE = os.path.join(TOOL_DIR, "license.sig")
INI_FILE = os.path.join(TOOL_DIR, "license.ini")

ENTITLEMENTS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.network.client</key><true/>
  <key>com.apple.security.network.server</key><true/>
</dict>
</plist>
"""

# ============================================================================
# Crypto
# ============================================================================
def fnv1a64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h

def io_platform_uuid():
    r = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                       capture_output=True, text=True)
    m = re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-F-]+)"', r.stdout)
    return m.group(1) if m else None

def get_device_fp():
    u = io_platform_uuid()
    return ("%016x" % fnv1a64(u.encode())) if u else None

def get_keys():
    """本机密钥对；首次运行时生成并存 mint_keys.json（不入库）。"""
    if os.path.isfile(KEYS_FILE):
        d = json.load(open(KEYS_FILE, encoding="utf-8"))
        return bytes.fromhex(d["priv"]), bytes.fromhex(d["pub"])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    with open(KEYS_FILE, "w") as f:
        json.dump({"priv": priv, "pub": pub}, f, indent=1)
    return bytes.fromhex(priv), bytes.fromhex(pub)

def my_pub():
    return get_keys()[1].hex()

def sign_ed25519(raw_priv, msg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(raw_priv).sign(msg)

def verify_ed25519(raw_pub, msg, sig):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False

# ============================================================================
# Anchors（版本无关：内容扫描 + 固定偏移回退）
# ============================================================================
def find_pubkey(data):
    """返回 (offset, state)：state ∈ orig/legacy/mine；找不到返回 None。"""
    for pub, state in ((ORIG_PUB, "orig"), (LEGACY_PUB, "legacy"),
                       (my_pub(), "mine")):
        i = data.find(pub.encode())
        if i != -1 and data.find(pub.encode(), i + 1) == -1:
            return i, state
    return None

def read_pub_at(data, off):
    seg = data[off:off + PUBKEY_LEN]
    try:
        s = seg.decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if re.fullmatch(r"[0-9a-f]{64}", s) else None

def find_header(data, key, size, fallback_off):
    i = data.find(b"# " + NAME.encode() + key)
    if i != -1:
        j = data.find(b"\n", i)
        if j != -1 and j - i + 1 == size:
            return i
    line = data[fallback_off:fallback_off + size]
    if line.endswith(b"\n") and line.startswith(b"# " + NAME.encode()):
        return fallback_off
    return None

def detect_version(data):
    c = Counter()
    for m in re.finditer(rb"(\d+\.\d+\.\d+)", data):
        s = m.group(1).decode()
        p = s.split(".")
        if len(p) == 3 and all(x.isdigit() for x in p) and int(p[1]) < 50:
            c[s] += 1
    if not c:
        return "?"
    return c.most_common(1)[0][0]

def codesign_flags():
    r = subprocess.run(["codesign", "-dvvv", BIN], capture_output=True, text=True)
    for line in (r.stdout + r.stderr).splitlines():
        if "flags=" in line:
            return line.strip()
    return "unknown"

def resign_app():
    ent = os.path.join(TOOL_DIR, "ent.plist")
    with open(ent, "w") as f:
        f.write(ENTITLEMENTS)
    r = subprocess.run(["codesign", "--force", "--sign", "-",
                        "--entitlements", ent, APP],
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[:300]

# ============================================================================
# Operations
# ============================================================================
def kill_process():
    try:
        subprocess.run(["pkill", "-f", BIN], capture_output=True, timeout=10)
        time.sleep(1)
    except Exception:
        pass

def check_status():
    if not os.path.isfile(BIN):
        return "❌ 未找到 binary:\n   " + BIN
    d = open(BIN, "rb").read()
    lines = []
    lines.append("binary : %.1f MB  md5=%s…" % (len(d) / 1048576,
                                                 hashlib.md5(d).hexdigest()[:16]))
    lines.append("版本   : v%s" % detect_version(d))
    lines.append("签名   : %s" % codesign_flags())
    r = find_pubkey(d)
    if r is None:
        pub = read_pub_at(d, FALLBACK_PUB_OFF)
        if pub:
            lines.append("信任锚 : %s (公钥槽 @0x%X, 未知公钥)" %
                         ("⚠️ 需处理" if pub == ORIG_PUB else "❓", FALLBACK_PUB_OFF))
        else:
            lines.append("信任锚 : ❓ 无法定位（公钥锚点缺失）")
    else:
        off, state = r
        label = {"orig": "⚠️ 原始（厂商公钥）", "legacy": "🔸 旧版自签",
                 "mine": "✅ 已补丁（本工具公钥）"}[state]
        lines.append("信任锚 : %s @0x%X" % (label, off))
    if os.path.isfile(BACKUP_BIN):
        lines.append("备份   : %s (%.1f MB)" % (
            os.path.basename(BACKUP_BIN), os.path.getsize(BACKUP_BIN) / 1048576))
    else:
        lines.append("备份   : 无（首次补丁将创建）")
    sig = os.path.isfile(os.path.join(LIVE_LICENSE_DIR, "license.sig"))
    ini = os.path.isfile(os.path.join(LIVE_LICENSE_DIR, "license.ini"))
    lines.append("许可   : %s" % ("✅ 已部署 (sig+ini)" if sig and ini
                                  else "⚠️ 未部署" if not (sig or ini)
                                  else "❓ 不完整 sig=%s ini=%s" % (sig, ini)))
    return "\n".join(lines)

def mint_license(log):
    """签发 license.sig / license.ini 到 TOOL_DIR，返回 (sig, signing_base)"""
    d = open(BIN, "rb").read()
    priv, pub = get_keys()

    sig_hdr_off = find_header(d, b" license proof", 103, FALLBACK_PROOF_OFF)
    ini_hdr_off = find_header(d, b" license store", 55, FALLBACK_STORE_OFF)
    if sig_hdr_off is None:
        raise RuntimeError("proof 头模板未找到")
    if ini_hdr_off is None:
        raise RuntimeError("store 头模板未找到")
    sig_hdr = d[sig_hdr_off:sig_hdr_off + 103]
    ini_hdr = d[ini_hdr_off:ini_hdr_off + 55]
    log("头模板: proof @0x%X (103B), store @0x%X (55B)" % (sig_hdr_off, ini_hdr_off))

    fp = get_device_fp()
    log("设备指纹: %s (FNV-1a-64(IOPlatformUUID))" % (fp or "N/A"))
    now = int(time.time())
    date_hdr = formatdate(timeval=now + SIG_DATE_OFFSET_DAYS * 86400,
                          localtime=False, usegmt=True)
    license_id = str(uuidlib.uuid4())
    p = lambda: int.from_bytes(os.urandom(2), "big")
    license_key = "%s-LAB-%04X-%04X-%04X" % (NAME[:6].upper(), p(), p(), p())

    scope = {"fingerprint": fp} if fp else {}
    body_obj = {
        "meta": {"code": "VALID", "scope": scope},
        "data": {"id": license_id, "attributes": {
            "expiry": EXPIRY + "T00:00:00.000Z",
            "key": license_key,
            "metadata": {"licensee": "Seep Reverse Lab",
                         "edition": "standard", "updates": "lifetime"}
        }}
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()
    digest = "sha-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
    signing_base = "host: %s\ndate: %s\ndigest: %s" % (VENDOR_HOST, date_hdr, digest)
    sig = sign_ed25519(priv, signing_base.encode())
    sig_b64 = base64.b64encode(sig).decode()

    sig_lines = [
        "schema = 1",
        "host = %s" % VENDOR_HOST,
        "path = %s" % LICENSE_PATH,
        "date = %s" % date_hdr,
        "digest = %s" % digest,
        'signature = algorithm="ed25519",signature="%s",headers="host date digest"' % sig_b64,
        "body_b64 = %s" % base64.b64encode(body).decode(),
    ]
    open(SIG_FILE, "wb").write(sig_hdr + ("\n".join(sig_lines) + "\n").encode())

    exp_ts = calendar.timegm(time.strptime(EXPIRY, "%Y-%m-%d"))
    ini_keys = [
        "schema = 1",
        "uuid = %s" % license_id,
        "install_id = %s" % uuidlib.uuid4().hex,
        "license_key = %s" % license_key,
        "updates = lifetime",
        "expiration = %d" % exp_ts,
        "last_validated = %d" % now,
        "quota = %d" % QUOTA,
        "activated = %d" % exp_ts,
    ]
    if fp:
        ini_keys.append("device_fp = %s" % fp)
    open(INI_FILE, "wb").write(ini_hdr + ("\n".join(ini_keys) + "\n").encode())

    log("✅ 许可证: %s" % license_key)
    log("   date 头: %s -> 宽限死线 = date + 14d" % date_hdr)
    return sig, signing_base

def do_patch_all(log):
    log("═══ 完整补丁 ═══")
    if not os.path.isfile(BIN):
        log("❌ 未找到 %s" % BIN)
        return False
    kill_process()
    log("已结束既有进程（若存在）")

    d = bytearray(open(BIN, "rb").read())
    r = find_pubkey(bytes(d))
    if r is None:
        pub = read_pub_at(bytes(d), FALLBACK_PUB_OFF)
        if pub:
            log("⚠️ 公钥槽 @0x%X 内容未知，按槽位处理" % FALLBACK_PUB_OFF)
            off = FALLBACK_PUB_OFF
        else:
            log("❌ 公钥锚点未定位——中止")
            return False
    else:
        off, state = r
        log("定位: 公钥锚点 @0x%X (%s)" % (
            off, {"orig": "原始", "legacy": "旧版自签", "mine": "已自签"}[state]))

    # 1. 备份当前 binary（保留最早的作为还原点）
    if not os.path.isfile(BACKUP_BIN):
        shutil.copy2(BIN, BACKUP_BIN)
        log("备份: %s (%.1f MB)" % (
            os.path.basename(BACKUP_BIN), os.path.getsize(BACKUP_BIN) / 1048576))
    else:
        log("备份已存在: %s" % os.path.basename(BACKUP_BIN))

    # 2. 替换公钥（幂等：目标恒为本工具公钥）
    mp = my_pub()
    d[off:off + PUBKEY_LEN] = mp.encode()
    open(BIN, "wb").write(bytes(d))
    log("✅ 公钥替换 @0x%X -> %s…" % (off, mp[:16]))

    # 3. ad-hoc 重签
    ok, msg = resign_app()
    if not ok:
        log("❌ codesign 重签失败: %s" % msg)
        return False
    log("✅ ad-hoc 重签: %s" % codesign_flags())

    # 4. 签发许可证
    sig, signing_base = mint_license(log)

    # 5. 部署
    os.makedirs(LIVE_LICENSE_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    for name in ("license.ini", "license.sig"):
        live = os.path.join(LIVE_LICENSE_DIR, name)
        if os.path.isfile(live):
            shutil.copy2(live, live + ".bak-" + ts)
        shutil.copy2(os.path.join(TOOL_DIR, name), live)
        log("✅ 部署: %s" % name)

    ok = verify_ed25519(bytes.fromhex(my_pub()), signing_base.encode(), sig)
    log("🔍 自校验: %s" % ("✅ OK" if ok else "❌ FAIL"))
    log("═══ 完成 ═══")
    return ok

def do_restore(log):
    log("═══ 还原 ═══")
    kill_process()
    if os.path.isfile(BACKUP_BIN):
        shutil.copy2(BACKUP_BIN, BIN)
        log("✅ 已还原 binary <- %s" % os.path.basename(BACKUP_BIN))
        ok, msg = resign_app()
        if not ok:
            log("❌ 还原后重签失败: %s" % msg)
            return False
        log("✅ 重签: %s" % codesign_flags())
    else:
        log("⚠️ 无备份可还原")
    for name in ("license.ini", "license.sig"):
        live = os.path.join(LIVE_LICENSE_DIR, name)
        if os.path.isfile(live):
            os.remove(live)
            log("✅ 已删除: %s" % name)
    log("═══ 完成 ═══")
    return True

def do_verify(log):
    if not os.path.isfile(SIG_FILE):
        log("❌ 缺少许可证文件（先执行补丁）")
        return False
    raw_pub = bytes.fromhex(my_pub())
    fields = {}
    for line in open(SIG_FILE, "rb").read().decode("utf-8", "replace").split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    base = "host: %s\ndate: %s\ndigest: %s" % (
        fields.get("host", ""), fields.get("date", ""), fields.get("digest", ""))
    m = re.search(r'signature="([^"]+)"', fields.get("signature", ""))
    if not m:
        log("❌ 无法解析 signature 字段")
        return False
    sig = base64.b64decode(m.group(1))
    ok = verify_ed25519(raw_pub, base.encode(), sig)
    try:
        body = base64.b64decode(fields.get("body_b64", ""))
        digest_ok = hashlib.sha256(body).digest() == \
            base64.b64decode(fields["digest"].split("=", 1)[1])
    except Exception:
        digest_ok = False
    log("签名: %s   摘要: %s" % ("✅ OK" if ok else "❌ FAIL",
                                 "✅ OK" if digest_ok else "❌ FAIL"))
    log("date: %s" % fields.get("date", ""))
    log("宽限死线 = date + %ds" % GRACE_SECONDS)
    try:
        log("body: %s" % base64.b64decode(fields.get("body_b64", "")).decode())
    except Exception:
        pass
    return ok and digest_ok

# ============================================================================
# GUI
# ============================================================================
def run_gui():
    import tkinter as tk
    from tkinter import scrolledtext

    root = tk.Tk()
    root.title(NAME + " 授权补丁工具 (macOS)")
    root.geometry("780x560")
    root.minsize(620, 420)

    sf = tk.Frame(root, bg="#f5f5f5", relief="sunken", bd=1)
    sf.pack(fill="x", padx=8, pady=(8, 4))
    status_var = tk.StringVar(value="加载中…")
    tk.Label(sf, textvariable=status_var, wraplength=740,
             justify="left", bg="#f5f5f5",
             font=("Menlo", 9)).pack(fill="x", padx=4, pady=2)

    bf = tk.Frame(root)
    bf.pack(fill="x", padx=8, pady=4)

    log_text = scrolledtext.ScrolledText(
        root, height=14, font=("Menlo", 9), state="disabled",
        bg="#1e1e1e", fg="#d4d4d4", relief="sunken", bd=1)
    log_text.pack(fill="both", expand=True, padx=8, pady=(4, 8))

    def log(msg):
        log_text.configure(state="normal")
        log_text.insert("end", msg + "\n")
        log_text.see("end")
        log_text.configure(state="disabled")

    def refresh():
        try:
            status_var.set(check_status())
        except Exception as e:
            status_var.set("错误: %s" % e)

    def run_bg(func):
        log_text.configure(state="normal")
        log_text.delete("1.0", "end")
        log_text.configure(state="disabled")

        def w():
            def l(msg):
                root.after(0, lambda: log(msg))
            try:
                func(l)
                root.after(0, refresh)
            except Exception as e:
                root.after(0, lambda: log("❌ %s\n%s" % (e, traceback.format_exc())))
        threading.Thread(target=w, daemon=True).start()

    def mk_btn(text, cmd, bg="#e0e0e0"):
        b = tk.Button(bf, text=text, command=cmd, bg=bg,
                      padx=14, pady=4, font=("PingFang SC", 10))
        b.pack(side="left", padx=4)

    mk_btn("状态 STATUS", refresh)
    mk_btn("完整补丁 PATCH", lambda: run_bg(do_patch_all), bg="#d4edda")
    mk_btn("验证 VERIFY", lambda: run_bg(do_verify), bg="#fff3cd")
    mk_btn("还原 RESTORE", lambda: run_bg(do_restore), bg="#f8d7da")

    refresh()
    root.mainloop()

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "gui"
    try:
        if mode == "gui":
            run_gui()
        else:
            if mode not in ("status", "patch", "verify", "restore"):
                print(__doc__)
                sys.exit(2)
            ok = {"status": lambda l: (print(check_status()), True)[1],
                  "patch": do_patch_all, "verify": do_verify,
                  "restore": do_restore}[mode](print)
            sys.exit(0 if ok else 1)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
