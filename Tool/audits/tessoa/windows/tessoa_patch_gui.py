#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tessa 授权补丁工具 — 双击即用版 (Windows x64)

功能（按钮）:
  [STATUS] 查看已安装 exe / 许可证 的当前状态
  [PATCH ] 结束进程 -> 备份 -> 等长替换内置公钥 -> 自签离线许可证 -> 部署
  [VERIFY] 校验本地已签发的 license.sig
  [RESTORE] 从同版本备份恢复 exe，删除已部署许可证

版本兼容: 内置公钥为版本无关锚点，工具自动在二进制中扫描定位
（不依赖固定偏移），许可证头模板同样按 "# <name> license proof/store"
行自动提取，扫描失败才回退 0.28.1 固定偏移。

密钥与中间产物存于 %APPDATA%\\<name>_patch_tool\\
"""

import os
import re
import sys
import json
import base64
import hashlib
import shutil
import time
import uuid as uuidlib
import threading
import traceback
from email.utils import formatdate

# ============================================================================
# CONFIG — 产品名恒从 hex 派生（终端渲染会错乱该 5 字母名）
# ============================================================================
NAME = bytes.fromhex("746573736f61").decode()     # 实测产品名（字节级确认）
EXE_NAME = NAME + ".exe"
BAKED_PUBKEY = "52dde2592618463044d4b602535494c2771dd08a5c3a2c0ca6804bb34e6f7167"
PUBKEY_LEN = 64
GRACE_SECONDS = 1209600        # 14 天离线宽限（实测常量全二进制唯一）
SIG_DATE_OFFSET_DAYS = 3650    # 签名 date 头前推 10 年 -> 宽限死线 = date + 14d
VENDOR_HOST = "api.keygen.sh"  # 签名基串 host 头（仅被我们自己的签名覆盖）
LICENSE_PATH = "/v1/accounts/" + NAME + "/licenses/actions/validate-key"
QUOTA = 5
EXPIRY = "2036-10-05"

# 0.28.1 固定偏移（仅回退用）
FALLBACK_SIG_OFF = 0xC063B2
FALLBACK_INI_OFF = 0xC04653

LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
APPDATA = os.environ.get("APPDATA", "")
INSTALL_DIR = os.path.join(LOCALAPPDATA, NAME)
INSTALL_EXE = os.path.join(INSTALL_DIR, EXE_NAME)
APPDATA_DIR = os.path.join(APPDATA, NAME)
BACKUP_EXE = INSTALL_EXE + ".orig-backup"  # generic fallback
def _versioned_backup(version):
    """Return version-specific backup path, e.g. tessoa.exe.orig-backup-0.28.3."""
    return INSTALL_EXE + ".orig-backup-" + version
TOOL_DIR = os.path.join(APPDATA, NAME + "_patch_tool")
KEYS_FILE = os.path.join(TOOL_DIR, "mint_keys.json")
SIG_FILE = os.path.join(TOOL_DIR, "license.sig")
INI_FILE = os.path.join(TOOL_DIR, "license.ini")

# ============================================================================
# Crypto
# ============================================================================
def fnv1a64(s):
    h = 0xCBF29CE484222325
    for b in s:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h

def machine_guid():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        return None

def get_device_fp():
    mg = machine_guid()
    return ("%016x" % fnv1a64(mg.encode())) if mg else None

def get_keys(new=False):
    os.makedirs(TOOL_DIR, exist_ok=True)
    if os.path.isfile(KEYS_FILE) and not new:
        d = json.load(open(KEYS_FILE, encoding="utf-8"))
        return bytes.fromhex(d["priv"]), bytes.fromhex(d["pub"])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    raw_pub = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    with open(KEYS_FILE, "w") as f:
        json.dump({"priv": raw_priv.hex(), "pub": raw_pub.hex()}, f, indent=1)
    return raw_priv, raw_pub

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
# Anchors（版本无关：内容扫描）
# ============================================================================
def find_pubkey(data):
    """返回 (偏移, 状态)：内置公钥 ASCII hex 串唯一处。找不到/多义 -> None。"""
    old = BAKED_PUBKEY.encode()
    i = data.find(old)
    if i == -1:
        if os.path.isfile(KEYS_FILE):
            my = json.load(open(KEYS_FILE, encoding="utf-8")).get("pub", "")
            j = data.find(my.encode())
            if j != -1 and data.find(my.encode(), j + 1) == -1:
                return j, "mine"
        return None
    if data.find(old, i + 1) != -1:
        return None
    return i, "orig"

def find_header(data, key, size):
    """扫描 '# <name><key>' 模板行，取完整行（含换行）。"""
    i = data.find(b"# " + NAME.encode() + key)
    if i == -1:
        return None
    j = data.find(b"\n", i)
    if j == -1:
        return None
    line = data[i:j + 1]
    return line if len(line) == size else None

def detect_version(data):
    """取出现次数最多的合法 semver：应用自身版本号重复出现，
    依赖库版本只出现 1-3 次，故最高频者即应用版本。"""
    from collections import Counter
    c = Counter()
    for m in re.finditer(rb"(\d+\.\d+\.\d+)", data):
        s = m.group(1).decode()
        p = s.split(".")
        if len(p) == 3 and all(x.isdigit() for x in p) and int(p[1]) < 50:
            c[s] += 1
    if not c:
        return "?"
    return c.most_common(1)[0][0]

# ============================================================================
# Operations
# ============================================================================
def kill_process():
    import subprocess
    try:
        subprocess.run(["taskkill", "/F", "/IM", EXE_NAME],
                       capture_output=True, timeout=10)
        time.sleep(1)
    except Exception:
        pass

def check_status():
    if not os.path.isfile(INSTALL_EXE):
        return "❌ 未找到已安装 exe:\n   " + INSTALL_EXE
    d = open(INSTALL_EXE, "rb").read()
    lines = []
    lines.append("exe    : %.1f MB  md5=%s…" % (len(d) / 1048576,
                                                 hashlib.md5(d).hexdigest()[:16]))
    lines.append("版本   : v%s" % detect_version(d))
    r = find_pubkey(d)
    if r is None:
        lines.append("信任锚 : ❓ 无法定位（公钥锚点缺失，版本可能已换）")
    elif r[1] == "mine":
        lines.append("信任锚 : ✅ 已补丁（自签公钥 @0x%X）" % r[0])
    else:
        lines.append("信任锚 : ⚠️ 原始（厂商公钥 @0x%X）" % r[0])
    lv = detect_version(d)
    vb = _versioned_backup(lv)
    if os.path.isfile(vb):
        lines.append("备份   : %s (%.1f MB)" % (
            os.path.basename(vb), os.path.getsize(vb) / 1048576))
    elif os.path.isfile(BACKUP_EXE):
        bv = detect_version(open(BACKUP_EXE, "rb").read())
        if bv != lv:
            lines.append("备份   : %s (v%s — 版本不符，仅参考)" % (
                os.path.basename(BACKUP_EXE), bv))
        else:
            lines.append("备份   : %s (%.1f MB)" % (
                os.path.basename(BACKUP_EXE), os.path.getsize(BACKUP_EXE) / 1048576))
    else:
        lines.append("备份   : 无")
    sig = os.path.isfile(os.path.join(APPDATA_DIR, "license.sig"))
    ini = os.path.isfile(os.path.join(APPDATA_DIR, "license.ini"))
    lines.append("许可   : %s" % ("✅ 已部署 (sig+ini)" if sig and ini
                                  else "⚠️ 未部署" if not (sig or ini)
                                  else "❓ 不完整 sig=%s ini=%s" % (sig, ini)))
    return "\n".join(lines)

def do_patch_all(log):
    log("═══ 完整补丁 ═══")
    if not os.path.isfile(INSTALL_EXE):
        log("❌ 未找到 %s" % INSTALL_EXE)
        return False
    kill_process()
    log("已结束既有进程（若存在）")

    d = bytearray(open(INSTALL_EXE, "rb").read())
    r = find_pubkey(bytes(d))
    if r is None:
        log("❌ 公钥锚点未定位（唯一性检查失败）——版本可能已换，中止")
        return False
    off, state = r
    log("定位: 公钥锚点 @0x%X (%s)" % (off, "原始" if state == "orig" else "已自签"))

    if state == "orig":
        ver = detect_version(bytes(d))
        vbackup = _versioned_backup(ver)
        if not os.path.isfile(vbackup):
            shutil.copy2(INSTALL_EXE, vbackup)
            log("备份: %s (v%s, %.1f MB)" % (
                os.path.basename(vbackup), ver, os.path.getsize(vbackup) / 1048576))
        else:
            log("备份已存在: %s" % os.path.basename(vbackup))
        raw_priv, raw_pub = get_keys()
        new = raw_pub.hex().encode()
        d[off:off + PUBKEY_LEN] = new
        open(INSTALL_EXE, "wb").write(bytes(d))
        log("✅ 公钥替换 @0x%X -> %s…" % (off, raw_pub.hex()[:16]))
    else:
        raw_priv, raw_pub = get_keys()
        log("exe 已是自签状态，跳过替换")

    # 头模板：内容扫描，失败回退 0.28.1 固定偏移
    sig_hdr = find_header(bytes(d), b" license proof", 103)
    ini_hdr = find_header(bytes(d), b" license store", 55)
    if sig_hdr is None:
        sig_hdr = bytes(d)[FALLBACK_SIG_OFF:FALLBACK_SIG_OFF + 103]
        log("⚠️ proof 头模板扫描未中，回退偏移 0x%X" % FALLBACK_SIG_OFF)
    if ini_hdr is None:
        ini_hdr = bytes(d)[FALLBACK_INI_OFF:FALLBACK_INI_OFF + 55]
        log("⚠️ store 头模板扫描未中，回退偏移 0x%X" % FALLBACK_INI_OFF)

    # 签发
    fp = get_device_fp()
    log("设备指纹: %s (FNV-1a-64(MachineGuid))" % (fp or "N/A"))
    now = int(time.time())
    date_ts = now + SIG_DATE_OFFSET_DAYS * 86400
    date_hdr = formatdate(timeval=date_ts, localtime=False, usegmt=True)
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
    sig = sign_ed25519(raw_priv, signing_base.encode())
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
    sig_blob = sig_hdr + ("\n".join(sig_lines) + "\n").encode()

    exp_ts = int(time.mktime(time.strptime(EXPIRY, "%Y-%m-%d")) - time.timezone)
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
    ini_blob = ini_hdr + ("\n".join(ini_keys) + "\n").encode()

    os.makedirs(TOOL_DIR, exist_ok=True)
    open(SIG_FILE, "wb").write(sig_blob)
    open(INI_FILE, "wb").write(ini_blob)
    log("✅ 许可证: %s" % license_key)
    log("   date 头: %s -> 宽限死线 = date + 14d" % date_hdr)

    # 部署
    os.makedirs(APPDATA_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    for name in ("license.ini", "license.sig"):
        live = os.path.join(APPDATA_DIR, name)
        if os.path.isfile(live):
            shutil.copy2(live, live + ".bak-" + ts)
        shutil.copy2(os.path.join(TOOL_DIR, name), live)
        log("✅ 部署: %s" % name)

    # 自校验
    ok = verify_ed25519(raw_pub, signing_base.encode(), sig)
    log("🔍 自校验: %s" % ("✅ OK" if ok else "❌ FAIL"))
    log("═══ 完成 ═══")
    return ok

def do_restore(log):
    log("═══ 还原 ═══")
    kill_process()
    restored = False
    live_ver = detect_version(open(INSTALL_EXE, "rb").read()) if os.path.isfile(INSTALL_EXE) else "?"
    cands = []
    vb = _versioned_backup(live_ver)
    if os.path.isfile(vb):
        cands.append(vb)
    if os.path.isfile(BACKUP_EXE):
        cands.append(BACKUP_EXE)
    for bak in cands:
        if not os.path.isfile(INSTALL_EXE):
            break
        bak_md5 = hashlib.md5(open(bak, "rb").read()).hexdigest()
        live_md5 = hashlib.md5(open(INSTALL_EXE, "rb").read()).hexdigest()
        if bak_md5 == live_md5:
            log("⚠️ 备份与当前 exe 相同（非原始），跳过")
            continue
        bak_ver = detect_version(open(bak, "rb").read())
        live_ver = detect_version(open(INSTALL_EXE, "rb").read())
        if bak_ver not in ("?",) and live_ver not in ("?",) and bak_ver != live_ver:
            log("⚠️ 备份是 v%s，当前 exe 是 v%s —— 版本不符，拒绝跨版本回滚" % (
                bak_ver, live_ver))
            continue
        shutil.copy2(bak, INSTALL_EXE)
        log("✅ 已还原 exe <- %s (v%s)" % (os.path.basename(bak), bak_ver))
        restored = True
        break
    if not restored:
        log("⚠️ 无可用的同版本原始备份")
    for name in ("license.ini", "license.sig"):
        live = os.path.join(APPDATA_DIR, name)
        if os.path.isfile(live):
            os.remove(live)
            log("✅ 已删除: %s（历史 .bak-* 备份保留）" % name)
    log("═══ 完成 ═══")
    return True

def do_verify(log):
    if not (os.path.isfile(KEYS_FILE) and os.path.isfile(SIG_FILE)):
        log("❌ 缺少密钥或许可证文件（先执行补丁）")
        return False
    raw_pub = bytes.fromhex(json.load(open(KEYS_FILE, encoding="utf-8"))["pub"])
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
        digest_ok = hashlib.sha256(body).digest() == base64.b64decode(fields["digest"].split("=", 1)[1])
    except Exception:
        digest_ok = False
    log("签名: %s   摘要: %s" % ("✅ OK" if ok else "❌ FAIL",
                                 "✅ OK" if digest_ok else "❌ FAIL"))
    log("date: %s" % fields.get("date", ""))
    log("宽限死线 = date + %ds（客户端无 skew 校验）" % GRACE_SECONDS)
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
    root.title(NAME + " 授权补丁工具")
    root.geometry("760x540")
    root.minsize(620, 420)

    sf = tk.Frame(root, bg="#f5f5f5", relief="sunken", bd=1)
    sf.pack(fill="x", padx=8, pady=(8, 4))
    status_var = tk.StringVar(value="加载中…")
    tk.Label(sf, textvariable=status_var, wraplength=720,
             justify="left", bg="#f5f5f5",
             font=("Consolas", 9)).pack(fill="x", padx=4, pady=2)

    bf = tk.Frame(root)
    bf.pack(fill="x", padx=8, pady=4)

    log_text = scrolledtext.ScrolledText(
        root, height=14, font=("Consolas", 9), state="disabled",
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
                      padx=14, pady=4, font=("Microsoft YaHei", 10))
        b.pack(side="left", padx=4)

    mk_btn("状态 STATUS", refresh)
    mk_btn("完整补丁 PATCH", lambda: run_bg(do_patch_all), bg="#d4edda")
    mk_btn("验证 VERIFY", lambda: run_bg(do_verify), bg="#fff3cd")
    mk_btn("还原 RESTORE", lambda: run_bg(do_restore), bg="#f8d7da")

    refresh()
    root.mainloop()

if __name__ == "__main__":
    try:
        run_gui()
    except Exception:
        traceback.print_exc()
        try:
            import tkinter.messagebox as mb
            mb.showerror("启动失败", traceback.format_exc()[-500:])
        except Exception:
            pass
        sys.exit(1)
