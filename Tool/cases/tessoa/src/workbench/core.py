#!/usr/bin/env python3
"""core.py — 补丁流水线工作台 · 无头核心（headless core）

设计目标
--------
1. **偏移漂移免疫**：从不接受手输地址。公钥锚点、两个文本头模板一律交给
   ``autolocate.locate()`` 按内容/结构特征现算。换版本只需把新二进制丢进来，
   零改码。
2. **可脚本化**：本模块 ``不 import curses``。既能被 TUI 包成界面，也能被
   agent / CI / shell 直接 ``import`` 或 ``python -m workbench run`` 驱动。
   每个步骤返回结构化 :class:`StepResult`，不抛裸异常。
3. **可逆**：打补丁前强制落地原件备份；下发许可前强制备份旧 ini/sig。

管线（9 步）
------------
    1 探测目标   2 定位锚点   3 备份原件   4 生成密钥对
    5 等长打补丁 6 ad-hoc 重签  7 签发许可  8 下发许可   9 本地自校验

外加独立的 ``verify_activation()``：强制重校验 + 读 ``exit.log`` 取**正向**
证据（不以"没看到拒绝日志"当激活结论）。

依赖
----
仅 ``cryptography``（Ed25519）+ Python 标准库。
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import glob
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
import uuid as _uuid
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------
# 把同级的 autolocate.py 拉进搜索路径（本包作为 src/workbench 存在）
# --------------------------------------------------------------------------
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_PKG_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

try:
    import autolocate  # type: ignore
except ImportError as _e:  # pragma: no cover
    raise SystemExit(
        "找不到 autolocate.py（应在 %s 下）。workbench 与 autolocate 必须同仓。" % _SRC_DIR
    ) from _e


# ==========================================================================
# 常量
# ==========================================================================

#: 厂商内置的许可公钥（历史值）。只用于判定"当前二进制是否已被别人打过补丁"。
VENDOR_PUBKEY = "52dde2592618463044d4b602535494c2771dd08a5c3a2c0ca6804bb34e6f7167"

#: 插件公钥 —— 跨版本不变，**不可动**。autolocate 靠它做对偶定位。
PLUGIN_PUBKEY = "e91ee607dde422ced7046908cf0ebd4ac0fba55ac0fbd85816dcab79fb81ae0f"

#: 离线证明里签的 host / path。校验只比对签名字节串，不做真实 DNS。
VENDOR_HOST = "api.keygen.sh"
LICENSE_PATH = "/v1/accounts/tessoa/licenses/actions/validate-key"

#: 许可载荷字段
LICENSEE = "Seep Reverse Lab"
EDITION = "standard"
QUOTA = 5
UPDATES = "lifetime"

#: 离线宽限期由 license.sig 里**被签名的 date 头**锚定，不是 ini 字段。
#: 所以这两个参数决定"离线能活多久"。
SIG_DATE_OFFSET_DAYS = 3650
EXPIRY_DAYS = 3650

#: 产品目录名 → 许可 key 前缀（TESSOA-LAB-XXXX-XXXX-XXXX）
_PRODUCT_DIRNAME = "tessoa"


class PipelineError(RuntimeError):
    """步骤级失败。调用方通常转成 ``StepResult(ok=False)``。"""


# ==========================================================================
# 结构化返回值
# ==========================================================================

@dataclass
class StepResult:
    """单步结果。``data`` 里放该步特有的键值，供 TUI 与脚本各取所需。"""

    name: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return "%s %s — %s" % ("OK  " if self.ok else "FAIL", self.name, self.detail)


@dataclass
class TargetInfo:
    """一次管线的目标快照。"""

    binary: str
    platform: str            # "darwin" | "windows"
    fmt: str                 # "macho" | "pe"
    version: str = "unknown"
    bundle: str | None = None
    size: int = 0
    md5: str = ""
    data_dir: str = ""       # license.ini / license.sig 落地目录
    backup_dir: str = ""
    out_dir: str = ""
    vendor_pub: str = VENDOR_PUBKEY

    @property
    def is_macos(self) -> bool:
        return self.platform == "darwin"

    @property
    def patched(self) -> bool:
        """当前二进制里的许可公钥是否已不是厂商原值。"""
        return self.vendor_pub != VENDOR_PUBKEY


@dataclass
class PipelineReport:
    target: TargetInfo
    steps: list[StepResult] = field(default_factory=list)
    ok: bool | None = None

    def __post_init__(self) -> None:
        if self.ok is None:
            self.ok = all(s.ok for s in self.steps) if self.steps else False

    def first_fail(self) -> StepResult | None:
        return next((s for s in self.steps if not s.ok), None)

    def summary(self) -> str:
        """只返回结论行。步骤明细由调用方自己遍历 steps 打印——
        之前这里把明细也拼进去，人读输出里每步都出现两遍。"""
        return "流水线 %s（共 %d 步%s）" % (
            "全部通过" if self.ok else "失败",
            len(self.steps),
            "，首败：%s" % self.first_fail().name if self.first_fail() else "")


# ==========================================================================
# 小工具
# ==========================================================================

def fnv1a64(s: str) -> str:
    """64 位 FNV-1a。许可设备指纹算法（单向，不可逆推出机器码）。"""
    h = 0xCBF29CE484222325
    for b in s.encode():
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return "%016x" % h


def _run(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """跑命令，返回 (rc, stdout, stderr)。不抛。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "%s：命令不存在" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s：超时" % cmd[0]


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _mkdirs(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _mkdirs_parent(path: str) -> str:
    _mkdirs(os.path.dirname(os.path.abspath(path)) or ".")
    return path


def _b64u(b: bytes) -> str:
    """标准 base64（带 padding）。证明文件里用的就是标准字母表。"""
    return base64.b64encode(b).decode("ascii")


def _b64u_decode(s: str) -> bytes:
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.b64decode(s + "=" * pad)


# ==========================================================================
# 设备指纹
# ==========================================================================

#: macOS 机器码的 4 种 FNV-1a-64 规范化变体（审计报告 §3.3 实测全通，
#: 结论取 ``as-is`` 为准）。变体表用于取证复现，别再凭印象改。
FP_VARIANTS = ("as-is", "lower-dash", "upper-nodash", "lower-nodash")


def normalize_machine_id(raw: str, variant: str = "as-is") -> str:
    """把机器码规范化成送进 FNV-1a-64 的字节串。"""
    v = raw.strip()
    if variant == "as-is":
        return v
    if variant == "lower-dash":
        return v.lower()
    if variant == "upper-nodash":
        return v.upper().replace("-", "")
    if variant == "lower-nodash":
        return v.lower().replace("-", "")
    raise ValueError("未知指纹变体 %r（可选：%s）" % (variant, " / ".join(FP_VARIANTS)))


def device_fp(platform: str | None = None, variant: str = "as-is") -> str | None:
    """取本机机器码 → FNV-1a-64 → 16 位小写 hex。

    macOS : IOPlatformUUID **原样**（``as-is``，大写带横线）。
            B96EE60C-28D5-53A1-AE4B-F2F07BD15E48 → ``5ac540371d81bd7c``
    Win   : 注册表 MachineGuid（剥花括号）→ 原样

    ★ 默认变体必须是 ``as-is``：审计报告 §3.3 的最终结论就是它，
      早先这里写成 ``lower().replace("-","")`` 属于取错变体，
      会让签发出去的许可带一个应用根本不认的指纹。

    取不到返回 None —— 调用方可退回 ``--no-fp``（只验签、不带机器码）。
    """
    plat = platform or sys.platform

    if plat == "darwin":
        rc, out, _ = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        if rc != 0:
            rc, out, _ = _run(["system_profiler", "SPHardwareDataType"])
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out) or \
            re.search(r"Hardware UUID:\s*([0-9A-Fa-f-]{36})", out)
        if not m:
            return None
        return fnv1a64(normalize_machine_id(m.group(1), variant))

    if plat.startswith("win"):
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Cryptography") as k:
                v, _t = winreg.QueryValueEx(k, "MachineGuid")
            return fnv1a64(str(v).strip().strip("{}"))
        except Exception:
            return None

    return None


# ==========================================================================
# 密钥对
# ==========================================================================

def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
    except ImportError as e:  # pragma: no cover
        raise PipelineError("缺少 cryptography（pip install cryptography）") from e
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def _priv_obj(priv_pem: bytes):
    """PEM 私钥 → ``Ed25519PrivateKey``。

    注意：``private_bytes()`` 在 cryptography ≥ 3 必须显式给
    encoding / format / encryption_Algorithm；取 PKCS8 里的 32 字节种子最稳。
    """
    Ed25519PrivateKey, _, ser = _require_crypto()
    obj = ser.load_pem_private_key(priv_pem, password=None)
    raw = obj.private_bytes(encoding=ser.Encoding.Raw,
                            format=ser.PrivateFormat.Raw,
                            encryption_algorithm=ser.NoEncryption())
    return Ed25519PrivateKey.from_private_bytes(raw)


# 既有审计资产（keygen.py / 各 probe 脚本）写的键名是 priv/pub，
# 本模块自己写的是 private_pem/public_hex。两种都得能直接吃，
# 否则「复用权威钥匙」根本做不到 —— 换 dir 就会静悄悄换一把新钥匙。
_PRIV_KEYS = ("private_pem", "priv", "private_key", "priv_pem")
_PUB_KEYS = ("public_hex", "pub", "pub_hex", "public_key")


def _blob_field(blob: dict, keys: tuple, label: str, keys_path: str) -> str:
    for k in keys:
        v = blob.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    raise PipelineError(
        "密钥文件 %s 缺少 %s 字段（接受任一：%s）" % (keys_path, label, " / ".join(keys)))


def _blob_pem(blob: dict, keys_path: str) -> bytes:
    """取私钥并统一归一成 PKCS8 PEM。

    历史资产有两种写法：一种是 PEM 明文，另一种是 **64 位 hex 原始种子**
    （keygen.py / 各 probe 都用后者）。不认后者的后果很隐蔽：
    直接当成 PEM 喂给 cryptography 会抛 MalformedFraming，
    而"换个 out dir 就换一把钥匙"更是灾难 —— 已打好的许可会全废。
    """
    raw = _blob_field(blob, _PRIV_KEYS, "私钥", keys_path)
    if raw.startswith("-----BEGIN"):
        return raw.encode()

    Ed25519PrivateKey, _pk, serialization = _require_crypto()
    if len(raw) != 64 or any(c not in "0123456789abcdefABCDEF" for c in raw):
        raise PipelineError(
            "密钥文件 %s 的私钥既不是 PEM 也不是 64 位 hex 种子" % keys_path)
    obj = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
    return obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _blob_pub(blob: dict, keys_path: str) -> str:
    h = _blob_field(blob, _PUB_KEYS, "公钥", keys_path)
    if len(h) != 64 or any(c not in "0123456789abcdefABCDEF" for c in h):
        raise PipelineError("密钥文件 %s 的公钥不是 64 位 hex：%r" % (keys_path, h[:20]))
    return h.lower()


def load_or_create_keypair(keys_path: str, new: bool = False,
                           dry_run: bool = False) -> tuple[bytes, str]:
    """读/建 Ed25519 密钥对。返回 ``(priv_pem, pub_hex)``。

    复用既有文件 → 同一把钥匙反复重跑，二进制补丁是幂等的。
    ``new=True`` 强制换新钥匙（会连带重打公钥槽）。
    ``dry_run=True`` 时**不写盘**，只在内存里生成一把临时钥匙。
    """
    Ed25519PrivateKey, Ed25519PublicKey, serialization = _require_crypto()

    if not new and os.path.exists(keys_path):
        try:
            blob = json.load(open(keys_path, "r", encoding="utf-8"))
            priv_pem = _blob_pem(blob, keys_path)
            pub_hex = _blob_pub(blob, keys_path)
            _priv_obj(priv_pem)          # 结构/类型自检
            return priv_pem, pub_hex
        except PipelineError:
            raise
        except Exception as e:
            raise PipelineError("密钥文件损坏 %s: %s" % (keys_path, e))

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()

    if dry_run:
        return priv_pem, pub_hex           # 不落盘

    _mkdirs_parent(keys_path)
    with open(keys_path, "w", encoding="utf-8") as f:
        json.dump({"public_hex": pub_hex, "private_pem": priv_pem.decode()}, f, indent=2)
    try:
        os.chmod(keys_path, 0o600)
    except OSError:
        pass
    return priv_pem, pub_hex


def verify_sig(sig_bytes: bytes, pub_hex: str) -> tuple[bool, str]:
    """用许可公钥验证 license.sig 的 Ed25519 签名。返回 (ok, 说明)。"""
    _, Ed25519PublicKey, serialization = _require_crypto()
    from cryptography.exceptions import InvalidSignature
    try:
        m = re.search(rb'^signature\s*=\s*algorithm="ed25519",\s*'
                      rb'signature="([^"]+)",\s*headers="([^"]*)"\s*$',
                      sig_bytes, re.M)
        if not m:
            return False, "签名行格式不匹配（缺 headers= 或算法不是 ed25519）"
        sig = _b64u_decode(m.group(1).decode())
        hdrs = m.group(2).decode().split()

        # 基串拼接规则必须与 step_mint 的签名端逐字节一致：
        # 头之间用 \n 连接、最后一个头后面【没有】换行。
        # 之前这里给每个头都补 \n，导致自产的许可都验不过自己（阳性对照直接翻车）。
        parts = []
        for h in hdrs:
            hm = re.search((r"^%s\s*=\s*(.*)$" % re.escape(h)).encode(), sig_bytes, re.M)
            if not hm:
                return False, "签名头缺少 %s" % h
            parts.append(h.encode() + b": " + hm.group(1).strip())
        base = b"\n".join(parts)

        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, bytes(base))
        return True, "Ed25519 验签通过（签名基串 %dB：%s）" % (len(base), " ".join(hdrs))
    except PipelineError:
        raise
    except InvalidSignature:
        # 裸 InvalidSignature 的 str() 是空的，不补上下文就只看到『验签失败: 』，
        # 根本分不清是基串拼错、用了别的私钥，还是许可压根不是这把钥匙签的。
        return False, ("Ed25519 验签不通过：签名不是公钥 %s… 签的"
                       "（基串 %s，%dB）——许可要么出自别的密钥，要么基串被改过"
                       % (pub_hex[:12], " ".join(hdrs) if "hdrs" in dir() else "?", len(base)))
    except Exception as e:
        return False, "验签失败 %s: %s" % (type(e).__name__, e)


# ==========================================================================
# 步骤 1 — 探测目标
# ==========================================================================

def _plist_version(bundle: str) -> tuple[str, str]:
    """从 .app/Contents/Info.plist 取 (版本, 可执行名)。plistlib 失败则正则兜底。"""
    pp = os.path.join(bundle, "Contents", "Info.plist")
    ver, exe = "unknown", ""
    try:
        with open(pp, "rb") as f:
            pl = plistlib.load(f)
        ver = str(pl.get("CFBundleShortVersionString") or "unknown")
        exe = str(pl.get("CFBundleExecutable") or "")
    except Exception:
        raw = _read(pp)
        m = re.search(rb"<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>", raw)
        if m:
            ver = m.group(1).decode()
    return ver, exe


def detect_target(binary: str | None = None,
                  platform: str | None = None,
                  app_glob: str = "tess",
                  data_dir: str | None = None,
                  backup_dir: str | None = None,
                  out_dir: str | None = None) -> TargetInfo:
    """探测待补丁二进制 + 许可数据目录。

    - 显式 ``binary`` 优先；否则在 macOS 扫 ``/Applications/<app_glob>*.app``，
      Windows 走 ``%LOCALAPPDATA%\\<app_glob>*\\*.exe``。
    - ``app_glob`` 是**前缀**（允许带尾随 ``*``，会被裁掉）。
    - 许可数据目录用同前缀定位，规避 tessa/telsea 拼写坑。
    - 主可执行名一律从 Info.plist 的 ``CFBundleExecutable`` 读，绝不手拼字符串。
    """
    plat = platform or sys.platform
    home = os.path.expanduser("~")
    prefix = app_glob.lower().rstrip("*")
    if not prefix:
        raise PipelineError("app_glob 前缀不能为空")

    bundle = None
    exe_name = ""

    if binary:
        binary = os.path.abspath(binary)
        # 若指向 .app 或其内部，尽量回推出 bundle + 版本
        probe = binary
        for _ in range(6):
            if os.path.isdir(probe) and probe.endswith(".app"):
                bundle = probe
                break
            probe = os.path.dirname(probe)
        if bundle:
            ver, exe_name = _plist_version(bundle)
        else:
            ver = _guess_version(binary)
    elif plat == "darwin":
        found = None
        for base in ("/Applications", os.path.join(home, "Applications")):
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base)):
                low = name.lower()
                if low.startswith(prefix) and low.endswith(".app"):
                    found = os.path.join(base, name)
                    break
            if found:
                break
        if not found:
            raise PipelineError("在 /Applications 未找到 %s*.app（用 --binary 显式指定）" % prefix)
        bundle = found
        ver, exe_name = _plist_version(bundle)
        binary = os.path.join(bundle, "Contents", "MacOS",
                              exe_name or _PRODUCT_DIRNAME)
        if not os.path.exists(binary):
            cands = []
            md = os.path.join(bundle, "Contents", "MacOS")
            if os.path.isdir(md):
                cands = [os.path.join(md, x) for x in os.listdir(md)
                         if not x.startswith(".")]
            if len(cands) != 1:
                raise PipelineError("无法确定主二进制: %s（候选 %s）" % (binary, cands))
            binary = cands[0]
    elif plat.startswith("win"):
        local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        base = os.path.join(local, _PRODUCT_DIRNAME)
        cands = [os.path.join(base, x) for x in os.listdir(base)] if os.path.isdir(base) else []
        cands = [c for c in cands if c.lower().endswith(".exe")]
        if not cands:
            raise PipelineError("未在 %s 找到 exe（用 --binary 显式指定）" % base)
        binary = cands[0]
        ver = _guess_version(binary)
    else:
        raise PipelineError("不支持的平台 %s" % plat)

    if not os.path.exists(binary):
        raise PipelineError("二进制不存在: %s" % binary)

    data = _read(binary)
    fmt = autolocate._klass(data)

    # 许可数据目录（含既有 ini/sig 的目录）
    if not data_dir:
        if plat == "darwin":
            support = os.path.join(home, "Library", "Application Support")
            hit = None
            if os.path.isdir(support):
                for name in sorted(os.listdir(support)):
                    if name.lower().startswith("tess") and os.path.isdir(os.path.join(support, name)):
                        hit = os.path.join(support, name)
                        break
            data_dir = hit or os.path.join(support, "tessoa")
        else:
            data_dir = os.path.join(os.environ.get("APPDATA", home), "tessoa")

    # ⚠️ 本机历史遗留 4 个几乎同名的目录，务必分清：
    #    telessa-mac-backup/ = 空壳
    #    telsea-mac-backup/ = ★权威：未打补丁原件 12138352 B / md5 7cb16105…
    #    tessa-mac-backup/  = 早期脚本产物，已打补丁态快照（无回滚价值）
    #    默认写到 telsea-mac-backup/，与人工回滚路径一致
    bdir = backup_dir or os.path.join(home, "githome", "telsea-mac-backup")
    odir = out_dir or os.path.join(home, "githome", "tessoa-wb-out")

    return TargetInfo(
        binary=binary, platform=plat, fmt=fmt, version=ver, bundle=bundle,
        size=len(data), md5=hashlib.md5(data).hexdigest(),
        # 探测阶段不落盘：目录在真正要写的步骤（backup/deploy）里按需建。
        # 之前这里把三个目录都先 makedirs 了，连 locate 这种只读命令
        # 都会在家目录里留三个空目录。
        data_dir=data_dir, backup_dir=bdir, out_dir=odir,
        vendor_pub=bytes_from_pubkey(data) or VENDOR_PUBKEY,
    )


def bytes_from_pubkey(data: bytes) -> str | None:
    """从二进制里读回当前许可公钥槽的值（hex str）。读不出返回 None。"""
    try:
        r = autolocate.locate(data)
        return r.pubkey_value.decode("latin1")
    except Exception:
        return None


def _guess_version(binary: str) -> str:
    """无 bundle 时从相邻文件名/资源里猜版本号，尽力而为。"""
    for cand in (os.path.basename(binary), os.path.basename(os.path.dirname(binary))):
        m = re.search(r"(\d+\.\d+\.\d+)", cand)
        if m:
            return m.group(1)
    return "unknown"


# ==========================================================================
# 步骤 2 — 定位锚点
# ==========================================================================

def _nearest_key(anchor: int, offsets) -> int | None:
    """从候选偏移里挑离 anchor 最近的那个；空列表返回 None。"""
    return min(offsets, key=lambda o: abs(o - anchor)) if offsets else None


def step_locate(target: TargetInfo, expect_pubkey: str | None = None) -> StepResult:
    """内容寻址定位公钥槽 + 两个头模板。永不要求手输偏移。"""
    data = _read(target.binary)
    r = autolocate.locate(data, expect_pubkey=expect_pubkey)

    detail = "许可公钥 @0x%X = %s…" % (r.pubkey_off, r.pubkey_value.decode()[:12])
    if r.sig_header_off is not None:
        detail += " | sig头 @0x%X %dB" % (r.sig_header_off, len(r.sig_header))
    if r.ini_header_off is not None:
        detail += " | ini头 @0x%X %dB" % (r.ini_header_off, len(r.ini_header))

    return StepResult("定位锚点", True, detail, {
        "pubkey_off": r.pubkey_off, "pubkey_value": r.pubkey_value.decode(),
        # 插件公钥 = other_pubkeys 里离许可公钥最近的那个（实测间距 0x106 = 262B）。
        # 直接取 [0] 会挑到文件里随便一把无关的 32B 序列。
        "plugin_off": _nearest_key(r.pubkey_off, r.other_pubkeys),
        "plugin_gap": (min(abs(o - r.pubkey_off) for o in r.other_pubkeys)
                       if r.other_pubkeys else None),
        "sig_header": r.sig_header, "sig_header_off": r.sig_header_off,
        "ini_header": r.ini_header, "ini_header_off": r.ini_header_off,
        "va_delta": r.va_delta, "imagebase": r.imagebase,
        "warnings": list(r.warnings), "report": r.report(),
    })


# ==========================================================================
# 步骤 3 — 备份原件
# ==========================================================================

def step_backup(target: TargetInfo, force: bool = False,
                dry_run: bool = False) -> StepResult:
    """落地原件备份（含版本号），已存在则跳过并校验。"""
    tag = re.sub(r"[^\w.\-]", "_", target.version or "unknown")
    base = os.path.basename(target.binary)
    dst = os.path.join(target.backup_dir, "%s.orig.%s" % (base, tag))

    if dry_run and not os.path.exists(dst):
        return StepResult("备份原件", True,
                          "[dry-run] 将新建 %s (md5=%s)" % (dst, target.md5[:12]),
                          {"path": dst, "created": False, "dry_run": True})

    if os.path.exists(dst) and not force:
        b = _read(dst)
        bmd5 = hashlib.md5(b).hexdigest()
        note = "已存在，跳过" if bmd5 == target.md5 else "已存在(与当前不同，保留原备份)"
        return StepResult("备份原件", True, "%s — %s md5=%s" % (dst, note, bmd5[:12]), {
            "path": dst, "created": False, "md5": bmd5,
        })

    data = _read(target.binary)
    _mkdirs_parent(dst)
    with open(dst, "wb") as f:
        f.write(data)
    bmd5 = hashlib.md5(data).hexdigest()
    return StepResult("备份原件", True, "%s (md5=%s)" % (dst, bmd5[:12]), {
        "path": dst, "created": True, "md5": bmd5,
    })


# ==========================================================================
# 步骤 5 — 等长打补丁
# ==========================================================================

def step_patch(target: TargetInfo, loc: dict, pub_hex: str, dry_run: bool = False) -> StepResult:
    """在自动定位的偏移处做 64 字节等长覆盖。

    不依赖旧值：直接覆写 autolocate 认定的公钥槽。所以已打过补丁的二进制
    再跑一次也是幂等的（只会把槽刷成当前 pub）。
    """
    off = loc["pubkey_off"]
    data = _read(target.binary)
    cur = data[off:off + 64].decode("latin1")
    new = pub_hex.lower()
    if len(new) != 64:
        raise PipelineError("公钥必须是 64 位 hex 字符串")

    if cur == new:
        return StepResult("等长打补丁", True, "已是目标公钥，幂等跳过 @0x%X" % off, {
            "offset": off, "changed": False, "old": cur, "new": new,
        })

    buf = bytearray(data)
    buf[off:off + 64] = new.encode()
    buf = bytes(buf)

    if buf[:off] != data[:off] or buf[off + 64:] != data[off + 64:]:
        raise PipelineError("补丁改变了槽位以外的字节（等长覆盖校验失败）")
    if len(buf) != len(data):
        raise PipelineError("补丁改变了文件长度")

    diff = sum(1 for a, b in zip(data, buf) if a != b)
    detail = "@0x%X 覆写 64B 差异 %dB md5 %s→%s" % (
        off, diff, hashlib.md5(data).hexdigest()[:8], hashlib.md5(buf).hexdigest()[:8])
    if dry_run:
        return StepResult("等长打补丁", True, "[dry-run] " + detail, {
            "offset": off, "changed": False, "old": cur, "new": new, "diff": diff,
        })

    _mkdirs_parent(target.binary)
    with open(target.binary, "wb") as f:
        f.write(buf)
    return StepResult("等长打补丁", True, detail, {
        "offset": off, "changed": True, "old": cur, "new": new, "diff": diff,
        "md5_after": hashlib.md5(buf).hexdigest(),
    })


# ==========================================================================
# 步骤 6 — ad-hoc 重签（仅 macOS）
# ==========================================================================

def step_resign(target: TargetInfo, dry_run: bool = False) -> StepResult:
    """macOS：改字节会破签名，必须 ad-hoc 重签才起得来。

    先签整个 .app bundle，失败再退到单个二进制。
    """
    if not target.is_macos:
        return StepResult("ad-hoc 重签", True, "非 macOS（PE 无代码签名）", {"skipped": True})

    if dry_run:
        return StepResult("ad-hoc 重签", True, "[dry-run] codesign --force --sign -", {})

    units = [target.bundle] if target.bundle else []
    units.append(target.binary)

    last = ""
    for unit in units:
        rc, _o, err = _run(["codesign", "--force", "--sign", "-", unit], timeout=180)
        if rc == 0:
            return StepResult("ad-hoc 重签", True, "codesign --sign - OK: %s" % unit, {
                "unit": unit,
            })
        last = err or "(rc=%d)" % rc
    return StepResult("ad-hoc 重签", False, "codesign 失败: %s" % last, {})


# ==========================================================================
# 步骤 7 — 签发许可
# ==========================================================================

def _grace_str(seconds: int) -> str:
    return "%d:%02d:%02d" % (seconds // 3600, (seconds % 3600) // 60, seconds % 60)


def _make_license_key() -> str:
    return "%s-LAB-%04X-%04X-%04X" % (
        _PRODUCT_DIRNAME[:6].upper(),
        int.from_bytes(os.urandom(2), "big"),
        int.from_bytes(os.urandom(2), "big"),
        int.from_bytes(os.urandom(2), "big"),
    )


def step_mint(target: TargetInfo, loc: dict, priv_pem: bytes, pub_hex: str,
              out_dir: str | None = None, sig_date_offset_days: int = SIG_DATE_OFFSET_DAYS,
              expiry_days: int = EXPIRY_DAYS, updates: str = UPDATES,
              license_key: str | None = None, fp: str | None = None,
              no_fp: bool = False, dry_run: bool = False) -> StepResult:
    """签发 ``license.sig``（Ed25519 自签离线证明）+ ``license.ini``（明文存储）。

    离线宽限期锚定在**被签名的 date 头**，不是 ini 字段 —— 所以
    ``sig_date_offset_days`` 才是决定离线存活时长的旋钮。
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # ★ dry-run 必须连目录都不建：_mkdirs 是落盘动作，放在 gate 之前
    #   等于「只读模式」偷偷在磁盘上留痕迹。
    out = out_dir or target.out_dir
    if not dry_run:
        out = _mkdirs(out)
    hdr_sig = loc.get("sig_header") or b"# tessoa license proof (v1)\n"
    hdr_ini = loc.get("ini_header") or b"# tessa license store (v1)\n"

    now = int(time.time())
    expiry = now + expiry_days * 86400
    key = license_key or _make_license_key()
    fp = None if no_fp else (fp or device_fp(target.platform))
    luid = str(_uuid.uuid4())
    inst = _uuid.uuid4().hex

    date_hdr = _dt.datetime.fromtimestamp(
        now + sig_date_offset_days * 86400, _dt.timezone.utc
    ).strftime("%a, %d %b %Y %H:%M:%S GMT")

    body_obj = {
        "meta": {"code": "VALID",
                 "scope": ({"fingerprint": fp} if fp else {})},
        "data": {"id": luid,
                 "attributes": {
                     "expiry": _dt.datetime.fromtimestamp(
                         expiry, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "key": key,
                     "metadata": {"licensee": LICENSEE, "edition": EDITION, "updates": updates},
                 }},
    }
    body = json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False).encode()
    digest = "sha-256=" + _b64u(hashlib.sha256(body).digest())

    base = ("host: %s\n" % VENDOR_HOST) + ("date: %s\n" % date_hdr) + ("digest: %s" % digest)
    priv = _priv_obj(priv_pem)
    signature = _b64u(priv.sign(base.encode()))

    sig = hdr_sig + (
        b"schema = 1\n"
        + b"host = " + VENDOR_HOST.encode() + b"\n"
        + b"path = " + LICENSE_PATH.encode() + b"\n"
        + b"date = " + date_hdr.encode() + b"\n"
        + b"digest = " + digest.encode() + b"\n"
        + b'signature = algorithm="ed25519",signature="'
        + signature.encode() + b'",headers="host date digest"\n'
        + b"body_b64 = " + _b64u(body).encode() + b"\n"
    )

    ini = hdr_ini + (
        b"schema = 1\n"
        + b"uuid = " + luid.encode() + b"\n"
        + b"install_id = " + inst.encode() + b"\n"
        + b"license_key = " + key.encode() + b"\n"
        + b"updates = " + updates.encode() + b"\n"
        + b"expiration = " + str(expiry).encode() + b"\n"
        + b"last_validated = " + str(now).encode() + b"\n"
        + b"quota = " + str(QUOTA).encode() + b"\n"
        + b"activated = " + str(expiry).encode() + b"\n"
        + b"device_fp = " + (fp or "").encode() + b"\n"
    )

    sig_path = os.path.join(out, "license.sig")
    ini_path = os.path.join(out, "license.ini")

    if dry_run:
        return StepResult("签发许可", True, "[dry-run] sig %dB / ini %dB date=%s" % (
            len(sig), len(ini), date_hdr), {
            "sig": sig, "ini": ini, "license_key": key, "date_hdr": date_hdr,
            "fp": fp, "sig_path": sig_path, "ini_path": ini_path,
        })

    with open(sig_path, "wb") as f:
        f.write(sig)
    with open(ini_path, "wb") as f:
        f.write(ini)

    return StepResult("签发许可", True, "sig %dB + ini %dB  key=%s  date=%s" % (
        len(sig), len(ini), key, date_hdr), {
        "sig_path": sig_path, "ini_path": ini_path, "sig": sig, "ini": ini,
        "license_key": key, "date_hdr": date_hdr, "fp": fp,
        "grace": _grace_str(sig_date_offset_days * 86400),
    })


# ==========================================================================
# 步骤 8 — 下发许可
# ==========================================================================

def deploy_license(target: TargetInfo, sig: bytes, ini: bytes,
                   force_revalidate: bool = False) -> StepResult:
    """写入许可数据目录（覆盖前自动备份旧件）。"""
    d = _mkdirs(target.data_dir)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    moved = []

    for name, blob in (("license.sig", sig), ("license.ini", ini)):
        dst = os.path.join(d, name)
        if os.path.exists(dst):
            bak = "%s.bak-%s" % (dst, stamp)
            shutil.copy2(dst, bak)
            moved.append(bak)
        with open(dst, "wb") as f:
            f.write(blob)

    note = ""
    if force_revalidate:
        note = "；已清零 last_validated/activated（强制下次启动重校验）"

    return StepResult("下发许可", True,
                      "写入 %s（备份 %d 个旧件）%s" % (d, len(moved), note),
                      {"data_dir": d, "backups": moved,
                       "force_revalidate": force_revalidate})


# ==========================================================================
# 步骤 9 — 本地自校验
# ==========================================================================

def step_verify(target: TargetInfo, sig: bytes, pub_hex: str) -> StepResult:
    """本地自校验：用二进制里那颗公钥验刚签出来的证明。"""
    data = _read(target.binary)
    try:
        r = autolocate.locate(data)
        live = r.pubkey_value.decode("latin1")
    except Exception as e:
        return StepResult("本地自校验", False, "回读二进制公钥失败: %s" % e, {})

    if live.lower() != pub_hex.lower():
        return StepResult("本地自校验", False,
                          "二进制公钥 %s… 与签发用公钥 %s… 不一致" % (
                              live[:12], pub_hex[:12]), {"live_pub": live})

    ok, msg = verify_sig(sig, live)
    return StepResult("本地自校验", ok, "%s（公钥 @0x%X = %s…）" % (
        msg, r.pubkey_off, live[:12]), {"live_pub": live, "pubkey_off": r.pubkey_off})


# ==========================================================================
# 激活态验证（独立步骤，macOS 走日志证据法）
# ==========================================================================

def _state_from_log(log: bytes) -> tuple[str, str]:
    """从 exit.log 判激活态。返回 (state, 依据)。

    state ∈ activated-offline / rejected / invalidated / indeterminate
    """
    t = log.decode("utf-8", "replace")
    if "offline proof rejected" in t:
        return "rejected", "出现『offline proof rejected』—— 离线证明未通过"
    if "server invalidated license" in t:
        return "invalidated", "出现『server invalidated license』—— 被服务端判无效"
    if "no license server could be reached" in t and "offline proof rejected" not in t:
        return "activated-offline", "离线兜底（server 不可达且离线证明未拒绝）"
    if "untrusted reply" in t:
        return "activated-offline", "『untrusted reply』—— 离线证明通过，仅在线回包验签失败（fail-open）"
    return "indeterminate", "本次未触发重校验（日志无许可相关行）"


def _read_log(data_dir: str) -> tuple[str, str, str, str]:
    """读 exit.log → (路径, 状态, 依据, 尾部 800B 文本)。状态不确定时返回 'unknown'。"""
    log_path = os.path.join(data_dir, "exit.log")
    log = _read(log_path) if os.path.exists(log_path) else b""
    state, why = _state_from_log(log)
    # 展示优先给 license 相关行：尾部净是 layout/session 落盘，掩盖了关键证据。
    lines = log.decode("utf-8", "replace").splitlines()
    hits = [l for l in lines if "license" in l or "[boot]" in l]
    tail = "\n".join(hits[-14:]) if hits else log[-800:].decode("utf-8", "replace")
    return log_path, state, why, tail


def verify_activation(target: TargetInfo, wait_s: float = 22.0,
                      launch: bool = True) -> StepResult:
    """强制重校验 → 启动应用 → 优雅退出 → 读 exit.log 取正向证据。

    先把 ini 里 ``last_validated`` / ``activated`` 清零，否则应用会跳过
    重校验，日志里什么都不写——那不是"成功"，是"没验"。
    """
    if not target.is_macos:
        return StepResult("验证激活", True, "非 macOS：跳过（需平台专用方案）", {"skipped": True})

    ini_path = os.path.join(target.data_dir, "license.ini")
    if not os.path.exists(ini_path):
        return StepResult("验证激活", False, "缺少 %s" % ini_path, {})

    if not launch:
        # --no-launch = 纯只读取证。绝不能顺手清时间戳：清了又不启动，
        # 等于把应用推进"下次启动强制重校验"的状态却不给结论，纯破坏。
        log_path, state, why, tail = _read_log(target.data_dir)
        return StepResult("验证激活", state in ("activated-offline",),
                          "只读：%s（依据：%s）" % (state, why),
                          {"state": state, "why": why, "log_path": log_path,
                           "log_tail": tail, "forced": False, "launched": False,
                           "read_only": True})

    raw = _read(ini_path)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(ini_path, "%s.bak-%s" % (ini_path, stamp))
    zeroed = re.sub(rb"(?m)^(last_validated|activated)\s*=\s*\d+",
                    rb"\1 = 0", raw)
    with open(ini_path, "wb") as f:
        f.write(zeroed)

    _run(["pkill", "-x", os.path.basename(target.binary)], timeout=10)
    _run(["open", "-n", target.bundle or target.binary], timeout=30)
    time.sleep(wait_s)

    pid = None
    rc, out, _ = _run(["pgrep", "-x", os.path.basename(target.binary)])
    if out:
        pid = out.split("\n")[0].strip()
    if pid:
        _run(["osascript", "-e",
              'tell application "System Events" to keystroke "q" using command down'], timeout=20)
        time.sleep(2)

    log_path, state, why, tail = _read_log(target.data_dir)
    return StepResult("验证激活", state in ("activated-offline",), "%s（依据：%s）" % (state, why), {
        "state": state, "why": why, "log_path": log_path,
        "log_tail": tail, "forced": True, "launched": True,
    })


# ==========================================================================
# 还原（对齐老 GUI 的 RESTORE 按钮 —— workbench 此前缺这最后一块）
# ==========================================================================

def restore_binary(target: TargetInfo, dry_run: bool = False,
                   keep_license: bool = False) -> StepResult:
    """把 binary 还原成补丁前原件 + ad-hoc 重签，可选清掉已部署许可。

    备份从 target.backup_dir 里找：优先与当前版本同名的
    ``<exe>.orig.<ver>``，没有就退回目录里最旧的 ``*.orig*``
    （最旧的 = 最早留存的未补原件）。
    """
    name = "还原原件"

    # 找备份
    bdir = target.backup_dir
    cand = None
    if os.path.isdir(bdir):
        prefer = "%s.orig.%s" % (os.path.basename(target.binary), target.version)
        cand = os.path.join(bdir, prefer)
        if not os.path.isfile(cand):
            olds = sorted(
                (os.path.getmtime(p), p)
                for p in glob.glob(os.path.join(bdir, "*.orig*"))
                if os.path.isfile(p))
            cand = olds[0][1] if olds else None

    if not cand:
        return StepResult(name, False,
                          "备份目录无 *.orig* 可还原：%s" % bdir, {})

    blob = _read(cand)
    cur = _read(target.binary)
    same = blob == cur
    if dry_run:
        return StepResult(name, True,
                          "[dry-run] %s → %s（当前%s补丁态）"
                          % (os.path.basename(cand), target.binary,
                             "无" if same else "已"), {})

    # 备份是整字节拷贝、自带完整签名，写回即还原，**不要**自动重签：
    # 重签会重新生成签名 blob（尺寸漂移），字节级就回不到备份态了。
    # 只有写回后 codesign 校验失败（备份损坏/曾被剥离签名）才补救性重签。
    with open(target.binary, "wb") as f:
        f.write(blob)
    rc, _o, err = _run(["codesign", "--verify", target.binary])
    if rc != 0:
        r = step_resign(target, dry_run=False)
        if not r.ok:
            r.name = name
            r.detail = "binary 已还原但签名校验失败且重签也不成: " + r.detail
            return r
        notes_pre = "binary ← %s（签名已损坏，已补救重签）" % os.path.basename(cand)
    else:
        notes_pre = "binary ← %s（签名完整，未重签）" % os.path.basename(cand)

    notes = [notes_pre]
    if not keep_license:
        removed = []
        for n in ("license.ini", "license.sig"):
            p2 = os.path.join(target.data_dir, n)
            if os.path.isfile(p2):
                os.remove(p2)
                removed.append(n)
        if removed:
            notes.append("已删许可 " + "/".join(removed))
    return StepResult(name, True, "；".join(notes) + "；重签 OK",
                      {"backup": cand, "was_patched": not same})


# ==========================================================================
# 编排
# ==========================================================================

def run_pipeline(target: TargetInfo, new_key: bool = False, dry_run: bool = False,
                 do_resign: bool = True, do_patch: bool = True,
                 do_deploy: bool = True, expect_pubkey: str | None = None,
                 sig_date_offset_days: int = SIG_DATE_OFFSET_DAYS,
                 expiry_days: int = EXPIRY_DAYS, updates: str = UPDATES,
                 license_key: str | None = None, fp: str | None = None,
                 no_fp: bool = False, force_revalidate: bool = False,
                 keys_path: str | None = None, out_dir: str | None = None,
                 emit: Any = None) -> PipelineReport:
    """跑完整管线。``emit`` 可传一个 ``callable(str)`` 实时吐日志（TUI 用）。"""
    rep = PipelineReport(target=target)
    log = emit or (lambda _m: None)

    def add(step: StepResult) -> StepResult:
        rep.steps.append(step)
        log("%s %s" % ("[OK]" if step.ok else "[!!]", step))
        return step

    # 1 探测
    add(StepResult("探测目标", True, "%s %s %s" % (target.fmt, target.version, target.binary),
                   {"binary": target.binary, "data_dir": target.data_dir}))

    # 2 定位
    try:
        loc = add(step_locate(target, expect_pubkey=expect_pubkey))
    except PipelineError as e:
        add(StepResult("定位锚点", False, str(e)))
        rep.ok = False
        return rep
    for w in loc.data.get("warnings", []):
        log("     · %s" % w)

    # 3 备份
    try:
        add(step_backup(target, dry_run=dry_run))
    except PipelineError as e:
        add(StepResult("备份原件", False, str(e)))
        rep.ok = False
        return rep

    # 4 密钥对
    kp = os.path.join(out_dir or target.out_dir, "mint_keys.json")
    try:
        priv_pem, pub_hex = load_or_create_keypair(kp, new=new_key,
                                                    dry_run=dry_run)
        add(StepResult("生成密钥对", True, "pub=%s… → %s" % (pub_hex[:12], kp),
                       {"pub_hex": pub_hex, "priv_pem": priv_pem}))
    except PipelineError as e:
        add(StepResult("生成密钥对", False, str(e)))
        rep.ok = False
        return rep

    # 5 补丁
    if do_patch:
        try:
            add(step_patch(target, loc.data, pub_hex, dry_run=dry_run))
        except PipelineError as e:
            add(StepResult("等长打补丁", False, str(e)))
            rep.ok = False
            return rep
    else:
        add(StepResult("等长打补丁", True, "跳过（--no-patch）", {"skipped": True}))

    # 6 重签
    if do_resign:
        add(step_resign(target, dry_run=dry_run))

    # 7 签发
    try:
        mint = add(step_mint(target, loc.data, priv_pem, pub_hex, out_dir=out_dir,
                             sig_date_offset_days=sig_date_offset_days,
                             expiry_days=expiry_days, updates=updates,
                             license_key=license_key, fp=fp, no_fp=no_fp,
                             dry_run=dry_run))
    except PipelineError as e:
        add(StepResult("签发许可", False, str(e)))
        rep.ok = False
        return rep

    # 8 下发
    if do_deploy and not dry_run:
        add(deploy_license(target, mint.data["sig"], mint.data["ini"],
                           force_revalidate=force_revalidate))
    else:
        add(StepResult("下发许可", True, "[dry-run] 未写入" if dry_run else "跳过（--no-deploy）",
                       {"skipped": True}))

    # 9 自校验
    if not dry_run:
        add(step_verify(target, mint.data["sig"], pub_hex))

    rep.ok = all(s.ok for s in rep.steps)
    return rep