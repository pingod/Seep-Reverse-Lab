#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""autolocate.py — tessoa 授权锚点自适应定位（内容寻址，不依赖硬编码偏移）.

为什么需要它
------------
tessoa 每次升级都会重排 .rdata，所有**文件偏移**随之漂移：

    版本        公钥偏移      签名头模板        存储头模板      VA_DELTA
    9/30 旧版   0xB98733      0xBA62DF          0xBA4418        0x140001000
    0.28.1      0xBF647B      0xC063B2          0xC04653        0x140001A00
    0.28.3(mac) 0x83C16E      —                 —               —

过去每升级一次就要重新跑探针、手改 keygen.py 的 5 个常量（"漂移 → 适配"循环）。
本模块把定位改成**内容寻址**：只要"锚点的内容特征"还在，就能自动算出新偏移。

锚点的内容特征（跨版本稳定）
----------------------------
1. 内置许可公钥：64 字符小写十六进制 ASCII 串。
   - **值跨版本不变**（`52dde259…7167`，Windows/macOS 同值），但为防厂商轮换密钥，
     定位只用"形状"（64-hex），再用**唯一性**约束锁定；若厂商换值也能定位。
   - 排除插件公钥：插件公钥是同一 64-hex 形状，靠"与许可公钥的相对关系"区分
     （间距 0x1AA(PE) / 0x106(macOS)，且**许可公钥总在较低偏移**）。见 `_keypair_by_gap()`。
2. 签名证明头模板：以 `# ` 开头、`.rdata` 内、以 `\\n` 结尾的 UTF-8 文本行，
   内容含 "license proof"。
3. 许可存储头模板：同上，内容含 "license store"。
4. VA_DELTA（PE）：由节表算出 `.rdata` 的 VA→file 差值，无需硬编码。

跨平台
------
- **PE (Windows)**：解析节表得到 VA 换算；文本模板在 `.rdata`。
- **Mach-O (macOS)**：无 VA 换算，公钥即文件偏移；文本模板直接字符串搜索。
- 不支持的格式：报错而非静默猜错。

用法
----
    from autolocate import locate
    L = locate(open(path,'rb').read())
    L.pubkey_off, L.pubkey_value, L.sig_header, L.ini_header, L.va_delta
    L.pubkey_unique          # 全二进制是否唯一
    L.report()               # 人类可读的定位报告

"漂移 → 适配"就此终结：换样本只换 input path，不再改编解码。
"""
import re
import struct

# 形状特征（跨版本稳定）
#
# 注意：不能加 `(?<![0-9a-f])` / `(?![0-9a-f])` 边界断言。Rust 把这类常量存进
# 长度前缀字符串表，公钥紧跟在 `\xC0\x00`（=64 的长度前缀）之后，**前一个字节
# 不是 hex**，但**后一个字节也不是**；真正的坑在于同一张表里相邻常量会拼接，
# 断言会把合法锚点整片漏掉（实测 v0.28.1 从 10 个匹配掉到 0 个）。
# 改用"贪心 64 位窗口 + 起始去重"，交由调用方用唯一性/期望值收敛。
HEX64_RE = re.compile(rb"[0-9a-f]{64}")
# 头模板：'# ' 开头，单行，10~120 字节，以 \n 结尾
HDR_RE = re.compile(rb"# [^\x00\n]{8,118}\n")

# 非重叠 64-hex 扫描的最大步进：命中后跳过 64 字节，避免同一长串内的滑动匹配
HEX_STEP = 64

PROOF_MARK = b"license proof"
STORE_MARK = b"license store"

# 许可公钥 / 插件公钥的已知相邻间距（README 与 macOS REPORT 记录，跨版本观察到的值）。
# 二者都是 64-hex，且**许可公钥总是在较低偏移、紧贴在插件公钥之前**。
# 这是区分"要替换的锚"与"绝不能动的插件锚"的唯一稳定结构特征。
KNOWN_KEY_GAPS = (0x1AA, 0x106)
KEY_GAP_TOL = 0x40          # 允许小范围漂移，但不允许跨越到别的常量


class LocateError(RuntimeError):
    """定位失败：给出可操作的诊断而不是让调用方猜。"""


def _u(data, fmt, off):
    return struct.unpack_from(fmt, data, off)[0]


def pe_sections(data):
    """返回 (imagebase, [(name, vaddr, vsize, rawoff, rawsize), ...])。"""
    if data[:2] != b"MZ":
        raise LocateError("不是 PE：缺少 MZ 头")
    pe_off = _u(data, "<I", 0x3C)
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise LocateError("不是 PE：0x%X 处无 PE\\0\\0 签名" % pe_off)
    coff = pe_off + 4
    # COFF 文件头固定 20 字节，可选头紧随其后（magic 在 +20，不是 +24）
    opt = coff + 20
    nsec = _u(data, "<H", coff + 2)
    optsize = _u(data, "<H", coff + 16)
    magic = _u(data, "<H", opt)
    pe32p = magic == 0x20B
    if magic not in (0x20B, 0x10B):
        raise LocateError("PE 可选头 magic=0x%X 异常（期望 0x20B/0x10B）" % magic)
    imgbase = _u(data, "<Q" if pe32p else "<I",
                 opt + (24 if pe32p else 28))
    base = opt + optsize
    secs = []
    for i in range(nsec):
        e = base + i * 40
        if e + 40 > len(data):
            raise LocateError("节表越界（声称 %d 节）" % nsec)
        name = data[e:e + 8].rstrip(b"\x00").decode("latin1")
        vsz, vaddr, rawsz, rawoff = struct.unpack_from("<IIII", data, e + 8)
        secs.append((name, vaddr, vsz, rawoff, rawsz))
    return imgbase, secs


def _klass(data):
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",   # LE / 32-bit LE
                    b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):  # BE variants
        return "macho"
    return "unknown"


class Located:
    """一次定位的全部结果。字段名保持与 keygen.py 的旧常量同名，便于替换。"""

    def __init__(self):
        self.fmt = None
        self.size = 0
        self.md5 = None
        self.sha256 = None
        # --- 公钥锚点 ---
        self.pubkey_off = None
        self.pubkey_value = None      # bytes, 64 字符 ASCII hex
        self.pubkey_unique = False
        self.pubkey_all_offsets = []
        self.other_pubkeys = []       # 同形状但被判定为其它用途的 64-hex
        # --- 文本头模板 ---
        self.sig_header = None        # bytes, 含结尾 \n
        self.sig_header_off = None
        self.ini_header = None
        self.ini_header_off = None
        # --- PE 专用 ---
        self.imagebase = None
        self.va_delta = None          # VA - file_off（.rdata）
        self.rdata = None
        self.sections = []
        self.warnings = []

    # 便捷换算
    def va_to_file(self, va):
        if self.va_delta is None:
            raise LocateError("Mach-O 无 VA 换算；直接用文件偏移")
        return va - self.va_delta

    def file_to_va(self, off):
        if self.va_delta is None:
            raise LocateError("Mach-O 无 VA 换算")
        return off + self.va_delta

    @property
    def sig_header_va(self):
        return self.file_to_va(self.sig_header_off) if self.va_delta is not None else None

    @property
    def ini_header_va(self):
        return self.file_to_va(self.ini_header_off) if self.va_delta is not None else None

    def report(self):
        L = []
        L.append("[autolocate] format=%s size=%d md5=%s" % (self.fmt, self.size, self.md5))
        if self.va_delta is not None:
            L.append("[autolocate] imagebase=0x%X  .rdata VA->file delta=0x%X"
                     % (self.imagebase, self.va_delta))
        L.append("[autolocate] pubkey      @0x%X = %s  (unique=%s, occurrences=%d)"
                 % (self.pubkey_off, self.pubkey_value.decode(), self.pubkey_unique,
                    len(self.pubkey_all_offsets)))
        if self.sig_header_off is not None:
            va = "" if self.va_delta is None else " (VA 0x%X)" % self.sig_header_va
            L.append("[autolocate] sig header  @0x%X%s = %dB"
                     % (self.sig_header_off, va, len(self.sig_header)))
        if self.ini_header_off is not None:
            va = "" if self.va_delta is None else " (VA 0x%X)" % self.ini_header_va
            L.append("[autolocate] ini header  @0x%X%s = %dB"
                     % (self.ini_header_off, va, len(self.ini_header)))
        for w in self.warnings:
            L.append("[autolocate][WARN] %s" % w)
        return "\n".join(L)


def _keypair_by_gap(cand):
    """按『许可公钥紧邻插件公钥之前』的结构特征挑出许可锚。

    cand: [(off, value_bytes), ...]（升序）。返回 ((lic_off, lic_val), plugin_off) 或 None。

    为什么这条特征可靠：许可公钥与插件公钥在 .rdata 常量区里是**相邻的两个
    长度前缀字符串**；逐版本重排会整体平移，但**二者相对间距保持**
    （README 记 0x1AA，macOS 记 0x106）。其它 64-hex 候选（hex 字母表片段、
    0x33/0x99 填充、base64-like 表）都是孤立长串，不会凑出这个间距。
    """
    # 插件公钥的已知值（README/REPORT 记录，跨版本不变）；优先用它直接定位对偶
    PLUGIN_KNOWN = "e91ee607dde422ced7046908cf0ebd4ac0fba55ac0fbd85816dcab79fb81ae0f"
    for i, (off, val) in enumerate(cand):
        if val.decode("latin1") != PLUGIN_KNOWN:
            continue
        # 找它前面最近的一个候选，间距应落在已知 gap 附近
        for poff, pval in reversed(cand[:i]):
            gap = off - poff
            if any(abs(gap - g) <= KEY_GAP_TOL for g in KNOWN_KEY_GAPS):
                return (poff, pval), off
    # 插件公钥值未知（厂商轮换）：退回"任意紧邻对 + 前者为锚"的保守判定
    for (a_off, a_val), (b_off, b_val) in zip(cand, cand[1:]):
        gap = b_off - a_off
        if any(abs(gap - g) <= KEY_GAP_TOL for g in KNOWN_KEY_GAPS):
            # 两者都不是已知插件公钥时无法断定方向，保守返回"较低偏移者为锚"
            return (a_off, a_val), b_off
    return None


def _find_headers(data):
    """扫描全部 `# ...\\n` 行，按关键字分类。返回 (proof, store) 各为 (off, bytes)。"""
    proof = store = None
    for m in HDR_RE.finditer(data):
        b = m.group()
        if PROOF_MARK in b and proof is None:
            proof = (m.start(), b)
        elif STORE_MARK in b and store is None:
            store = (m.start(), b)
    return proof, store


def locate(data, expect_pubkey=None):
    """内容寻址定位。expect_pubkey: 可选的 64-hex 字符串，用于交叉校验。

    不修改任何数据（纯只读）。
    """
    import hashlib
    r = Located()
    r.fmt = _klass(data)
    r.size = len(data)
    r.md5 = hashlib.md5(data).hexdigest()
    r.sha256 = hashlib.sha256(data).hexdigest()

    if r.fmt == "unknown":
        raise LocateError("未知二进制格式（既非 PE 也非 Mach-O）")

    # ---- 1. 公钥锚点：64-hex 形状 + 唯一性 ----
    hits = []
    last = -HEX_STEP
    for m in HEX64_RE.finditer(data):
        if m.start() >= last + HEX_STEP:   # 同一长串内的滑动匹配去重
            hits.append(m.start())
            last = m.start()
    cand = [(off, data[off:off + 64]) for off in hits]
    if not cand:
        raise LocateError("未找到任何 64 字符十六进制 ASCII 常量（形状特征不匹配？）")

    # ---- 选锚策略（按可信度降序）----
    # A. 期望值精确匹配：最强，直接采用。
    # B. 结构特征：许可公钥与插件公钥成对出现，许可在**较低偏移**，间距 ≈0x1AA/0x106。
    # C. 邻近头模板：弱启发式，仅在 A/B 都不可用时兜底，并强制告警。
    chosen = None
    if expect_pubkey is not None:
        ev = expect_pubkey.encode() if isinstance(expect_pubkey, str) else expect_pubkey
        for off, v in cand:
            if v == ev:
                chosen = (off, v)
                break
        if chosen is None:
            r.warnings.append("期望公钥 %s… 未在文件中出现 —— 厂商可能已轮换密钥，"
                              "退回结构/形状定位（请人工确认候选）" % ev[:16].decode())

    if chosen is None:
        pair = _keypair_by_gap(cand)
        if pair is not None:
            chosen, plugin_off = pair
            r.other_pubkeys = [o for o, _ in cand if o != chosen[0]]
            r.warnings.append("未给出期望公钥：按『许可/插件公钥成对』结构特征选定 "
                              "@0x%X（插件公钥 @0x%X，间距 0x%X）"
                              % (chosen[0], plugin_off, plugin_off - chosen[0]))
        else:
            proof, store = _find_headers(data)
            ref = proof[0] if proof else (store[0] if store else None)
            if ref is not None:
                cand.sort(key=lambda t: abs(t[0] - ref))
            chosen = cand[0]
            r.other_pubkeys = [o for o, _ in cand[1:]]
            r.warnings.append("既无期望公钥、也未匹配到公钥结构特征：退回『离头模板最近』"
                              "弱启发式 @0x%X —— 该结果**不可直接用于打补丁**，"
                              "请用 --expect-pubkey 或人工核对。其余候选：%s"
                              % (chosen[0], ", ".join("0x%X" % o for o in r.other_pubkeys)))
    r.pubkey_off, r.pubkey_value = chosen
    r.pubkey_all_offsets = [o for o, _ in cand]
    r.pubkey_unique = len(cand) == 1

    # ---- 2. 文本头模板 ----
    proof, store = _find_headers(data)
    if proof:
        r.sig_header_off, r.sig_header = proof
    else:
        r.warnings.append("未找到签名证明头模板（'# ...license proof...'）"
                          "—— 宽限/自签流程需要它，请确认样本版本")
    if store:
        r.ini_header_off, r.ini_header = store
    else:
        r.warnings.append("未找到许可存储头模板（'# ...license store...'）")

    # ---- 3. PE：节表 + VA_DELTA ----
    if r.fmt == "pe":
        imgbase, secs = pe_sections(data)
        r.imagebase = imgbase
        r.sections = secs
        rd = [s for s in secs if s[0] == ".rdata"]
        if not rd:
            raise LocateError("PE 无 .rdata 节 —— 地址级假设失效")
        _, vaddr, _, rawoff, _ = rd[0]
        r.rdata = rd[0]
        r.va_delta = imgbase + vaddr - rawoff
        # 一致性：两个头模板都应落在 .rdata 内
        for tag, off in (("sig", r.sig_header_off), ("ini", r.ini_header_off)):
            if off is None:
                continue
            if not (rawoff <= off < rawoff + rd[0][4]):
                r.warnings.append("%s 头模板 @0x%X 不在 .rdata 内（0x%X..0x%X）"
                                  % (tag, off, rawoff, rawoff + rd[0][4]))

    # ---- 4. 自洽性断言 ----
    if r.pubkey_value and r.sig_header is not None:
        # 许可公钥与头模板应同处常量区（相对距离合理，通常 < 1MB）
        dist = abs(r.pubkey_off - r.sig_header_off)
        if dist > (1 << 20):
            r.warnings.append("公钥与签名头模板相距 0x%X（>1MB）—— 疑似定位错误" % dist)
    return r


def locate_file(path, expect_pubkey=None):
    with open(path, "rb") as f:
        return locate(f.read(), expect_pubkey=expect_pubkey)


def _mk_pe(pub, plugin, proof, store, rdata_va=0x1000, rdata_raw=0x400):
    """构造最小可用 PE32+ 样本，用于回归测试容器解析。

    布局刻意与真实样本同构：COFF 头 20 字节 + 可选头 0xF0 字节 + 节表，
    .rdata 内含 proof 模板 / store 模板 / 许可公钥 / 插件公钥（后者在后）。
    """
    pe_off = 0x100
    nsec = 1
    buf = bytearray(0x4000)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = pe_off.to_bytes(4, "little")
    # pe_off 指向 "PE\0\0" 签名本身；COFF 头从签名之后开始
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"
    coff = pe_off + 4
    buf[coff + 2:coff + 4] = nsec.to_bytes(2, "little")     # NumberOfSections
    buf[coff + 16:coff + 18] = (0xF0).to_bytes(2, "little")  # SizeOfOptionalHeader
    opt = coff + 20
    buf[opt:opt + 2] = (0x20B).to_bytes(2, "little")         # PE32+
    buf[opt + 24:opt + 32] = (0x140000000).to_bytes(8, "little")  # ImageBase
    st = opt + 0xF0
    buf[st:st + 8] = b".rdata\x00\x00"
    vsz, rva, rawsz, rawptr = 0x2000, rdata_va, 0x2000, rdata_raw
    buf[st + 8:st + 12] = vsz.to_bytes(4, "little")
    buf[st + 12:st + 16] = rva.to_bytes(4, "little")
    buf[st + 16:st + 20] = rawsz.to_bytes(4, "little")
    buf[st + 20:st + 24] = rawptr.to_bytes(4, "little")
    # 节表结束于 st+40，raw 数据必须落在其后，否则会与节表自身重叠
    assert rdata_raw >= st + 40, "fixture: .rdata raw 起点与节表重叠"
    base = rawptr
    buf[base:base + len(store)] = store
    buf[base + 0x100:base + 0x100 + 64] = pub.encode()
    buf[base + 0x100 + 0x1AA:base + 0x100 + 0x1AA + 64] = plugin.encode()
    buf[base + 0x400:base + 0x400 + len(proof)] = proof
    return bytes(buf)


def _mk_macho(pub, plugin, proof, store):
    """构造最小 Mach-O 样本：无 VA 换算，锚点即文件偏移。"""
    buf = bytearray(0x4000)
    buf[0:4] = (0xFEEDFACF).to_bytes(4, "little")   # MH_MAGIC_64
    buf[0x200:0x200 + len(store)] = store
    buf[0x300:0x300 + 64] = pub.encode()
    buf[0x300 + 0x106:0x300 + 0x106 + 64] = plugin.encode()
    buf[0x800:0x800 + len(proof)] = proof
    return bytes(buf)


def _selftest():
    """autolocate 自身的回归用例（合成 fixture，不依赖外部样本）。"""
    PROOF = b"# fake license proof \xe2\x80\x94 do not edit\n"
    STORE = b"# fake license store \xe2\x80\x94 do not edit\n"
    PUB = "aa" * 32
    PLUGIN = "e91ee607dde422ced7046908cf0ebd4ac0fba55ac0fbd85816dcab79fb81ae0f"
    n = [0, 0]   # [总数, 失败数]

    def chk(name, ok, detail=""):
        n[0] += 1
        if not ok:
            n[1] += 1
        print("  [%s] %s%s" % ("OK  " if ok else "FAIL", name,
                               "" if ok or not detail else "  <- " + detail))
        return ok

    pe = _mk_pe(PUB, PLUGIN, PROOF, STORE)
    r = locate(pe, expect_pubkey=PUB)
    chk("PE: 解析出 imagebase", r.imagebase == 0x140000000, hex(r.imagebase or 0))
    chk("PE: VA->file delta 正确", r.va_delta == 0x140000000 + 0x1000 - 0x400,
        hex(r.va_delta or 0))
    chk("PE: 公钥锚点在较低偏移（非插件公钥）", r.pubkey_value.decode() == PUB,
        r.pubkey_value.decode()[:16])
    chk("PE: proof 模板定位", r.sig_header == PROOF and r.sig_header_off == 0x400 + 0x400)
    chk("PE: store 模板定位", r.ini_header == STORE and r.ini_header_off == 0x400)
    chk("PE: sig_header_va 换算", r.sig_header_va == 0x400 + 0x400 + r.va_delta)

    # 关键回归：不给期望值时，必须靠"公钥成对"结构特征排除插件公钥
    r2 = locate(pe)
    chk("PE: 无期望值时仍选中许可公钥（结构特征）", r2.pubkey_value.decode() == PUB,
        r2.pubkey_value.decode()[:16])
    chk("PE: 结构特征命中时给出告警说明依据",
        any("成对" in w or "pair" in w.lower() for w in r2.warnings), str(r2.warnings))

    m = _mk_macho(PUB, PLUGIN, PROOF, STORE)
    rm = locate(m, expect_pubkey=PUB)
    chk("Mach-O: 识别格式", rm.fmt == "macho", rm.fmt)
    chk("Mach-O: 公钥锚点正确", rm.pubkey_off == 0x300, hex(rm.pubkey_off or 0))
    chk("Mach-O: 无 VA delta", rm.va_delta is None)
    rm2 = locate(m)
    chk("Mach-O: 无期望值时仍选中许可公钥", rm2.pubkey_value.decode() == PUB,
        rm2.pubkey_value.decode()[:16])

    # 负例：既非 PE 也非 Mach-O 必须报错，而不是静默猜一个偏移
    try:
        locate(b"\x00" * 0x1000)
        chk("非容器输入应报错", False, "未抛 LocateError")
    except LocateError:
        chk("非容器输入应报错", True)

    print("\n  %d/%d autolocate 自检通过" % (n[0] - n[1], n[0]))
    return 1 if n[1] else 0


def main():
    import argparse
    import json
    ap = argparse.ArgumentParser(description="tessoa 授权锚点自适应定位（只读）")
    ap.add_argument("sample", nargs="?", help="样本路径（PE 或 Mach-O，pristine 或已打补丁均可）")
    ap.add_argument("--expect-pubkey", default=None,
                    help="期望的内置公钥（64-hex）；给定时优先精确匹配")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--selftest", action="store_true", help="跑内置回归用例（合成 fixture）")
    a = ap.parse_args()

    if a.selftest:
        return _selftest()
    if not a.sample:
        ap.error("需要 sample 路径，或用 --selftest")

    r = locate_file(a.sample, a.expect_pubkey)
    if a.json:
        print(json.dumps({
            "format": r.fmt, "size": r.size, "md5": r.md5, "sha256": r.sha256,
            "pubkey_off": None if r.pubkey_off is None else hex(r.pubkey_off),
            "pubkey_value": None if r.pubkey_value is None else r.pubkey_value.decode(),
            "pubkey_unique": r.pubkey_unique,
            "signature_header_off": None if r.sig_header_off is None else hex(r.sig_header_off),
            "signature_header_len": None if r.sig_header is None else len(r.sig_header),
            "signature_header_va": None if r.sig_header_va is None else hex(r.sig_header_va),
            "store_header_off": None if r.ini_header_off is None else hex(r.ini_header_off),
            "store_header_len": None if r.ini_header is None else len(r.ini_header),
            "store_header_va": None if r.ini_header_va is None else hex(r.ini_header_va),
            "imagebase": None if r.imagebase is None else hex(r.imagebase),
            "va_delta": None if r.va_delta is None else hex(r.va_delta),
            "warnings": r.warnings,
        }, indent=1, ensure_ascii=False))
    else:
        print(r.report())
        if r.warnings:
            print("\n[warnings] %d 项需要人工确认" % len(r.warnings))
    return 0


if __name__ == "__main__":
    import sys
    try:
        sys.exit(main())
    except LocateError as e:
        print("FATAL: %s" % e)
        sys.exit(2)
