#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ida_mcp_handshake.py — 官方 Hex-Rays ida-mcp 的自检 + 真实握手（SKILL: ida-reverse §7）

设计要点（全部为 2026-09-27 实测结论）：
  * 不再有「轮询 127.0.0.1:13337」—— 官方 server 用 ida-nexus 发现后端，端口每次随机。
  * 不再需要 Ctrl+Alt+M 唤醒插件 —— open_database 自己就能起无头 idalib worker。
  * 就绪判据 = open_database 返回 isError:false 且 len(db.functions) / len(db.strings) > 0。

用法：
  python ida_mcp_handshake.py --status                     # 只体检，不碰任何数据库
  python ida_mcp_handshake.py --target "D:\\x\\a.exe"       # 体检 + 真握手（开库→读量→保存→关闭）
  python ida_mcp_handshake.py --target ... --keep-open     # 握手后不 close（继续在同一 lease 里干活）
  python ida_mcp_handshake.py --no-save                    # 握手时不落盘（只读侦察）
退出码：0=就绪可用；1=环境缺件；2=握手失败。
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

try:  # Windows 控制台默认 cp936，统一改按 UTF-8 写出（重定向到文件时保持可读）
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

APPMATA = os.environ.get("APPDATA", "")
IDA_APP = os.path.join(APPMATA, "Hex-Rays", "IDA Pro")
NEXUS_INST = os.path.join(IDA_APP, "nexus", "instances")
NEXUS_LOGS = os.path.join(IDA_APP, "nexus", "logs")
SESSIONS = os.path.join(IDA_APP, "mcp", "sessions")
PLUGIN_DIR = os.path.join(IDA_APP, "plugins", "ida-mcp")


def say(tag, msg):
    print("%-10s %s" % (tag, msg), flush=True)


# ------------------------------------------------------------------ 定位组件
def find_uvx():
    """uvx 必须是**绝对路径**：MCP 里写裸 'uvx' 在 Windows 上会 WinError 2。"""
    cands = []
    w = shutil.which("uvx") or shutil.which("uvx.exe")
    if w:
        cands.append(w)
    pats = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python*", "Scripts", "uvx.exe"),
        os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Programs", "Python", "Python*", "Scripts", "uvx.exe"),
        os.path.join(os.environ.get("USERPROFILE", ""), ".local", "bin", "uvx.exe"),
        r"D:\Program Files\Python\Python*\Scripts\uvx.exe",
        r"C:\Program Files\Python*\Scripts\uvx.exe",
    ]
    for p in pats:
        cands.extend(sorted(glob.glob(p)))
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def ida_root():
    """IDABase 首选 ida-config.json，其次环境变量，最后扫常见安装位置。"""
    cfg = os.path.join(IDA_APP, "ida-config.json")
    if os.path.isfile(cfg):
        try:
            d = json.load(open(cfg, encoding="utf-8"))
            for key in ("ida-install-dir", "IDA-install-dir", "ida_install_dir"):
                p = d.get("Paths", {}).get(key)
                if p and os.path.isdir(p):
                    return p
        except Exception:
            pass
    env = os.environ.get("IDAPATH")
    if env and os.path.isdir(env):
        return env.rstrip("\\/")
    for pat in [r"D:\Program Files\IDA*", r"C:\Program Files\IDA*",
                r"D:\Program Files (x86)\IDA*", r"C:\Program Files (x86)\IDA*"]:
        for d in sorted(glob.glob(pat), reverse=True):
            if os.path.isfile(os.path.join(d, "ida.exe")):
                return d
    return None


def ida_python(root):
    """GUI 插件用的解释器：IDA 根下的 python3xx（9.4 自身不带 Python，靠 idapyswitch 绑定）。"""
    if not root:
        return None
    for d in sorted(glob.glob(os.path.join(root, "python3*")), reverse=True):
        exe = os.path.join(d, "python.exe")
        if os.path.isfile(exe):
            return exe
    return None


def pkg_in(python_exe, names):
    """在指定解释器里探测包版本（官方 GUI 插件依赖 ida-nexus / ida-domain）。"""
    if not python_exe or not os.path.isfile(python_exe):
        return None
    code = ("import importlib.metadata as m\n"
            "for n in %r:\n"
            "    try: print(n + '=' + m.version(n))\n"
            "    except Exception: print(n + '=MISSING')\n" % (names,))
    try:
        r = subprocess.run([python_exe, "-c", code], capture_output=True, text=True, timeout=60)
        return dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
    except Exception as e:
        return {"_error": str(e)}


def mcp_entries():
    """两个 agent 的 MCP 注册是否指向官方 server（而不是已废弃的 ida_pro_mcp）。"""
    out = []
    for label, path, key in [
        ("qoder", os.path.join(os.environ.get("USERPROFILE", ""), ".qoder", "settings.json"), "mcpServers"),
        ("pi", os.path.join(os.environ.get("USERPROFILE", ""), ".pi", "agent", "mcp.json"), "mcpServers"),
    ]:
        if not os.path.isfile(path):
            out.append((label, path, "文件不存在"))
            continue
        try:
            d = json.load(open(path, encoding="utf-8"))
            e = d.get(key, {}).get("ida")
            if not e:
                out.append((label, path, "无 ida 条目"))
                continue
            blob = json.dumps(e, ensure_ascii=False)
            bad = "ida_pro_mcp" in blob or "13337" in blob
            out.append((label, path, ("陈旧(mrexodia)" if bad else "官方 ok") +
                        " | " + " ".join(map(str, [e.get("command"), (e.get("args") or [""])[0]])) +
                        " | timeout=" + str(e.get("requestTimeoutMs", "-"))))
        except Exception as ex:
            out.append((label, path, "解析失败: %s" % ex))
    return out


# ------------------------------------------------------------------ 体检
def status():
    say("IDA_ROOT", ida_root() or "未找到（ida-config.json / IDAPATH / 常见目录都落空）")
    root = ida_root()
    py = ida_python(root)
    say("IDA_PY", py or "未找到 python3xx —— GUI 插件不可用（9.4 需 idapyswitch 绑定）")
    if py:
        for k, v in (pkg_in(py, ["ida-nexus", "ida-domain"]) or {}).items():
            say("  " + k, v)
    exe = find_uvx()
    say("UVX", exe or "未找到 uvx（官方 server 靠它启动）")
    say("PLUGIN", PLUGIN_DIR + ("  存在" if os.path.isdir(PLUGIN_DIR) else "  缺失"))
    if os.path.isdir(PLUGIN_DIR):
        say("  files", ", ".join(sorted(os.listdir(PLUGIN_DIR))))
    inst = sorted(glob.glob(os.path.join(NEXUS_INST, "*.json")))
    say("NEXUS", "%d 个在线后端" % len(inst))
    for f in inst:
        try:
            j = json.load(open(f, encoding="utf-8"))
            say("  inst", "pid=%s backend=%s port=%s exe=%s" %
                (j.get("pid"), j.get("backend"), j.get("port"), j.get("exe_path")))
        except Exception as e:
            say("  inst", os.path.basename(f) + " 读取失败(占用?) " + str(e)[:60])
    logs = sorted(glob.glob(os.path.join(NEXUS_LOGS, "*.log")), key=os.path.getmtime)
    if logs:
        last = logs[-1]
        try:
            say("  lastlog", os.path.basename(last) + " -> " + open(last, encoding="utf-8", errors="replace").read().strip())
        except Exception:
            pass
    sess = sorted(glob.glob(os.path.join(SESSIONS, "*.jsonl")), key=os.path.getmtime)
    say("SESSIONS", "%d 份 execute_python 留痕%s" %
        (len(sess), ("，最新 " + time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(sess[-1]))) if sess else "")))
    for label, path, verdict in mcp_entries():
        say("MCP:" + label, verdict + "   [" + path + "]")
    ok = bool(root and exe and os.path.isdir(PLUGIN_DIR))
    say("VERDICT", "环境齐备" if ok else "缺件 —— 见上面 FAIL 行")
    return 0 if ok else 1


# ------------------------------------------------------------------ JSON-RPC 握手
class Bridge(object):
    def __init__(self, uvx, agent):
        self.p = subprocess.Popen([uvx, "ida-mcp", "stdio", "--agent=" + agent],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True,
                                  encoding="utf-8", bufsize=1)
        self.i = 0

    def _send(self, o):
        self.p.stdin.write(json.dumps(o) + "\n")
        self.p.stdin.flush()

    def _read(self, timeout):
        t0 = time.time()
        while time.time() - t0 < timeout:
            line = self.p.stdout.readline()
            if line and line.strip():
                return json.loads(line.strip())
            if self.p.poll() is not None:
                return {"_died": self.p.stderr.read()[:800]}
        return {"_timeout": timeout}

    def call(self, method, params=None, timeout=60, is_id=True):
        if not is_id:
            self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})
            return None
        self.i += 1
        self._send({"jsonrpc": "2.0", "id": self.i, "method": method, "params": params or {}})
        return self._read(timeout)

    def tool(self, name, args, timeout=600):
        d = self.call("tools/call", {"name": name, "arguments": args}, timeout=timeout)
        if "_died" in d:
            say("FAIL", "server 进程退出：" + d["_died"])
            return None, True
        if "_timeout" in d:
            say("FAIL", "%s 超时 %ss" % (name, d["_timeout"]))
            return None, True
        if "error" in d:
            say("FAIL", "JSON-RPC 错误：" + json.dumps(d["error"], ensure_ascii=False)[:500])
            return None, True
        r = d.get("result", {})
        err = bool(r.get("isError"))
        sc = r.get("structuredContent") or {}
        txt = sc.get("stdout") or sc.get("stderr") or ""
        if not txt.strip():
            txt = "\n".join((c.get("text") or "") for c in r.get("content", []))
        return (sc if sc else {"text": txt}), err

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass


def handshake(target, keep_open, save):
    root, uvx = ida_root(), find_uvx()
    if not uvx:
        say("FAIL", "找不到 uvx，无法启动官方 ida-mcp")
        return 1
    if not os.path.isfile(target):
        say("FAIL", "目标不存在：" + target)
        return 1
    b = Bridge(uvx, "ensure")
    init = b.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "ensure", "version": "1"}}, timeout=120)
    if init is None or "error" in init or "_died" in init:
        say("FAIL", "initialize 失败：" + json.dumps(init, ensure_ascii=False)[:400])
        return 2
    si = init.get("result", {}).get("serverInfo", {})
    say("SERVER", "%s %s" % (si.get("name"), si.get("version")))
    tools = b.call("tools/list", {}, timeout=60).get("result", {}).get("tools", [])
    say("TOOLS", "%d 个：%s" % (len(tools), ", ".join(t["name"] for t in tools)))
    b.call("notifications/initialized", {}, is_id=False)

    t0 = time.time()
    sc, err = b.tool("open_database", {"path": target}, timeout=900)
    if err:
        say("FAIL", "open_database 失败（见上）")
        return 2
    say("OPEN", "%.1fs backend=%s instance=%s status=%s" %
        (time.time() - t0, sc.get("backend"), sc.get("instance_id"), sc.get("status")))
    say("LOG", str(sc.get("log_path")))

    probe = ("import idaapi\n"
             "print('kernel', idaapi.get_kernel_version())\n"
             "print('module', db.module, '| arch', db.architecture, db.bitness, '| size', db.filesize)\n"
             "print('imagebase', hex(db.base_address), '| sha256', db.sha256)\n"
             "print('functions', len(db.functions), '| strings', len(db.strings), '| imports', len(db.imports))")
    t1 = time.time()
    sc2, err2 = b.tool("execute_python", {"code": probe}, timeout=900)
    if err2:
        say("FAIL", "execute_python 失败（就绪判据不成立）")
        return 2
    say("READY", "%.1fs" % (time.time() - t1))
    for line in (sc2.get("stdout") or "").splitlines():
        say("  |", line)

    if save:
        sc3, err3 = b.tool("save_database", {}, timeout=300)
        if not err3:
            say("SAVED", str(sc3.get("path")))
    if keep_open:
        sc4, _ = b.tool("list_databases", {}, timeout=60)
        say("KEEP-OPEN", json.dumps(sc4, ensure_ascii=False))
    else:
        sc5, err5 = b.tool("close_database", {}, timeout=120)
        say("CLOSED", json.dumps(sc5, ensure_ascii=False) if not err5 else "关闭失败")
    b.close()
    say("VERDICT", "ida-mcp 可用，可以直接开始逆向会话")
    return 0


def main():
    ap = argparse.ArgumentParser(description="官方 ida-mcp 自检/握手")
    ap.add_argument("--status", action="store_true", help="只体检")
    ap.add_argument("--target", help="要握手的二进制绝对路径")
    ap.add_argument("--keep-open", action="store_true", help="握手后不 close")
    ap.add_argument("--no-save", action="store_true", help="握手时不 save_database")
    a = ap.parse_args()
    if a.target:
        return handshake(a.target, a.keep_open, not a.no_save)
    return status()


if __name__ == "__main__":
    sys.exit(main())
