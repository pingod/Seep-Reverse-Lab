#!/usr/bin/env python3
"""tui.py — 补丁流水线工作台 · 终端界面（stdlib curses，零额外依赖）

为什么是 curses 而不是 textual/rich：本机 ``pip install`` 被 PEP 668 锁死，
而系统 Python 不值得冒险破。curses 是标准库，零安装、零风险、可移植。

界面分四区
----------
    ┌ 目标区   二进制路径 / 版本 / 格式 / 大小 / md5 / 许可数据目录
    ├ 锚点区   **自动定位** 出来的许可公钥槽、插件槽、两个头模板
    ├ 管线区   9 步流水线，每步 状态 + 一行摘要
    └ 日志区   实时滚动（每个子进程输出、每步结果都往这里落）

按键
----
    R  跑全流水线        V  验证激活（强制重校验 + 日志取证）
    L  只定位            N  切换「换新钥匙」
    D  切换 dry-run       Q / Ctrl-C  退出
    ↑↓ PgUp/PgDn         翻日志        Enter  暂停/继续
"""

from __future__ import annotations

import curses
import sys
import time
import unicodedata

from . import __version__
from . import core
from .core import TargetInfo

#: 管线的展示顺序（与 core.run_pipeline 产出的步骤名一一对应）
PLAN = [
    "探测目标",
    "定位锚点",
    "备份原件",
    "生成密钥对",
    "等长打补丁",
    "ad-hoc 重签",
    "签发许可",
    "下发许可",
    "本地自校验",
]

STATUS_PENDING = "○"    # ○ 待执行
STATUS_RUNNING = "◐"    # ◐ 执行中
STATUS_OK = "✓"         # ✓ 成功
STATUS_FAIL = "✗"       # ✗ 失败


# --------------------------------------------------------------------------
# 显示宽度（CJK 占两列，否则表格会错位）
# --------------------------------------------------------------------------

def dwidth(s: str) -> int:
    w = 0
    for ch in s:
        if unicodedata.combining(ch):
            continue
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def clip(s: str, width: int) -> str:
    """按显示宽度裁剪，超长加省略号。"""
    if width <= 0:
        return ""
    if dwidth(s) <= width:
        return s
    out, w = [], 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if w + cw > width - 1:
            break
        out.append(ch)
        w += cw
    return "".join(out) + "…"


def pad(s: str, width: int) -> str:
    return clip(s, width) + " " * max(0, width - dwidth(clip(s, width)))


# --------------------------------------------------------------------------
# 配色（无色终端也不崩）
# --------------------------------------------------------------------------

class Palette:
    OK = 0
    FAIL = 0
    WARN = 0
    DIM = 0
    HEAD = 0
    ACCENT = 0
    INVERSE = 0

    @classmethod
    def setup(cls) -> None:
        try:
            curses.start_color()
            curses.use_default_colors()
            b = curses.A_BOLD
            pairs = {
                "OK": (curses.COLOR_GREEN, -1, b),
                "FAIL": (curses.COLOR_RED, -1, b),
                "WARN": (curses.COLOR_YELLOW, -1, 0),
                "DIM": (curses.COLOR_CYAN, -1, 0),
                "HEAD": (curses.COLOR_WHITE, curses.COLOR_BLUE, b),
                "ACCENT": (curses.COLOR_MAGENTA, -1, b),
            }
            for i, (name, (fg, bg, attr)) in enumerate(pairs.items(), start=1):
                try:
                    curses.init_pair(i, fg, bg)
                except curses.error:
                    continue
                setattr(cls, name, curses.color_pair(i) | attr)
            cls.INVERSE = curses.A_REVERSE
        except curses.error:
            pass


# --------------------------------------------------------------------------
# 应用状态
# --------------------------------------------------------------------------

class App:
    def __init__(self, stdscr, binary: str | None = None,
                 out_dir: str | None = None, data_dir: str | None = None,
                 backup_dir: str | None = None, autoscan: bool = True):
        self.scr = stdscr
        self.binary_arg = binary
        self.out_dir = out_dir
        self.data_dir = data_dir
        self.backup_dir = backup_dir
        self.autoscan = autoscan

        self.target: TargetInfo | None = None
        self.target_err: str = ""
        self.anchors: dict = {}
        self.state: dict[str, tuple[str, str]] = {n: (STATUS_PENDING, "") for n in PLAN}
        self.logs: list[str] = []
        self.log_scroll = 0
        self.busy = False
        self.paused = False
        self.dry_run = False
        self.new_key = False
        self.force_rev = True
        self.status = "按 R 跑流水线 · L 先定位 · Q 退出"
        self.quit = False
        self.last_run: str = ""

    # -- 日志 -------------------------------------------------------------
    def log(self, msg: str = "") -> None:
        ts = time.strftime("%H:%M:%S")
        for line in str(msg).split("\n"):
            self.logs.append("%s %s" % (ts, line))
        self.log_scroll = 0
        self.draw()

    def clear_log(self) -> None:
        self.logs.clear()
        self.log_scroll = 0

    # -- 探测 -------------------------------------------------------------
    def scan(self, quiet: bool = False) -> bool:
        try:
            self.target = core.detect_target(
                binary=self.binary_arg, data_dir=self.data_dir,
                backup_dir=self.backup_dir, out_dir=self.out_dir,
            )
            self.target_err = ""
            if not quiet:
                self.log("● 探测 %s %s %s (%d B, md5 %s)"
                         % (self.target.fmt, self.target.version,
                            self.target.binary, self.target.size, self.target.md5[:12]))
                self.log("  许可数据目录: %s" % self.target.data_dir)
            return True
        except Exception as e:
            self.target = None
            self.target_err = str(e)
            if not quiet:
                self.log("✗ 探测失败: %s" % e)
            return False

    def locate(self) -> None:
        if not self.target and not self.scan():
            return
        self.state["定位锚点"] = (STATUS_RUNNING, "…")
        self.draw()
        try:
            r = core.step_locate(self.target)
            self.anchors = r.data
            self.state["定位锚点"] = (STATUS_OK, r.detail)
            self.log("✓ %s" % r.detail)
            for w in r.data.get("warnings", []):
                self.log("  ⚠ %s" % w)
        except Exception as e:
            self.state["定位锚点"] = (STATUS_FAIL, str(e))
            self.log("✗ 定位失败: %s" % e)

    # -- 动作 -------------------------------------------------------------
    def act_pipeline(self) -> None:
        if not self.target and not self.scan():
            return
        self.busy = True
        self.paused = False
        self.status = "管线执行中…"
        self.clear_log()
        for n in self.state:
            self.state[n] = (STATUS_PENDING, "")
        self.draw()

        def emit(msg: str) -> None:
            self.log(msg)

        try:
            rep = core.run_pipeline(
                self.target, new_key=self.new_key, dry_run=self.dry_run,
                force_revalidate=self.force_rev and not self.dry_run,
                out_dir=self.out_dir, emit=emit,
            )
            # 用返回值刷新状态区
            for n in PLAN:
                self.state[n] = (STATUS_PENDING, "")
            for s in rep.steps:
                if s.name in self.state:
                    self.state[s.name] = (
                        (STATUS_OK if s.ok else STATUS_FAIL), s.detail)
            if "定位锚点" in [s.name for s in rep.steps]:
                try:
                    self.anchors = core.step_locate(self.target).data
                except Exception:
                    pass
            ok = sum(1 for s in rep.steps if s.ok)
            self.last_run = "OK" if rep.ok else "FAILED"
            self.status = "管线%s · %d/%d 步通过%s" % (
                self.last_run, ok, len(rep.steps),
                "（dry-run）" if self.dry_run else "")
            self.log("")
            self.log("━━━ 管线%s ━━━" % self.last_run)
            for s in rep.steps:
                self.log("  %s %s" % ("✓" if s.ok else "✗", s))
            self.log("提示: 按 V 做激活态正向取证")
        except KeyboardInterrupt:
            self.status = "已中断"
            self.log("✗ 用户中断")
        except Exception as e:
            self.status = "异常: %s" % e
            self.log("✗ 管线异常: %s" % e)
        finally:
            self.busy = False
            self.draw()

    def act_verify(self) -> None:
        if not self.target and not self.scan():
            return
        self.busy = True
        self.status = "强制重校验中（启动应用 → 等待 → ⌘Q → 读 exit.log）…"
        self.log("── 激活态取证：清零 last_validated/activated，强制下次启动重校验 ──")
        self.draw()
        try:
            r = core.verify_activation(self.target, wait_s=22.0)
            self.state.setdefault("验证激活", (STATUS_OK, r.detail))
            extra = "验证激活" if "验证激活" not in PLAN else None
            if extra:
                self.log("✓ %s" % r.detail)
            self.status = "激活态: %s" % r.data.get("state", r.detail)
            tail = r.data.get("log_tail", "")
            if tail:
                self.log("── exit.log 尾部 ──")
                self.log(tail.rstrip())
        except KeyboardInterrupt:
            self.status = "已中断"
        except Exception as e:
            self.status = "异常: %s" % e
            self.log("✗ 验证异常: %s" % e)
        finally:
            self.busy = False
            self.draw()

    def act_restore(self) -> None:
        if not self.target and not self.scan():
            return
        # 破坏性动作两段确认：第一回 X 只显示预览，再按一次 X 才真做。
        if not getattr(self, "restore_armed", False):
            self.restore_armed = True
            self.status = "还原预览 —— 再按一次 X 确认执行，按其他键取消"
            self.log("── [预览] 还原将覆盖 binary 并删除 license.* ──")
            self.draw()
            return
        self.restore_armed = False
        self.busy = True
        self.status = "还原补丁前原件 + ad-hoc 重签 + 清许可…"
        self.log("── 还原：binary ← 备份原件，许可文件一并清除 ──")
        self.draw()
        try:
            r = core.restore_binary(self.target)
            self.restored = r.ok
            self.log(("✓ " if r.ok else "✗ ") + r.detail)
            self.status = "还原完成 —— 重跑流水线可再打补丁" if r.ok else "还原失败"
        except Exception as e:
            self.status = "异常: %s" % e
            self.log("✗ 还原异常: %s" % e)
        finally:
            self.busy = False
            self.draw()

    # -- 绘制 -------------------------------------------------------------
    def draw(self) -> None:
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        if h < 12 or w < 60:
            self._centered("终端太小：需要至少 60×12（当前 %d×%d）" % (w, h), h, w,
                           Palette.WARN)
            self.scr.refresh()
            return

        P = Palette
        row = 0

        # ---- 标题 ----
        title = " 补丁流水线工作台 · workbench %s " % __version__
        self._bar(row, title, P.HEAD, w)
        row += 1
        # ---- 目标区 ----
        row = self._target_panel(row, h, w, P)

        # ---- 锚点区 ----
        row = self._anchor_panel(row, h, w, P)

        # ---- 管线区 ----
        row = self._plan_panel(row, h, w, P)

        # ---- 日志区（填到状态栏之上）----
        status_row = h - 2
        log_h = max(3, status_row - row)
        row += 1
        self._bar(row, " 日志 ", P.DIM, w)
        row += 1
        row = self._log_panel(row, log_h, w, P)

        # ---- 状态栏 / 按键栏 ----
        self._bar(h - 2, " %s " % clip(self.status, w - 2), P.ACCENT, w)
        self._bar(h - 1,
                  " [R]流水线  [V]验证激活  [L]定位  [X]还原%s  [N]新钥匙%s  [D]dry-run%s  [↑↓]日志  [Q]退出"
                  % ("●" if getattr(self, "restored", False) else "○",
                     "●" if self.new_key else "○",
                     "●" if self.dry_run else "○"),
                  P.DIM, w)

        self.scr.refresh()

    def _bar(self, y: int, text: str, attr: int, w: int) -> None:
        self._put(y, 0, pad(text, w), attr)

    def _put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h:
            return
        text = text[:max(0, w - x)]
        if x >= w:
            return
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass  # 右下角写满会抛，忽略

    def _centered(self, text: str, h: int, w: int, attr: int) -> None:
        self._put(h // 2, max(0, (w - dwidth(text)) // 2), clip(text, w), attr)

    def _target_panel(self, row: int, h: int, w: int, P) -> int:
        self._bar(row, " 目标 ", P.DIM, w)
        row += 1
        t = self.target
        if not t:
            msg = ("✗ %s" % self.target_err) if self.target_err else "（尚未探测，按 L 或 R）"
            self._put(row, 1, clip(msg, w - 2), P.FAIL if self.target_err else P.DIM)
            return row + 1

        self._put(row, 1, pad(t.binary, w - 2), P.OK)
        row += 1
        tag = "已打补丁" if t.patched else "厂商原版"
        line = "  %s  %s  %s B  md5 %s  [%s]" % (t.fmt, t.version, t.size, t.md5[:12], tag)
        self._put(row, 1, clip(line, w - 2),
                  P.WARN if t.patched else 0)
        row += 1
        self._put(row, 1, clip("  数据目录: %s" % t.data_dir, w - 2), P.DIM)
        return row + 1

    def _anchor_panel(self, row: int, h: int, w: int, P) -> int:
        self._bar(row, " 自动定位锚点 ", P.DIM, w)
        row += 1
        a = self.anchors
        if not a:
            self._put(row, 1, clip("（按 L 现算，无需手输任何偏移）", w - 2), P.DIM)
            return row + 1
        plug = a.get("plugin_off")
        lines = [
            "  许可公钥槽 @0x%X  %s…" % (a["pubkey_off"], a["pubkey_value"][:16]),
            "  插件公钥槽 @%s   (对偶定位参照，不修改)"
            % ("0x%X" % plug if plug else "—"),
            "  sig 头 @0x%X  %dB   ini 头 @0x%X  %dB"
            % (a.get("sig_header_off") or 0, len(a.get("sig_header") or b""),
               a.get("ini_header_off") or 0, len(a.get("ini_header") or b"")),
        ]
        for ln in lines:
            self._put(row, 0, clip(ln, w), 0)
            row += 1
        return row + 1

    def _plan_panel(self, row: int, h: int, w: int, P) -> int:
        self._bar(row, " 管线 ", P.DIM, w)
        row += 1
        name_w = max(dwidth(n) for n in PLAN) + 2
        detail_w = w - name_w - 5
        for n in PLAN:
            icon, detail = self.state.get(n, (STATUS_PENDING, ""))
            attr = P.OK if icon == STATUS_OK else (P.FAIL if icon == STATUS_FAIL else 0)
            self._put(row, 1, icon + " ", attr)
            self._put(row, 3, pad(n, name_w), attr)
            self._put(row, 3 + name_w, clip(detail, detail_w), P.DIM)
            row += 1
        return row

    def _log_panel(self, row: int, height: int, w: int, P) -> int:
        end = row + height - 1
        view = self.logs[max(0, len(self.logs) - self.log_scroll - height):
                         len(self.logs) - self.log_scroll if self.log_scroll else len(self.logs)]
        if self.paused and self.logs:
            self._put(row, w - 6, " ⏸暂停", P.WARN)
        for i, ln in enumerate(view):
            self._put(row + i, 0, clip(ln, w), 0)
        return end

    # -- 主循环 -----------------------------------------------------------
    def loop(self) -> None:
        Palette.setup()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        self.scr.keypad(True)
        if self.autoscan:
            self.scan(quiet=True)
            try:
                self.anchors = core.step_locate(self.target).data
            except Exception:
                pass

        while not self.quit:
            self.draw()
            try:
                ch = self.scr.getch()
            except KeyboardInterrupt:
                break
            if ch == -1:
                time.sleep(0.15)
                continue

            self.restore_armed = False
            if ch in (ord("q"), ord("Q"), 27):
                self.quit = True
                break

            if self.busy:
                if ch == ord("\n"):
                    self.paused = not self.paused
                    self.status = "已暂停显示（再按 Enter 继续）" if self.paused else "继续"
                continue

            if ch in (ord("r"), ord("R")):
                self.act_pipeline()
            elif ch in (ord("v"), ord("V")):
                self.act_verify()
            elif ch in (ord("l"), ord("L")):
                self.clear_log()
                self.locate()
                self.status = "定位完成 —— 偏移已现算，无需手输"
            elif ch in (ord("n"), ord("N")):
                self.new_key = not self.new_key
                self.status = "换新钥匙: %s" % ("开（下次 R 生成新密钥对）" if self.new_key
                                                else "关（复用既有密钥对）")
            elif ch in (ord("d"), ord("D")):
                self.dry_run = not self.dry_run
                self.status = "dry-run: %s" % ("开（不写盘、不重签）" if self.dry_run
                                                else "关（真实执行）")
            elif ch in (ord("x"), ord("X")):
                self.act_restore()
            elif ch in (ord("s"), ord("S")):
                if self.scan():
                    try:
                        self.anchors = core.step_locate(self.target).data
                        self.status = "已重新探测"
                    except Exception as e:
                        self.status = "探测到但定位失败: %s" % e
                else:
                    self.status = "探测失败: %s" % self.target_err
            elif ch == ord("\n"):
                self.paused = not self.paused
            elif ch in (curses.KEY_UP, ord("k")):
                self.log_scroll += 1
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.log_scroll = max(0, self.log_scroll - 1)
            elif ch == curses.KEY_PPAGE:
                self.log_scroll += 10
            elif ch == curses.KEY_NPAGE:
                self.log_scroll = max(0, self.log_scroll - 10)
            elif ch == curses.KEY_RESIZE:
                pass


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------

def run(binary: str | None = None, out_dir: str | None = None,
        data_dir: str | None = None, backup_dir: str | None = None) -> int:
    if not sys.stdout.isatty():
        sys.stderr.write(
            "workbench TUI 需要交互式终端。\n"
            "脚本 / agent 场景请用无头模式：\n"
            "    python -m workbench run --json\n"
            "    python -m workbench locate\n"
            "    python -m workbench verify\n")
        return 2
    try:
        curses.wrapper(
            lambda scr: App(scr, binary, out_dir, data_dir, backup_dir).loop())
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
