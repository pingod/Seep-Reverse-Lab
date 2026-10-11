#!/usr/bin/env python3
"""__main__.py — workbench 入口

三种用法，一个二进制目标：

    # 1) 交互式 TUI（人）
    python -m workbench

    # 2) 无头一键（脚本 / agent / CI）
    python -m workbench run   --dry-run --json
    python -m workbench locate --json
    python -m workbench verify --wait 25 --json

退出码：0 全部通过 / 1 有步骤失败 / 2 用法或环境错误。
``--json`` 把结构化结果打到 stdout，人类可读日志走 stderr，方便
``| jq`` 和 agent 直接消费。
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from . import core


def _human(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def _dump(obj) -> None:
    json.dump(obj, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")


# --------------------------------------------------------------------------
# 参数
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    # 公共参数做成 parent：**`--json locate` 与 `locate --json` 都认**。
    # 只挂顶层的话，子命令后置 flag 会报 unrecognized arguments，脚本/agent 极易踩坑，
    # 所以顶层与 5 个子命令各挂一份（默认值一致，后写的覆盖先写的）。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--binary", default=argparse.SUPPRESS, help="指定二进制；默认自动扫 /Applications 与 %%APPDATA%%")
    common.add_argument("--out-dir", default=argparse.SUPPRESS, help="工作目录（密钥对、许可产物），默认 ~/githome/tessa-wb-out")
    common.add_argument("--data-dir", default=argparse.SUPPRESS, help="许可数据目录（license.ini / license.sig 所在）")
    common.add_argument("--backup-dir", default=argparse.SUPPRESS, help="原件备份目录，默认 ~/githome/telsea-mac-backup")
    common.add_argument("--json", default=argparse.SUPPRESS, action="store_true", help="结果以 JSON 打到 stdout（人类日志走 stderr）")

    p = argparse.ArgumentParser(
        prog="python -m workbench",
        parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="补丁流水线工作台：换版本只需丢进新二进制，偏移现算。",
        epilog=__doc__,
    )

    sub = p.add_subparsers(dest="cmd")

    # TUI 参数
    sub.add_parser("tui", parents=[common], help="交互式 TUI（默认命令）")

    r = sub.add_parser("run", parents=[common], help="无头跑完整条流水线")
    r.add_argument("--dry-run", action="store_true",
                   help="只算不写：不改二进制、不重签、不下发许可")
    r.add_argument("--new-key", action="store_true", help="强制新生成密钥对（默认复用）")
    r.add_argument("--no-resign", action="store_true", help="跳过 ad-hoc 重签（Windows 自动跳过）")
    r.add_argument("--no-patch", action="store_true", help="不打补丁（只重签发证）")
    r.add_argument("--no-deploy", action="store_true", help="不把 license.* 下发到数据目录")
    r.add_argument("--no-revalidate", action="store_true",
                   help="不下发强制重校验标记（保留现有 last_validated/activated）")
    r.add_argument("--expect-pubkey", help="期望的许可公钥（交叉校验用，十六进制 64 字符）")
    r.add_argument("--fp", help="覆盖设备指纹（默认现算）")
    r.add_argument("--no-fp", action="store_true", help="不绑设备指纹")
    r.add_argument("--license-key", help="自定义许可号")
    r.add_argument("--updates", default=core.UPDATES, help="updates 字段（默认 %s）" % core.UPDATES)
    r.add_argument("--sig-date-offset-days", type=int, default=core.SIG_DATE_OFFSET_DAYS)
    r.add_argument("--expiry-days", type=int, default=core.EXPIRY_DAYS)

    lo = sub.add_parser("locate", parents=[common], help="只做锚点定位")
    lo.add_argument("--expect-pubkey", help="期望的许可公钥（十六进制 64 字符）")

    v = sub.add_parser("verify", parents=[common], help="强制重校验 + 日志正向取证（确认激活态）")
    v.add_argument("--wait", type=float, default=22.0, help="应用启动后等待秒数（默认 22）")
    v.add_argument("--no-launch", action="store_true", help="不拉起应用，只读现有 exit.log")

    sub.add_parser("info", parents=[common], help="打印目标与锚点概览（只读）")
    rs = sub.add_parser("restore", parents=[common],
                        help="还原补丁前原件 + 重签（默认同时清许可）")
    rs.add_argument("--keep-license", action="store_true",
                    help="只还原 binary，保留已部署 license.*")
    rs.add_argument("--yes", action="store_true",
                    help="确认执行（不带则只预览）")
    return p


def _detect(a) -> core.TargetInfo:
    return core.detect_target(
        binary=getattr(a, "binary", None), data_dir=getattr(a, "data_dir", None),
        backup_dir=getattr(a, "backup_dir", None), out_dir=getattr(a, "out_dir", None),
    )


# --------------------------------------------------------------------------
# 子命令
# --------------------------------------------------------------------------

def cmd_locate(a) -> int:
    t = _detect(a)
    r = core.step_locate(t, expect_pubkey=getattr(a, "expect_pubkey", None))
    if getattr(a, "json", False):
        d = dict(r.data)
        d.pop("report", None)
        _dump({"ok": r.ok, "detail": r.detail, "target": {
            "binary": t.binary, "platform": t.platform, "fmt": t.fmt,
            "version": t.version, "size": t.size, "md5": t.md5,
            "data_dir": t.data_dir, "patched": t.patched,
        }, "anchors": d})
    else:
        print(r.detail)
        print()
        print(r.data.get("report", ""))
    return 0 if r.ok else 1


def cmd_info(a) -> int:
    t = _detect(a)
    if getattr(a, "json", False):
        _dump({"binary": t.binary, "platform": t.platform, "fmt": t.fmt,
               "version": t.version, "bundle": t.bundle, "size": t.size,
               "md5": t.md5, "data_dir": t.data_dir, "backup_dir": t.backup_dir,
               "out_dir": t.out_dir, "patched": t.patched, "vendor_pub": t.vendor_pub})
        return 0
    print("二进制   : %s" % t.binary)
    print("平台/格式: %s / %s" % (t.platform, t.fmt))
    print("版本     : %s" % (t.version or "?"))
    print("大小     : %d B" % t.size)
    print("md5      : %s" % t.md5)
    print("许可数据 : %s" % t.data_dir)
    print("备份目录 : %s" % t.backup_dir)
    print("工作目录 : %s" % t.out_dir)
    print("当前公钥 : %s%s" % (t.vendor_pub[:16] + "…",
                               "  [已打补丁]" if t.patched else "  [厂商原版]"))
    return 0


def cmd_run(a) -> int:
    t = _detect(a)
    rep = core.run_pipeline(
        t,
        new_key=a.new_key,
        dry_run=a.dry_run,
        do_resign=not a.no_resign,
        do_patch=not a.no_patch,
        do_deploy=not a.no_deploy,
        expect_pubkey=a.expect_pubkey,
        sig_date_offset_days=a.sig_date_offset_days,
        expiry_days=a.expiry_days,
        updates=a.updates,
        license_key=a.license_key,
        fp=a.fp,
        no_fp=a.no_fp,
        force_revalidate=not a.no_revalidate,
        out_dir=getattr(a, "out_dir", None),
        emit=_human,
    )
    if getattr(a, "json", False):
        _dump({"ok": rep.ok, "summary": rep.summary(),
               "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail}
                         for s in rep.steps],
               "out_dir": t.out_dir})
    else:
        sys.stdout.flush()               # 让 emit 的 stderr 先落地，合并输出不串行
        print()
        print("━━━ %s ━━━" % rep.summary())
        for s in rep.steps:
            print("  %s" % s)
        print()
        print("下一步: python -m workbench verify   # 强制重校验 + 日志取证")
    return 0 if rep.ok else 1


def cmd_verify(a) -> int:
    t = _detect(a)
    r = core.verify_activation(t, wait_s=a.wait, launch=not a.no_launch)
    if getattr(a, "json", False):
        _dump({"ok": r.ok, "detail": r.detail, "state": r.data.get("state"),
               "log_path": r.data.get("log_path"), "log_tail": r.data.get("log_tail")})
    else:
        print(r.detail)
        print()
        print("── exit.log 尾部 ──")
        print((r.data.get("log_tail") or "").rstrip())
    return 0 if r.ok else 1


def cmd_restore(a) -> int:
    t = _detect(a)
    # 还原是破坏性动作（真机二进制/许可会被覆盖删除），
    # 不许在没显式指定 --binary 时静默扫到真机就动手 —— 那正是这次真机许可被误删的根因。
    # 显式 --binary 仍要 --yes 才动真格；两者都不给 = 只打印将要做什么。
    if not getattr(a, "yes", False):
        print("[预览] 将对以下目标执行还原（覆盖 binary + 删除 license.*）：")
        print("  binary    :", t.binary)
        print("  backup_dir:", t.backup_dir)
        print("  data_dir  :", t.data_dir)
        print("确认无误加 --yes 执行；只还原 binary 保留许可加 --keep-license。")
        return 2
    r = core.restore_binary(t, keep_license=getattr(a, "keep_license", False))
    if getattr(a, "json", False):
        _dump({"ok": r.ok, "detail": r.detail, "data": r.data})
    else:
        print(("[OK] " if r.ok else "[!!] ") + r.detail)
        if r.ok:
            print("下一步: python -m workbench verify --no-launch  # 或重新跑 run 重打补丁")
    return 0 if r.ok else 1


def cmd_tui(a) -> int:
    from .tui import run as tui_run          # 延迟导入：非 TTY 场景不必碰 curses
    return tui_run(binary=getattr(a, "binary", None),
                   out_dir=getattr(a, "out_dir", None),
                   data_dir=getattr(a, "data_dir", None),
                   backup_dir=getattr(a, "backup_dir", None))


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    a = p.parse_args(argv)
    cmd = a.cmd or ("tui" if sys.stdout.isatty() else "run")

    fn = {"run": cmd_run, "locate": cmd_locate, "verify": cmd_verify,
          "info": cmd_info, "tui": cmd_tui, "restore": cmd_restore}[cmd]
    try:
        return fn(a)
    except core.PipelineError as e:
        _human("✗ %s" % e)
        return 1
    except KeyboardInterrupt:
        _human("已中断")
        return 130
    except Exception as e:                     # noqa: BLE001
        _human("✗ 未预期异常: %s" % e)
        _human(traceback.format_exc())
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
