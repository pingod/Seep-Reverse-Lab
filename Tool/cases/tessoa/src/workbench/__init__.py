"""workbench — 补丁流水线工作台

自动化导向：换版本只需把新二进制丢进来，偏移由内容寻址现算，整条链自动重跑。

    python -m workbench            # 交互式 TUI（curses，零额外依赖）
    python -m workbench run        # 无头一键，供脚本 / agent / CI 驱动
    python -m workbench locate     # 只做定位，打印锚点
    python -m workbench verify     # 强制重校验 + 日志正向取证

核心 API（可 import）::

    from workbench import detect_target, run_pipeline, verify_activation
    t = detect_target()
    rep = run_pipeline(t)
    assert rep.ok
"""

from .core import (  # noqa: F401
    PLUGIN_PUBKEY,
    VENDOR_PUBKEY,
    PipelineError,
    PipelineReport,
    StepResult,
    TargetInfo,
    deploy_license,
    detect_target,
    device_fp,
    fnv1a64,
    load_or_create_keypair,
    run_pipeline,
    step_backup,
    step_locate,
    step_mint,
    step_patch,
    step_resign,
    step_verify,
    verify_activation,
    verify_sig,
)

__all__ = [
    "PLUGIN_PUBKEY",
    "VENDOR_PUBKEY",
    "PipelineError",
    "PipelineReport",
    "StepResult",
    "TargetInfo",
    "deploy_license",
    "detect_target",
    "device_fp",
    "fnv1a64",
    "load_or_create_keypair",
    "run_pipeline",
    "step_backup",
    "step_locate",
    "step_mint",
    "step_patch",
    "step_resign",
    "step_verify",
    "verify_activation",
    "verify_sig",
]

__version__ = "1.0.0"
