#!/bin/bash
# 双击运行 tessoa 授权补丁工具 (macOS GUI)
DIR="$(cd "$(dirname "$0")" && pwd)"
PY=/opt/homebrew/bin/python3.14
[ -x "$PY" ] || PY=/usr/bin/python3
cd "$DIR" && exec "$PY" "tessoa_mac_patcher.py" gui
echo "退出码 $?"; read -p "按回车关闭..."
