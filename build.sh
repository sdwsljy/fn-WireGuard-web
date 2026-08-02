#!/bin/bash
# ============================================================
# fn-wg-web 打包脚本（Linux / fnOS）
# 生成 fnOS 可安装的 .fpk 应用包
# ============================================================
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "==> 生成图标"
python3 "$ROOT/build-tools/make-icons.py"

echo "==> 打包 fpk"
python3 "$ROOT/build-tools/build_fpk.py"
