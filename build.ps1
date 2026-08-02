# ============================================================
# fn-wg-web package script (Windows PowerShell)
# Build a .fpk app package installable on fnOS
# ============================================================
$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==> generate icons"
python (Join-Path $ROOT "build-tools\make-icons.py")

Write-Host "==> build fpk package"
python (Join-Path $ROOT "build-tools\build_fpk.py")
