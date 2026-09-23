# ============================================================================
# DirNetBlock 一键编译脚本
# 需要 Windows + .NET Framework 4.0+（自带 csc.exe）
# 用法：右键 build.ps1 -> 使用 PowerShell 运行（或在 PowerShell 中执行）
# 产物输出到 bin\ 目录
# ============================================================================
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path $root "src"
$outDir = Join-Path $root "bin"

# 定位 csc.exe（64 位优先，回退 32 位）
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    $csc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
if (-not (Test-Path $csc)) {
    Write-Host "[错误] 未找到 .NET Framework 4.0 的 csc.exe，请确认系统装有 .NET Framework 4+" -ForegroundColor Red
    exit 1
}

# 停掉可能正在运行的旧进程，避免 exe 被占用
Get-Process DirNetBlock, DirNetBlock_cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$commonArgs = @(
    "/nologo",
    "/win32icon:$srcDir\DirNetBlock.ico",
    "/win32manifest:$srcDir\app.manifest",
    "/r:System.dll",
    "/r:System.Windows.Forms.dll",
    "/r:System.Drawing.dll",
    "/r:System.Management.dll",
    "/r:Microsoft.CSharp.dll",
    (Join-Path $srcDir "DirNetBlock.cs")
)

Write-Host "正在编译 GUI 版 (DirNetBlock.exe) ..." -ForegroundColor Cyan
& $csc @commonArgs /target:winexe /out:(Join-Path $outDir "DirNetBlock.exe")
if ($LASTEXITCODE -ne 0) { Write-Host "[错误] GUI 编译失败" -ForegroundColor Red; exit 1 }

Write-Host "正在编译 CLI 版 (DirNetBlock_cli.exe) ..." -ForegroundColor Cyan
& $csc @commonArgs /target:exe /out:(Join-Path $outDir "DirNetBlock_cli.exe")
if ($LASTEXITCODE -ne 0) { Write-Host "[错误] CLI 编译失败" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "编译完成！产物位置：" -ForegroundColor Green
Write-Host "  GUI: $outDir\DirNetBlock.exe"
Write-Host "  CLI: $outDir\DirNetBlock_cli.exe"
