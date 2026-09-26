# 构建 westy_scan（Windows / PowerShell）
#
# 前置：Go 1.21+（PATH 中，或已放置便携版到 .tools\go）
# 用法：powershell -ExecutionPolicy Bypass -File scripts/build.ps1

param(
    [string]$Out = "bin/westy.exe"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'find-go.ps1')
$go = Get-GoExe -RepoRoot $root

Push-Location $root
try {
    Write-Host "[build] Go: $go"
    Write-Host "[build] 工作目录: $root"
    & $go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet 未通过" }
    & $go build -trimpath -ldflags "-s -w" -o $Out ./cmd/westy
    if ($LASTEXITCODE -ne 0) { throw "go build 失败" }
    Write-Host "[build] 完成: $Out"
    & (Join-Path $root $Out) -version
} finally {
    Pop-Location
}
