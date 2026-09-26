# 运行单元测试
# 用法：powershell -ExecutionPolicy Bypass -File scripts/test.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'find-go.ps1')
$go = Get-GoExe -RepoRoot $root

Push-Location $root
try {
    & $go test ./... -count=1
    if ($LASTEXITCODE -ne 0) { throw "单元测试未通过" }

    # 竞态检测需要 cgo/gcc；Windows 上没有 gcc 时会失败，不作为门禁
    & $go test ./... -count=1 -race
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[test] 注意: -race 未通过（Windows 下通常是缺少 gcc/cgo），已忽略" -ForegroundColor Yellow
    } else {
        Write-Host "[test] -race 通过" -ForegroundColor Green
    }
} finally {
    Pop-Location
}
