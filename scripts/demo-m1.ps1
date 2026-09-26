# M1 验收演示：服务识别（协议握手解析）
#
# 流程：
#   1. 起本地假服务（SSH/MySQL/PostgreSQL/Redis/Memcached/VNC，仅监听 127.0.0.1）
#   2. 用 westy_scan 扫描这些端口，开启协议握手识别
#   3. 打印报告与 JSONL，收工清理
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-m1.ps1

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'bin\westy.exe'
if (-not (Test-Path $bin)) {
    throw "未找到 $bin，请先执行: powershell -ExecutionPolicy Bypass -File scripts/build.ps1"
}

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { throw "未找到 python，无法启动本地假服务" }

$outDir = Join-Path $root 'out'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$fake = Join-Path $PSScriptRoot 'fake-services.py'
$srv = Start-Process -FilePath $python -ArgumentList $fake, '--quiet' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    Write-Host "[demo-m1] 假服务已启动，开始扫描 127.0.0.1 的 6 个服务端口`n"
    & $bin -target 127.0.0.1 `
        -allow '127.0.0.1/32' -authorized -strict-scope `
        -ports '2222,3306,5432,6379,11211,5900' `
        -service-detect -service-timeout 3 `
        -udp -udp-ports '53' -udp-timeout 3 `
        -format table `
        -report (Join-Path $outDir 'm1-report.txt') `
        -o (Join-Path $outDir 'm1.jsonl') `
        -audit (Join-Path $outDir 'm1-audit.jsonl') `
        -v

    Write-Host "`n--- 识别结果（HOST PORT SERVICE PRODUCT VERSION CONFIDENCE）---"
    if (Test-Path (Join-Path $outDir 'm1.jsonl')) {
        Get-Content (Join-Path $outDir 'm1.jsonl') -Encoding UTF8 | ForEach-Object {
            $a = $_ | ConvertFrom-Json
            "{0}:{1,-6} {2,-12} {3,-12} {4,-10} {5}" -f $a.host, $a.port, $a.service, $a.product, $a.version, $a.confidence
        }
    }
    Write-Host "`n[demo-m1] 完整结果: out\m1.jsonl  审计: out\m1-audit.jsonl"
} finally {
    if ($srv -and -not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Get-Process python -ErrorAction SilentlyContinue |
        Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-2) } |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[demo-m1] 假服务已清理"
}
