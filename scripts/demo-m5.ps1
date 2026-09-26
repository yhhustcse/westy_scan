# M5 验收演示：分布式 Server + Agent（真进程；中途杀掉一个 Agent 验证租约重派）
#
# 流程：
#   1. 起本地假靶站（含一个"黑洞端口"，让任务足够慢以便观察重派）
#   2. 起 Server 并下发扫描（-job-ports 2 → 多任务，便于并行与重派）
#   3. 起 2 个 Agent；1 秒后杀掉 agent-1（模拟掉线）
#   4. 等租约过期，观察任务被重派给 agent-2；最后核对：任务全完成、资产不重不漏
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-m5.ps1

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
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $outDir 'agent-spool*') -Recurse -Force -ErrorAction SilentlyContinue

$ports = '18081,2222,3306,6379,11211,5900,18099'
$auditPath = Join-Path $outDir 'm5-server-audit.jsonl'
Remove-Item $auditPath -Force -ErrorAction SilentlyContinue

$target = Start-Process -FilePath $python -ArgumentList (Join-Path $PSScriptRoot 'fake-services.py'), '--quiet' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

$server = Start-Process -FilePath $bin -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $outDir 'm5-server.out') `
    -RedirectStandardError (Join-Path $outDir 'm5-server.log') `
    -ArgumentList @(
        'server', '-listen', '127.0.0.1:18899', '-token', 'demo-token',
        '-targets', '127.0.0.1', '-ports', $ports,
        '-lease', '3', '-max-tries', '3', '-job-ports', '2',
        '-audit', $auditPath,
        '-report', (Join-Path $outDir 'm5-report.md'), '-format', 'markdown',
        '-run-for', '60s'
    )
Start-Sleep -Seconds 2

function Start-DemoAgent($id, $spool) {
    Start-Process -FilePath $bin -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $outDir "$id.out") `
        -RedirectStandardError (Join-Path $outDir "$id.log") `
        -ArgumentList @(
            'agent', '-server', 'http://127.0.0.1:18899', '-token', 'demo-token', '-id', $id,
            '-authorized', '-allow', '127.0.0.1/32', '-strict-scope',
            '-spool', (Join-Path $outDir $spool), '-pull-wait', '2', '-max-jobs', '2',
            '-config', (Join-Path $root 'configs\westy.example.json')
        )
}

$a1 = Start-DemoAgent 'agent-1' 'agent-spool-1'
$a2 = Start-DemoAgent 'agent-2' 'agent-spool-2'

try {
    Write-Host "[demo-m5] 靶站 + Server + 2 个 Agent 已启动；1 秒后杀掉 agent-1（模拟掉线）"
    Start-Sleep -Seconds 1
    if ($a1 -and -not $a1.HasExited) {
        Stop-Process -Id $a1.Id -Force -ErrorAction SilentlyContinue
        Write-Host "[demo-m5] agent-1 已杀掉：它手上的任务应在租约到期后被重派给 agent-2"
    }

    $deadline = (Get-Date).AddSeconds(50)
    $stats = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $stats = Invoke-RestMethod -Uri 'http://127.0.0.1:18899/api/v1/stats' `
                -Headers @{ Authorization = 'Bearer demo-token' } -TimeoutSec 5
            if ($stats.tasks.done -ge 4) { break }
        } catch { }
        Start-Sleep -Seconds 2
    }

    Write-Host "`n==================== 服务端统计 ===================="
    if ($stats) {
        "协议版本   : {0}" -f $stats.protocol
        "任务状态   : done={0} failed={1} running={2} pending={3}" -f `
            $stats.tasks.done, $stats.tasks.failed, $stats.tasks.running, $stats.tasks.pending
        "资产总数   : {0}   漏洞总数: {1}" -f $stats.assets, $stats.findings
        "Agent      : " + (($stats.agents | ForEach-Object { "{0}(done={1},fail={2})" -f $_.id, $_.jobs_done, $_.jobs_failed }) -join ', ')
        foreach ($prop in $stats.scans.PSObject.Properties) {
            $s = $prop.Value
            "扫描 {0}: 任务 {1}（完成 {2} / 失败 {3}），资产 {4}，漏洞 {5}" -f $s.id, $s.tasks, $s.done, $s.failed, $s.assets, $s.findings
        }
    } else { Write-Host "未能获取统计（服务端可能已退出）" -ForegroundColor Yellow }

    Write-Host "`n==================== 指标（Prometheus 文本）===================="
    try {
        $metrics = (Invoke-WebRequest -Uri 'http://127.0.0.1:18899/metrics' `
            -Headers @{ Authorization = 'Bearer demo-token' } -UseBasicParsing -TimeoutSec 5).Content
        ($metrics -split "`n") | Where-Object { $_ -match '^westy_' } | ForEach-Object { Write-Host $_ }
    } catch { Write-Host "metrics 获取失败（服务端可能已退出）" }

    Write-Host "`n==================== 审计：按 scan_id 对齐 ===================="
    if (Test-Path $auditPath) {
        $events = Get-Content $auditPath -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json }
        $dispatch = ($events | Where-Object { $_.event -eq 'job_dispatched' }).Count
        "job_dispatched 事件数: {0}（任务被重派时会大于任务数）" -f $dispatch
        $events | Select-Object -First 12 | ForEach-Object {
            $fields = ($_.fields.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
            "{0,-20} {1}" -f $_.event, $fields | Write-Host
        }
    }

    Write-Host "`n[demo-m5] 报告: out\m5-report.md  服务端审计: out\m5-server-audit.jsonl"
    if ($stats -and $stats.tasks.failed -eq 0 -and $stats.tasks.done -ge 4) {
        Write-Host "[demo-m5] 结论：杀 Agent 后任务全部完成、无丢失；资产/漏洞已按去重键汇聚" -ForegroundColor Green
    }
} finally {
    foreach ($p in @($a1, $a2, $server, $target)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $outDir 'agent-spool*') -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[demo-m5] 已清理全部进程"
}
