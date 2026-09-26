# M6 验收演示：平台化（授权书闸门 / RBAC / 变更对比 / 持久化重启 / 通知 / Web UI）
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-m6.ps1

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'bin\westy.exe'
if (-not (Test-Path $bin)) { throw "未找到 $bin，请先执行 scripts/build.ps1" }
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { throw "未找到 python" }

$outDir = Join-Path $root 'out'
$dataDir = Join-Path $outDir 'm6-data'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue

$admTok = 'adm-token-demo'
$opTok = 'op-token-demo'
$viewTok = 'view-token-demo'
$svcPorts = '18081,2222'

# 1) 授权书文件（合规闸门的依据）
$authzPath = Join-Path $outDir 'm6-authz.json'
$now = (Get-Date).ToUniversalTime()
@"
[
  {
    "id": "AB-LAB-2026-001",
    "client": "本地实验靶场",
    "allow": ["127.0.0.1/32"],
    "valid_from": "$($now.AddHours(-1).ToString('o'))",
    "valid_to": "$($now.AddHours(24).ToString('o'))",
    "approver": "演示脚本",
    "ticket": "LAB-001",
    "note": "仅用于本机靶场演示"
  }
]
"@ | Set-Content -Path $authzPath -Encoding UTF8

# 2) 通知接收器（用它验证 webhook 真的发出去了）
$hookFile = Join-Path $outDir 'm6-webhook.log'
Remove-Item $hookFile -Force -ErrorAction SilentlyContinue
$hookPy = Join-Path $outDir 'm6-hook.py'
@"
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n).decode('utf-8', 'ignore')
        with open(sys.argv[2], 'a', encoding='utf-8') as f:
            f.write(body + '\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
"@ | Set-Content -Path $hookPy -Encoding UTF8

$site = Start-Process -FilePath $python -ArgumentList (Join-Path $PSScriptRoot 'fake-services.py'), '--quiet' -PassThru -WindowStyle Hidden
$hook = Start-Process -FilePath $python -ArgumentList $hookPy, '18901', $hookFile -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

function Start-DemoServer($extra) {
    $args = @('server', '-listen', '127.0.0.1:18899',
        '-roles', "admin=$admTok,operator=$opTok,viewer=$viewTok",
        '-data-dir', $dataDir,
        '-authz-file', $authzPath,
        '-lease', '3', '-job-ports', '1',
        '-notify-url', 'http://127.0.0.1:18901/hook', '-notify-format', 'wecom', '-notify-min-severity', 'high',
        '-audit', (Join-Path $outDir 'm6-server-audit.jsonl'))
    if ($extra) { $args += $extra }
    return Start-Process -FilePath $bin -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $outDir 'm6-server.out') `
        -RedirectStandardError (Join-Path $outDir 'm6-server.log') -ArgumentList $args
}

function Api($method, $path, $token, $body) {
    $headers = @{ Authorization = "Bearer $token" }
    try {
        if ($body) {
            return Invoke-RestMethod -Method $method -Uri ("http://127.0.0.1:18899" + $path) -Headers $headers `
                -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 6) -TimeoutSec 10
        }
        return Invoke-RestMethod -Method $method -Uri ("http://127.0.0.1:18899" + $path) -Headers $headers -TimeoutSec 10
    } catch {
        return @{ __error = $_.Exception.Message; __status = $_.Exception.Response.StatusCode.value__ }
    }
}

# 按 id 查单条扫描记录。
# 注意：Invoke-RestMethod 在 PS 5.1 里返回数组时可能被包成"数组里套数组"，
# 所以这里对两层都做一次展开，避免 $s2 意外变成集合导致按属性比较时报类型错。
function Find-Scan($token, $id) {
    $raw = Api 'GET' '/api/v1/scans' $token
    foreach ($item in @($raw)) {
        foreach ($one in @($item)) {
            if ("$($one.id)" -eq "$id") { return $one }
        }
    }
    return $null
}

$server = $null
$agent = $null
try {
    # 3) 启动 Server（带授权书引用）与 Agent
    $server = Start-DemoServer @('-targets', '127.0.0.1', '-ports', $svcPorts, '-authorization', 'AB-LAB-2026-001')
    Start-Sleep -Seconds 2
    $agent = Start-Process -FilePath $bin -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $outDir 'm6-agent.out') `
        -RedirectStandardError (Join-Path $outDir 'm6-agent.log') `
        -ArgumentList @('agent', '-server', 'http://127.0.0.1:18899', '-token', $opTok, '-id', 'agent-m6',
            '-authorized', '-allow', '127.0.0.1/32', '-strict-scope',
            '-spool', (Join-Path $outDir 'm6-spool'), '-pull-wait', '2',
            '-config', (Join-Path $root 'configs\westy.example.json'))

    # 等第一次扫描完成（server 用 -targets 建的那次）
    $deadline = (Get-Date).AddSeconds(60)
    $first = $null
    while ((Get-Date) -lt $deadline) {
        $raw = Api 'GET' '/api/v1/scans' $viewTok
        $first = $null
        foreach ($item in @($raw)) { foreach ($one in @($item)) { if (-not $first) { $first = $one } } }
        if ($first -and ([int]"$($first.done)" + [int]"$($first.failed)") -ge [int]"$($first.tasks)") { break }
        Start-Sleep -Seconds 2
    }
    Write-Host "`n==================== 1) 授权扫描完成 ===================="
    "扫描 {0}：任务 {1}（完成 {2} / 失败 {3}），资产 {4}，漏洞 {5}" -f $first.id, $first.tasks, $first.done, $first.failed, $first.assets, $first.findings

    Write-Host "`n==================== 2) 授权书闸门（越界必须拒绝）===================="
    $denied = Api 'POST' '/api/v1/scans' $opTok @{ hosts = @('10.9.9.9'); ports = @(80); authorization = 'AB-LAB-2026-001' }
    "越界目标 10.9.9.9 → HTTP {0}｜{1}" -f $denied.__status, $denied.__error
    $noAuthz = Api 'POST' '/api/v1/scans' $opTok @{ hosts = @('127.0.0.1'); ports = @(80) }
    "不给授权书 → HTTP {0}｜{1}" -f $noAuthz.__status, $noAuthz.__error

    Write-Host "`n==================== 3) RBAC（viewer 不能建扫描）===================="
    $rbac = Api 'POST' '/api/v1/scans' $viewTok @{ hosts = @('127.0.0.1'); ports = @(80); authorization = 'AB-LAB-2026-001' }
    "viewer 建扫描 → HTTP {0}｜{1}" -f $rbac.__status, $rbac.__error
    $viewOk = Api 'GET' '/api/v1/assets?limit=1' $viewTok
    "viewer 读资产 → 成功（{0} 条）" -f $viewOk.Count

    Write-Host "`n==================== 4) 变更对比（新增端口）===================="
    $second = Api 'POST' '/api/v1/scans' $opTok @{ hosts = @('127.0.0.1'); ports = @(18081, 2222, 6379); authorization = 'AB-LAB-2026-001'; job_ports = 1 }
    "已创建第二次扫描 {0}" -f $second.id
    $deadline = (Get-Date).AddSeconds(60)
    $s2 = $null
    while ((Get-Date) -lt $deadline) {
        $s2 = Find-Scan $viewTok $second.id
        if ($s2 -and ([int]"$($s2.done)" + [int]"$($s2.failed)") -ge [int]"$($s2.tasks)") { break }
        Start-Sleep -Seconds 2
    }
    "第二次扫描 {0}：任务 {1}（完成 {2} / 失败 {3}）" -f $s2.id, $s2.tasks, $s2.done, $s2.failed
    $diff = Api 'GET' ("/api/v1/scans/diff?scan_id=" + $second.id + "&against=" + $first.id) $viewTok
    "新增资产 {0}｜新增漏洞 {1}（高危及以上 {2}）｜已修复 {3}" -f `
        $diff.summary.new_assets, $diff.summary.new_findings, $diff.summary.new_high_risk, $diff.summary.fixed_findings
    foreach ($a in $diff.new_assets) { "  + 新资产: {0}:{1} {2}" -f $a.host, $a.port, $a.product }

    Write-Host "`n==================== 5) 通知（webhook 是否真的发出）===================="
    Start-Sleep -Seconds 2
    if (Test-Path $hookFile) {
        $hooks = Get-Content $hookFile -Encoding UTF8
        "收到 {0} 条通知；样例：{1}" -f $hooks.Count, ($hooks[-1].Substring(0, [Math]::Min(160, $hooks[-1].Length)))
    } else { Write-Host "未收到通知（检查 -notify-url 与阈值）" -ForegroundColor Yellow }

    Write-Host "`n==================== 6) 持久化：重启 Server 后状态还在吗 ===================="
    if ($agent -and -not $agent.HasExited) { Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue }
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    $server = Start-DemoServer @()
    Start-Sleep -Seconds 2
    $stats2 = Api 'GET' '/api/v1/stats' $admTok
    "重启后：扫描 {0} 个，资产 {1}，漏洞 {2}，授权书 {3} 份" -f `
        @($stats2.scans.PSObject.Properties).Count, $stats2.assets, $stats2.findings, (Api 'GET' '/api/v1/authorizations' $admTok).Count

    Write-Host "`n==================== 7) Web UI 与报告导出 ===================="
    $ui = (Invoke-WebRequest -Uri 'http://127.0.0.1:18899/' -UseBasicParsing -TimeoutSec 5).Content
    "Web UI: {0} 字节，包含控制台标记: {1}" -f $ui.Length, ($ui -match 'westy_scan 控制台')
    $html = (Invoke-WebRequest -Uri ("http://127.0.0.1:18899/api/v1/report?format=html&scan_id=" + $first.id) `
        -Headers @{ Authorization = "Bearer $viewTok" } -UseBasicParsing -TimeoutSec 10).Content
    "HTML 报告: {0} 字节，含漏洞章节: {1}，含授权书提示: {2}" -f $html.Length, ($html -match '漏洞验证结果'), ($html -match '漏洞')
    Set-Content -Path (Join-Path $outDir 'm6-report.html') -Value $html -Encoding UTF8

    Write-Host "`n[demo-m6] 报告: out\m6-report.html｜审计: out\m6-server-audit.jsonl｜数据目录: out\m6-data"
} finally {
    foreach ($p in @($agent, $server, $site, $hook)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "[demo-m6] 已清理全部进程"
}
