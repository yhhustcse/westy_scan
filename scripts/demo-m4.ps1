# M4 验收演示：漏洞模板引擎（只读验证 + 二次确认 + 证据留存）
#
# 流程：
#   1. 起本地假站点：既有正常页面，也有一批典型暴露点（.git/.env/actuator/nacos/…）
#   2. 用内置模板做验证（默认开启二次确认），输出漏洞清单与证据
#   3. 再对一个"干净的静态站点"跑同一批模板，验证 **误报为 0**
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-m4.ps1

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

# 先清理历史残留进程（否则会与本次的假服务抢端口，导致结果自相矛盾）
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 干净站点：只有静态文件，用于验证"误报为 0"
$clean = Join-Path $env:TEMP ('westy-clean-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $clean -Force | Out-Null
Set-Content -Path (Join-Path $clean 'index.html') -Encoding UTF8 -Value @'
<html><head><title>Clean Site</title></head><body>
<h1>正常站点</h1>
<p>open 的服务说明、paths 目录、status UP 的文案都在这里。</p>
<form action="/login" method="get"><input name="q"></form>
</body></html>
'@

$target = Start-Process -FilePath $python -ArgumentList (Join-Path $PSScriptRoot 'fake-services.py'), '--quiet' -PassThru -WindowStyle Hidden
$plain = Start-Process -FilePath $python -ArgumentList '-m', 'http.server', '18080', '--bind', '127.0.0.1', '--directory', $clean -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    Write-Host "==================== 1) 有暴露面的靶站 ===================="
    & $bin -target 127.0.0.1 `
        -allow '127.0.0.1/32' -authorized -strict-scope `
        -ports '18081' `
        -poc -verify `
        -vulns (Join-Path $outDir 'm4-vulns.jsonl') `
        -o (Join-Path $outDir 'm4-assets.jsonl') `
        -audit (Join-Path $outDir 'm4-audit.jsonl') `
        -report (Join-Path $outDir 'm4-report.md') `
        -format markdown `
        -v

    Write-Host "`n--- 漏洞清单（来自 vulns.jsonl）---"
    $vulns = @()
    if (Test-Path (Join-Path $outDir 'm4-vulns.jsonl')) {
        Get-Content (Join-Path $outDir 'm4-vulns.jsonl') -Encoding UTF8 | ForEach-Object {
            $v = $_ | ConvertFrom-Json
            $vulns += $v
            "{0,-9} {1,-34} {2,-46} verified={3}" -f $v.severity, $v.template_id, $v.matched_at, $v.verified
        }
    }
    Write-Host ("命中模板数: " + $vulns.Count)

    Write-Host "`n--- 一条命中的完整证据（可复现性）---"
    if ($vulns.Count -gt 0) {
        $one = $vulns[0]
        Write-Host ("模板   : " + $one.name + " [" + $one.template_id + "]")
        Write-Host ("命中   : " + $one.matched_at)
        Write-Host ("匹配依据: " + $one.evidence.matcher)
        Write-Host "--- 请求 ---"; Write-Host $one.evidence.request
        Write-Host "--- 响应 ---"; Write-Host $one.evidence.response
    }

    Write-Host "`n==================== 2) 干净站点（误报应为 0）===================="
    & $bin -target http://127.0.0.1:18080 `
        -allow '127.0.0.1/32' -authorized -strict-scope `
        -ports '18080' -crawl -crawl-depth 1 `
        -poc -verify `
        -vulns (Join-Path $outDir 'm4-clean-vulns.jsonl') `
        -format table

    $cleanCount = 0
    if (Test-Path (Join-Path $outDir 'm4-clean-vulns.jsonl')) {
        $cleanCount = (Get-Content (Join-Path $outDir 'm4-clean-vulns.jsonl') -Encoding UTF8 | Measure-Object).Count
    }
    Write-Host ("`n干净站点命中数: " + $cleanCount + "（期望 0）")

    if ($vulns.Count -gt 0 -and $cleanCount -eq 0) {
        Write-Host "`n[demo-m4] 结论：有暴露面靶站命中 $($vulns.Count) 条，干净站点 0 条 —— 检出与零误报同时成立" -ForegroundColor Green
    } else {
        Write-Host "`n[demo-m4] 结论异常：请检查模板与靶点" -ForegroundColor Red
    }
    Write-Host "[demo-m4] 报告: out\m4-report.md  漏洞: out\m4-vulns.jsonl  审计: out\m4-audit.jsonl"
} finally {
    foreach ($p in @($target, $plain)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $clean -ErrorAction SilentlyContinue
    Write-Host "[demo-m4] 假服务已清理"
}
