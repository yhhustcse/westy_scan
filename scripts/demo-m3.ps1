# M3 验收演示：爬虫强化（robots/sitemap 入口 + JS 抽取 + 表单参数 + 近似重复）
#
# 流程：
#   1. 起本地假站点（127.0.0.1:18081），带 robots.txt / sitemap.xml / JS / 表单 / 两页重复内容
#   2. 用 -crawl 抓取，开启站点地图入口与 JS 抽取
#   3. 打印参数清单、JS 接口与疑似凭据（掩码）、重复页面标记
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-m3.ps1

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

$srv = Start-Process -FilePath $python -ArgumentList (Join-Path $PSScriptRoot 'fake-services.py'), '--quiet' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    Write-Host "[demo-m3] 假站点已启动：robots/sitemap/app.js/表单/重复页`n"
    & $bin -target 127.0.0.1 `
        -allow '127.0.0.1/32' -authorized -strict-scope `
        -ports '18081' `
        -crawl -crawl-depth 2 -crawl-pages 50 `
        -sitemap -crawl-js `
        -format table `
        -o (Join-Path $outDir 'm3.jsonl') `
        -audit (Join-Path $outDir 'm3-audit.jsonl') `
        -report (Join-Path $outDir 'm3-report.txt')

    Write-Host "`n--- 抓到的资产与 M3 字段 ---"
    $params = @{}
    Get-Content (Join-Path $outDir 'm3.jsonl') -Encoding UTF8 | ForEach-Object {
        $a = $_ | ConvertFrom-Json
        $line = "{0,-45} src={1,-9}" -f $a.url, $a.source
        if ($a.params) { $line += " params=[{0}]" -f ($a.params -join ',') }
        if ($a.forms)  { $line += " forms={0}" -f $a.forms.Count }
        if ($a.meta.'js.endpoint_count') { $line += " js接口={0}" -f $a.meta.'js.endpoint_count' }
        if ($a.meta.'js.secret_count')   { $line += " 疑似凭据={0}" -f $a.meta.'js.secret_count' }
        if ($a.meta.duplicate_of)        { $line += " 重复于={0}" -f $a.meta.duplicate_of }
        Write-Host $line
        foreach ($p in $a.params) { $params[$p] = $true }
        if ($a.meta.'js.secrets') { Write-Host ("    JS 凭据（已掩码）: " + $a.meta.'js.secrets') }
    }

    Write-Host "`n--- 参数清单（M4 注入类测试的输入面）---"
    ($params.Keys | Sort-Object) -join ', ' | Write-Host

    Write-Host "`n--- robots/sitemap 审计事件 ---"
    Get-Content (Join-Path $outDir 'm3-audit.jsonl') -Encoding UTF8 |
        Select-String -Pattern 'robots_disallow' | ForEach-Object { $_.Line } | Write-Host
    Write-Host "`n[demo-m3] 完整结果: out\m3.jsonl  审计: out\m3-audit.jsonl  报告: out\m3-report.txt"
} finally {
    if ($srv -and -not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Get-Process python -ErrorAction SilentlyContinue |
        Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-2) } |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[demo-m3] 假服务已清理"
}
