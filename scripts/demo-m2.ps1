# M2 验收演示：Web 指纹增强（favicon mmh3 + CDN/WAF 被动识别 + 报告列）
#
# 流程：
#   1. 起本地假服务（含一个带 favicon 与 CDN 特征头的 HTTP 站点，仅监听 127.0.0.1）
#   2. 扫描该站点，输出报告与 JSONL
#   3. 打印 favicon 哈希、CDN/WAF、置信度等 M2 字段
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-m2.ps1

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
    Write-Host "[demo-m2] 假站点已在 127.0.0.1:18081 启动（带 favicon 与 CF-RAY 头）`n"
    & $bin -target 127.0.0.1 `
        -allow '127.0.0.1/32' -authorized -strict-scope `
        -ports '18081' `
        -crawl -crawl-depth 1 `
        -format table `
        -report (Join-Path $outDir 'm2-report.txt') `
        -o (Join-Path $outDir 'm2.jsonl') `
        -audit (Join-Path $outDir 'm2-audit.jsonl')

    Write-Host "`n--- 报告（注意 PRODUCT/CONF/CDN-WAF 列）---"
    Get-Content (Join-Path $outDir 'm2-report.txt') -Encoding UTF8 -ErrorAction SilentlyContinue | Write-Host

    Write-Host "--- M2 关键字段 ---"
    Get-Content (Join-Path $outDir 'm2.jsonl') -Encoding UTF8 | ForEach-Object {
        $a = $_ | ConvertFrom-Json
        if ($a.url) {
            "URL      : {0}" -f $a.url
            "标题     : {0}" -f $a.title
            "favicon  : mmh3={0}（Shodan 约定，来自 {1}）" -f $a.favicon_hash, $a.meta.'favicon.url'
            "CDN/WAF  : CDN={0} WAF={1} BehindCDN={2}" -f $a.cdn, $a.waf, $a.behind_cdn
            "源站提示 : {0}" -f $a.origin_note
            "置信度   : {0}  判据: {1}" -f $a.confidence, ($a.evidence -join ',')
            ""
        }
    }
    Write-Host "[demo-m2] 完整结果: out\m2.jsonl  审计: out\m2-audit.jsonl"
} finally {
    if ($srv -and -not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Get-Process python -ErrorAction SilentlyContinue |
        Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-2) } |
        ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "[demo-m2] 假服务已清理"
}
