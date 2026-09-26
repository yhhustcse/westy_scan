# M7 验收演示：规则库"弹药"体检（指纹规则数 + 模板金丝雀命中 + 干净站点零误报）
#
# 为什么需要这个演示：模板库最危险的失效模式不是报错，而是**写了却永远不命中**
# （路径写错、匹配器太严、正则用了引擎不支持的语法、变量拼错）。
# 加载期校验只能挡住"格式非法"，挡不住"语法正确但逻辑是死的"。
#
# 做法：
#   1. 起金丝雀靶站（127.0.0.1:18082），它严格按 scripts/rules-fixtures/*.json 返回响应；
#   2. 用内置模板打它 → 每条模板都必须命中（少一条就是死模板）；
#   3. 用同一批模板打干净站点 → 必须 0 命中；
#   4. 顺带验证指纹库在真实 HTTP 响应上能识别出产品。
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-rules.ps1

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

# 夹具是"模板 ↔ 靶站"的契约：每条夹具声明某个模板命中时长什么样
$fixtureDir = Join-Path $PSScriptRoot 'rules-fixtures'

# PowerShell 5.1 的 ConvertFrom-Json 遇到 JSON 数组会把整个数组当"一个对象"返回，
# 再用 @(...) 包一次就变成"数组套数组"（Count=1）。这个助手统一展开一层，
# 免得出现"256 条规则数成 1 条"这种看着像框架坏了、其实是脚本坏了的假象。
function Get-JsonList($path) {
    $v = Get-Content $path -Encoding UTF8 -Raw | ConvertFrom-Json
    $list = @($v)
    if ($list.Count -eq 1 -and $list[0] -is [System.Array]) { $list = @($list[0]) }
    return , $list
}

$expected = @()
$fixtureCount = 0
foreach ($f in (Get-ChildItem $fixtureDir -Filter *.json -ErrorAction SilentlyContinue)) {
    $items = Get-JsonList $f.FullName
    foreach ($it in $items) {
        $fixtureCount++
        if ($it.template_id) { $expected += $it.template_id }
        foreach ($x in @($it.also_serves)) { if ($x) { $expected += $x } }
    }
}
$expected = @($expected | Sort-Object -Unique)

$target = Start-Process -FilePath $python -ArgumentList (Join-Path $PSScriptRoot 'fake-services.py'), '--quiet' -PassThru -WindowStyle Hidden
$plain = Start-Process -FilePath $python -ArgumentList '-m', 'http.server', '18080', '--bind', '127.0.0.1', '--directory', $clean -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

function Run-Westy($argline) {
    # 外部程序输出直接管道在本沙箱不可靠，统一重定向到文件再读
    & cmd.exe /c "cd /d $root && `"$bin`" $argline > out\rules-run.log 2>&1"
    return $LASTEXITCODE
}

try {
    Write-Host "==================== 1) 指纹规则库规模 ===================="
    & cmd.exe /c "cd /d $root && `"$bin`" -list-rules > out\rules-list.json 2>&1"
    $rules = Get-JsonList (Join-Path $outDir 'rules-list.json')
    "指纹规则: {0} 条" -f $rules.Count
    $byConf = $rules | Group-Object confidence | Sort-Object Name
    foreach ($g in $byConf) { "  confidence={0,-6} {1} 条" -f ($g.Name, $g.Count) }

    Write-Host "`n==================== 2) 金丝雀靶站：每条模板都必须命中 ===================="
    & cmd.exe /c "cd /d $root && `"$bin`" -list-templates > out\rules-templates.json 2> out\rules-templates.err"
    $tpls = Get-JsonList (Join-Path $outDir 'rules-templates.json')
    "漏洞模板: {0} 条（按级别）" -f $tpls.Count
    $tpls | Group-Object severity | Sort-Object Name | ForEach-Object { "  {0,-9} {1}" -f $_.Name, $_.Count }
    "夹具 {0} 条，覆盖模板 {1} 条（127.0.0.1:18082）" -f $fixtureCount, $expected.Count
    if ($tpls.Count -ne $expected.Count) {
        # 这一条是"有人加了模板却没写金丝雀夹具"的现场提示：
        # Go 侧的门禁（TestLibraryEveryTemplateHasFixture）会直接失败，演示里也再说一次。
        Write-Host ("⚠ 模板数 {0} ≠ 有夹具的模板数 {1}：有模板没被真跑验证过" -f $tpls.Count, $expected.Count) -ForegroundColor Yellow
    }
    Run-Westy "-target 127.0.0.1 -allow 127.0.0.1/32 -authorized -strict-scope -ports 18082 -poc -verify -vulns out\rules-canary-vulns.jsonl -o out\rules-canary-assets.jsonl -audit out\rules-canary-audit.jsonl -format table" | Out-Null

    $hits = @()
    if (Test-Path (Join-Path $outDir 'rules-canary-vulns.jsonl')) {
        Get-Content (Join-Path $outDir 'rules-canary-vulns.jsonl') -Encoding UTF8 | ForEach-Object {
            if ($_.Trim()) { $hits += ($_ | ConvertFrom-Json) }
        }
    }
    $hitIds = @($hits | ForEach-Object { $_.template_id } | Sort-Object -Unique)
    "命中模板 {0} 条，漏洞记录 {1} 条" -f $hitIds.Count, $hits.Count

    $dead = @($expected | Where-Object { $hitIds -notcontains $_ })
    if ($dead.Count -eq 0) {
        Write-Host ("✅ 无死模板：{0}/{0} 全部命中" -f $expected.Count) -ForegroundColor Green
    } else {
        Write-Host ("❌ 死模板 {0} 条：" -f $dead.Count) -ForegroundColor Red
        $dead | ForEach-Object { "   - $_" }
    }
    $unexpected = @($hitIds | Where-Object { $expected -notcontains $_ })
    if ($unexpected.Count -gt 0) {
        Write-Host ("⚠ 非预期命中 {0} 条（模板间匹配器重叠，需人工看一眼）：" -f $unexpected.Count) -ForegroundColor Yellow
        $unexpected | ForEach-Object { "   - $_" }
    }

    Write-Host "`n--- 命中按级别分布 ---"
    $hits | Group-Object severity | Sort-Object Name | ForEach-Object { "  {0,-9} {1}" -f $_.Name, $_.Count }
    Write-Host "`n--- 抽样 5 条（含匹配依据，用于人工复核）---"
    $hits | Select-Object -First 5 | ForEach-Object {
        "  [{0,-8}] {1,-46} {2}" -f $_.severity, $_.template_id, $_.matched_at
    }

    Write-Host "`n==================== 3) 干净站点（误报必须为 0）===================="
    Run-Westy "-target http://127.0.0.1:18080 -allow 127.0.0.1/32 -authorized -strict-scope -ports 18080 -crawl -crawl-depth 1 -poc -verify -vulns out\rules-clean-vulns.jsonl -format table" | Out-Null
    $cleanCount = 0
    if (Test-Path (Join-Path $outDir 'rules-clean-vulns.jsonl')) {
        $cleanCount = @(Get-Content (Join-Path $outDir 'rules-clean-vulns.jsonl') -Encoding UTF8 | Where-Object { $_.Trim() }).Count
    }
    if ($cleanCount -eq 0) {
        Write-Host "✅ 干净站点命中 0 条" -ForegroundColor Green
    } else {
        Write-Host ("❌ 干净站点命中 {0} 条（误报）：" -f $cleanCount) -ForegroundColor Red
        Get-Content (Join-Path $outDir 'rules-clean-vulns.jsonl') -Encoding UTF8 | ForEach-Object { "   $_" }
    }

    Write-Host "`n==================== 4) 指纹识别（真实 HTTP 响应）===================="
    $assets = @()
    if (Test-Path (Join-Path $outDir 'rules-canary-assets.jsonl')) {
        Get-Content (Join-Path $outDir 'rules-canary-assets.jsonl') -Encoding UTF8 | ForEach-Object {
            if ($_.Trim()) { $assets += ($_ | ConvertFrom-Json) }
        }
    }
    foreach ($a in $assets) {
        if ($a.url) { "  {0} -> service={1} product={2} confidence={3}" -f $a.url, $a.service, $a.product, $a.confidence }
    }

    Write-Host ""
    if ($dead.Count -eq 0 -and $cleanCount -eq 0 -and $expected.Count -gt 0) {
        Write-Host ("[demo-rules] 结论：指纹 {0} 条；模板 {1}/{1} 全部命中，干净站点 0 误报" -f $rules.Count, $expected.Count) -ForegroundColor Green
    } else {
        Write-Host "[demo-rules] 结论异常：请检查上面的死模板/误报清单" -ForegroundColor Red
    }
    Write-Host "[demo-rules] 输出: out\rules-canary-vulns.jsonl / out\rules-clean-vulns.jsonl / out\rules-list.json"
} finally {
    foreach ($p in @($target, $plain)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $clean -ErrorAction SilentlyContinue
    Write-Host "[demo-rules] 假服务已清理"
}
