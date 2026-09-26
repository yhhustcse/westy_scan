# 本地闭环演示（自证可运行，且不接触任何第三方目标）
#
# 流程：
#   1. 在 127.0.0.1:18080 起一个 Python 静态站点当"靶机"
#   2. 用 westy_scan 扫描它，开启爬虫
#   3. 收工并清理临时站点
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/demo-local.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'bin/westy.exe'
if (-not (Test-Path $bin)) {
    throw "未找到 $bin，请先执行: powershell -ExecutionPolicy Bypass -File scripts/build.ps1"
}

$site = Join-Path $env:TEMP ('westy-demo-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $site | Out-Null

$index = @'
<html><head><title>Westy Demo</title></head><body>
<h1>demo</h1>
<a href="/admin.html">admin</a>
<a href="/missing.html">missing</a>
<form action="/login"><input name="user"></form>
</body></html>
'@
Set-Content -Path (Join-Path $site 'index.html') -Value $index -Encoding UTF8
Set-Content -Path (Join-Path $site 'admin.html') -Value '<html><title>Admin Console</title></html>' -Encoding UTF8

$port = 18080
$srv = Start-Process -FilePath 'python' -ArgumentList '-m', 'http.server', $port, '--bind', '127.0.0.1', '--directory', $site -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

$outDir = Join-Path $root 'out'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

try {
    Write-Host "[demo] 靶机已启动: http://127.0.0.1:$port"
    & $bin -target "http://127.0.0.1:$port" `
        -allow '127.0.0.1/32' `
        -authorized `
        -strict-scope `
        -ports "18080" `
        -crawl -crawl-depth 2 `
        -format table `
        -o (Join-Path $outDir 'demo.jsonl') `
        -audit (Join-Path $outDir 'audit.jsonl') `
        -v
    Write-Host "[demo] 结果: $outDir\demo.jsonl  审计: $outDir\audit.jsonl"
} finally {
    if ($srv -and -not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $site -ErrorAction SilentlyContinue
    Write-Host "[demo] 靶机与临时文件已清理"
}
