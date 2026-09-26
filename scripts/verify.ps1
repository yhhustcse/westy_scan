# 一键验证：编译 / 静态检查 / 单测，完整输出写入 out/verify.log
#
# 用法：powershell -ExecutionPolicy Bypass -File scripts/verify.ps1
# 前置：Go 1.21+（PATH 中，或已放置便携版到 .tools\go）
# 说明：本项目零第三方依赖，GOPROXY=off 也能完整构建与测试。

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'find-go.ps1')

$outDir = Join-Path $root 'out'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$log = Join-Path $outDir 'verify.log'
Set-Content -Path $log -Value ("=== westy_scan 验证日志 " + (Get-Date -Format s) + " ===") -Encoding UTF8

$script:failed = 0

function Write-Both([string]$Text) {
    Add-Content -Path $log -Value $Text -Encoding UTF8
    Write-Host $Text
}

function Step([string]$Title, [string[]]$GoArgs) {
    Write-Both ""
    Write-Both "--- $Title ---"
    # 用 cmd 自己做重定向：某些受限环境下 PowerShell 直接管道捕获外部程序输出会被拒绝
    $tmp = Join-Path $outDir ('step_' + [guid]::NewGuid().ToString('N') + '.tmp')
    & cmd.exe /c ('cd /d "' + $root + '" && "' + $go + '" ' + ($GoArgs -join ' ') + ' > "' + $tmp + '" 2>&1')
    $code = $LASTEXITCODE
    $text = [string](Get-Content $tmp -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Both ("exit=" + $code)
    if ($text -and $text.Trim()) { Write-Both $text.Trim() } else { Write-Both "(无输出)" }
    if ($code -ne 0) { $script:failed++ }
}

try {
    $go = Get-GoExe -RepoRoot $root
} catch {
    Write-Both ("错误: " + $_.Exception.Message)
    Pop-Location
    exit 1
}

# 零依赖验证：关闭模块代理，确保不是靠联网拉包才编过
$env:GOTOOLCHAIN = 'local'
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
$env:GOROOT = Split-Path -Parent (Split-Path -Parent $go)
$env:GOCACHE = Join-Path $root '.tools\gocache'
$env:GOPATH = Join-Path $root '.tools\gopath'

Step "go version" @('version')
Step "go build ./..." @('build', './...')
Step "go vet ./..." @('vet', './...')
Step "go test ./... -count=1" @('test', './...', '-count=1')
Step "go test ./internal/... -cover（逐包覆盖率）" @('test', './internal/...', '-count=1', '-cover')
Step "go test ./... -race（竞态检测）" @('test', './...', '-count=1', '-race')
Step "go build -o bin/westy.exe ./cmd/westy" @('build', '-o', 'bin/westy.exe', './cmd/westy')

# 规则库体检：把规模写进日志（下限在 internal/fingerprint/rules_library_gate_test.go 里强制）
Write-Both ""
Write-Both "--- 规则库规模（bin/westy.exe -list-rules）---"
$ruleFile = Join-Path $outDir 'rules-list.json'
& cmd.exe /c ('cd /d "' + $root + '" && "bin\westy.exe" -list-rules > "' + $ruleFile + '" 2>&1')
$ruleCode = $LASTEXITCODE
if ($ruleCode -ne 0) {
    Write-Both ("exit=" + $ruleCode + "（规则文件读取失败）")
    $script:failed++
} else {
    try {
        # PowerShell 5.1 的 ConvertFrom-Json 遇到 JSON 数组会把整个数组当成"一个对象"返回，
        # 再套 @(...) 就成了数组套数组（256 条规则会显示成 1 条）。这里统一展开一层。
        $rules = @(Get-Content $ruleFile -Raw -Encoding UTF8 | ConvertFrom-Json)
        if ($rules.Count -eq 1 -and $rules[0] -is [System.Array]) { $rules = @($rules[0]) }
        Write-Both ("指纹规则: " + $rules.Count + " 条（下限 150）")
        $fixtureDir = Join-Path $root 'scripts\rules-fixtures'
        $fcount = 0
        foreach ($f in (Get-ChildItem $fixtureDir -Filter *.json -ErrorAction SilentlyContinue)) {
            $items = @(Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)
            if ($items.Count -eq 1 -and $items[0] -is [System.Array]) { $items = @($items[0]) }
            $fcount += $items.Count
        }
        Write-Both ("金丝雀夹具: " + $fcount + " 条（模板↔夹具一一对应由 internal/poc/library_fixtures_test.go 强制）")
    } catch {
        Write-Both ("规则库统计失败: " + $_.Exception.Message)
        $script:failed++
    }
}

Write-Both ""
Write-Both ("=== 结束：失败步骤数 " + $script:failed + "，日志: " + $log + " ===")
Write-Host ""
if ($script:failed -eq 0) {
    Write-Host "全部通过 ✅  日志: out\verify.log" -ForegroundColor Green
} else {
    Write-Host "有 $script:failed 个步骤失败 ❌  日志: out\verify.log" -ForegroundColor Red
}
