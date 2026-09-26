# 定位 Go 可执行文件：优先 PATH，其次使用随仓库的便携版 .tools\go
# 由其他脚本 dot-source 使用：. (Join-Path $PSScriptRoot 'find-go.ps1')

function Get-GoExe {
    param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $cand = Join-Path $RepoRoot '.tools\go\bin\go.exe'
    if (Test-Path $cand) { return $cand }

    throw @"
未找到 Go 工具链。任选一种方式：
  1) winget install --id GoLang.Go -e      （需联网，装完重开终端）
  2) 从 https://golang.google.cn/dl/ 下载 go1.x.windows-amd64.zip
     解压后把 go 目录放到 $RepoRoot\.tools\go
"@
}
