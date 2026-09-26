#!/usr/bin/env bash
# 在 CI 里跑 go test，并在失败时把关键行输出为 **check-run annotation**。
#
# 为什么需要这个脚本：GitHub 的 job 日志必须账号鉴权才能读（API 返回 403），
# 而 check-run annotation 是公开可读的。把失败摘要转成 annotation，
# 排查 CI 就不需要先拿到仓库权限 —— 顺带也让失败信息直接出现在 PR/提交页面上。
#
# 用法：scripts/ci-run-tests.sh <日志名> [go test 参数...]
#   scripts/ci-run-tests.sh go-test      ./... -count=1
#   scripts/ci-run-tests.sh go-test-race ./... -count=1 -race

set -o pipefail

name="${1:-go-test}"
shift || true

log="${RUNNER_TEMP:-/tmp}/${name}.log"

if go test "$@" >"$log" 2>&1; then
  tail -n 5 "$log" || true
  exit 0
fi

echo "--- 环境 ---"
go version || true
go env GOOS GOARCH CGO_ENABLED GOFLAGS GOMAXPROCS || true

echo "--- 失败摘要（同时会作为 annotation 出现在 UI 上）---"
grep -nE '^(--- FAIL|FAIL|panic:|# )|_test\.go:[0-9]+:' "$log" | tail -n 40 | while IFS= read -r line; do
  # annotation 消息里的 % 必须转义，否则 GitHub 会丢弃整条注解
  esc=$(printf '%s' "$line" | sed -e 's/%/%25/g' -e 's/\r/%0D/g')
  echo "::error title=${name}::${esc}"
done

echo "--- go test 日志尾部 40 行 ---"
tail -n 40 "$log"
exit 1
