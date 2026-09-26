// Package portscan 的可插拔扫描器抽象。
//
// 为什么要把扫描方式做成接口：
//   - connect 扫描（默认）：无需特权、跨平台，但每条连接都会被目标记录；
//   - SYN 半开扫描（Linux，需 CAP_NET_RAW）：快一个数量级、更隐蔽，但无法抓 Banner；
//   - 未来还可以加 UDP（见 internal/udpscan）、代理扫描、Masscan 式无状态扫描。
//
// 上层流水线只依赖 Scanner 接口，换实现不需要改任何编排代码。
package portscan

import (
	"context"
	"fmt"
	"strings"

	"westy_scan/internal/model"
	"westy_scan/internal/scope"
)

// 扫描方式。
const (
	ModeConnect = "connect"
	ModeSYN     = "syn"
)

// Scanner 是端口扫描器实现，必须并发安全且尊重 ctx 取消。
type Scanner interface {
	Name() string
	Scan(ctx context.Context, sc *scope.Scope, hosts []string, ports []int, opt Options) <-chan model.Asset
}

// NewScanner 按名称创建扫描器。unknown 会直接报错，避免静默降级成别的扫描方式。
func NewScanner(mode string) (Scanner, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeConnect:
		return ConnectScanner{}, nil
	case ModeSYN:
		return NewSynScanner()
	default:
		return nil, fmt.Errorf("未知扫描方式 %q（可选 %s / %s）", mode, ModeConnect, ModeSYN)
	}
}

// Scan 用默认的 connect 扫描器，保留兼容入口。
func Scan(ctx context.Context, sc *scope.Scope, hosts []string, ports []int, opt Options) <-chan model.Asset {
	return ConnectScanner{}.Scan(ctx, sc, hosts, ports, opt)
}
