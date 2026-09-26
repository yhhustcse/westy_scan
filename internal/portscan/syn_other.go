//go:build !linux

package portscan

import "fmt"

// NewSynScanner 在非 Linux 平台不可用。
//
// Windows / macOS 的原始套接字权限模型与收包语义差异较大，与其给出一份
// 未经充分验证的半成品，不如显式拒绝并让用户使用 connect 扫描。
func NewSynScanner() (Scanner, error) {
	return nil, fmt.Errorf("SYN 扫描目前仅支持 Linux（需要 root 或 CAP_NET_RAW）；当前平台请使用 -scan-mode connect")
}
