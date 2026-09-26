//go:build linux || darwin

// Package sysinfo 提供极简的系统资源探测，用于在启动时给出容量提示。
package sysinfo

import "syscall"

// FDSoftLimit 返回当前进程可打开的文件描述符软上限。
// 端口扫描每个并发连接占一个 fd，上限过低会直接导致大批连接失败。
func FDSoftLimit() (uint64, bool) {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0, false
	}
	return r.Cur, true
}
