//go:build !linux && !darwin

// Package sysinfo 提供极简的系统资源探测，用于在启动时给出容量提示。
package sysinfo

// FDSoftLimit 在 Windows 上不适用（无 RLIMIT_NOFILE 概念），返回 false。
func FDSoftLimit() (uint64, bool) {
	return 0, false
}
