package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// shortHash 生成 16 个十六进制字符的稳定短哈希（任务幂等键用）。
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func itoa(n int) string { return strconv.Itoa(n) }
