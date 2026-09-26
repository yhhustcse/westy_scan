// Package favhash 实现 favicon 指纹哈希。
//
// 为什么要自己实现 MurmurHash3：favicon hash 是社区通行的资产关联手段
// （Shodan 的 http.favicon.hash、FOFA 的 icon_hash、hunter 的 web.icon），
// 而上游工具用的都是 python-mmh3 的 x86_32 实现。为了保持"零第三方依赖"，
// 这里按参考实现逐位复刻，并用已知向量做回归。
//
// 约定差异（很容易踩坑，务必分清）：
//   - Shodan：先对 favicon 字节做 base64（每 76 字符换行 + 结尾换行），再取 mmh3 x86_32 的**有符号**结果；
//   - FOFA/hunter：直接对 favicon 原始字节取 mmh3 x86_32 的有符号结果。
//
// 两种都提供，报告里分别标注，避免"哈希对不上"的排查成本。
package favhash

import (
	"encoding/base64"
	"encoding/binary"
)

// MMH3 计算 MurmurHash3 x86_32（seed=0），返回有符号 32 位整数。
//
// 与 python-mmh3 的 mmh3.hash(data) 完全一致：同样的乘法、轮转、尾块处理与最终混淆。
func MMH3(data []byte) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)

	h1 := uint32(0) // seed
	nblocks := len(data) / 4

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4 : i*4+4])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17) // ROTL32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19) // ROTL32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	// 尾块：把剩余 1-3 字节按小端拼进 k1
	var k1 uint32
	switch len(data) & 3 {
	case 3:
		k1 ^= uint32(data[nblocks*4+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(data[nblocks*4+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(data[nblocks*4])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// 最终混淆
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}

// ShodanHash 计算 Shodan 风格的 favicon 哈希（base64 后取 mmh3，有符号）。
func ShodanHash(favicon []byte) int32 {
	return MMH3([]byte(Base64Lines(favicon, 76)))
}

// RawHash 计算 FOFA/hunter 风格的哈希（原始字节直接取 mmh3，有符号）。
func RawHash(favicon []byte) int32 {
	return MMH3(favicon)
}

// Base64Lines 按 Python base64.encodebytes 的行为编码：
// 标准 base64 字母表，每 lineLen 个字符插入一个 '\n'，**结尾也补 '\n'**。
//
// 结尾那个换行是 Shodan 哈希对不上的最常见原因，不要"优化"掉。
func Base64Lines(data []byte, lineLen int) string {
	if lineLen <= 0 {
		lineLen = 76
	}
	enc := base64.StdEncoding.EncodeToString(data)
	if enc == "" {
		return ""
	}
	out := make([]byte, 0, len(enc)+len(enc)/lineLen+1)
	for len(enc) > lineLen {
		out = append(out, enc[:lineLen]...)
		out = append(out, '\n')
		enc = enc[lineLen:]
	}
	out = append(out, enc...)
	out = append(out, '\n')
	return string(out)
}
