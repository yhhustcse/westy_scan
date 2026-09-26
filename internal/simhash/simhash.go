// Package simhash 提供 64 位 SimHash，用于识别"近似重复"的页面。
//
// 为什么需要它：真实站点有大量模板化页面（商品列表、分页、帮助中心），
// 它们内容 95% 相同但 URL 各不相同。如果不去重，报告会被几百条同质资产淹没，
// 真正的攻击面反而被埋掉。
//
// 实现要点：把文本切成 token → 每个 token 取 64 位哈希 →
// 按位加权求和（1 加 1、0 减 1）→ 取符号位。两段文本的相似度用汉明距离衡量，
// 经验阈值：距离 ≤ 3 视为近似重复。
package simhash

import (
	"hash/fnv"
	"math/bits"
	"strings"
	"unicode"
)

// Hash 计算文本的 64 位 SimHash。空文本返回 0。
func Hash(text string) uint64 {
	tokens := Tokenize(text)
	if len(tokens) == 0 {
		return 0
	}
	var weights [64]int
	for _, tok := range tokens {
		h := fnv1a(tok)
		for i := 0; i < 64; i++ {
			if h&(1<<uint(i)) != 0 {
				weights[i]++
			} else {
				weights[i]--
			}
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if weights[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

// Distance 返回两个 SimHash 的汉明距离（0 表示完全一致，64 表示毫不相干）。
func Distance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// Similar 判断两个哈希是否近似重复（默认阈值 3）。
func Similar(a, b uint64, threshold int) bool {
	if threshold <= 0 {
		threshold = 3
	}
	return Distance(a, b) <= threshold
}

// Tokenize 把文本切成 token：
//   - ASCII 字母数字连续段算一个词（转小写）；
//   - 每个汉字单独算一个 token（无需引入分词器，中文页面照样能算相似度）。
func Tokenize(text string) []string {
	out := make([]string, 0, len(text)/4+1)
	var buf []rune
	flush := func() {
		if len(buf) > 0 {
			out = append(out, string(buf))
			buf = buf[:0]
		}
	}
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.Is(unicode.Han, r):
			flush()
			out = append(out, string(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			buf = append(buf, r)
		default:
			flush()
		}
	}
	flush()
	return out
}

// PlainText 粗略地把 HTML 变成纯文本（只用于相似度计算，不做精确解析）：
// 去掉 script/style/注释，剥掉标签，压缩空白。
func PlainText(html []byte) string {
	s := string(html)
	s = reScript.ReplaceAllString(s, " ")
	s = reStyle.ReplaceAllString(s, " ")
	s = reComment.ReplaceAllString(s, " ")
	s = reTag.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	return strings.Join(strings.Fields(s), " ")
}

func fnv1a(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}
